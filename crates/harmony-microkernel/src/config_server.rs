// SPDX-License-Identifier: GPL-2.0-or-later
//! ConfigServer — 9P file server for declarative node configuration.
//! Mounted at `/env/config`, provides two-phase activation:
//! stage (validate + verify) → commit (atomic pointer swap) → rollback.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::content_server::{format_cid_hex, parse_hex_cid, slice_data, ContentServer};
use crate::fid_tracker::FidTracker;
use crate::node_config::NodeConfig;
use crate::signed_config::{SignedConfig, SignedConfigError};
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

// ── QPath constants ──────────────────────────────────────────────────

const ROOT: QPath = 0;
const ACTIVE: QPath = 1;
const PENDING: QPath = 2;
const PREVIOUS: QPath = 3;
const STAGE: QPath = 4;
const COMMIT: QPath = 5;
const ROLLBACK: QPath = 6;
const NODE_CBOR: QPath = 7;
const STATE: QPath = 8;

// ── Node taxonomy ────────────────────────────────────────────────────

/// What kind of virtual-filesystem node a fid points at.
#[derive(Debug, Clone)]
enum NodeKind {
    Root,
    Active,
    Pending,
    Previous,
    Stage,
    Commit,
    Rollback,
    NodeCbor,
    State,
}

// ── State serialization ───────────────────────────────────────────────

/// Serializable snapshot of transferable `ConfigServer` state.
/// The `cas` Arc is excluded — it is infrastructure wiring, not server state.
#[derive(Serialize, Deserialize)]
struct ConfigServerState {
    trusted_operators: Vec<[u8; 16]>,
    active_cid: Option<[u8; 32]>,
    active_config: Option<NodeConfig>,
    pending_cid: Option<[u8; 32]>,
    pending_config: Option<NodeConfig>,
    previous_cid: Option<[u8; 32]>,
    previous_config: Option<NodeConfig>,
}

// ── ConfigServer ─────────────────────────────────────────────────────

/// A 9P file server for two-phase declarative node configuration.
///
/// Exposes the following virtual filesystem:
///
/// ```text
/// /
/// ├── active    — hex CID of the active SignedConfig envelope in the CAS (read-only)
/// ├── pending   — hex CID of the staged SignedConfig envelope (read-only)
/// ├── previous  — hex CID of the previous SignedConfig envelope (read-only)
/// ├── stage     — ctl-file: write a hex CID to stage it (validates + verifies)
/// ├── commit    — ctl-file: write any byte to atomically commit pending → active
/// ├── rollback  — ctl-file: write any byte to swap active ↔ previous
/// └── node.cbor — inner NodeConfig CBOR extracted from the active SignedConfig (read-only)
/// ```
///
/// **CID semantics:** `active`/`pending`/`previous` return the CID of the
/// outer `SignedConfig` envelope (what's stored in the CAS). `node.cbor`
/// returns the inner `NodeConfig` CBOR bytes; its SHA-256 hash will differ
/// from the `active` CID. To verify the inner config against the CAS, fetch
/// the `SignedConfig` by the `active` CID and extract `config_bytes`.
pub struct ConfigServer {
    cas: Arc<ContentServer>,
    tracker: FidTracker<NodeKind>,
    trusted_operators: Vec<[u8; 16]>,
    active_cid: Option<[u8; 32]>,
    active_config: Option<NodeConfig>,
    pending_cid: Option<[u8; 32]>,
    pending_config: Option<NodeConfig>,
    previous_cid: Option<[u8; 32]>,
    previous_config: Option<NodeConfig>,
}

impl ConfigServer {
    /// Create a new `ConfigServer` backed by the given CAS and trusted operator list.
    pub fn new(cas: Arc<ContentServer>, trusted_operators: Vec<[u8; 16]>) -> Self {
        Self {
            cas,
            tracker: FidTracker::new(ROOT, NodeKind::Root),
            trusted_operators,
            active_cid: None,
            active_config: None,
            pending_cid: None,
            pending_config: None,
            previous_cid: None,
            previous_config: None,
        }
    }

    /// Stage a config by its hex CID.
    ///
    /// Validates the pipeline:
    /// 1. Parse hex CID.
    /// 2. Fetch signed config bytes from CAS.
    /// 3. Deserialize `SignedConfig`.
    /// 4. Verify signature against trusted operators.
    /// 5. Deserialize the embedded `NodeConfig`.
    /// 6. Validate service entries (count, name length, uniqueness).
    /// 7. Verify all referenced CIDs exist in CAS.
    /// 8. Store as pending (unconditionally overwrites any existing
    ///    pending config — single-actor design, no concurrent staging).
    fn do_stage(&mut self, cid_hex: &str) -> Result<(), IpcError> {
        // 1. Parse hex CID.
        let cid = parse_hex_cid(cid_hex.trim()).ok_or(IpcError::InvalidArgument)?;

        // 2. Fetch signed config bytes from CAS.
        let bytes = self.cas.get_book_bytes(&cid).ok_or(IpcError::NotFound)?;

        // 3. Deserialize SignedConfig.
        let signed = SignedConfig::from_cbor(&bytes).map_err(|_| IpcError::InvalidArgument)?;

        // 4. Verify signature against trusted operators.
        signed
            .verify(&self.trusted_operators)
            .map_err(|e| match e {
                // All authentication failures → PermissionDenied to avoid
                // leaking which step failed (oracle resistance).
                SignedConfigError::UntrustedSigner
                | SignedConfigError::AddressMismatch
                | SignedConfigError::SignatureInvalid(_) => IpcError::PermissionDenied,
                // Structural/parsing failures → InvalidArgument.
                SignedConfigError::DeserializeFailed(_)
                | SignedConfigError::InvalidPublicKey(_) => IpcError::InvalidArgument,
            })?;

        // 5. Deserialize the embedded NodeConfig.
        let config =
            NodeConfig::from_cbor(&signed.config_bytes).map_err(|_| IpcError::InvalidArgument)?;

        if config.version != crate::node_config::SCHEMA_VERSION {
            return Err(IpcError::InvalidArgument);
        }

        // 6a. Reject oversized service lists — bounds the CAS-probe loop
        //     below and limits resource consumption from a single config.
        const MAX_SERVICES: usize = 256;
        if config.services.len() > MAX_SERVICES {
            return Err(IpcError::InvalidArgument);
        }

        // 6b. Reject invalid service names: empty, too long, or duplicate.
        const MAX_SERVICE_NAME_LEN: usize = 64;
        {
            let mut seen = alloc::collections::BTreeSet::new();
            for svc in &config.services {
                if svc.name.is_empty()
                    || svc.name.len() > MAX_SERVICE_NAME_LEN
                    || !seen.insert(svc.name.as_str())
                {
                    return Err(IpcError::InvalidArgument);
                }
            }
        }

        // 6c. Verify all referenced CIDs exist in CAS.
        if !self.cas.has_book(&config.kernel) {
            return Err(IpcError::NotFound);
        }
        if !self.cas.has_book(&config.identity) {
            return Err(IpcError::NotFound);
        }
        for service in &config.services {
            if !self.cas.has_book(&service.binary) {
                return Err(IpcError::NotFound);
            }
            if let Some(cfg_cid) = &service.config {
                if !self.cas.has_book(cfg_cid) {
                    return Err(IpcError::NotFound);
                }
            }
        }

        // 7. Store as pending.
        self.pending_cid = Some(cid);
        self.pending_config = Some(config);
        Ok(())
    }

    /// Commit the pending config: active → previous, pending → active.
    ///
    /// Requires a pending config to be staged; returns `InvalidArgument` if none.
    fn do_commit(&mut self) -> Result<(), IpcError> {
        // Validate both fields present before mutating — avoids silently
        // dropping pending_cid if pending_config is somehow None.
        if self.pending_cid.is_none() || self.pending_config.is_none() {
            return Err(IpcError::InvalidArgument);
        }
        let pending_cid = self.pending_cid.take().unwrap();
        let pending_config = self.pending_config.take().unwrap();

        // Rotate: active → previous.
        self.previous_cid = self.active_cid.take();
        self.previous_config = self.active_config.take();

        // Pending → active.
        self.active_cid = Some(pending_cid);
        self.active_config = Some(pending_config);

        Ok(())
    }

    /// Rollback: swap active ↔ previous.
    ///
    /// Requires a previous config; returns `InvalidArgument` if none.
    /// Any staged-but-uncommitted pending config is preserved — a caller
    /// can rollback and then immediately commit the pending config.
    fn do_rollback(&mut self) -> Result<(), IpcError> {
        if self.previous_cid.is_none() || self.previous_config.is_none() {
            return Err(IpcError::InvalidArgument);
        }

        core::mem::swap(&mut self.active_cid, &mut self.previous_cid);
        core::mem::swap(&mut self.active_config, &mut self.previous_config);

        Ok(())
    }

    /// Return the hex CID bytes for a slot, or an empty vec if unset.
    fn cid_hex_bytes(cid: &Option<[u8; 32]>) -> Vec<u8> {
        match cid {
            Some(c) => format_cid_hex(c).into_bytes(),
            None => Vec::new(),
        }
    }
}

// ── FileServer impl ──────────────────────────────────────────────────

impl FileServer for ConfigServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        let parent_node = entry.payload.clone();

        let (qpath, node) = match &parent_node {
            NodeKind::Root => match name {
                "active" => (ACTIVE, NodeKind::Active),
                "pending" => (PENDING, NodeKind::Pending),
                "previous" => (PREVIOUS, NodeKind::Previous),
                "stage" => (STAGE, NodeKind::Stage),
                "commit" => (COMMIT, NodeKind::Commit),
                "rollback" => (ROLLBACK, NodeKind::Rollback),
                "node.cbor" => (NODE_CBOR, NodeKind::NodeCbor),
                "state" => (STATE, NodeKind::State),
                _ => return Err(IpcError::NotFound),
            },
            // All non-root nodes are leaves — cannot walk into them.
            NodeKind::Active
            | NodeKind::Pending
            | NodeKind::Previous
            | NodeKind::Stage
            | NodeKind::Commit
            | NodeKind::Rollback
            | NodeKind::NodeCbor
            | NodeKind::State => return Err(IpcError::NotDirectory),
        };

        self.tracker.insert(new_fid, qpath, node)?;
        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        match &entry.payload {
            // Root is a directory — read-only.
            NodeKind::Root => {
                if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
                    return Err(IpcError::IsDirectory);
                }
            }
            // Read-only files.
            NodeKind::Active | NodeKind::Pending | NodeKind::Previous | NodeKind::NodeCbor => {
                if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
                    return Err(IpcError::ReadOnly);
                }
            }
            // Write-only ctl-files.
            NodeKind::Stage | NodeKind::Commit | NodeKind::Rollback => {
                if !matches!(mode, OpenMode::Write) {
                    return Err(IpcError::PermissionDenied);
                }
            }
            // State allows Read, Write, and ReadWrite.
            NodeKind::State => {}
        }
        entry.mark_open(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        // Write-only files cannot be read.
        if matches!(entry.mode(), Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }
        let node = entry.payload.clone();
        match &node {
            NodeKind::Root => Err(IpcError::IsDirectory),
            NodeKind::Active => {
                let data = Self::cid_hex_bytes(&self.active_cid);
                Ok(slice_data(&data, offset, count))
            }
            NodeKind::Pending => {
                let data = Self::cid_hex_bytes(&self.pending_cid);
                Ok(slice_data(&data, offset, count))
            }
            NodeKind::Previous => {
                let data = Self::cid_hex_bytes(&self.previous_cid);
                Ok(slice_data(&data, offset, count))
            }
            NodeKind::NodeCbor => {
                let data = match &self.active_config {
                    Some(cfg) => cfg.to_cbor(),
                    None => Vec::new(),
                };
                Ok(slice_data(&data, offset, count))
            }
            // Write-only nodes — already handled above, but exhaustive match.
            NodeKind::Stage | NodeKind::Commit | NodeKind::Rollback => Err(IpcError::ReadOnly),
            NodeKind::State => {
                let state = ConfigServerState {
                    trusted_operators: self.trusted_operators.clone(),
                    active_cid: self.active_cid,
                    active_config: self.active_config.clone(),
                    pending_cid: self.pending_cid,
                    pending_config: self.pending_config.clone(),
                    previous_cid: self.previous_cid,
                    previous_config: self.previous_config.clone(),
                };
                let mut buf = Vec::new();
                ciborium::into_writer(&state, &mut buf).map_err(|_| IpcError::ResourceExhausted)?;
                Ok(slice_data(&buf, offset, count))
            }
        }
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        // Read-only files cannot be written.
        if matches!(entry.mode(), Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }
        let node = entry.payload.clone();
        let written = u32::try_from(data.len()).map_err(|_| IpcError::ResourceExhausted)?;
        match &node {
            NodeKind::Root => Err(IpcError::IsDirectory),
            NodeKind::Active | NodeKind::Pending | NodeKind::Previous | NodeKind::NodeCbor => {
                Err(IpcError::ReadOnly)
            }
            NodeKind::Stage => {
                let hex = core::str::from_utf8(data).map_err(|_| IpcError::InvalidArgument)?;
                self.do_stage(hex)?;
                Ok(written)
            }
            NodeKind::Commit => {
                self.do_commit()?;
                Ok(written)
            }
            NodeKind::Rollback => {
                self.do_rollback()?;
                Ok(written)
            }
            NodeKind::State => {
                // NOTE: State restore bypasses do_stage validation (signature
                // verification, schema version check, CAS reference checks).
                // This is intentional — /state is a trusted kernel-internal
                // operation. The data was serialized from a ConfigServer that
                // already validated everything. Re-validation would require
                // CAS access which isn't available during state transfer.
                let state: ConfigServerState =
                    ciborium::from_reader(data).map_err(|_| IpcError::InvalidArgument)?;
                self.trusted_operators = state.trusted_operators;
                self.active_cid = state.active_cid;
                self.active_config = state.active_config;
                self.pending_cid = state.pending_cid;
                self.pending_config = state.pending_config;
                self.previous_cid = state.previous_cid;
                self.previous_config = state.previous_config;
                Ok(written)
            }
        }
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        let node = entry.payload.clone();
        match &node {
            NodeKind::Root => Ok(FileStat {
                qpath: ROOT,
                name: Arc::from("config"),
                size: 0,
                file_type: FileType::Directory,
            }),
            NodeKind::Active => Ok(FileStat {
                qpath: ACTIVE,
                name: Arc::from("active"),
                size: self.active_cid.map(|_| 64).unwrap_or(0),
                file_type: FileType::Regular,
            }),
            NodeKind::Pending => Ok(FileStat {
                qpath: PENDING,
                name: Arc::from("pending"),
                size: self.pending_cid.map(|_| 64).unwrap_or(0),
                file_type: FileType::Regular,
            }),
            NodeKind::Previous => Ok(FileStat {
                qpath: PREVIOUS,
                name: Arc::from("previous"),
                size: self.previous_cid.map(|_| 64).unwrap_or(0),
                file_type: FileType::Regular,
            }),
            NodeKind::Stage => Ok(FileStat {
                qpath: STAGE,
                name: Arc::from("stage"),
                size: 0,
                file_type: FileType::Regular,
            }),
            NodeKind::Commit => Ok(FileStat {
                qpath: COMMIT,
                name: Arc::from("commit"),
                size: 0,
                file_type: FileType::Regular,
            }),
            NodeKind::Rollback => Ok(FileStat {
                qpath: ROLLBACK,
                name: Arc::from("rollback"),
                size: 0,
                file_type: FileType::Regular,
            }),
            NodeKind::NodeCbor => Ok(FileStat {
                qpath: NODE_CBOR,
                name: Arc::from("node.cbor"),
                // Note: re-serializes CBOR on every stat. Configs are <1KB
                // and stat on this file is rare, so caching is not worth the
                // state management complexity. Revisit if this becomes a hot path.
                size: self
                    .active_config
                    .as_ref()
                    .map(|c| c.to_cbor().len() as u64)
                    .unwrap_or(0),
                file_type: FileType::Regular,
            }),
            NodeKind::State => Ok(FileStat {
                qpath: STATE,
                name: Arc::from("state"),
                size: 0,
                file_type: FileType::Regular,
            }),
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_config::{NetworkConfig, NodeConfig, ServiceEntry, SCHEMA_VERSION};
    use crate::signed_config::SignedConfig;
    use harmony_identity::PqPrivateIdentity;
    use rand::rngs::OsRng;

    // ── Test helpers ──────────────────────────────────────────────────

    /// Ingest raw bytes into `ContentServer` via 9P, returning the CID.
    fn ingest_book(cas: &mut ContentServer, data: &[u8]) -> [u8; 32] {
        // Walk to ingest, open ReadWrite, write data, read response (40 bytes).
        // Use a fresh fid each time — pick one above 100 to avoid collisions.
        static FID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(100);
        let fid = FID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        cas.walk(0, fid, "ingest").unwrap();
        cas.open(fid, OpenMode::ReadWrite).unwrap();
        cas.write(fid, 0, data).unwrap();
        let response = cas.read(fid, 0, 40).unwrap();
        cas.clunk(fid).unwrap();

        response[..32].try_into().unwrap()
    }

    /// Sign a `NodeConfig` and ingest the resulting `SignedConfig` into the CAS.
    /// Returns the CID of the ingested `SignedConfig`.
    fn sign_and_ingest(
        cas: &mut ContentServer,
        config: &NodeConfig,
        signer: &PqPrivateIdentity,
    ) -> [u8; 32] {
        let config_bytes = config.to_cbor();
        let signature = signer.sign(&config_bytes).expect("signing must succeed");
        let pub_id = signer.public_identity();
        let signed = SignedConfig {
            config_bytes,
            signature,
            signer: pub_id.address_hash,
            signer_pubkey: pub_id.to_public_bytes(),
        };
        let cbor = signed.to_cbor();
        ingest_book(cas, &cbor)
    }

    /// Build a minimal `NodeConfig` that references already-ingested CIDs.
    fn make_config(kernel: [u8; 32], identity: [u8; 32]) -> NodeConfig {
        NodeConfig {
            version: SCHEMA_VERSION,
            kernel,
            identity,
            network: NetworkConfig {
                mesh_seeds: alloc::vec![],
                port: 7777,
            },
            services: alloc::vec![],
        }
    }

    /// Set up a `ContentServer` with stub books and a signed config.
    ///
    /// Returns:
    /// - A `ContentServer` (wrapped in `Arc` after mutating)
    /// - The CID of the ingested `SignedConfig`
    /// - The trusted operator list (single signer)
    fn setup() -> (Arc<ContentServer>, [u8; 32], Vec<[u8; 16]>) {
        let mut cas = ContentServer::new();

        // Ingest stub kernel and identity books.
        let kernel_cid = ingest_book(&mut cas, b"stub-kernel-binary");
        let identity_cid = ingest_book(&mut cas, b"stub-identity-blob");

        // Build and sign a NodeConfig referencing those CIDs.
        let config = make_config(kernel_cid, identity_cid);
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let signed_cid = sign_and_ingest(&mut cas, &config, &signer);

        let trusted = alloc::vec![signer.public_identity().address_hash];
        (Arc::new(cas), signed_cid, trusted)
    }

    /// Write a hex CID to the `stage` ctl-file.
    fn stage_config(server: &mut ConfigServer, cid: &[u8; 32]) -> Result<(), IpcError> {
        let hex = format_cid_hex(cid);
        server.walk(0, 10, "stage").unwrap();
        server.open(10, OpenMode::Write).unwrap();
        let result = server.write(10, 0, hex.as_bytes()).map(|_| ());
        server.clunk(10).unwrap();
        result
    }

    /// Write "1" to the `commit` ctl-file.
    fn commit(server: &mut ConfigServer) -> Result<(), IpcError> {
        server.walk(0, 11, "commit").unwrap();
        server.open(11, OpenMode::Write).unwrap();
        let result = server.write(11, 0, b"1").map(|_| ());
        server.clunk(11).unwrap();
        result
    }

    /// Write "1" to the `rollback` ctl-file.
    fn rollback(server: &mut ConfigServer) -> Result<(), IpcError> {
        server.walk(0, 12, "rollback").unwrap();
        server.open(12, OpenMode::Write).unwrap();
        let result = server.write(12, 0, b"1").map(|_| ());
        server.clunk(12).unwrap();
        result
    }

    /// Read the `active` file and return its bytes.
    fn read_active(server: &mut ConfigServer) -> Vec<u8> {
        server.walk(0, 13, "active").unwrap();
        server.open(13, OpenMode::Read).unwrap();
        let data = server.read(13, 0, 128).unwrap();
        server.clunk(13).unwrap();
        data
    }

    // ── Tests ─────────────────────────────────────────────────────────

    #[test]
    fn stage_commit_read_active() {
        let (cas, signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        stage_config(&mut server, &signed_cid).expect("stage must succeed");
        commit(&mut server).expect("commit must succeed");

        let active = read_active(&mut server);
        assert_eq!(active, format_cid_hex(&signed_cid).into_bytes());
    }

    #[test]
    fn commit_without_pending_fails() {
        let (cas, _, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        let result = commit(&mut server);
        assert_eq!(result, Err(IpcError::InvalidArgument));
    }

    #[test]
    fn rollback_without_previous_fails() {
        let (cas, signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        // Even after one commit, there is no previous yet.
        stage_config(&mut server, &signed_cid).unwrap();
        commit(&mut server).unwrap();

        // No previous exists — rollback must fail.
        let result = rollback(&mut server);
        assert_eq!(result, Err(IpcError::InvalidArgument));
    }

    #[test]
    fn rollback_swaps_active_and_previous() {
        // Need two different configs with their own stub books.
        let mut cas = ContentServer::new();

        let kernel1_cid = ingest_book(&mut cas, b"kernel-v1");
        let identity1_cid = ingest_book(&mut cas, b"identity-v1");
        let kernel2_cid = ingest_book(&mut cas, b"kernel-v2");
        let identity2_cid = ingest_book(&mut cas, b"identity-v2");

        let config1 = make_config(kernel1_cid, identity1_cid);
        let config2 = make_config(kernel2_cid, identity2_cid);

        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let cid1 = sign_and_ingest(&mut cas, &config1, &signer);
        let cid2 = sign_and_ingest(&mut cas, &config2, &signer);

        let trusted = alloc::vec![signer.public_identity().address_hash];
        let cas = Arc::new(cas);
        let mut server = ConfigServer::new(cas, trusted);

        // Commit config1.
        stage_config(&mut server, &cid1).unwrap();
        commit(&mut server).unwrap();

        // Commit config2. Now: active=config2, previous=config1.
        stage_config(&mut server, &cid2).unwrap();
        commit(&mut server).unwrap();

        // Rollback: active should become config1.
        rollback(&mut server).expect("first rollback must succeed");
        let active = read_active(&mut server);
        assert_eq!(active, format_cid_hex(&cid1).into_bytes());

        // Second rollback toggles back to config2.
        rollback(&mut server).expect("second rollback must succeed");
        let active = read_active(&mut server);
        assert_eq!(active, format_cid_hex(&cid2).into_bytes());
    }

    #[test]
    fn active_empty_before_any_config() {
        let (cas, _, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        let active = read_active(&mut server);
        assert!(active.is_empty(), "active must be empty before any commit");
    }

    #[test]
    fn stage_bad_cid_fails() {
        let (cas, _, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        // Use a valid hex CID that is NOT in the CAS.
        let nonexistent_cid = [0xDEu8; 32];
        let result = stage_config(&mut server, &nonexistent_cid);
        assert_eq!(result, Err(IpcError::NotFound));
    }

    #[test]
    fn pending_set_after_stage() {
        let (cas, signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        stage_config(&mut server, &signed_cid).unwrap();

        // Read pending — should be the hex CID.
        server.walk(0, 20, "pending").unwrap();
        server.open(20, OpenMode::Read).unwrap();
        let pending = server.read(20, 0, 128).unwrap();
        server.clunk(20).unwrap();

        assert_eq!(pending, format_cid_hex(&signed_cid).into_bytes());
    }

    #[test]
    fn pending_cleared_after_commit() {
        let (cas, signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        stage_config(&mut server, &signed_cid).unwrap();
        commit(&mut server).unwrap();

        // Pending should now be empty.
        server.walk(0, 21, "pending").unwrap();
        server.open(21, OpenMode::Read).unwrap();
        let pending = server.read(21, 0, 128).unwrap();
        server.clunk(21).unwrap();

        assert!(pending.is_empty(), "pending must be empty after commit");
    }

    #[test]
    fn read_node_cbor_after_commit() {
        let (cas, signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        stage_config(&mut server, &signed_cid).unwrap();
        commit(&mut server).unwrap();

        // Read node.cbor.
        server.walk(0, 22, "node.cbor").unwrap();
        server.open(22, OpenMode::Read).unwrap();
        let cbor = server.read(22, 0, 4096).unwrap();
        server.clunk(22).unwrap();

        assert!(!cbor.is_empty(), "node.cbor must not be empty after commit");

        // Decode must succeed and produce a valid NodeConfig.
        let decoded = NodeConfig::from_cbor(&cbor).expect("node.cbor must decode to NodeConfig");
        assert_eq!(decoded.version, SCHEMA_VERSION);
    }

    #[test]
    fn stage_with_service_entries() {
        let mut cas = ContentServer::new();

        let kernel_cid = ingest_book(&mut cas, b"kernel-bin");
        let identity_cid = ingest_book(&mut cas, b"identity-bin");
        let service_bin_cid = ingest_book(&mut cas, b"service-binary");
        let service_cfg_cid = ingest_book(&mut cas, b"service-config");

        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: kernel_cid,
            identity: identity_cid,
            network: NetworkConfig {
                mesh_seeds: alloc::vec![],
                port: 9999,
            },
            services: alloc::vec![ServiceEntry {
                name: alloc::string::String::from("test-service"),
                binary: service_bin_cid,
                config: Some(service_cfg_cid),
            }],
        };

        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let signed_cid = sign_and_ingest(&mut cas, &config, &signer);
        let trusted = alloc::vec![signer.public_identity().address_hash];
        let cas = Arc::new(cas);
        let mut server = ConfigServer::new(cas, trusted);

        stage_config(&mut server, &signed_cid).expect("stage with service entries must succeed");
        commit(&mut server).unwrap();

        let active = read_active(&mut server);
        assert_eq!(active, format_cid_hex(&signed_cid).into_bytes());
    }

    #[test]
    fn stage_missing_service_binary_fails() {
        let mut cas = ContentServer::new();

        let kernel_cid = ingest_book(&mut cas, b"kernel-bin");
        let identity_cid = ingest_book(&mut cas, b"identity-bin");
        // Intentionally NOT ingesting the service binary.
        let fake_service_bin = [0xAAu8; 32];

        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: kernel_cid,
            identity: identity_cid,
            network: NetworkConfig {
                mesh_seeds: alloc::vec![],
                port: 9999,
            },
            services: alloc::vec![ServiceEntry {
                name: alloc::string::String::from("broken-service"),
                binary: fake_service_bin,
                config: None,
            }],
        };

        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let signed_cid = sign_and_ingest(&mut cas, &config, &signer);
        let trusted = alloc::vec![signer.public_identity().address_hash];
        let cas = Arc::new(cas);
        let mut server = ConfigServer::new(cas, trusted);

        let result = stage_config(&mut server, &signed_cid);
        assert_eq!(result, Err(IpcError::NotFound));
    }

    #[test]
    fn stage_untrusted_signer_fails() {
        // Sign with a valid identity, but DON'T include it in trusted_operators
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let _pub_id = signer.public_identity();

        let mut cas = ContentServer::new();
        let kernel_cid = ingest_book(&mut cas, &alloc::vec![0x4Bu8; 4096]);
        let identity_cid = ingest_book(&mut cas, &alloc::vec![0x49u8; 4096]);

        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: kernel_cid,
            identity: identity_cid,
            network: NetworkConfig {
                mesh_seeds: vec![],
                port: 4242,
            },
            services: vec![],
        };

        let signed_cid = sign_and_ingest(&mut cas, &config, &signer);

        // Use an EMPTY trusted list — signer is not trusted
        let cas = Arc::new(cas);
        let mut server = ConfigServer::new(cas, vec![]);

        assert_eq!(
            stage_config(&mut server, &signed_cid),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn stage_duplicate_service_names_rejected() {
        let mut cas = ContentServer::new();
        let kernel_cid = ingest_book(&mut cas, b"kernel-bin");
        let identity_cid = ingest_book(&mut cas, b"identity-bin");
        let bin1 = ingest_book(&mut cas, b"binary-one");
        let bin2 = ingest_book(&mut cas, b"binary-two");

        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: kernel_cid,
            identity: identity_cid,
            network: NetworkConfig {
                mesh_seeds: alloc::vec![],
                port: 4242,
            },
            services: alloc::vec![
                ServiceEntry {
                    name: alloc::string::String::from("echo"),
                    binary: bin1,
                    config: None,
                },
                ServiceEntry {
                    name: alloc::string::String::from("echo"), // duplicate
                    binary: bin2,
                    config: None,
                },
            ],
        };

        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let signed_cid = sign_and_ingest(&mut cas, &config, &signer);
        let trusted = alloc::vec![signer.public_identity().address_hash];
        let cas = Arc::new(cas);
        let mut server = ConfigServer::new(cas, trusted);

        assert_eq!(
            stage_config(&mut server, &signed_cid),
            Err(IpcError::InvalidArgument)
        );
    }

    #[test]
    fn stage_empty_service_name_rejected() {
        let mut cas = ContentServer::new();
        let kernel_cid = ingest_book(&mut cas, b"kernel-bin");
        let identity_cid = ingest_book(&mut cas, b"identity-bin");
        let bin = ingest_book(&mut cas, b"binary-one");

        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: kernel_cid,
            identity: identity_cid,
            network: NetworkConfig {
                mesh_seeds: alloc::vec![],
                port: 4242,
            },
            services: alloc::vec![ServiceEntry {
                name: alloc::string::String::new(), // empty
                binary: bin,
                config: None,
            }],
        };

        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let signed_cid = sign_and_ingest(&mut cas, &config, &signer);
        let trusted = alloc::vec![signer.public_identity().address_hash];
        let cas = Arc::new(cas);
        let mut server = ConfigServer::new(cas, trusted);

        assert_eq!(
            stage_config(&mut server, &signed_cid),
            Err(IpcError::InvalidArgument)
        );
    }

    #[test]
    fn stage_too_many_services_rejected() {
        let mut cas = ContentServer::new();
        let kernel_cid = ingest_book(&mut cas, b"kernel-bin");
        let identity_cid = ingest_book(&mut cas, b"identity-bin");
        let bin = ingest_book(&mut cas, b"binary-one");

        let services: Vec<ServiceEntry> = (0..257)
            .map(|i| ServiceEntry {
                name: alloc::format!("svc-{i}"),
                binary: bin,
                config: None,
            })
            .collect();

        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: kernel_cid,
            identity: identity_cid,
            network: NetworkConfig {
                mesh_seeds: alloc::vec![],
                port: 4242,
            },
            services,
        };

        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let signed_cid = sign_and_ingest(&mut cas, &config, &signer);
        let trusted = alloc::vec![signer.public_identity().address_hash];
        let cas = Arc::new(cas);
        let mut server = ConfigServer::new(cas, trusted);

        assert_eq!(
            stage_config(&mut server, &signed_cid),
            Err(IpcError::InvalidArgument)
        );
    }

    #[test]
    fn stage_overlong_service_name_rejected() {
        let mut cas = ContentServer::new();
        let kernel_cid = ingest_book(&mut cas, b"kernel-bin");
        let identity_cid = ingest_book(&mut cas, b"identity-bin");
        let bin = ingest_book(&mut cas, b"binary-one");

        let long_name: alloc::string::String = alloc::string::String::from("x").repeat(65);
        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: kernel_cid,
            identity: identity_cid,
            network: NetworkConfig {
                mesh_seeds: alloc::vec![],
                port: 4242,
            },
            services: alloc::vec![ServiceEntry {
                name: long_name,
                binary: bin,
                config: None,
            }],
        };

        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let signed_cid = sign_and_ingest(&mut cas, &config, &signer);
        let trusted = alloc::vec![signer.public_identity().address_hash];
        let cas = Arc::new(cas);
        let mut server = ConfigServer::new(cas, trusted);

        assert_eq!(
            stage_config(&mut server, &signed_cid),
            Err(IpcError::InvalidArgument)
        );
    }

    #[test]
    fn state_round_trip() {
        let (cas, signed_cid, trusted) = setup();
        let mut old = ConfigServer::new(cas.clone(), trusted.clone());

        // Stage + commit a config
        stage_config(&mut old, &signed_cid).unwrap();
        commit(&mut old).unwrap();

        // Read state
        old.walk(0, 20, "state").unwrap();
        old.open(20, OpenMode::Read).unwrap();
        let state_bytes = old.read(20, 0, 4 * 1024 * 1024).unwrap();
        old.clunk(20).unwrap();

        // Write state to new server (same CAS Arc)
        let mut new_srv = ConfigServer::new(cas, trusted);
        new_srv.walk(0, 21, "state").unwrap();
        new_srv.open(21, OpenMode::Write).unwrap();
        new_srv.write(21, 0, &state_bytes).unwrap();
        new_srv.clunk(21).unwrap();

        // Verify: active CID matches
        let active = read_active(&mut new_srv);
        let expected = format_cid_hex(&signed_cid);
        assert_eq!(core::str::from_utf8(&active).unwrap(), &expected);
    }

    #[test]
    fn state_walk_exists() {
        let (cas, _signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);
        server.walk(0, 1, "state").unwrap();
    }
}
