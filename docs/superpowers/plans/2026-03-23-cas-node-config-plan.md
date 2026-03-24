# CAS NodeConfig Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement declarative node configuration via content-addressed CBOR bundles with ML-DSA-65 signature verification and two-phase activation via a 9P ConfigServer.

**Architecture:** Types + validation in Ring 2 (`harmony-microkernel`), application logic in Ring 3 (`harmony-os`). NodeConfig is CBOR-serialized, signed in a `SignedConfig` envelope, stored as books in the existing CAS, and distributed via Zenoh. ConfigServer exposes `/env/config` as a 9P filesystem for stage→commit→rollback lifecycle.

**Tech Stack:** Rust, `serde` + `ciborium` (CBOR), `harmony-identity` (ML-DSA-65 PQ crypto), `harmony-athenaeum` (CAS), 9P `FileServer` trait.

**Spec:** `docs/superpowers/specs/2026-03-23-cas-node-config-design.md`

---

### Task 1: Add serde + ciborium workspace dependencies

**Files:**
- Modify: `Cargo.toml` (workspace root, lines 22-53)
- Modify: `crates/harmony-microkernel/Cargo.toml` (lines 10-36)

- [ ] **Step 1: Add workspace dependencies**

In root `Cargo.toml`, add to `[workspace.dependencies]`:

```toml
serde = { version = "1", default-features = false, features = ["derive", "alloc"] }
ciborium = { version = "0.2", default-features = false }
```

- [ ] **Step 2: Wire into harmony-microkernel**

In `crates/harmony-microkernel/Cargo.toml`:

Add to the `kernel` feature list:
```toml
"dep:serde",
"dep:ciborium",
```

Add to `[dependencies]`:
```toml
serde = { workspace = true, optional = true }
ciborium = { workspace = true, optional = true }
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p harmony-microkernel`
Expected: compiles with no errors.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/harmony-microkernel/Cargo.toml
git commit -m "build: add serde + ciborium workspace deps for CBOR config serialization"
```

---

### Task 2: NodeConfig types + CBOR serialization (`node_config.rs`)

**Files:**
- Create: `crates/harmony-microkernel/src/node_config.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add module declaration)

**Context:**
- This file lives in Ring 2 (`harmony-microkernel`), gated behind `#[cfg(feature = "kernel")]` like `content_server`, `key_hierarchy`, etc.
- Uses `serde::{Serialize, Deserialize}` derives with `ciborium` for CBOR encoding.
- CID = `sha256_hash(cbor_bytes)` using `harmony_athenaeum::sha256_hash`.
- All types use `alloc` (no `std` required): `Vec`, `String` from `alloc`.
- Add SPDX license header `// SPDX-License-Identifier: GPL-2.0-or-later` to all new files.

- [ ] **Step 1: Write failing tests**

Create `crates/harmony-microkernel/src/node_config.rs` with the test module first:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! NodeConfig — declarative node configuration types with CBOR serialization.
//!
//! Every node's running state is determined by a single `NodeConfig` whose
//! CBOR encoding produces a stable content ID (CID = SHA-256 of CBOR bytes).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use harmony_athenaeum::sha256_hash;

/// Current schema version. Increment on breaking changes.
pub const SCHEMA_VERSION: u32 = 1;

// Struct definitions go here in step 3...

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> NodeConfig {
        NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [0xAA; 32],
            identity: [0xBB; 32],
            network: NetworkConfig {
                mesh_seeds: vec![[0xCC; 16], [0xDD; 16]],
                port: 4242,
            },
            services: vec![ServiceEntry {
                name: String::from("content-server"),
                binary: [0xEE; 32],
                config: Some([0xFF; 32]),
            }],
        }
    }

    #[test]
    fn cbor_round_trip() {
        let config = sample_config();
        let bytes = config.to_cbor();
        let decoded = NodeConfig::from_cbor(&bytes).unwrap();
        assert_eq!(config, decoded);
    }

    #[test]
    fn cbor_deterministic() {
        let config = sample_config();
        let bytes1 = config.to_cbor();
        let bytes2 = config.to_cbor();
        assert_eq!(bytes1, bytes2, "CBOR encoding must be deterministic");
    }

    #[test]
    fn cid_stable() {
        let config = sample_config();
        let cid1 = config.cid();
        let cid2 = config.cid();
        assert_eq!(cid1, cid2);
        // CID is SHA-256 of CBOR bytes
        assert_eq!(cid1, sha256_hash(&config.to_cbor()));
    }

    #[test]
    fn cid_changes_with_content() {
        let mut config = sample_config();
        let cid1 = config.cid();
        config.network.port = 9999;
        let cid2 = config.cid();
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn from_cbor_rejects_garbage() {
        assert!(NodeConfig::from_cbor(&[0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn empty_services_round_trips() {
        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [0x11; 32],
            identity: [0x22; 32],
            network: NetworkConfig {
                mesh_seeds: vec![],
                port: 4242,
            },
            services: vec![],
        };
        let bytes = config.to_cbor();
        let decoded = NodeConfig::from_cbor(&bytes).unwrap();
        assert_eq!(config, decoded);
    }

    #[test]
    fn service_without_config_round_trips() {
        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [0x11; 32],
            identity: [0x22; 32],
            network: NetworkConfig {
                mesh_seeds: vec![],
                port: 4242,
            },
            services: vec![ServiceEntry {
                name: String::from("echo"),
                binary: [0x33; 32],
                config: None,
            }],
        };
        let bytes = config.to_cbor();
        let decoded = NodeConfig::from_cbor(&bytes).unwrap();
        assert_eq!(config, decoded);
    }
}
```

- [ ] **Step 2: Add module declaration to lib.rs**

In `crates/harmony-microkernel/src/lib.rs`, add alongside the other `#[cfg(feature = "kernel")]` modules:

```rust
#[cfg(feature = "kernel")]
pub mod node_config;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel node_config`
Expected: FAIL — struct types don't exist yet.

- [ ] **Step 4: Implement the types and serialization**

Add above the test module in `node_config.rs`:

```rust
/// Serialization error wrapper.
#[derive(Debug)]
pub enum ConfigError {
    /// CBOR deserialization failed.
    DeserializeFailed(String),
}

/// A node's declarative configuration — content-addressed via CBOR + SHA-256.
///
/// Each field referencing external content stores a 32-byte CID (SHA-256 hash)
/// of the content-addressed book in the CAS. The `NodeConfig` itself is
/// serialized to deterministic CBOR, and its CID is `SHA-256(cbor_bytes)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Schema version for forward compatibility (starts at 1).
    pub version: u32,
    /// CID of the kernel binary (ELF/PE image in CAS).
    pub kernel: [u8; 32],
    /// CID of the node's encrypted PqIdentity bundle.
    pub identity: [u8; 32],
    /// Inline network config (small enough to not need its own CID).
    pub network: NetworkConfig,
    /// Service entries to launch at boot.
    pub services: Vec<ServiceEntry>,
}

/// Network configuration — mesh seeds and port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Mesh seed peers (address hashes to bootstrap from).
    pub mesh_seeds: Vec<[u8; 16]>,
    /// UDP port for mesh traffic.
    pub port: u16,
}

/// A service to launch as part of the node configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEntry {
    /// Human-readable service name (e.g., "content-server").
    pub name: String,
    /// CID of the service binary in CAS.
    pub binary: [u8; 32],
    /// Optional CID of service-specific config blob.
    pub config: Option<[u8; 32]>,
}

impl NodeConfig {
    /// Serialize to deterministic CBOR bytes.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR serialization of NodeConfig is infallible");
        buf
    }

    /// Deserialize from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ConfigError> {
        ciborium::from_reader(bytes)
            .map_err(|e| ConfigError::DeserializeFailed(format!("{e}")))
    }

    /// Compute the content ID: SHA-256 of the CBOR encoding.
    pub fn cid(&self) -> [u8; 32] {
        sha256_hash(&self.to_cbor())
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel node_config`
Expected: all 7 tests PASS.

- [ ] **Step 6: Run clippy**

Run: `cargo clippy -p harmony-microkernel -- -D warnings`
Expected: no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/node_config.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(config): add NodeConfig types with CBOR serialization and CID computation"
```

---

### Task 3: SignedConfig envelope + signature verification (`signed_config.rs`)

**Files:**
- Create: `crates/harmony-microkernel/src/signed_config.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add module declaration)

**Context:**
- Uses `PqIdentity` from `harmony-identity` for ML-DSA-65 signature verification.
- `PqIdentity::from_public_bytes(bytes)` deserializes a public key (3136 bytes: 1184 ML-KEM-768 + 1952 ML-DSA-65).
- `PqIdentity::verify(message, signature)` verifies an ML-DSA-65 signature.
- `PqIdentity.address_hash` is the 16-byte truncated SHA-256 of the public keys.
- `PqPrivateIdentity::generate(&mut OsRng)` creates a keypair for tests.
- `PqPrivateIdentity::sign(message)` signs with ML-DSA-65.
- `PqPrivateIdentity.public_identity()` extracts the `PqIdentity`.
- The `SignedConfig` contains: `config_bytes` (raw CBOR), `signature`, `signer` (16-byte address), `signer_pubkey` (raw public key bytes).
- Verification: (1) deserialize `signer_pubkey` to `PqIdentity`, (2) check `address_hash == signer`, (3) verify signature over `config_bytes`.
- Trust check: `signer` must be in a provided set of trusted operator address hashes.

- [ ] **Step 1: Write failing tests**

Create `crates/harmony-microkernel/src/signed_config.rs` with tests first. Tests need `harmony-identity` with `test-utils` feature (already present in `kernel` feature gate):

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! SignedConfig — cryptographically signed NodeConfig envelope.
//!
//! Wraps CBOR-serialized `NodeConfig` bytes with an ML-DSA-65 signature
//! from the operator's PQ identity. ConfigServer verifies the signature
//! before allowing a config to be staged.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use harmony_athenaeum::sha256_hash;
use harmony_identity::PqIdentity;

// Types + impl go here in step 3...

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_config::{NetworkConfig, NodeConfig, SCHEMA_VERSION};
    use harmony_identity::PqPrivateIdentity;
    use rand_core::OsRng;

    fn sample_config() -> NodeConfig {
        NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [0xAA; 32],
            identity: [0xBB; 32],
            network: NetworkConfig {
                mesh_seeds: vec![],
                port: 4242,
            },
            services: vec![],
        }
    }

    fn sign_config(config: &NodeConfig, signer: &PqPrivateIdentity) -> SignedConfig {
        let config_bytes = config.to_cbor();
        let signature = signer.sign(&config_bytes).expect("signing should succeed");
        let pub_id = signer.public_identity();
        SignedConfig {
            config_bytes,
            signature,
            signer: pub_id.address_hash,
            signer_pubkey: pub_id.to_public_bytes(),
        }
    }

    #[test]
    fn valid_signature_accepted() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let signed = sign_config(&config, &signer);
        let trusted = vec![signer.public_identity().address_hash];
        assert!(signed.verify(&trusted).is_ok());
    }

    #[test]
    fn tampered_bytes_rejected() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let mut signed = sign_config(&config, &signer);
        signed.config_bytes[0] ^= 0xFF; // tamper
        let trusted = vec![signer.public_identity().address_hash];
        assert!(matches!(
            signed.verify(&trusted),
            Err(SignedConfigError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn wrong_signer_address_rejected() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let mut signed = sign_config(&config, &signer);
        signed.signer = [0xFF; 16]; // wrong address
        let trusted = vec![[0xFF; 16]]; // trust the wrong address
        assert!(matches!(
            signed.verify(&trusted),
            Err(SignedConfigError::AddressMismatch)
        ));
    }

    #[test]
    fn untrusted_signer_rejected() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let signed = sign_config(&config, &signer);
        let trusted: Vec<[u8; 16]> = vec![[0x00; 16]]; // doesn't include signer
        assert!(matches!(
            signed.verify(&trusted),
            Err(SignedConfigError::UntrustedSigner)
        ));
    }

    #[test]
    fn invalid_pubkey_bytes_rejected() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let mut signed = sign_config(&config, &signer);
        signed.signer_pubkey = vec![0xFF; 10]; // garbage pubkey
        let trusted = vec![signer.public_identity().address_hash];
        assert!(matches!(
            signed.verify(&trusted),
            Err(SignedConfigError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn cbor_round_trip() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let signed = sign_config(&config, &signer);
        let bytes = signed.to_cbor();
        let decoded = SignedConfig::from_cbor(&bytes).unwrap();
        assert_eq!(signed.config_bytes, decoded.config_bytes);
        assert_eq!(signed.signer, decoded.signer);
        assert_eq!(signed.signature, decoded.signature);
        assert_eq!(signed.signer_pubkey, decoded.signer_pubkey);
    }

    #[test]
    fn cid_is_sha256_of_cbor() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let signed = sign_config(&config, &signer);
        let cbor = signed.to_cbor();
        assert_eq!(signed.cid(), sha256_hash(&cbor));
    }
}
```

- [ ] **Step 2: Add module declaration to lib.rs**

In `crates/harmony-microkernel/src/lib.rs`, add:

```rust
#[cfg(feature = "kernel")]
pub mod signed_config;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel signed_config`
Expected: FAIL — types don't exist yet.

- [ ] **Step 4: Implement the types**

Add above the test module in `signed_config.rs`:

```rust
/// Errors from SignedConfig verification.
#[derive(Debug)]
pub enum SignedConfigError {
    /// CBOR deserialization failed.
    DeserializeFailed(String),
    /// `signer_pubkey` could not be parsed as a PQ public key.
    InvalidPublicKey(String),
    /// `signer` address does not match address derived from `signer_pubkey`.
    AddressMismatch,
    /// Signer is not in the trusted operator set.
    UntrustedSigner,
    /// ML-DSA-65 signature verification failed.
    SignatureInvalid(String),
}

/// A signed NodeConfig envelope.
///
/// The `config_bytes` field contains the deterministic CBOR encoding of a
/// `NodeConfig`. The signature covers exactly these bytes — no additional
/// framing. The signer's public key is included for self-contained
/// verification; the `signer` address field is verified to match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    /// CBOR-encoded NodeConfig bytes (deterministic).
    pub config_bytes: Vec<u8>,
    /// ML-DSA-65 signature over `config_bytes`.
    pub signature: Vec<u8>,
    /// Operator's PQ address hash (must match address derived from `signer_pubkey`).
    pub signer: [u8; 16],
    /// Operator's full PQ public key bytes (ML-KEM-768 + ML-DSA-65 = 3136 bytes).
    pub signer_pubkey: Vec<u8>,
}

impl SignedConfig {
    /// Verify the signature and trust chain.
    ///
    /// 1. Deserialize `signer_pubkey` → `PqIdentity`
    /// 2. Check `signer == identity.address_hash`
    /// 3. Check `signer` is in `trusted_operators`
    /// 4. Verify ML-DSA-65 signature over `config_bytes`
    pub fn verify(&self, trusted_operators: &[[u8; 16]]) -> Result<PqIdentity, SignedConfigError> {
        // 1. Parse public key
        let identity = PqIdentity::from_public_bytes(&self.signer_pubkey)
            .map_err(|e| SignedConfigError::InvalidPublicKey(format!("{e:?}")))?;

        // 2. Verify address matches pubkey
        if identity.address_hash != self.signer {
            return Err(SignedConfigError::AddressMismatch);
        }

        // 3. Trust check
        if !trusted_operators.contains(&self.signer) {
            return Err(SignedConfigError::UntrustedSigner);
        }

        // 4. Verify signature
        identity
            .verify(&self.config_bytes, &self.signature)
            .map_err(|e| SignedConfigError::SignatureInvalid(format!("{e:?}")))?;

        Ok(identity)
    }

    /// Serialize the entire SignedConfig to CBOR.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .expect("CBOR serialization of SignedConfig is infallible");
        buf
    }

    /// Deserialize a SignedConfig from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, SignedConfigError> {
        ciborium::from_reader(bytes)
            .map_err(|e| SignedConfigError::DeserializeFailed(format!("{e}")))
    }

    /// Compute the content ID: SHA-256 of the CBOR encoding.
    pub fn cid(&self) -> [u8; 32] {
        sha256_hash(&self.to_cbor())
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel signed_config`
Expected: all 7 tests PASS.

- [ ] **Step 6: Run clippy**

Run: `cargo clippy -p harmony-microkernel -- -D warnings`
Expected: no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/signed_config.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(config): add SignedConfig envelope with ML-DSA-65 verification"
```

---

### Task 4: ContentServer public API (`get_book_bytes`, `has_book`)

**Files:**
- Modify: `crates/harmony-microkernel/src/content_server.rs`

**Context:**
- Currently `ContentServer` only exposes content via the 9P `FileServer` trait.
- ConfigServer needs direct Rust API access to fetch books by CID and check existence.
- Add two public methods: `get_book_bytes(&self, cid) -> Option<Vec<u8>>` and `has_book(&self, cid) -> bool`.
- `get_book_bytes` reassembles the book from pages (same as `read_book` but returns the full content).
- The existing `read_book` method is private and takes offset/count — the new method wraps it for full-content retrieval.

- [ ] **Step 1: Write failing tests**

Add to the existing `#[cfg(test)] mod tests` block in `content_server.rs`:

```rust
    #[test]
    fn get_book_bytes_returns_full_content() {
        let mut server = ContentServer::new();
        let blob = alloc::vec![0x42u8; 8000];
        // Ingest
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &blob).unwrap();
        let resp = server.read(1, 0, 256).unwrap();
        let cid: [u8; 32] = resp[..32].try_into().unwrap();
        server.clunk(1).unwrap();

        let retrieved = server.get_book_bytes(&cid).unwrap();
        assert_eq!(retrieved, blob);
    }

    #[test]
    fn get_book_bytes_missing_returns_none() {
        let server = ContentServer::new();
        assert!(server.get_book_bytes(&[0xAA; 32]).is_none());
    }

    #[test]
    fn has_book_true_after_ingest() {
        let mut server = ContentServer::new();
        let blob = alloc::vec![0x55u8; PAGE_SIZE];
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &blob).unwrap();
        let resp = server.read(1, 0, 256).unwrap();
        let cid: [u8; 32] = resp[..32].try_into().unwrap();
        server.clunk(1).unwrap();

        assert!(server.has_book(&cid));
    }

    #[test]
    fn has_book_false_for_missing() {
        let server = ContentServer::new();
        assert!(!server.has_book(&[0xBB; 32]));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel content_server::tests::get_book_bytes`
Expected: FAIL — methods don't exist.

- [ ] **Step 3: Implement the methods**

Add to the `impl ContentServer` block (after the existing `page_count` method, around line 124):

```rust
    /// Retrieve full book content by CID, reassembled from stored pages.
    ///
    /// Returns `None` if the book is not stored. This is the direct API
    /// equivalent of walking to `/books/{cid_hex}` and reading via 9P,
    /// intended for internal Ring 2 consumers like `ConfigServer`.
    pub fn get_book_bytes(&self, cid: &[u8; 32]) -> Option<Vec<u8>> {
        let book = self.books.get(cid)?;
        let pages = &self.pages;
        book.reassemble(|idx| {
            let addr = book.pages.get(idx as usize).and_then(|v| v.first()).copied()?;
            pages.get(&addr.hash_bits()).map(|(_, d)| d.clone())
        })
        .ok()
    }

    /// Check whether a book with the given CID is stored.
    pub fn has_book(&self, cid: &[u8; 32]) -> bool {
        self.books.contains_key(cid)
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel content_server`
Expected: all tests PASS (existing + 4 new).

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -p harmony-microkernel -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/content_server.rs
git commit -m "feat(content): add get_book_bytes and has_book public API for direct CAS access"
```

---

### Task 5: ConfigServer — 9P file server at `/env/config` (`config_server.rs`)

**Files:**
- Create: `crates/harmony-microkernel/src/config_server.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add module declaration)

**Context:**
- Implements `FileServer` trait (walk/open/read/write/clunk/stat/clone_fid).
- Virtual filesystem: `active`, `pending`, `previous`, `stage`, `commit`, `rollback`, `node.cbor`.
- Holds `Arc<core::cell::RefCell<ContentServer>>` (or similar shared-interior-mutability pattern matching existing codebase — check how `kernel.rs` composes servers).
- Write to `stage`: hex CID → fetch `SignedConfig` from CAS → verify → store as pending.
- Write to `commit`: pending → active, active → previous.
- Write to `rollback`: swap active ↔ previous.
- Follows the `FidTracker<NodeKind>` pattern from `ContentServer`.
- Trusted operators list: `Vec<[u8; 16]>` passed at construction.

**Important patterns to follow from `content_server.rs`:**
- QPath constants for each virtual file
- `NodeKind` enum for fid tracking
- `FidTracker<NodeKind>` for fid management
- `slice_data()` helper for read offset/count
- `parse_hex_cid()` for hex string → `[u8; 32]`
- Error mapping: `IpcError::PermissionDenied` for auth failures, `IpcError::InvalidArgument` for bad input

- [ ] **Step 1: Write failing tests**

Create `crates/harmony-microkernel/src/config_server.rs` with test module. The full test suite covers: stage+commit lifecycle, rollback, read active/pending/previous/node.cbor, stage with bad signature, stage with missing CID refs, commit without pending, rollback without previous.

Tests use a helper that creates a `ContentServer` pre-loaded with a signed config book, plus fake books for the kernel/identity/service CIDs referenced in the config.

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! ConfigServer — 9P file server for declarative node configuration.
//!
//! Mounted at `/env/config`, provides two-phase config activation:
//! stage (validate + verify signature) → commit (atomic pointer swap) → rollback.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::content_server::{format_cid_hex, ContentServer};
use crate::fid_tracker::FidTracker;
use crate::node_config::NodeConfig;
use crate::signed_config::{SignedConfig, SignedConfigError};
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

// Types + impl go here in step 3...

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_config::{NetworkConfig, ServiceEntry, SCHEMA_VERSION};
    use harmony_identity::PqPrivateIdentity;
    use rand_core::OsRng;

    /// Helper: create a ContentServer with a signed config book ingested,
    /// plus stub books for all CIDs referenced by the config.
    fn setup() -> (Arc<ContentServer>, [u8; 32], Vec<[u8; 16]>) {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let pub_id = signer.public_identity();

        // Create stub CIDs for referenced content
        let kernel_data = alloc::vec![0xK1u8; 4096];  // Won't compile — use 0x4B
        // Actually use valid bytes:
        let kernel_data = alloc::vec![0x4Bu8; 4096];
        let identity_data = alloc::vec![0x49u8; 4096];
        let service_binary = alloc::vec![0x53u8; 4096];

        let mut cas = ContentServer::new();

        // Ingest stub books to satisfy CID reference checks
        let kernel_cid = ingest_book(&mut cas, &kernel_data);
        let identity_cid = ingest_book(&mut cas, &identity_data);
        let binary_cid = ingest_book(&mut cas, &service_binary);

        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: kernel_cid,
            identity: identity_cid,
            network: NetworkConfig {
                mesh_seeds: vec![],
                port: 4242,
            },
            services: vec![ServiceEntry {
                name: alloc::string::String::from("test-svc"),
                binary: binary_cid,
                config: None,
            }],
        };

        let config_bytes = config.to_cbor();
        let signature = signer.sign(&config_bytes).unwrap();
        let signed = SignedConfig {
            config_bytes,
            signature,
            signer: pub_id.address_hash,
            signer_pubkey: pub_id.to_public_bytes(),
        };

        let signed_cbor = signed.to_cbor();
        let signed_cid = ingest_book(&mut cas, &signed_cbor);

        let trusted = vec![pub_id.address_hash];
        (Arc::new(cas), signed_cid, trusted)
    }

    /// Ingest raw bytes into a ContentServer, return the CID.
    fn ingest_book(cas: &mut ContentServer, data: &[u8]) -> [u8; 32] {
        // Use a fresh fid for each ingest
        static NEXT_FID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(100);
        let fid = NEXT_FID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        cas.walk(0, fid, "ingest").unwrap();
        cas.open(fid, OpenMode::ReadWrite).unwrap();
        cas.write(fid, 0, data).unwrap();
        let resp = cas.read(fid, 0, 256).unwrap();
        cas.clunk(fid).unwrap();
        resp[..32].try_into().unwrap()
    }

    /// Write a hex CID string to the `stage` file.
    fn stage_config(server: &mut ConfigServer, cid: &[u8; 32]) -> Result<u32, IpcError> {
        server.walk(0, 10, "stage").unwrap();
        server.open(10, OpenMode::Write).unwrap();
        let hex = format_cid_hex(cid);
        let result = server.write(10, 0, hex.as_bytes());
        server.clunk(10).unwrap();
        result
    }

    /// Write "1" to the `commit` file.
    fn commit(server: &mut ConfigServer) -> Result<u32, IpcError> {
        server.walk(0, 11, "commit").unwrap();
        server.open(11, OpenMode::Write).unwrap();
        let result = server.write(11, 0, b"1");
        server.clunk(11).unwrap();
        result
    }

    /// Write "1" to the `rollback` file.
    fn rollback(server: &mut ConfigServer) -> Result<u32, IpcError> {
        server.walk(0, 12, "rollback").unwrap();
        server.open(12, OpenMode::Write).unwrap();
        let result = server.write(12, 0, b"1");
        server.clunk(12).unwrap();
        result
    }

    /// Read the `active` file contents.
    fn read_active(server: &mut ConfigServer) -> Vec<u8> {
        server.walk(0, 20, "active").unwrap();
        server.open(20, OpenMode::Read).unwrap();
        let data = server.read(20, 0, 256).unwrap();
        server.clunk(20).unwrap();
        data
    }

    #[test]
    fn stage_commit_read_active() {
        let (cas, signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        stage_config(&mut server, &signed_cid).unwrap();
        commit(&mut server).unwrap();

        let active = read_active(&mut server);
        let expected_hex = format_cid_hex(&signed_cid);
        assert_eq!(core::str::from_utf8(&active).unwrap(), &expected_hex);
    }

    #[test]
    fn commit_without_pending_fails() {
        let (cas, _signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        assert_eq!(commit(&mut server), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn rollback_without_previous_fails() {
        let (cas, _signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        assert_eq!(rollback(&mut server), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn rollback_swaps_active_and_previous() {
        // Need two different configs to test the swap.
        // Build a second signed config with different content.
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let pub_id = signer.public_identity();
        let trusted = vec![pub_id.address_hash];

        let mut cas = ContentServer::new();

        // Stub CIDs for config 1
        let k1 = ingest_book(&mut cas, &alloc::vec![0x4Bu8; 4096]);
        let i1 = ingest_book(&mut cas, &alloc::vec![0x49u8; 4096]);

        // Stub CIDs for config 2 (different data)
        let k2 = ingest_book(&mut cas, &alloc::vec![0x4Cu8; 4096]);
        let i2 = ingest_book(&mut cas, &alloc::vec![0x4Au8; 4096]);

        let config1 = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: k1, identity: i1,
            network: NetworkConfig { mesh_seeds: vec![], port: 4242 },
            services: vec![],
        };
        let config2 = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: k2, identity: i2,
            network: NetworkConfig { mesh_seeds: vec![], port: 5555 },
            services: vec![],
        };

        let signed_cid1 = sign_and_ingest(&mut cas, &config1, &signer);
        let signed_cid2 = sign_and_ingest(&mut cas, &config2, &signer);

        let cas = Arc::new(cas);
        let mut server = ConfigServer::new(cas, trusted);

        // Commit config 1
        stage_config(&mut server, &signed_cid1).unwrap();
        commit(&mut server).unwrap();

        // Commit config 2 (config 1 → previous)
        stage_config(&mut server, &signed_cid2).unwrap();
        commit(&mut server).unwrap();

        let active_before = read_active(&mut server);
        assert_eq!(core::str::from_utf8(&active_before).unwrap(), &format_cid_hex(&signed_cid2));

        // Rollback: should swap active ↔ previous
        rollback(&mut server).unwrap();

        let active_after = read_active(&mut server);
        assert_eq!(core::str::from_utf8(&active_after).unwrap(), &format_cid_hex(&signed_cid1));

        // Second rollback toggles back
        rollback(&mut server).unwrap();
        let active_toggled = read_active(&mut server);
        assert_eq!(core::str::from_utf8(&active_toggled).unwrap(), &format_cid_hex(&signed_cid2));
    }

    /// Helper: sign a NodeConfig and ingest the SignedConfig into the CAS.
    fn sign_and_ingest(
        cas: &mut ContentServer,
        config: &NodeConfig,
        signer: &PqPrivateIdentity,
    ) -> [u8; 32] {
        let config_bytes = config.to_cbor();
        let signature = signer.sign(&config_bytes).unwrap();
        let pub_id = signer.public_identity();
        let signed = SignedConfig {
            config_bytes,
            signature,
            signer: pub_id.address_hash,
            signer_pubkey: pub_id.to_public_bytes(),
        };
        ingest_book(cas, &signed.to_cbor())
    }

    #[test]
    fn active_empty_before_any_config() {
        let (cas, _signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        let active = read_active(&mut server);
        assert!(active.is_empty());
    }

    #[test]
    fn stage_bad_cid_fails() {
        let (cas, _signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        let bad_cid = [0xFF; 32]; // not in CAS
        assert_eq!(
            stage_config(&mut server, &bad_cid),
            Err(IpcError::NotFound)
        );
    }

    #[test]
    fn pending_set_after_stage() {
        let (cas, signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        stage_config(&mut server, &signed_cid).unwrap();

        // Read pending
        server.walk(0, 30, "pending").unwrap();
        server.open(30, OpenMode::Read).unwrap();
        let pending = server.read(30, 0, 256).unwrap();
        server.clunk(30).unwrap();

        let expected_hex = format_cid_hex(&signed_cid);
        assert_eq!(core::str::from_utf8(&pending).unwrap(), &expected_hex);
    }

    #[test]
    fn pending_cleared_after_commit() {
        let (cas, signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        stage_config(&mut server, &signed_cid).unwrap();
        commit(&mut server).unwrap();

        server.walk(0, 30, "pending").unwrap();
        server.open(30, OpenMode::Read).unwrap();
        let pending = server.read(30, 0, 256).unwrap();
        server.clunk(30).unwrap();

        assert!(pending.is_empty());
    }

    #[test]
    fn read_node_cbor_after_commit() {
        let (cas, signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);

        stage_config(&mut server, &signed_cid).unwrap();
        commit(&mut server).unwrap();

        server.walk(0, 40, "node.cbor").unwrap();
        server.open(40, OpenMode::Read).unwrap();
        let cbor = server.read(40, 0, 65536).unwrap();
        server.clunk(40).unwrap();

        // Should be valid CBOR that decodes to a NodeConfig
        let config = NodeConfig::from_cbor(&cbor).unwrap();
        assert_eq!(config.version, SCHEMA_VERSION);
    }
}
```

- [ ] **Step 2: Add module declaration to lib.rs**

```rust
#[cfg(feature = "kernel")]
pub mod config_server;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel config_server`
Expected: FAIL — `ConfigServer` doesn't exist.

- [ ] **Step 4: Implement ConfigServer**

Add the implementation above the test module. The structure follows `ContentServer`'s pattern exactly:

```rust
// QPath constants
const ROOT: QPath = 0;
const ACTIVE: QPath = 1;
const PENDING: QPath = 2;
const PREVIOUS: QPath = 3;
const STAGE: QPath = 4;
const COMMIT: QPath = 5;
const ROLLBACK: QPath = 6;
const NODE_CBOR: QPath = 7;

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
}

/// ConfigServer — two-phase config activation via 9P.
///
/// Holds a shared reference to the `ContentServer` for CAS access.
/// The trusted operator list controls which signers are accepted.
pub struct ConfigServer {
    cas: Arc<ContentServer>,
    tracker: FidTracker<NodeKind>,
    trusted_operators: Vec<[u8; 16]>,
    /// CID of the active config (None = unconfigured).
    active_cid: Option<[u8; 32]>,
    /// Deserialized active NodeConfig (cached).
    active_config: Option<NodeConfig>,
    /// CID of the pending (staged, validated) config.
    pending_cid: Option<[u8; 32]>,
    /// Deserialized pending NodeConfig (cached).
    pending_config: Option<NodeConfig>,
    /// CID of the previous config (for rollback).
    previous_cid: Option<[u8; 32]>,
    /// Deserialized previous NodeConfig (cached).
    previous_config: Option<NodeConfig>,
}

impl ConfigServer {
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

    /// Stage a config: fetch from CAS, verify signature, validate references.
    fn do_stage(&mut self, cid_hex: &str) -> Result<(), IpcError> {
        use crate::content_server::parse_hex_cid;

        let cid = parse_hex_cid(cid_hex).ok_or(IpcError::InvalidArgument)?;

        // Fetch SignedConfig from CAS
        let book_bytes = self.cas.get_book_bytes(&cid).ok_or(IpcError::NotFound)?;

        // Deserialize SignedConfig
        let signed = SignedConfig::from_cbor(&book_bytes)
            .map_err(|_| IpcError::InvalidArgument)?;

        // Verify signature + trust
        signed
            .verify(&self.trusted_operators)
            .map_err(|e| match e {
                SignedConfigError::UntrustedSigner
                | SignedConfigError::AddressMismatch
                | SignedConfigError::SignatureInvalid(_) => IpcError::PermissionDenied,
                _ => IpcError::InvalidArgument,
            })?;

        // Deserialize inner NodeConfig
        let config = NodeConfig::from_cbor(&signed.config_bytes)
            .map_err(|_| IpcError::InvalidArgument)?;

        // Validate CID references exist in CAS
        if !self.cas.has_book(&config.kernel) {
            return Err(IpcError::NotFound);
        }
        if !self.cas.has_book(&config.identity) {
            return Err(IpcError::NotFound);
        }
        for svc in &config.services {
            if !self.cas.has_book(&svc.binary) {
                return Err(IpcError::NotFound);
            }
            if let Some(ref cfg_cid) = svc.config {
                if !self.cas.has_book(cfg_cid) {
                    return Err(IpcError::NotFound);
                }
            }
        }

        self.pending_cid = Some(cid);
        self.pending_config = Some(config);
        Ok(())
    }

    fn do_commit(&mut self) -> Result<(), IpcError> {
        if self.pending_cid.is_none() {
            return Err(IpcError::InvalidArgument);
        }
        // active → previous
        self.previous_cid = self.active_cid.take();
        self.previous_config = self.active_config.take();
        // pending → active
        self.active_cid = self.pending_cid.take();
        self.active_config = self.pending_config.take();
        Ok(())
    }

    fn do_rollback(&mut self) -> Result<(), IpcError> {
        if self.previous_cid.is_none() {
            return Err(IpcError::InvalidArgument);
        }
        core::mem::swap(&mut self.active_cid, &mut self.previous_cid);
        core::mem::swap(&mut self.active_config, &mut self.previous_config);
        Ok(())
    }

    fn cid_hex_bytes(cid: &Option<[u8; 32]>) -> Vec<u8> {
        match cid {
            Some(c) => format_cid_hex(c).into_bytes(),
            None => Vec::new(),
        }
    }
}
```

Then implement the `FileServer` trait following `ContentServer`'s exact pattern — walk routes names to NodeKind variants, open validates modes (read-only for active/pending/previous/node.cbor, write-only for stage/commit/rollback), read returns CID hex or CBOR, write dispatches to do_stage/do_commit/do_rollback.

**Visibility changes in `content_server.rs`:** Two helpers need visibility bumps:
1. `parse_hex_cid` — currently private (`fn`). Change to `pub(crate)` so `config_server.rs` can use it.
2. `format_cid_hex` — currently `pub(crate)`. Change to `pub` so the integration test in `tests/config_lifecycle.rs` can import it.

```rust
// In content_server.rs, change:
fn parse_hex_cid(s: &str) -> Option<[u8; 32]> {
// to:
pub(crate) fn parse_hex_cid(s: &str) -> Option<[u8; 32]> {

// And change:
pub(crate) fn format_cid_hex(cid: &[u8; 32]) -> alloc::string::String {
// to:
pub fn format_cid_hex(cid: &[u8; 32]) -> alloc::string::String {
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel config_server`
Expected: all tests PASS.

- [ ] **Step 6: Run full workspace tests + clippy**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings`
Expected: all pass, no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/config_server.rs crates/harmony-microkernel/src/content_server.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(config): add ConfigServer 9P file server for two-phase config activation"
```

---

### Task 6: ConfigApplicator — Ring 3 config diff + apply logic (`config_applicator.rs`)

**Files:**
- Create: `crates/harmony-os/src/config_applicator.rs`
- Modify: `crates/harmony-os/src/lib.rs` (add module declaration)

**Context:**
- Ring 3 (`harmony-os`), `#[cfg(feature = "std")]` gated.
- Consumes `NodeConfig` from `harmony-microkernel::node_config`.
- `ConfigDiff` computes what changed between two configs.
- `ConfigApplicator` holds the active config state and applies diffs.
- Zenoh subscription is out of scope for the pure-logic first pass — the applicator exposes a `fn handle_new_config(&mut self, config: NodeConfig) -> ConfigDiff` method. Zenoh wiring is future integration work.
- Focus this task on the diff computation and application logic (start/stop detection), not actual process management.

- [ ] **Step 1: Write failing tests**

Create `crates/harmony-os/src/config_applicator.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! ConfigApplicator — computes and applies NodeConfig diffs.
//!
//! Given a new `NodeConfig`, computes what changed vs. the previous config
//! and reports the diff. Actual service management (start/stop processes)
//! is handled by the caller; this module provides pure diff logic.

use harmony_microkernel::node_config::{NodeConfig, ServiceEntry};

// Types + impl go here in step 3...

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_microkernel::node_config::{NetworkConfig, SCHEMA_VERSION};

    fn base_config() -> NodeConfig {
        NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [0xAA; 32],
            identity: [0xBB; 32],
            network: NetworkConfig {
                mesh_seeds: vec![],
                port: 4242,
            },
            services: vec![
                ServiceEntry {
                    name: String::from("echo"),
                    binary: [0x11; 32],
                    config: None,
                },
                ServiceEntry {
                    name: String::from("content"),
                    binary: [0x22; 32],
                    config: None,
                },
            ],
        }
    }

    #[test]
    fn identical_configs_produce_empty_diff() {
        let a = base_config();
        let b = a.clone();
        let diff = ConfigDiff::compute(&a, &b);
        assert!(!diff.kernel_changed);
        assert!(!diff.identity_changed);
        assert!(!diff.network_changed);
        assert!(diff.services_added.is_empty());
        assert!(diff.services_removed.is_empty());
        assert!(diff.services_updated.is_empty());
    }

    #[test]
    fn kernel_change_detected() {
        let a = base_config();
        let mut b = a.clone();
        b.kernel = [0xFF; 32];
        let diff = ConfigDiff::compute(&a, &b);
        assert!(diff.kernel_changed);
    }

    #[test]
    fn identity_change_detected() {
        let a = base_config();
        let mut b = a.clone();
        b.identity = [0xFF; 32];
        let diff = ConfigDiff::compute(&a, &b);
        assert!(diff.identity_changed);
    }

    #[test]
    fn network_port_change_detected() {
        let a = base_config();
        let mut b = a.clone();
        b.network.port = 9999;
        let diff = ConfigDiff::compute(&a, &b);
        assert!(diff.network_changed);
    }

    #[test]
    fn service_added() {
        let a = base_config();
        let mut b = a.clone();
        b.services.push(ServiceEntry {
            name: String::from("new-svc"),
            binary: [0x33; 32],
            config: None,
        });
        let diff = ConfigDiff::compute(&a, &b);
        assert_eq!(diff.services_added, vec!["new-svc"]);
        assert!(diff.services_removed.is_empty());
    }

    #[test]
    fn service_removed() {
        let a = base_config();
        let mut b = a.clone();
        b.services.retain(|s| s.name != "echo");
        let diff = ConfigDiff::compute(&a, &b);
        assert_eq!(diff.services_removed, vec!["echo"]);
        assert!(diff.services_added.is_empty());
    }

    #[test]
    fn service_updated() {
        let a = base_config();
        let mut b = a.clone();
        b.services[0].binary = [0xFF; 32]; // changed binary for "echo"
        let diff = ConfigDiff::compute(&a, &b);
        assert_eq!(diff.services_updated, vec!["echo"]);
        assert!(diff.services_added.is_empty());
        assert!(diff.services_removed.is_empty());
    }

    #[test]
    fn applicator_tracks_active_config() {
        let mut app = ConfigApplicator::new();
        assert!(app.active().is_none());

        let config = base_config();
        let diff = app.apply(config.clone());
        // First apply: everything is "added"
        assert_eq!(diff.services_added.len(), 2);

        assert!(app.active().is_some());
        assert_eq!(app.active().unwrap(), &config);
    }

    #[test]
    fn applicator_second_apply_computes_diff() {
        let mut app = ConfigApplicator::new();
        let config1 = base_config();
        app.apply(config1);

        let mut config2 = base_config();
        config2.services.push(ServiceEntry {
            name: String::from("new-svc"),
            binary: [0x33; 32],
            config: None,
        });
        let diff = app.apply(config2);
        assert_eq!(diff.services_added, vec!["new-svc"]);
    }
}
```

- [ ] **Step 2: Add module declaration to lib.rs**

In `crates/harmony-os/src/lib.rs`:

```rust
#[cfg(feature = "std")]
pub mod config_applicator;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-os config_applicator`
Expected: FAIL — types don't exist.

- [ ] **Step 4: Implement ConfigDiff and ConfigApplicator**

Add above the test module:

```rust
use alloc::string::String;
use alloc::vec::Vec;
use std::collections::HashMap;

/// Diff between two NodeConfig values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDiff {
    pub kernel_changed: bool,
    pub identity_changed: bool,
    pub network_changed: bool,
    pub services_added: Vec<String>,
    pub services_removed: Vec<String>,
    pub services_updated: Vec<String>,
}

impl ConfigDiff {
    /// Compute the diff from `old` to `new`.
    pub fn compute(old: &NodeConfig, new: &NodeConfig) -> Self {
        let kernel_changed = old.kernel != new.kernel;
        let identity_changed = old.identity != new.identity;
        let network_changed = old.network != new.network;

        let old_svcs: HashMap<&str, &ServiceEntry> =
            old.services.iter().map(|s| (s.name.as_str(), s)).collect();
        let new_svcs: HashMap<&str, &ServiceEntry> =
            new.services.iter().map(|s| (s.name.as_str(), s)).collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut updated = Vec::new();

        for (name, new_entry) in &new_svcs {
            match old_svcs.get(name) {
                None => added.push((*name).to_owned()),
                Some(old_entry) => {
                    if old_entry.binary != new_entry.binary
                        || old_entry.config != new_entry.config
                    {
                        updated.push((*name).to_owned());
                    }
                }
            }
        }

        for name in old_svcs.keys() {
            if !new_svcs.contains_key(name) {
                removed.push((*name).to_owned());
            }
        }

        // Sort for deterministic output
        added.sort();
        removed.sort();
        updated.sort();

        Self {
            kernel_changed,
            identity_changed,
            network_changed,
            services_added: added,
            services_removed: removed,
            services_updated: updated,
        }
    }
}

/// Tracks the active config and computes diffs on apply.
pub struct ConfigApplicator {
    active: Option<NodeConfig>,
}

impl ConfigApplicator {
    pub fn new() -> Self {
        Self { active: None }
    }

    /// Apply a new config, returning the diff from the previous state.
    ///
    /// If no previous config exists, all services are reported as "added".
    pub fn apply(&mut self, new_config: NodeConfig) -> ConfigDiff {
        let diff = match &self.active {
            Some(old) => ConfigDiff::compute(old, &new_config),
            None => {
                // First config — everything is new
                let mut added: Vec<String> =
                    new_config.services.iter().map(|s| s.name.clone()).collect();
                added.sort();
                ConfigDiff {
                    kernel_changed: true,
                    identity_changed: true,
                    network_changed: true,
                    services_added: added,
                    services_removed: Vec::new(),
                    services_updated: Vec::new(),
                }
            }
        };
        self.active = Some(new_config);
        diff
    }

    /// Get the currently active config, if any.
    pub fn active(&self) -> Option<&NodeConfig> {
        self.active.as_ref()
    }
}

impl Default for ConfigApplicator {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p harmony-os config_applicator`
Expected: all 9 tests PASS.

- [ ] **Step 6: Run full workspace tests + clippy**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings`
Expected: all pass, no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/config_applicator.rs crates/harmony-os/src/lib.rs
git commit -m "feat(config): add ConfigApplicator with diff computation for live config changes"
```

---

### Task 7: Integration test — end-to-end config lifecycle

**Files:**
- Create: `crates/harmony-microkernel/tests/config_lifecycle.rs`

**Context:**
- Integration test that exercises the full flow: build NodeConfig → sign → ingest into CAS → stage via ConfigServer → commit → read back → verify.
- Uses `ContentServer`, `ConfigServer`, `NodeConfig`, `SignedConfig` together.
- This validates the seams between all components work correctly.

- [ ] **Step 1: Write the integration test**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! End-to-end integration test for the config lifecycle:
//! Build → Sign → Ingest → Stage → Commit → Read back → Verify.

use std::sync::Arc;

use harmony_microkernel::content_server::{format_cid_hex, ContentServer};
use harmony_microkernel::config_server::ConfigServer;
use harmony_microkernel::node_config::{NetworkConfig, NodeConfig, ServiceEntry, SCHEMA_VERSION};
use harmony_microkernel::signed_config::SignedConfig;
use harmony_microkernel::{FileServer, OpenMode};
use harmony_identity::PqPrivateIdentity;
use rand_core::OsRng;

/// Ingest bytes into ContentServer via 9P, return the CID.
fn ingest(cas: &mut ContentServer, data: &[u8], fid: u32) -> [u8; 32] {
    cas.walk(0, fid, "ingest").unwrap();
    cas.open(fid, OpenMode::ReadWrite).unwrap();
    cas.write(fid, 0, data).unwrap();
    let resp = cas.read(fid, 0, 256).unwrap();
    cas.clunk(fid).unwrap();
    resp[..32].try_into().unwrap()
}

#[test]
fn full_config_lifecycle() {
    // 1. Create operator identity
    let operator = PqPrivateIdentity::generate(&mut OsRng);
    let pub_id = operator.public_identity();

    // 2. Create stub content for referenced CIDs
    let mut cas = ContentServer::new();
    let kernel_cid = ingest(&mut cas, &[0x4Bu8; 4096], 1);
    let identity_cid = ingest(&mut cas, &[0x49u8; 4096], 2);
    let binary_cid = ingest(&mut cas, &[0x53u8; 4096], 3);

    // 3. Build NodeConfig
    let config = NodeConfig {
        version: SCHEMA_VERSION,
        kernel: kernel_cid,
        identity: identity_cid,
        network: NetworkConfig {
            mesh_seeds: vec![[0x01; 16]],
            port: 4242,
        },
        services: vec![ServiceEntry {
            name: String::from("echo"),
            binary: binary_cid,
            config: None,
        }],
    };

    // 4. Sign it
    let config_bytes = config.to_cbor();
    let signature = operator.sign(&config_bytes).unwrap();
    let signed = SignedConfig {
        config_bytes: config_bytes.clone(),
        signature,
        signer: pub_id.address_hash,
        signer_pubkey: pub_id.to_public_bytes(),
    };

    // 5. Verify the config CID is stable
    let config_cid = config.cid();
    assert_eq!(config_cid, harmony_athenaeum::sha256_hash(&config_bytes));

    // 6. Ingest SignedConfig into CAS
    let signed_cbor = signed.to_cbor();
    let signed_cid = ingest(&mut cas, &signed_cbor, 4);

    // 7. Create ConfigServer, stage + commit
    let cas = Arc::new(cas);
    let trusted = vec![pub_id.address_hash];
    let mut cfg_server = ConfigServer::new(cas, trusted);

    // Stage
    let hex = format_cid_hex(&signed_cid);
    cfg_server.walk(0, 10, "stage").unwrap();
    cfg_server.open(10, OpenMode::Write).unwrap();
    cfg_server.write(10, 0, hex.as_bytes()).unwrap();
    cfg_server.clunk(10).unwrap();

    // Commit
    cfg_server.walk(0, 11, "commit").unwrap();
    cfg_server.open(11, OpenMode::Write).unwrap();
    cfg_server.write(11, 0, b"1").unwrap();
    cfg_server.clunk(11).unwrap();

    // 8. Read back active CID
    cfg_server.walk(0, 20, "active").unwrap();
    cfg_server.open(20, OpenMode::Read).unwrap();
    let active_hex = cfg_server.read(20, 0, 256).unwrap();
    cfg_server.clunk(20).unwrap();
    assert_eq!(
        core::str::from_utf8(&active_hex).unwrap(),
        &format_cid_hex(&signed_cid)
    );

    // 9. Read back node.cbor and verify it decodes
    cfg_server.walk(0, 30, "node.cbor").unwrap();
    cfg_server.open(30, OpenMode::Read).unwrap();
    let cbor = cfg_server.read(30, 0, 65536).unwrap();
    cfg_server.clunk(30).unwrap();

    let decoded = NodeConfig::from_cbor(&cbor).unwrap();
    assert_eq!(decoded, config);
    assert_eq!(decoded.cid(), config_cid);
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p harmony-microkernel --test config_lifecycle`
Expected: PASS.

- [ ] **Step 3: Run full workspace tests + clippy**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings`
Expected: all pass, no warnings.

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-microkernel/tests/config_lifecycle.rs
git commit -m "test(config): add end-to-end config lifecycle integration test"
```
