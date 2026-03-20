// SPDX-License-Identifier: GPL-2.0-or-later
//! Microkernel — process table, IPC dispatch, capability enforcement.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_identity::{CapabilityType, MemoryRevocationSet, PqPrivateIdentity, PqUcanToken};
use harmony_platform::EntropySource;
use rand_core::CryptoRngCore;

use crate::key_hierarchy::{verify_session_binding, AttestationPair, BoundCapability};
use crate::pq_capability::{verify_pq_token, PqMemoryIdentityStore, PqMemoryProofStore};

use crate::integrity::lyll::{HashEntry, Lyll, LyllConfig};
use crate::integrity::nakaiah::{CapChain, Nakaiah};
use crate::namespace::Namespace;
use crate::vm::cap_tracker::MemoryBudget;
use crate::vm::manager::AddressSpaceManager;
use crate::vm::page_table::PageTable;
use crate::vm::{
    ContentHash, FrameClassification, MemoryZone, PageFlags, PhysAddr, VirtAddr, VmError,
};
use crate::{Fid, FileServer, IpcError, OpenMode, QPath};

/// Maximum UCAN delegation chain depth for capability verification.
/// Chains longer than this are rejected. 5 is generous for milestone A
/// where all tokens are root-issued (depth 0).
const MAX_DELEGATION_DEPTH: usize = 5;

/// Default capability TTL in **milliseconds** of abstract kernel time.
/// A value of `1_000_000_000` gives a ~11.5-day window, generous for
/// milestone A where short-lived processes are the norm.
/// Production builds should use context-appropriate, shorter TTLs.
const DEFAULT_CAP_TTL: u64 = 1_000_000_000;

/// Maximum number of session-binding nonces tracked per boot cycle.
/// Each entry is 16 bytes + BTreeSet node overhead (~64 bytes total).
/// 4096 entries ≈ 256 KB — bounded and predictable. Once reached, no
/// new user-capability bindings are accepted until the next reboot.
const MAX_BINDING_NONCES: usize = 4096;

/// A process in the microkernel.
pub struct Process {
    pub pid: u32,
    pub name: Arc<str>,
    pub(crate) namespace: Namespace,
    /// Kernel-issued capabilities (signed by session key, no binding needed).
    pub(crate) kernel_capabilities: Vec<PqUcanToken>,
    /// User-submitted capabilities (require session binding).
    pub(crate) user_capabilities: Vec<BoundCapability>,
    /// Milestone A: PID-derived placeholder. Production builds will use
    /// a cryptographic address (e.g. SHA-256 of the process's public key).
    pub(crate) address_hash: [u8; 16],
    server: Box<dyn FileServer>,
}

/// The microkernel: process table, IPC dispatch, capability enforcement.
pub struct Kernel<P: PageTable> {
    processes: BTreeMap<u32, Process>,
    next_pid: u32,
    hardware_identity: PqPrivateIdentity,
    session_identity: PqPrivateIdentity,
    /// Stored for future boot verification and user provisioning.
    /// Not yet read — will be used when owner provisioning UX is added.
    #[allow(dead_code)]
    attestation: AttestationPair,
    used_binding_nonces: BTreeSet<[u8; 16]>,
    identity_store: PqMemoryIdentityStore,
    proof_store: PqMemoryProofStore,
    revocations: MemoryRevocationSet,
    /// Maps (client_pid, client_fid) -> (target_pid, server_fid).
    /// The kernel translates client fids to server-local fids to prevent
    /// collisions when multiple clients share a server.
    fid_owners: BTreeMap<(u32, Fid), (u32, Fid)>,
    /// Monotonic counter for allocating server-side fids.
    next_server_fid: Fid,
    /// Virtual memory manager — owns per-process address spaces, the buddy
    /// allocator, and capability tracker.
    vm: AddressSpaceManager<P>,
    /// Lyll — the probabilistic public-memory auditor.
    lyll: Lyll,
    /// Nakaiah — the deterministic private-memory bodyguard.
    nakaiah: Nakaiah,
}

impl<P: PageTable> Kernel<P> {
    /// Create a new microkernel with the given key hierarchy and VM manager.
    pub fn new(
        hardware_identity: PqPrivateIdentity,
        session_identity: PqPrivateIdentity,
        attestation: AttestationPair,
        vm: AddressSpaceManager<P>,
    ) -> Self {
        let mut identity_store = PqMemoryIdentityStore::new();
        identity_store.insert(hardware_identity.public_identity().clone());
        identity_store.insert(session_identity.public_identity().clone());
        // Register the owner's public identity so Chain-2 UCANs (Owner → User)
        // can be verified. The owner's identity is extracted from the attestation
        // pair's claim — the owner_address is their PQ address hash, and we need
        // to resolve their full public key for signature verification.
        // NOTE: For the owner's public key to be verifiable, it must be submitted
        // separately (e.g., via a provisioning step). For now, the attestation pair
        // carries the address hashes but not the full public keys. User capability
        // verification requires the owner's full PqIdentity in the store — this is
        // wired up during provisioning (future work) or in tests via identity_store.
        let mut kernel = Kernel {
            processes: BTreeMap::new(),
            next_pid: 0,
            hardware_identity,
            session_identity,
            attestation,
            used_binding_nonces: BTreeSet::new(),
            identity_store,
            proof_store: PqMemoryProofStore::new(),
            revocations: MemoryRevocationSet::new(),
            fid_owners: BTreeMap::new(),
            next_server_fid: 1,
            vm,
            lyll: Lyll::new(LyllConfig {
                sampling_rate_percent: 5,
                sweep_interval_ticks: 100,
            }),
            nakaiah: Nakaiah::new(100), // 100 bps = 1%
        };
        kernel.sync_guardian_state_hashes();
        kernel
    }

    /// Register an external identity (e.g., the owner's public key) so that
    /// UCANs issued by that identity can be verified via `verify_pq_token`.
    ///
    /// The owner's public key must be registered before user capabilities
    /// (Chain-2 UCANs signed by the owner) can pass verification.
    pub fn register_identity(&mut self, identity: harmony_identity::PqIdentity) {
        self.identity_store.insert(identity);
    }

    /// Submit a user capability (UCAN + session binding) to a process.
    ///
    /// The capability is NOT verified at submission time — it will be verified
    /// lazily at walk time via `check_endpoint_cap`.
    pub fn submit_user_capability(
        &mut self,
        pid: u32,
        capability: BoundCapability,
    ) -> Result<(), IpcError> {
        let process = self.processes.get_mut(&pid).ok_or(IpcError::NotFound)?;
        process.user_capabilities.push(capability);
        Ok(())
    }

    /// Exchange state hashes between Lyll and Nakaiah so each guardian
    /// holds an up-to-date snapshot of the other's state for mutual
    /// verification.
    fn sync_guardian_state_hashes(&mut self) {
        self.lyll.set_nakaiah_state_hash(self.nakaiah.state_hash());
        self.nakaiah.set_lyll_state_hash(self.lyll.state_hash());
    }

    /// Allocate a unique server-side fid. Returns an error if the
    /// fid counter is exhausted (after ~4 billion allocations).
    ///
    /// Counter values are monotonic and never recycled. On walk failure,
    /// pre-allocated fid values are "lost" — this is intentional: the u32
    /// space is enormous and recycling would add error-prone complexity.
    fn allocate_server_fid(&mut self) -> Result<Fid, IpcError> {
        let fid = self.next_server_fid;
        self.next_server_fid = self
            .next_server_fid
            .checked_add(1)
            .ok_or(IpcError::ResourceExhausted)?;
        Ok(fid)
    }

    /// Spawn a process. Returns the assigned PID.
    ///
    /// `mounts` are (path, target_pid, root_fid) tuples to pre-populate
    /// the process's namespace. `target_pid` must refer to an already-spawned
    /// process. `root_fid` is trusted — it is not validated against the
    /// target server's fid table (by convention, 0 = root directory).
    ///
    /// When `vm_config` is `Some`, a VM address space is created for the
    /// process with the given budget and page table. When `None`, no VM
    /// space is created (suitable for kernel-internal processes).
    pub fn spawn_process(
        &mut self,
        name: &str,
        server: Box<dyn FileServer>,
        mounts: &[(&str, u32, Fid)],
        vm_config: Option<(MemoryBudget, P)>,
    ) -> Result<u32, IpcError> {
        // Validate mounts before allocating a PID so failures don't waste IDs.
        let mut namespace = Namespace::new();
        for &(path, target_pid, root_fid) in mounts {
            if !self.processes.contains_key(&target_pid) {
                return Err(IpcError::InvalidArgument);
            }
            namespace.mount(path, target_pid, root_fid)?;
        }

        let pid = self.next_pid;
        self.next_pid = self
            .next_pid
            .checked_add(1)
            .ok_or(IpcError::ResourceExhausted)?;

        // Create VM address space if configured.
        if let Some((budget, page_table)) = vm_config {
            self.vm
                .create_space(pid, budget, page_table)
                .map_err(|_| IpcError::ResourceExhausted)?;
        }

        // Derive a simple address hash from the pid.
        let mut address_hash = [0u8; 16];
        address_hash[..4].copy_from_slice(&pid.to_be_bytes());

        self.processes.insert(
            pid,
            Process {
                pid,
                name: Arc::from(name),
                namespace,
                kernel_capabilities: Vec::new(),
                user_capabilities: Vec::new(),
                address_hash,
                server,
            },
        );

        Ok(pid)
    }

    /// Destroy a process, removing it from the process table and
    /// cleaning up its VM address space (if one exists).
    ///
    /// Returns `Err(IpcError::NotFound)` if the PID does not exist.
    /// VM cleanup is best-effort — if the process has no VM space,
    /// the error is silently ignored.
    pub fn destroy_process(&mut self, pid: u32) -> Result<(), IpcError> {
        self.processes.remove(&pid).ok_or(IpcError::NotFound)?;

        // Collect client-side fids so we can notify the target servers.
        // These are fids where the destroyed process was the client.
        let client_fids: Vec<(u32, Fid)> = self
            .fid_owners
            .iter()
            .filter(|&(&(p, _), _)| p == pid)
            .map(|(&(_, _), &(target_pid, server_fid))| (target_pid, server_fid))
            .collect();

        // Clunk each client-side fid against its target server to release
        // server-side resources (open file handles, buffers, etc.).
        for &(target_pid, server_fid) in &client_fids {
            if let Some(target) = self.processes.get_mut(&target_pid) {
                let _ = target.server.clunk(server_fid);
            }
        }

        // Remove all fid ownership entries: both where this process is the
        // client (key side) and where it is the target server (value side).
        self.fid_owners
            .retain(|&(p, _), &mut (tp, _)| p != pid && tp != pid);

        // Collect integrity info before destroying VM space.
        if let Some(space) = self.vm.space(pid) {
            let frame_info: Vec<(PhysAddr, FrameClassification)> = space
                .regions
                .values()
                .flat_map(|r| r.frames.iter().map(|&p| (p, r.classification)))
                .collect();

            for (paddr, class) in frame_info {
                self.lyll.unregister_frame(paddr);
                if class.contains(FrameClassification::ENCRYPTED) {
                    self.nakaiah.unregister_frame(paddr);
                }
            }
        }

        // Destroy VM space. Ignore NoSuchProcess — the process may
        // have been spawned without a VM config.
        let _ = self.vm.destroy_space(pid);

        self.sync_guardian_state_hashes();

        Ok(())
    }

    /// Grant an endpoint capability to a process, allowing it to access
    /// the target process's FileServer via IPC.
    pub fn grant_endpoint_cap(
        &mut self,
        entropy: &mut (impl EntropySource + CryptoRngCore),
        process_pid: u32,
        target_pid: u32,
        now: u64,
    ) -> Result<(), IpcError> {
        if !self.processes.contains_key(&target_pid) {
            return Err(IpcError::InvalidArgument);
        }
        let process = self.processes.get(&process_pid).ok_or(IpcError::NotFound)?;
        let audience = process.address_hash;

        let resource = alloc::format!("pid:{}", target_pid);
        let cap = self
            .session_identity
            .issue_pq_root_token(
                entropy,
                &audience,
                CapabilityType::Endpoint,
                resource.as_bytes(),
                now,
                now.saturating_add(DEFAULT_CAP_TTL),
            )
            .map_err(|_| IpcError::PermissionDenied)?;

        let process = self
            .processes
            .get_mut(&process_pid)
            .ok_or(IpcError::NotFound)?;
        process.kernel_capabilities.push(cap);
        Ok(())
    }

    /// Check whether a process holds a valid EndpointCap for `target_pid`.
    ///
    /// Scans both `kernel_capabilities` (session-key-signed, no binding)
    /// and `user_capabilities` (UCAN + session binding). Either vector
    /// producing a valid match returns `Ok`.
    /// Check whether `process` holds a valid endpoint capability for `target_pid`.
    ///
    /// Returns `Ok(nonce)` where `nonce` is `Some` if a user capability's
    /// session binding was accepted (the caller MUST record this nonce in
    /// `used_binding_nonces` to prevent replay), or `None` for kernel caps.
    pub(crate) fn check_endpoint_cap(
        &self,
        process: &Process,
        target_pid: u32,
        now: u64,
    ) -> Result<Option<[u8; 16]>, IpcError> {
        let target_resource = alloc::format!("pid:{}", target_pid);
        let audience_hash = process.address_hash;

        // 1. Scan kernel-issued capabilities (signed by session key).
        for cap in &process.kernel_capabilities {
            if cap.capability != CapabilityType::Endpoint {
                continue;
            }
            if cap.audience != audience_hash {
                continue;
            }
            let resource_str = match core::str::from_utf8(&cap.resource) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if resource_str != target_resource && resource_str != "*" {
                continue;
            }
            if verify_pq_token(
                cap,
                now,
                &self.proof_store,
                &self.identity_store,
                &self.revocations,
                MAX_DELEGATION_DEPTH,
            )
            .is_ok()
            {
                return Ok(None);
            }
        }

        // 2. Scan user-submitted capabilities (UCAN + session binding).
        for bound in &process.user_capabilities {
            let cap = &bound.token;
            if cap.capability != CapabilityType::Endpoint {
                continue;
            }
            // The UCAN's audience is the *user's* cryptographic address (not the
            // PID-derived process address). The binding attests which user is
            // active, so verify binding.user_address == cap.audience to ensure
            // the session binding matches the UCAN's intended recipient.
            if bound.binding.user_address != cap.audience {
                continue;
            }
            let resource_str = match core::str::from_utf8(&cap.resource) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if resource_str != target_resource && resource_str != "*" {
                continue;
            }
            // Verify the UCAN token itself.
            if verify_pq_token(
                cap,
                now,
                &self.proof_store,
                &self.identity_store,
                &self.revocations,
                MAX_DELEGATION_DEPTH,
            )
            .is_err()
            {
                continue;
            }
            // Verify the session binding.
            let token_hash = cap.content_hash();
            if verify_session_binding(
                &bound.binding,
                self.session_identity.public_identity(),
                &self.hardware_identity.public_identity().address_hash,
                &token_hash,
                &self.used_binding_nonces,
            )
            .is_ok()
            {
                return Ok(Some(bound.binding.nonce));
            }
        }

        Err(IpcError::PermissionDenied)
    }

    /// Walk a path on behalf of `from_pid`. Resolves the namespace,
    /// checks capabilities, and dispatches to the target FileServer.
    ///
    /// `_root_fid` is intentionally unused: the kernel resolves the
    /// server's root fid from the namespace mount table, not from
    /// the client's fid space. Retained in the signature for future
    /// relative-walk support (walking from a non-root fid).
    pub fn walk(
        &mut self,
        from_pid: u32,
        path: &str,
        _root_fid: Fid,
        new_fid: Fid,
        now: u64,
    ) -> Result<QPath, IpcError> {
        // Cheap validation first, before expensive crypto checks.
        if self.fid_owners.contains_key(&(from_pid, new_fid)) {
            return Err(IpcError::InvalidFid);
        }

        // Resolve namespace and check capabilities. Split lifetimes on
        // resolve() mean `remainder` borrows from `path`, not from `self`,
        // so no heap allocation is needed to release the process borrow.
        let (target_pid, server_root_fid, remainder) = {
            let (target_pid, server_root_fid, remainder, accepted_nonce) = {
                let process = self.processes.get(&from_pid).ok_or(IpcError::NotFound)?;
                let (mount, remainder) =
                    process.namespace.resolve(path).ok_or(IpcError::NotFound)?;
                let target_pid = mount.target_pid;
                let server_root_fid = mount.root_fid;
                let remainder = remainder.to_owned();
                let accepted_nonce = self.check_endpoint_cap(process, target_pid, now)?;
                (target_pid, server_root_fid, remainder, accepted_nonce)
            };
            // Record session binding nonce after the process borrow is released.
            if let Some(nonce) = accepted_nonce {
                if self.used_binding_nonces.len() >= MAX_BINDING_NONCES {
                    return Err(IpcError::NonceLimitExceeded);
                }
                self.used_binding_nonces.insert(nonce);
            }
            (target_pid, server_root_fid, remainder)
        };

        // Split remainder into path components for multi-level walks.
        // Filter "." (no-op) and reject ".." (traversal above mount root).
        let components: Vec<&str> = remainder
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();
        if components.contains(&"..") {
            return Err(IpcError::PermissionDenied);
        }

        // Pre-allocate all server-side fids before borrowing target mutably.
        // Skip any allocation that collides with server_root_fid to prevent
        // clone_fid/walk failures when the monotonic counter reaches that value.
        let mut server_fid = self.allocate_server_fid()?;
        if server_fid == server_root_fid {
            server_fid = self.allocate_server_fid()?;
        }
        let mut intermediate_fids = Vec::new();
        for _ in 0..components.len().saturating_sub(1) {
            let mut fid = self.allocate_server_fid()?;
            if fid == server_root_fid {
                fid = self.allocate_server_fid()?;
            }
            intermediate_fids.push(fid);
        }

        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;

        let qpath = if components.is_empty() {
            // Walking to the mount root — clone the root fid
            target.server.clone_fid(server_root_fid, server_fid)?
        } else {
            // Walk each path component, clunking intermediate fids.
            // On failure, clean up any fids already created.
            intermediate_fids.push(server_fid);
            let mut current_fid = server_root_fid;
            let mut qpath = 0;
            for (i, component) in components.iter().enumerate() {
                match target
                    .server
                    .walk(current_fid, intermediate_fids[i], component)
                {
                    Ok(q) => {
                        qpath = q;
                        if current_fid != server_root_fid {
                            let _ = target.server.clunk(current_fid);
                        }
                        current_fid = intermediate_fids[i];
                    }
                    Err(e) => {
                        // Clean up intermediate fid from previous iteration
                        if current_fid != server_root_fid {
                            let _ = target.server.clunk(current_fid);
                        }
                        return Err(e);
                    }
                }
            }
            qpath
        };

        // Record fid ownership with the server-side fid translation
        self.fid_owners
            .insert((from_pid, new_fid), (target_pid, server_fid));
        Ok(qpath)
    }

    /// Open a previously walked fid.
    ///
    /// Capability tokens are validated at walk time only, not on
    /// subsequent operations. Once a fid is established, it remains
    /// usable even if the originating token expires. This matches 9P
    /// semantics where authentication gates session setup, not every I/O.
    pub fn open(&mut self, from_pid: u32, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let &(target_pid, server_fid) = self
            .fid_owners
            .get(&(from_pid, fid))
            .ok_or(IpcError::InvalidFid)?;
        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;
        target.server.open(server_fid, mode)
    }

    /// Read from a previously opened fid.
    pub fn read(
        &mut self,
        from_pid: u32,
        fid: Fid,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, IpcError> {
        let &(target_pid, server_fid) = self
            .fid_owners
            .get(&(from_pid, fid))
            .ok_or(IpcError::InvalidFid)?;
        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;
        target.server.read(server_fid, offset, count)
    }

    /// Write to a previously opened fid.
    pub fn write(
        &mut self,
        from_pid: u32,
        fid: Fid,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, IpcError> {
        let &(target_pid, server_fid) = self
            .fid_owners
            .get(&(from_pid, fid))
            .ok_or(IpcError::InvalidFid)?;
        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;
        target.server.write(server_fid, offset, data)
    }

    /// Stat a previously walked fid. Does not require the fid to be open.
    pub fn stat(&mut self, from_pid: u32, fid: Fid) -> Result<crate::FileStat, IpcError> {
        let &(target_pid, server_fid) = self
            .fid_owners
            .get(&(from_pid, fid))
            .ok_or(IpcError::InvalidFid)?;
        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;
        target.server.stat(server_fid)
    }

    /// Release a fid. Always removes the kernel-side tracking entry,
    /// even if the server-side clunk fails — this prevents the client
    /// from being stuck with an unclunkable fid.
    pub fn clunk(&mut self, from_pid: u32, fid: Fid) -> Result<(), IpcError> {
        let (target_pid, server_fid) = self
            .fid_owners
            .remove(&(from_pid, fid))
            .ok_or(IpcError::InvalidFid)?;
        // Best-effort — process may be gone; fid_owners tracking is already removed
        if let Some(target) = self.processes.get_mut(&target_pid) {
            let _ = target.server.clunk(server_fid);
        }
        Ok(())
    }

    // ── Integrity guardians ────────────────────────────────────────────

    /// Read-only access to the Lyll auditor.
    pub fn lyll(&self) -> &Lyll {
        &self.lyll
    }

    /// Mutable access to the Lyll auditor.
    ///
    /// # Sync caveat
    ///
    /// All mutations that change `state_hash` — including
    /// [`Lyll::update_snapshot`], register, and unregister — require a
    /// [`sync_guardian_state_hashes`](Self::sync_guardian_state_hashes) call
    /// afterward so the cross-guardian hashes stay consistent. Prefer the
    /// orchestrated `vm_map_region` / `vm_unmap_region` / `destroy_process`
    /// methods which handle sync automatically.
    pub fn lyll_mut(&mut self) -> &mut Lyll {
        &mut self.lyll
    }

    /// Read-only access to the Nakaiah bodyguard.
    pub fn nakaiah(&self) -> &Nakaiah {
        &self.nakaiah
    }

    /// Mutable access to the Nakaiah bodyguard.
    ///
    /// # Sync caveat
    ///
    /// Structural mutations (register/unregister, grant/revoke) should go
    /// through the orchestrated Kernel methods which call
    /// [`sync_guardian_state_hashes`](Self::sync_guardian_state_hashes)
    /// automatically. Direct mutation without sync may break the
    /// dual-guardian consistency invariant.
    pub fn nakaiah_mut(&mut self) -> &mut Nakaiah {
        &mut self.nakaiah
    }

    /// Read-only access to the VM manager.
    pub fn vm(&self) -> &AddressSpaceManager<P> {
        &self.vm
    }

    // ── VM delegation ────────────────────────────────────────────────

    /// Create a VM address space for a process.
    pub fn vm_create_space(
        &mut self,
        pid: u32,
        budget: MemoryBudget,
        page_table: P,
    ) -> Result<(), VmError> {
        self.vm.create_space(pid, budget, page_table)
    }

    /// Map a region of virtual memory for a process.
    ///
    /// Delegates to the `AddressSpaceManager`, then registers newly mapped
    /// frames with the integrity guardians:
    /// - All frames are registered with Lyll (public memory auditor).
    /// - ENCRYPTED frames are additionally registered with Nakaiah (private
    ///   memory bodyguard).
    pub fn vm_map_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        flags: PageFlags,
        classification: FrameClassification,
    ) -> Result<(), VmError> {
        self.vm.map_region(pid, vaddr, len, flags, classification)?;

        // Register frames with integrity guardians.
        let space = self.vm.space(pid).unwrap();
        let region = space.regions.get(&vaddr).unwrap();
        for &paddr in &region.frames {
            let content_hash = ContentHash::ZERO;
            // Writable or ephemeral frames use Snapshot entries (hash updates via
            // write barrier). Only truly immutable frames use CidBacked.
            let hash_entry = if flags.contains(PageFlags::WRITABLE)
                || classification.contains(FrameClassification::EPHEMERAL)
            {
                HashEntry::Snapshot {
                    hash: content_hash.0,
                    generation: 0,
                }
            } else {
                HashEntry::CidBacked {
                    cid: content_hash.0,
                }
            };
            self.lyll
                .register_frame(paddr, hash_entry, pid, MemoryZone::from(classification));
            if classification.contains(FrameClassification::ENCRYPTED) {
                self.nakaiah.register_frame(paddr, content_hash.0);
                self.nakaiah.grant_access(pid, paddr, CapChain::Owner);
            }
        }

        self.sync_guardian_state_hashes();
        Ok(())
    }

    /// Unmap a region previously mapped at `vaddr` for process `pid`.
    ///
    /// Collects frame and classification info before unmapping, then
    /// unregisters frames from the integrity guardians.
    pub fn vm_unmap_region(&mut self, pid: u32, vaddr: VirtAddr) -> Result<(), VmError> {
        // Collect frames and classification before unmapping (unmap removes the region).
        let (frames, classification) = {
            let space = self.vm.space(pid).ok_or(VmError::NoSuchProcess(pid))?;
            let region = space.regions.get(&vaddr).ok_or(VmError::NotMapped(vaddr))?;
            (region.frames.clone(), region.classification)
        };

        self.vm.unmap_region(pid, vaddr)?;

        // Unregister from guardians.
        for &paddr in &frames {
            self.lyll.unregister_frame(paddr);
            if classification.contains(FrameClassification::ENCRYPTED) {
                self.nakaiah.unregister_frame(paddr);
            }
        }

        self.sync_guardian_state_hashes();
        Ok(())
    }

    /// Change the permission flags on an existing region.
    ///
    /// If the region gains WRITABLE, any CidBacked hash entries are promoted
    /// to Snapshot so that write-barrier hash updates are not silently lost.
    pub fn vm_protect_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        // Check if this is a read-only → writable transition before mutating.
        let was_writable = self
            .vm
            .space(pid)
            .and_then(|s| s.regions.get(&vaddr))
            .map(|r| r.flags.contains(PageFlags::WRITABLE))
            .unwrap_or(false);

        self.vm.protect_region(pid, vaddr, new_flags)?;

        // Promote CidBacked → Snapshot for frames that just became writable.
        if !was_writable && new_flags.contains(PageFlags::WRITABLE) {
            let frames: Vec<PhysAddr> = self
                .vm
                .space(pid)
                .unwrap()
                .regions
                .get(&vaddr)
                .unwrap()
                .frames
                .clone();
            for paddr in frames {
                self.lyll.promote_to_snapshot(paddr);
            }
            self.sync_guardian_state_hashes();
        }

        Ok(())
    }

    /// Find a free region of at least `len` bytes in the process's
    /// address space.
    pub fn vm_find_free_region(&self, pid: u32, len: usize) -> Result<VirtAddr, VmError> {
        self.vm.find_free_region(pid, len)
    }

    /// Check whether a process has a VM address space.
    pub fn has_vm_space(&self, pid: u32) -> bool {
        self.vm.space(pid).is_some()
    }

    /// Translate a virtual address in the given process's page table.
    ///
    /// Returns the mapped physical address and flags, or `None` if unmapped.
    /// Useful for verifying page table state from outside the crate.
    pub fn vm_translate(
        &self,
        pid: u32,
        vaddr: VirtAddr,
    ) -> Option<(crate::vm::PhysAddr, PageFlags)> {
        self.vm.space(pid)?.page_table.translate(vaddr)
    }

    /// Read-only access to the VM manager.
    ///
    /// Exposes the `AddressSpaceManager` for querying buddy allocator state,
    /// capability tracker state, and per-process region tables.
    pub fn vm_manager(&self) -> &AddressSpaceManager<P> {
        &self.vm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::echo::EchoServer;
    use crate::key_hierarchy::{
        AttestationPair, BoundCapability, HardwareAcceptance, OwnerClaim, SessionBinding,
    };
    use crate::vm::buddy::BuddyAllocator;
    use crate::vm::mock::MockPageTable;
    use crate::vm::PhysAddr;
    use harmony_unikernel::KernelEntropy;
    use rand_core::CryptoRngCore;

    fn make_test_entropy() -> KernelEntropy<impl FnMut(&mut [u8])> {
        let mut seed = 42u64;
        KernelEntropy::new(move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
        })
    }

    /// Create a test VM manager with 64 frames.
    fn make_test_vm() -> AddressSpaceManager<MockPageTable> {
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 64).unwrap();
        AddressSpaceManager::new(buddy)
    }

    /// Generate a minimal key hierarchy for tests: hardware identity,
    /// session identity, and a valid `AttestationPair`.
    ///
    /// Generates identities sequentially, dropping the owner before
    /// generating the session key, so only two PQ identities coexist
    /// on the stack at any point. ML-DSA-65 key generation still uses
    /// substantial stack space — see `.cargo/config.toml` for the
    /// `RUST_MIN_STACK` setting that accommodates this.
    fn make_test_hierarchy(
        entropy: &mut impl CryptoRngCore,
    ) -> (PqPrivateIdentity, PqPrivateIdentity, AttestationPair) {
        let owner = PqPrivateIdentity::generate(entropy);
        let owner_addr = owner.public_identity().address_hash;

        let hardware = PqPrivateIdentity::generate(entropy);
        let hw_addr = hardware.public_identity().address_hash;

        // Create OwnerClaim
        let mut nonce = [0u8; 16];
        entropy.fill_bytes(&mut nonce);
        let mut claim = OwnerClaim {
            owner_address: owner_addr,
            hardware_address: hw_addr,
            claimed_at: 0,
            owner_index: 0,
            nonce,
            signature: [0u8; 3309],
        };
        let sig = owner.sign(&claim.signable_bytes()).unwrap();
        claim.signature.copy_from_slice(&sig);

        // Create HardwareAcceptance
        let mut acceptance = HardwareAcceptance {
            hardware_address: hw_addr,
            owner_address: owner_addr,
            accepted_at: 0,
            owner_claim_hash: claim.content_hash(),
            signature: [0u8; 3309],
        };
        let sig = hardware.sign(&acceptance.signable_bytes()).unwrap();
        acceptance.signature.copy_from_slice(&sig);

        // Drop owner — only needed for signing, not stored in the kernel.
        drop(owner);

        let session = PqPrivateIdentity::generate(entropy);

        let attestation = AttestationPair {
            owner_claim: claim,
            hardware_acceptance: acceptance,
        };
        (hardware, session, attestation)
    }

    #[test]
    fn spawn_process_assigns_pid() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let pid = kernel
            .spawn_process("echo", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        assert_eq!(pid, 0);

        let pid2 = kernel
            .spawn_process("echo2", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        assert_eq!(pid2, 1);
    }

    #[test]
    fn capability_check_with_valid_cap() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);

        // Issue the token using the session key before moving it into the kernel.
        let process_addr = [0x01u8; 16];
        let cap = session
            .issue_pq_root_token(
                &mut entropy,
                &process_addr,
                CapabilityType::Endpoint,
                b"pid:1",
                0,
                0,
            )
            .unwrap();

        let kernel = Kernel::new(hw, session, attestation, make_test_vm());

        // Build a synthetic process with the kernel capability.
        let process = Process {
            pid: 0,
            name: Arc::from("test"),
            namespace: crate::namespace::Namespace::new(),
            kernel_capabilities: alloc::vec![cap],
            user_capabilities: Vec::new(),
            address_hash: process_addr,
            server: Box::new(EchoServer::new()),
        };

        assert!(kernel.check_endpoint_cap(&process, 1, 0).is_ok());
    }

    #[test]
    fn capability_check_no_cap() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let process = Process {
            pid: 0,
            name: Arc::from("test"),
            namespace: crate::namespace::Namespace::new(),
            kernel_capabilities: Vec::new(),
            user_capabilities: Vec::new(),
            address_hash: [0x01u8; 16],
            server: Box::new(EchoServer::new()),
        };
        assert_eq!(
            kernel.check_endpoint_cap(&process, 1, 0),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn capability_check_wrong_pid() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);

        // Issue the token using the session key before moving it into the kernel.
        let process_addr = [0x01u8; 16];
        let cap = session
            .issue_pq_root_token(
                &mut entropy,
                &process_addr,
                CapabilityType::Endpoint,
                b"pid:1",
                0,
                0,
            )
            .unwrap();

        let kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let process = Process {
            pid: 0,
            name: Arc::from("test"),
            namespace: crate::namespace::Namespace::new(),
            kernel_capabilities: alloc::vec![cap],
            user_capabilities: Vec::new(),
            address_hash: process_addr,
            server: Box::new(EchoServer::new()),
        };

        // Cap is for pid:1, trying to access pid:2
        assert_eq!(
            kernel.check_endpoint_cap(&process, 2, 0),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn capability_check_wildcard() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);

        // Issue the token using the session key before moving it into the kernel.
        let process_addr = [0x01u8; 16];
        let cap = session
            .issue_pq_root_token(
                &mut entropy,
                &process_addr,
                CapabilityType::Endpoint,
                b"*",
                0,
                0,
            )
            .unwrap();

        let kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let process = Process {
            pid: 0,
            name: Arc::from("test"),
            namespace: crate::namespace::Namespace::new(),
            kernel_capabilities: alloc::vec![cap],
            user_capabilities: Vec::new(),
            address_hash: process_addr,
            server: Box::new(EchoServer::new()),
        };

        // Wildcard should match any pid
        assert!(kernel.check_endpoint_cap(&process, 1, 0).is_ok());
        assert!(kernel.check_endpoint_cap(&process, 99, 0).is_ok());
    }

    // ── IPC dispatch tests ──────────────────────────────────────────

    fn setup_kernel_with_echo() -> (Kernel<MockPageTable>, u32, u32) {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        // pid 0 = echo server
        let server_pid = kernel
            .spawn_process("echo-server", Box::new(EchoServer::new()), &[], None)
            .unwrap();

        // pid 1 = client (also an echo server, but we don't use its server)
        let client_pid = kernel
            .spawn_process(
                "client",
                Box::new(EchoServer::new()),
                &[("/echo", server_pid, 0)],
                None,
            )
            .unwrap();

        // Grant client access to server
        kernel
            .grant_endpoint_cap(&mut entropy, client_pid, server_pid, 0)
            .unwrap();

        (kernel, client_pid, server_pid)
    }

    #[test]
    fn ipc_stat_through_namespace() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        kernel.walk(client, "/echo/hello", 0, 1, 0).unwrap();
        let stat = kernel.stat(client, 1).unwrap();
        assert_eq!(&*stat.name, "hello");
        assert_eq!(stat.file_type, crate::FileType::Regular);
    }

    #[test]
    fn ipc_walk_through_namespace() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        let qpath = kernel.walk(client, "/echo/hello", 0, 1, 0).unwrap();
        assert_eq!(qpath, 1); // hello's qpath
    }

    #[test]
    fn ipc_read_through_namespace() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        kernel.walk(client, "/echo/hello", 0, 1, 0).unwrap();
        kernel.open(client, 1, OpenMode::Read).unwrap();
        let data = kernel.read(client, 1, 0, 256).unwrap();
        assert_eq!(data, b"Hello from echo server!");
    }

    #[test]
    fn ipc_write_and_read_echo() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        kernel.walk(client, "/echo/echo", 0, 1, 0).unwrap();
        kernel.open(client, 1, OpenMode::ReadWrite).unwrap();
        kernel.write(client, 1, 0, b"round trip").unwrap();
        let data = kernel.read(client, 1, 0, 256).unwrap();
        assert_eq!(data, b"round trip");
    }

    #[test]
    fn ipc_denied_without_capability() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let server_pid = kernel
            .spawn_process("echo-server", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        // Client has mount but NO capability
        let client_pid = kernel
            .spawn_process(
                "client",
                Box::new(EchoServer::new()),
                &[("/echo", server_pid, 0)],
                None,
            )
            .unwrap();

        assert_eq!(
            kernel.walk(client_pid, "/echo/hello", 0, 1, 0),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn ipc_unmounted_path() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        assert_eq!(
            kernel.walk(client, "/nonexistent/file", 0, 1, 0),
            Err(IpcError::NotFound)
        );
    }

    #[test]
    fn ipc_clunk_then_read_fails() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        kernel.walk(client, "/echo/hello", 0, 1, 0).unwrap();
        kernel.open(client, 1, OpenMode::Read).unwrap();
        kernel.clunk(client, 1).unwrap();
        assert_eq!(kernel.read(client, 1, 0, 256), Err(IpcError::InvalidFid));
    }

    #[test]
    fn ipc_walk_mount_root() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        // Walk to the mount root itself (no file after mount point)
        let qpath = kernel.walk(client, "/echo", 0, 1, 0).unwrap();
        assert_eq!(qpath, 0); // root qpath

        // The fid should be usable — open succeeds
        kernel.open(client, 1, OpenMode::Read).unwrap();
        kernel.clunk(client, 1).unwrap();
    }

    #[test]
    fn ipc_multi_client_fid_isolation() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        // Shared echo server
        let server_pid = kernel
            .spawn_process("echo-server", Box::new(EchoServer::new()), &[], None)
            .unwrap();

        // Two clients, both mounting the same server
        let client_a = kernel
            .spawn_process(
                "client-a",
                Box::new(EchoServer::new()),
                &[("/echo", server_pid, 0)],
                None,
            )
            .unwrap();
        let client_b = kernel
            .spawn_process(
                "client-b",
                Box::new(EchoServer::new()),
                &[("/echo", server_pid, 0)],
                None,
            )
            .unwrap();

        kernel
            .grant_endpoint_cap(&mut entropy, client_a, server_pid, 0)
            .unwrap();
        kernel
            .grant_endpoint_cap(&mut entropy, client_b, server_pid, 0)
            .unwrap();

        // Both clients walk to /echo/hello using the SAME client fid (1).
        // Without fid virtualization, the second walk would overwrite the first.
        kernel.walk(client_a, "/echo/hello", 0, 1, 0).unwrap();
        kernel.walk(client_b, "/echo/hello", 0, 1, 0).unwrap();

        // Both open and read independently
        kernel.open(client_a, 1, OpenMode::Read).unwrap();
        kernel.open(client_b, 1, OpenMode::Read).unwrap();

        let data_a = kernel.read(client_a, 1, 0, 256).unwrap();
        let data_b = kernel.read(client_b, 1, 0, 256).unwrap();
        assert_eq!(data_a, b"Hello from echo server!");
        assert_eq!(data_b, b"Hello from echo server!");

        // Client A clunks — client B's fid is unaffected
        kernel.clunk(client_a, 1).unwrap();
        assert_eq!(kernel.read(client_a, 1, 0, 256), Err(IpcError::InvalidFid));

        // Client B still works
        let data_b2 = kernel.read(client_b, 1, 0, 256).unwrap();
        assert_eq!(data_b2, b"Hello from echo server!");
    }

    #[test]
    fn ipc_walk_duplicate_fid_rejected() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        kernel.walk(client, "/echo/hello", 0, 1, 0).unwrap();
        // Second walk with same fid without clunking must fail
        assert_eq!(
            kernel.walk(client, "/echo/echo", 0, 1, 0),
            Err(IpcError::InvalidFid)
        );
    }

    #[test]
    fn ipc_walk_dotdot_rejected() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        assert_eq!(
            kernel.walk(client, "/echo/../etc/passwd", 0, 1, 0),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn ipc_walk_dot_ignored() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        // "." components should be silently stripped
        let qpath = kernel.walk(client, "/echo/./hello", 0, 1, 0).unwrap();
        assert_eq!(qpath, 1); // hello's qpath
    }

    #[test]
    fn grant_cap_nonexistent_target_rejected() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let pid = kernel
            .spawn_process("test", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        // target pid 99 doesn't exist
        assert_eq!(
            kernel.grant_endpoint_cap(&mut entropy, pid, 99, 0),
            Err(IpcError::InvalidArgument)
        );
    }

    #[test]
    fn capability_check_expired_token_rejected() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);

        let process_addr = [0x01u8; 16];
        // Token that expires at time 100
        let cap = session
            .issue_pq_root_token(
                &mut entropy,
                &process_addr,
                CapabilityType::Endpoint,
                b"pid:1",
                0,   // not_before: immediate
                100, // expires_at: time 100
            )
            .unwrap();

        let kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let process = Process {
            pid: 0,
            name: Arc::from("test"),
            namespace: crate::namespace::Namespace::new(),
            kernel_capabilities: alloc::vec![cap],
            user_capabilities: Vec::new(),
            address_hash: process_addr,
            server: Box::new(EchoServer::new()),
        };

        // At time 50 — token is valid
        assert!(kernel.check_endpoint_cap(&process, 1, 50).is_ok());

        // At time 200 — token has expired
        assert_eq!(
            kernel.check_endpoint_cap(&process, 1, 200),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn ipc_walk_with_nonzero_now() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        // Tokens are issued with expires_at = DEFAULT_CAP_TTL (1_000_000_000).
        // Walking at now=1_000_000 is well within the TTL, so the walk succeeds.
        let qpath = kernel.walk(client, "/echo/hello", 0, 1, 1_000_000).unwrap();
        assert_eq!(qpath, 1);
    }

    #[test]
    fn integration_two_processes_full_ipc() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        // Spawn echo server as pid 0
        let server_pid = kernel
            .spawn_process("echo-server", Box::new(EchoServer::new()), &[], None)
            .unwrap();

        // Spawn client as pid 1, with echo server mounted at /svc/echo
        let client_pid = kernel
            .spawn_process(
                "harmony-node",
                Box::new(EchoServer::new()), // client also serves, but we test as client
                &[("/svc/echo", server_pid, 0)],
                None,
            )
            .unwrap();

        // Grant client capability to access echo server
        kernel
            .grant_endpoint_cap(&mut entropy, client_pid, server_pid, 0)
            .unwrap();

        // -- Full IPC sequence: walk → open → read → clunk --

        // 1. Walk to /svc/echo/hello
        let qpath = kernel.walk(client_pid, "/svc/echo/hello", 0, 1, 0).unwrap();
        assert_eq!(qpath, 1); // hello qpath

        // 2. Open for reading
        kernel.open(client_pid, 1, OpenMode::Read).unwrap();

        // 3. Read the greeting
        let data = kernel.read(client_pid, 1, 0, 256).unwrap();
        assert_eq!(data, b"Hello from echo server!");

        // 4. Clunk the fid
        kernel.clunk(client_pid, 1).unwrap();

        // -- Echo round-trip: walk → open → write → read → clunk --

        // 5. Walk to /svc/echo/echo
        kernel.walk(client_pid, "/svc/echo/echo", 0, 2, 0).unwrap();

        // 6. Open for read/write
        kernel.open(client_pid, 2, OpenMode::ReadWrite).unwrap();

        // 7. Write data
        let written = kernel.write(client_pid, 2, 0, b"Harmony Ring 2!").unwrap();
        assert_eq!(written, 15);

        // 8. Read it back
        let data = kernel.read(client_pid, 2, 0, 256).unwrap();
        assert_eq!(data, b"Harmony Ring 2!");

        // 9. Clunk
        kernel.clunk(client_pid, 2).unwrap();

        // Verify clunked fids are invalid
        assert_eq!(
            kernel.read(client_pid, 1, 0, 256),
            Err(IpcError::InvalidFid)
        );
        assert_eq!(
            kernel.read(client_pid, 2, 0, 256),
            Err(IpcError::InvalidFid)
        );
    }

    #[test]
    fn content_server_ingest_and_read_via_kernel() {
        use crate::content_server::ContentServer;

        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        // Spawn content server
        let server_pid = kernel
            .spawn_process("content-store", Box::new(ContentServer::new()), &[], None)
            .unwrap();

        // Spawn client with /store mounted to content server
        let client_pid = kernel
            .spawn_process(
                "test-client",
                Box::new(crate::echo::EchoServer::new()),
                &[("/store", server_pid, 0)],
                None,
            )
            .unwrap();

        // Grant capability
        kernel
            .grant_endpoint_cap(&mut entropy, client_pid, server_pid, 0)
            .unwrap();

        // Walk to /store/ingest and open for ReadWrite
        kernel.walk(client_pid, "/store/ingest", 0, 1, 0).unwrap();
        kernel.open(client_pid, 1, OpenMode::ReadWrite).unwrap();

        // Write blob data
        let blob_data = alloc::vec![0x42u8; 4096];
        let written = kernel.write(client_pid, 1, 0, &blob_data).unwrap();
        assert_eq!(written, 4096);

        // Read to finalize — get back CID + metadata
        let response = kernel.read(client_pid, 1, 0, 256).unwrap();
        assert_eq!(response.len(), 40);

        // Parse the CID from response
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&response[..32]);

        // Format CID as hex for the walk path
        let cid_hex = crate::content_server::format_cid_hex(&cid);

        kernel.clunk(client_pid, 1).unwrap();

        // Now walk to /store/blobs/<cid> and read the blob back
        let blob_path = alloc::format!("/store/blobs/{}", cid_hex);
        kernel.walk(client_pid, &blob_path, 0, 2, 0).unwrap();
        kernel.open(client_pid, 2, OpenMode::Read).unwrap();

        let read_back = kernel.read(client_pid, 2, 0, 16384).unwrap();
        assert_eq!(read_back, blob_data);

        kernel.clunk(client_pid, 2).unwrap();
    }

    // ── VM integration tests ──────────────────────────────────────────

    #[test]
    fn spawn_with_vm_config_creates_address_space() {
        use crate::vm::{FrameClassification, PAGE_SIZE};

        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let budget = MemoryBudget::new(PAGE_SIZE as usize * 16, FrameClassification::all());
        let page_table = MockPageTable::new(PhysAddr(0x20_0000));

        let pid = kernel
            .spawn_process(
                "vm-process",
                Box::new(EchoServer::new()),
                &[],
                Some((budget, page_table)),
            )
            .unwrap();

        // The VM manager should now have a space for this PID.
        assert!(kernel.vm.space(pid).is_some());
    }

    #[test]
    fn spawn_without_vm_config_no_address_space() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let pid = kernel
            .spawn_process("no-vm", Box::new(EchoServer::new()), &[], None)
            .unwrap();

        // No VM space should exist.
        assert!(kernel.vm.space(pid).is_none());
    }

    #[test]
    fn destroy_process_removes_from_table() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let pid = kernel
            .spawn_process("doomed", Box::new(EchoServer::new()), &[], None)
            .unwrap();

        kernel.destroy_process(pid).unwrap();

        // Process should be gone — spawning a new one should get the next PID.
        let pid2 = kernel
            .spawn_process("replacement", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        assert_eq!(pid2, 1); // PID counter is monotonic, not recycled.
    }

    #[test]
    fn destroy_process_cleans_up_vm_space() {
        use crate::vm::{FrameClassification, PAGE_SIZE};

        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let budget = MemoryBudget::new(PAGE_SIZE as usize * 16, FrameClassification::all());
        let page_table = MockPageTable::new(PhysAddr(0x20_0000));

        let pid = kernel
            .spawn_process(
                "vm-process",
                Box::new(EchoServer::new()),
                &[],
                Some((budget, page_table)),
            )
            .unwrap();

        assert!(kernel.vm.space(pid).is_some());

        kernel.destroy_process(pid).unwrap();

        // VM space should be destroyed.
        assert!(kernel.vm.space(pid).is_none());
    }

    #[test]
    fn destroy_process_cleans_up_fid_ownership() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();

        // Walk to create a fid mapping.
        kernel.walk(client, "/echo/hello", 0, 1, 0).unwrap();

        // Destroy the client process.
        kernel.destroy_process(client).unwrap();

        // The fid should no longer be tracked — operations should fail with NotFound
        // (process gone), not InvalidFid (fid tracking stale).
        assert_eq!(kernel.read(client, 1, 0, 256), Err(IpcError::InvalidFid));
    }

    #[test]
    fn destroy_nonexistent_process_fails() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        assert_eq!(kernel.destroy_process(99), Err(IpcError::NotFound));
    }

    #[test]
    fn destroy_process_without_vm_succeeds() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let pid = kernel
            .spawn_process("no-vm", Box::new(EchoServer::new()), &[], None)
            .unwrap();

        // destroy_process should succeed even though there's no VM space.
        kernel.destroy_process(pid).unwrap();
    }

    #[test]
    fn ipc_still_works_with_vm_enabled_processes() {
        use crate::vm::{FrameClassification, PAGE_SIZE};

        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let budget = MemoryBudget::new(PAGE_SIZE as usize * 16, FrameClassification::all());

        // Spawn server with VM space.
        let server_pid = kernel
            .spawn_process(
                "echo-server",
                Box::new(EchoServer::new()),
                &[],
                Some((budget.clone(), MockPageTable::new(PhysAddr(0x20_0000)))),
            )
            .unwrap();

        // Spawn client with VM space.
        let client_pid = kernel
            .spawn_process(
                "client",
                Box::new(EchoServer::new()),
                &[("/echo", server_pid, 0)],
                Some((budget, MockPageTable::new(PhysAddr(0x30_0000)))),
            )
            .unwrap();

        kernel
            .grant_endpoint_cap(&mut entropy, client_pid, server_pid, 0)
            .unwrap();

        // Full IPC round trip should work identically to without VM.
        kernel.walk(client_pid, "/echo/hello", 0, 1, 0).unwrap();
        kernel.open(client_pid, 1, OpenMode::Read).unwrap();
        let data = kernel.read(client_pid, 1, 0, 256).unwrap();
        assert_eq!(data, b"Hello from echo server!");
        kernel.clunk(client_pid, 1).unwrap();
    }

    // ── Cross-component integration tests ────────────────────────────

    #[test]
    fn test_two_processes_isolated() {
        use crate::vm::{FrameClassification, PAGE_SIZE};

        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let budget = MemoryBudget::new(PAGE_SIZE as usize * 16, FrameClassification::all());

        // Spawn two VM-enabled processes with separate page tables.
        let pid_a = kernel
            .spawn_process(
                "process-a",
                Box::new(EchoServer::new()),
                &[],
                Some((budget.clone(), MockPageTable::new(PhysAddr(0x20_0000)))),
            )
            .unwrap();

        let pid_b = kernel
            .spawn_process(
                "process-b",
                Box::new(EchoServer::new()),
                &[],
                Some((budget, MockPageTable::new(PhysAddr(0x30_0000)))),
            )
            .unwrap();

        let rw_user = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER;

        // Map a region in process A at 0x1000.
        kernel
            .vm_map_region(
                pid_a,
                VirtAddr(0x1000),
                PAGE_SIZE as usize * 2,
                rw_user,
                FrameClassification::empty(),
            )
            .unwrap();

        // Map a region in process B at 0x5000.
        kernel
            .vm_map_region(
                pid_b,
                VirtAddr(0x5000),
                PAGE_SIZE as usize * 2,
                rw_user,
                FrameClassification::empty(),
            )
            .unwrap();

        // Verify process A can see its own mapping.
        let space_a = kernel.vm.space(pid_a).unwrap();
        assert!(
            space_a.page_table.translate(VirtAddr(0x1000)).is_some(),
            "Process A should see its own mapping at 0x1000"
        );
        assert!(
            space_a.page_table.translate(VirtAddr(0x2000)).is_some(),
            "Process A should see its own mapping at 0x2000"
        );

        // Verify process A does NOT see process B's mapping.
        assert!(
            space_a.page_table.translate(VirtAddr(0x5000)).is_none(),
            "Process A must NOT see process B's mapping at 0x5000"
        );
        assert!(
            space_a.page_table.translate(VirtAddr(0x6000)).is_none(),
            "Process A must NOT see process B's mapping at 0x6000"
        );

        // Verify process B can see its own mapping.
        let space_b = kernel.vm.space(pid_b).unwrap();
        assert!(
            space_b.page_table.translate(VirtAddr(0x5000)).is_some(),
            "Process B should see its own mapping at 0x5000"
        );
        assert!(
            space_b.page_table.translate(VirtAddr(0x6000)).is_some(),
            "Process B should see its own mapping at 0x6000"
        );

        // Verify process B does NOT see process A's mapping.
        assert!(
            space_b.page_table.translate(VirtAddr(0x1000)).is_none(),
            "Process B must NOT see process A's mapping at 0x1000"
        );
        assert!(
            space_b.page_table.translate(VirtAddr(0x2000)).is_none(),
            "Process B must NOT see process A's mapping at 0x2000"
        );

        // Even at the same virtual address, mappings go to different physical frames.
        // Map at 0x9000 in both processes — they should get different physical frames.
        kernel
            .vm_map_region(
                pid_a,
                VirtAddr(0x9000),
                PAGE_SIZE as usize,
                rw_user,
                FrameClassification::empty(),
            )
            .unwrap();
        kernel
            .vm_map_region(
                pid_b,
                VirtAddr(0x9000),
                PAGE_SIZE as usize,
                rw_user,
                FrameClassification::empty(),
            )
            .unwrap();

        let (phys_a, _) = kernel
            .vm
            .space(pid_a)
            .unwrap()
            .page_table
            .translate(VirtAddr(0x9000))
            .unwrap();
        let (phys_b, _) = kernel
            .vm
            .space(pid_b)
            .unwrap()
            .page_table
            .translate(VirtAddr(0x9000))
            .unwrap();
        assert_ne!(
            phys_a, phys_b,
            "Same vaddr in different processes must map to different physical frames"
        );
    }

    /// Verify that ENCRYPTED frames are tracked and cleaned up on unmap.
    ///
    /// NOTE: MockPageTable does not model frame contents, so actual zero-fill
    /// is not verified here. On real hardware, the unmap path zeroizes frames
    /// classified as ENCRYPTED before returning them to the buddy pool.
    #[test]
    fn test_encrypted_zeroize_on_unmap() {
        use crate::vm::{FrameClassification, PAGE_SIZE};

        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let budget = MemoryBudget::new(PAGE_SIZE as usize * 16, FrameClassification::all());
        let pid = kernel
            .spawn_process(
                "enc-process",
                Box::new(EchoServer::new()),
                &[],
                Some((budget, MockPageTable::new(PhysAddr(0x20_0000)))),
            )
            .unwrap();

        let initial_free = kernel.vm.buddy().free_frame_count();

        // Map 2 pages as ENCRYPTED.
        let vaddr = VirtAddr(0x1000);
        kernel
            .vm_map_region(
                pid,
                vaddr,
                PAGE_SIZE as usize * 2,
                PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER,
                FrameClassification::ENCRYPTED,
            )
            .unwrap();

        // Verify the cap_tracker tracks them as ENCRYPTED.
        let encrypted_frames = kernel
            .vm
            .cap_tracker()
            .frames_with_classification(FrameClassification::ENCRYPTED);
        assert_eq!(
            encrypted_frames.len(),
            2,
            "Both frames should be tracked as ENCRYPTED"
        );
        for (_, pids) in &encrypted_frames {
            assert!(
                pids.contains(&pid),
                "Encrypted frames should be owned by our process"
            );
        }

        // Verify buddy allocator shows 2 fewer free frames.
        assert_eq!(kernel.vm.buddy().free_frame_count(), initial_free - 2);

        // Unmap the region — this returns classification from cap_tracker
        // internally, signaling the caller to zeroize ENCRYPTED frames.
        kernel.vm_unmap_region(pid, vaddr).unwrap();

        // After unmap: cap_tracker should have no ENCRYPTED frames tracked.
        let encrypted_after = kernel
            .vm
            .cap_tracker()
            .frames_with_classification(FrameClassification::ENCRYPTED);
        assert_eq!(
            encrypted_after.len(),
            0,
            "No encrypted frames should be tracked after unmap"
        );

        // Frames should be returned to the buddy allocator.
        assert_eq!(
            kernel.vm.buddy().free_frame_count(),
            initial_free,
            "All frames should be freed back to the buddy allocator"
        );

        // The page table should no longer have these mappings.
        let space = kernel.vm.space(pid).unwrap();
        assert!(space.page_table.translate(VirtAddr(0x1000)).is_none());
        assert!(space.page_table.translate(VirtAddr(0x2000)).is_none());
    }

    #[test]
    fn test_process_exit_cleanup() {
        use crate::vm::{FrameClassification, PAGE_SIZE};

        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let initial_free = kernel.vm.buddy().free_frame_count();

        let budget = MemoryBudget::new(PAGE_SIZE as usize * 32, FrameClassification::all());
        let pid = kernel
            .spawn_process(
                "doomed-process",
                Box::new(EchoServer::new()),
                &[],
                Some((budget, MockPageTable::new(PhysAddr(0x20_0000)))),
            )
            .unwrap();

        // Map several regions with different sizes and classifications.

        // Region 1: 4 pages, public
        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize * 4,
                PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER,
                FrameClassification::empty(),
            )
            .unwrap();

        // Region 2: 2 pages, ENCRYPTED
        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x10000),
                PAGE_SIZE as usize * 2,
                PageFlags::READABLE | PageFlags::USER,
                FrameClassification::ENCRYPTED,
            )
            .unwrap();

        // Region 3: 1 page, EPHEMERAL
        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x20000),
                PAGE_SIZE as usize,
                PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER,
                FrameClassification::EPHEMERAL,
            )
            .unwrap();

        // Region 4: 3 pages, ENCRYPTED | EPHEMERAL
        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x30000),
                PAGE_SIZE as usize * 3,
                PageFlags::READABLE | PageFlags::EXECUTABLE | PageFlags::USER,
                FrameClassification::ENCRYPTED | FrameClassification::EPHEMERAL,
            )
            .unwrap();

        // Total: 4 + 2 + 1 + 3 = 10 frames consumed.
        assert_eq!(kernel.vm.buddy().free_frame_count(), initial_free - 10);

        // Verify classified frames are tracked.
        assert!(!kernel
            .vm
            .cap_tracker()
            .frames_with_classification(FrameClassification::ENCRYPTED)
            .is_empty());

        // Destroy the process.
        kernel.destroy_process(pid).unwrap();

        // All 10 frames should be returned to the buddy allocator.
        assert_eq!(
            kernel.vm.buddy().free_frame_count(),
            initial_free,
            "All frames must be freed on process destruction"
        );

        // VM space should be gone.
        assert!(
            kernel.vm.space(pid).is_none(),
            "VM space should be removed after process destruction"
        );

        // Process should be gone from the kernel.
        assert!(
            !kernel.has_vm_space(pid),
            "has_vm_space should return false for destroyed process"
        );

        // Cap tracker budget should be removed.
        assert!(
            kernel.vm.cap_tracker().budget(pid).is_none(),
            "Budget should be removed after process destruction"
        );

        // Cap tracker should have no frames from this process.
        let all_encrypted = kernel
            .vm
            .cap_tracker()
            .frames_with_classification(FrameClassification::ENCRYPTED);
        for (_, pids) in &all_encrypted {
            assert!(
                !pids.contains(&pid),
                "No encrypted frames should reference the destroyed process"
            );
        }
        let all_ephemeral = kernel
            .vm
            .cap_tracker()
            .frames_with_classification(FrameClassification::EPHEMERAL);
        for (_, pids) in &all_ephemeral {
            assert!(
                !pids.contains(&pid),
                "No ephemeral frames should reference the destroyed process"
            );
        }
    }

    // ── Integrity guardian tests ────────────────────────────────────────

    use crate::vm::PAGE_SIZE;

    fn make_kernel() -> Kernel<MockPageTable> {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        Kernel::new(hw, session, attestation, make_test_vm())
    }

    fn default_budget() -> MemoryBudget {
        MemoryBudget::new(64 * PAGE_SIZE as usize, FrameClassification::all())
    }

    fn rw_user_flags() -> PageFlags {
        PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER
    }

    fn spawn_test_process(kernel: &mut Kernel<MockPageTable>) -> u32 {
        kernel
            .spawn_process("test", Box::new(EchoServer::new()), &[], None)
            .unwrap()
    }

    #[test]
    fn kernel_has_integrity_guardians() {
        let kernel = make_kernel();
        assert_eq!(kernel.lyll().registry_len(), 0);
        assert_eq!(kernel.nakaiah().integrity_registry_len(), 0);
    }

    #[test]
    fn map_region_registers_with_lyll() {
        let mut kernel = make_kernel();
        let pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::empty(),
            )
            .unwrap();

        assert_eq!(kernel.lyll().registry_len(), 1);
    }

    #[test]
    fn map_encrypted_region_registers_with_both() {
        let mut kernel = make_kernel();
        let pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::ENCRYPTED,
            )
            .unwrap();

        assert_eq!(kernel.lyll().registry_len(), 1);
        assert_eq!(kernel.nakaiah().integrity_registry_len(), 1);
    }

    use crate::integrity::IntegrityVerdict;
    use crate::vm::{AccessOp, ViolationReason};

    #[test]
    fn public_corruption_detected_and_quarantined() {
        let mut kernel = make_kernel();
        let pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::empty(),
            )
            .unwrap();

        // Get the physical address of the mapped frame.
        let paddr = kernel
            .vm()
            .space(pid)
            .unwrap()
            .regions
            .get(&VirtAddr(0x1000))
            .unwrap()
            .frames[0];

        // Simulate Lyll spot-checking and finding tampered content.
        let tampered_hash = [0xFF; 32];
        let verdict = kernel.lyll_mut().verify_frame(paddr, tampered_hash, 100);
        assert!(
            matches!(verdict, IntegrityVerdict::Quarantine { .. }),
            "expected Quarantine, got {:?}",
            verdict
        );
        assert!(kernel.lyll().quarantine.is_quarantined(paddr));
    }

    #[test]
    fn private_corruption_kills_process() {
        let mut kernel = make_kernel();
        let pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::ENCRYPTED,
            )
            .unwrap();

        let paddr = kernel
            .vm()
            .space(pid)
            .unwrap()
            .regions
            .get(&VirtAddr(0x1000))
            .unwrap()
            .frames[0];

        // vm_map_region auto-grants CapChain::Owner to the owning process.
        // Tampered content -> kill.
        let verdict = kernel.nakaiah().verify_access(
            pid,
            paddr,
            AccessOp::Read,
            [0xFF; 32], // Wrong hash -- content was zeroed at map time.
        );
        assert!(
            matches!(
                verdict,
                IntegrityVerdict::Kill {
                    reason: ViolationReason::ContentTampered,
                    ..
                }
            ),
            "expected Kill/ContentTampered, got {:?}",
            verdict
        );
    }

    #[test]
    fn unauthorized_access_kills_process() {
        let mut kernel = make_kernel();
        let owner_pid = spawn_test_process(&mut kernel);
        let intruder_pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                owner_pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        kernel
            .vm_map_region(
                owner_pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::ENCRYPTED,
            )
            .unwrap();

        let paddr = kernel
            .vm()
            .space(owner_pid)
            .unwrap()
            .regions
            .get(&VirtAddr(0x1000))
            .unwrap()
            .frames[0];

        // Intruder process has no capability -- unauthorized.
        let verdict = kernel.nakaiah().verify_access(
            intruder_pid,
            paddr,
            AccessOp::Read,
            [0u8; 32], // Content matches (it's zeroed).
        );
        assert!(
            matches!(
                verdict,
                IntegrityVerdict::Kill {
                    reason: ViolationReason::UnauthorizedAccess,
                    ..
                }
            ),
            "expected Kill/UnauthorizedAccess, got {:?}",
            verdict
        );
    }

    #[test]
    fn destroy_process_cleans_up_integrity() {
        let mut kernel = make_kernel();
        let pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize * 3,
                rw_user_flags(),
                FrameClassification::ENCRYPTED,
            )
            .unwrap();

        assert_eq!(kernel.lyll().registry_len(), 3);
        assert_eq!(kernel.nakaiah().integrity_registry_len(), 3);

        kernel.destroy_process(pid).unwrap();

        // Both guardians should have cleaned up.
        assert_eq!(kernel.lyll().registry_len(), 0);
        assert_eq!(kernel.nakaiah().integrity_registry_len(), 0);
    }

    #[test]
    fn kernel_syncs_guardian_state_hashes_on_construction() {
        let kernel = make_kernel();
        // After construction, Lyll should hold Nakaiah's state hash and vice versa.
        assert_eq!(
            kernel.lyll().nakaiah_state_hash(),
            kernel.nakaiah().state_hash()
        );
        assert_eq!(
            kernel.nakaiah().lyll_state_hash(),
            kernel.lyll().state_hash()
        );
    }

    #[test]
    fn guardian_compromise_panics() {
        let mut kernel = make_kernel();

        // Kernel::new already exchanges initial state hashes.
        // Simulate Nakaiah compromise — change its state hash to something unexpected.
        kernel.nakaiah_mut().set_state_hash(ContentHash([0xFF; 32]));

        // Lyll detects it.
        let verdict = kernel
            .lyll()
            .co_verify_nakaiah(kernel.nakaiah().state_hash());
        assert!(
            matches!(
                verdict,
                IntegrityVerdict::Panic {
                    reason: ViolationReason::GuardianStateCorrupted
                }
            ),
            "expected Panic/GuardianStateCorrupted, got {:?}",
            verdict
        );
    }

    #[test]
    fn unmap_region_unregisters_from_guardians() {
        let mut kernel = make_kernel();
        let pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::ENCRYPTED,
            )
            .unwrap();
        assert_eq!(kernel.lyll().registry_len(), 1);
        assert_eq!(kernel.nakaiah().integrity_registry_len(), 1);

        kernel.vm_unmap_region(pid, VirtAddr(0x1000)).unwrap();
        assert_eq!(kernel.lyll().registry_len(), 0);
        assert_eq!(kernel.nakaiah().integrity_registry_len(), 0);
    }

    #[test]
    fn encrypted_frame_auto_grants_owner_capability() {
        let mut kernel = make_kernel();
        let pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::ENCRYPTED,
            )
            .unwrap();

        let paddr = kernel
            .vm()
            .space(pid)
            .unwrap()
            .regions
            .get(&VirtAddr(0x1000))
            .unwrap()
            .frames[0];

        // Owner should be able to access without a manual grant_access call.
        let verdict = kernel
            .nakaiah()
            .verify_access(pid, paddr, AccessOp::Read, [0u8; 32]);
        assert_eq!(verdict, IntegrityVerdict::Allow);
    }

    #[test]
    fn writable_frame_gets_snapshot_entry() {
        let mut kernel = make_kernel();
        let pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        // Map a writable, non-ephemeral public frame.
        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::empty(),
            )
            .unwrap();

        let paddr = kernel
            .vm()
            .space(pid)
            .unwrap()
            .regions
            .get(&VirtAddr(0x1000))
            .unwrap()
            .frames[0];

        // Writable frames should use Snapshot entries, so update_snapshot works.
        kernel.lyll_mut().update_snapshot(paddr, [0xAA; 32]);
        assert_eq!(kernel.lyll().expected_hash(paddr), Some([0xAA; 32]));
    }

    #[test]
    fn protect_region_promotes_cid_to_snapshot_on_write() {
        let mut kernel = make_kernel();
        let pid = spawn_test_process(&mut kernel);
        kernel
            .vm_create_space(
                pid,
                default_budget(),
                MockPageTable::new(PhysAddr(0x20_0000)),
            )
            .unwrap();

        // Map read-only, non-ephemeral → CidBacked entry.
        let ro_flags = PageFlags::READABLE | PageFlags::USER;
        kernel
            .vm_map_region(
                pid,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                ro_flags,
                FrameClassification::empty(),
            )
            .unwrap();

        let paddr = kernel
            .vm()
            .space(pid)
            .unwrap()
            .regions
            .get(&VirtAddr(0x1000))
            .unwrap()
            .frames[0];

        // CidBacked → update_snapshot is a no-op.
        kernel.lyll_mut().update_snapshot(paddr, [0xAA; 32]);
        assert_eq!(kernel.lyll().expected_hash(paddr), Some([0u8; 32]));

        // Promote to writable.
        kernel
            .vm_protect_region(pid, VirtAddr(0x1000), rw_user_flags())
            .unwrap();

        // Now it's a Snapshot entry → update_snapshot works.
        kernel.lyll_mut().update_snapshot(paddr, [0xBB; 32]);
        assert_eq!(kernel.lyll().expected_hash(paddr), Some([0xBB; 32]));
    }

    // ── User capability tests ────────────────────────────────────────

    /// Helper: generate an owner identity, issue a UCAN to a user, create a
    /// valid SessionBinding, and return everything needed for user-cap tests.
    ///
    /// Signs the session binding *before* moving the session key into the
    /// kernel, so the signature is valid.
    ///
    /// Returns `(kernel, client_pid, server_pid, bound_cap)`.
    fn setup_user_capability() -> (
        Kernel<MockPageTable>,
        u32,
        u32,
        BoundCapability,
    ) {
        let mut entropy = make_test_entropy();

        let owner = PqPrivateIdentity::generate(&mut entropy);
        let owner_pub = owner.public_identity().clone();

        let user = PqPrivateIdentity::generate(&mut entropy);
        let user_addr = user.public_identity().address_hash;

        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let session_pub = session.public_identity().clone();
        let hw_addr = hw.public_identity().address_hash;

        // Issue UCAN and sign binding BEFORE session key moves into kernel.
        let ucan = owner
            .issue_pq_root_token(
                &mut entropy,
                &user_addr,
                CapabilityType::Endpoint,
                b"pid:0",
                0,
                1_000_000_000,
            )
            .unwrap();

        let token_hash = ucan.content_hash();
        let mut nonce = [0u8; 16];
        entropy.fill_bytes(&mut nonce);
        let mut binding = SessionBinding {
            session_address: session_pub.address_hash,
            user_address: user_addr,
            user_token_hash: token_hash,
            hardware_address: hw_addr,
            bound_at: 0,
            nonce,
            signature: [0u8; 3309],
        };
        let sig = session.sign(&binding.signable_bytes()).unwrap();
        binding.signature.copy_from_slice(&sig);

        let bound_cap = BoundCapability {
            token: ucan,
            binding,
        };

        // Now construct the kernel (session key moves here).
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());
        kernel.register_identity(owner_pub);

        let server_pid = kernel
            .spawn_process("echo-server", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        let client_pid = kernel
            .spawn_process(
                "client",
                Box::new(EchoServer::new()),
                &[("/echo", server_pid, 0)],
                None,
            )
            .unwrap();

        kernel
            .submit_user_capability(client_pid, bound_cap.clone())
            .unwrap();

        (kernel, client_pid, server_pid, bound_cap)
    }

    #[test]
    fn user_capability_accepted_with_valid_binding() {
        let (mut kernel, client, _server, _cap) = setup_user_capability();
        // Walk should succeed using the user capability path.
        let result = kernel.walk(client, "/echo/hello", 0, 1, 0);
        assert!(result.is_ok(), "User capability with valid binding should be accepted");
    }

    #[test]
    fn user_capability_rejected_when_binding_user_mismatches_audience() {
        let mut entropy = make_test_entropy();

        let owner = PqPrivateIdentity::generate(&mut entropy);
        let owner_pub = owner.public_identity().clone();

        let user = PqPrivateIdentity::generate(&mut entropy);
        let user_addr = user.public_identity().address_hash;

        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let session_pub = session.public_identity().clone();
        let hw_addr = hw.public_identity().address_hash;

        // Issue UCAN to the real user.
        let ucan = owner
            .issue_pq_root_token(
                &mut entropy,
                &user_addr,
                CapabilityType::Endpoint,
                b"pid:0",
                0,
                1_000_000_000,
            )
            .unwrap();

        // Create binding with a DIFFERENT user_address (attacker tries to
        // use someone else's UCAN with their own session binding).
        let wrong_user_addr = [0xFFu8; 16];
        let token_hash = ucan.content_hash();
        let mut nonce = [0u8; 16];
        entropy.fill_bytes(&mut nonce);
        let mut binding = SessionBinding {
            session_address: session_pub.address_hash,
            user_address: wrong_user_addr, // doesn't match UCAN audience
            user_token_hash: token_hash,
            hardware_address: hw_addr,
            bound_at: 0,
            nonce,
            signature: [0u8; 3309],
        };
        let sig = session.sign(&binding.signable_bytes()).unwrap();
        binding.signature.copy_from_slice(&sig);

        let bound_cap = BoundCapability {
            token: ucan,
            binding,
        };

        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());
        kernel.register_identity(owner_pub);

        let server_pid = kernel
            .spawn_process("echo-server", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        let client_pid = kernel
            .spawn_process(
                "client",
                Box::new(EchoServer::new()),
                &[("/echo", server_pid, 0)],
                None,
            )
            .unwrap();
        kernel
            .submit_user_capability(client_pid, bound_cap)
            .unwrap();

        // Walk should fail — binding.user_address != cap.audience.
        assert_eq!(
            kernel.walk(client_pid, "/echo/hello", 0, 1, 0),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn nonce_limit_exceeded_returns_error() {
        let (mut kernel, client, _server, _cap) = setup_user_capability();

        // Fill the nonce set to capacity.
        for i in 0..MAX_BINDING_NONCES {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            kernel.used_binding_nonces.insert(nonce);
        }
        assert_eq!(kernel.used_binding_nonces.len(), MAX_BINDING_NONCES);

        // The next walk that accepts a user capability should fail
        // because the nonce table is full.
        assert_eq!(
            kernel.walk(client, "/echo/hello", 0, 1, 0),
            Err(IpcError::NonceLimitExceeded)
        );
    }

    #[test]
    fn kernel_cap_unaffected_by_nonce_limit() {
        let (mut kernel, client, server, _cap) = setup_user_capability();

        // Grant a kernel capability so the kernel-cap path is taken first.
        let mut entropy = make_test_entropy();
        kernel
            .grant_endpoint_cap(&mut entropy, client, server, 0)
            .unwrap();

        // Fill nonce set to capacity.
        for i in 0..MAX_BINDING_NONCES {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            kernel.used_binding_nonces.insert(nonce);
        }

        // Walk should still succeed via the kernel capability path
        // (returns Ok(None) — no nonce to record).
        assert!(kernel.walk(client, "/echo/hello", 0, 1, 0).is_ok());
    }
}
