// SPDX-License-Identifier: GPL-2.0-or-later
//! Microkernel — process table, IPC dispatch, capability enforcement.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_identity::{
    verify_token, CapabilityType, MemoryIdentityStore, MemoryProofStore, MemoryRevocationSet,
    PrivateIdentity, UcanToken,
};
use harmony_platform::EntropySource;

use crate::namespace::Namespace;
use crate::{Fid, FileServer, IpcError, OpenMode, QPath};

/// Maximum UCAN delegation chain depth for capability verification.
/// Chains longer than this are rejected. 5 is generous for milestone A
/// where all tokens are root-issued (depth 0).
const MAX_DELEGATION_DEPTH: usize = 5;

/// A process in the microkernel.
pub struct Process {
    pub pid: u32,
    pub name: Arc<str>,
    pub(crate) namespace: Namespace,
    pub(crate) capabilities: Vec<UcanToken>,
    /// Milestone A: PID-derived placeholder. Production builds will use
    /// a cryptographic address (e.g. SHA-256 of the process's public key).
    pub(crate) address_hash: [u8; 16],
    pub(crate) server: Box<dyn FileServer>,
}

/// The microkernel: process table, IPC dispatch, capability enforcement.
pub struct Kernel {
    processes: BTreeMap<u32, Process>,
    next_pid: u32,
    identity: PrivateIdentity,
    identity_store: MemoryIdentityStore,
    proof_store: MemoryProofStore,
    revocations: MemoryRevocationSet,
    /// Maps (client_pid, client_fid) -> (target_pid, server_fid).
    /// The kernel translates client fids to server-local fids to prevent
    /// collisions when multiple clients share a server.
    fid_owners: BTreeMap<(u32, Fid), (u32, Fid)>,
    /// Monotonic counter for allocating server-side fids.
    next_server_fid: Fid,
}

impl Kernel {
    /// Create a new microkernel with the given identity.
    pub fn new(identity: PrivateIdentity) -> Self {
        let mut identity_store = MemoryIdentityStore::new();
        identity_store.insert(identity.public_identity().clone());
        Kernel {
            processes: BTreeMap::new(),
            next_pid: 0,
            identity,
            identity_store,
            proof_store: MemoryProofStore::new(),
            revocations: MemoryRevocationSet::new(),
            fid_owners: BTreeMap::new(),
            next_server_fid: 1,
        }
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
    /// the process's namespace.
    pub fn spawn_process(
        &mut self,
        name: &str,
        server: Box<dyn FileServer>,
        mounts: &[(&str, u32, Fid)],
    ) -> Result<u32, IpcError> {
        let pid = self.next_pid;
        self.next_pid = self
            .next_pid
            .checked_add(1)
            .ok_or(IpcError::ResourceExhausted)?;

        // Derive a simple address hash from the pid.
        let mut address_hash = [0u8; 16];
        address_hash[..4].copy_from_slice(&pid.to_be_bytes());

        let mut namespace = Namespace::new();
        for &(path, target_pid, root_fid) in mounts {
            if !self.processes.contains_key(&target_pid) {
                return Err(IpcError::NotFound);
            }
            namespace.mount(path, target_pid, root_fid)?;
        }

        self.processes.insert(
            pid,
            Process {
                pid,
                name: Arc::from(name),
                namespace,
                capabilities: Vec::new(),
                address_hash,
                server,
            },
        );

        Ok(pid)
    }

    /// Grant an endpoint capability to a process, allowing it to access
    /// the target process's FileServer via IPC.
    pub fn grant_endpoint_cap(
        &mut self,
        entropy: &mut impl EntropySource,
        process_pid: u32,
        target_pid: u32,
        _now: u64,
    ) -> Result<(), IpcError> {
        if !self.processes.contains_key(&target_pid) {
            return Err(IpcError::NotFound);
        }
        let process = self.processes.get(&process_pid).ok_or(IpcError::NotFound)?;
        let audience = process.address_hash;

        let resource = alloc::format!("pid:{}", target_pid);
        let cap = self
            .identity
            .issue_root_token(
                entropy,
                &audience,
                CapabilityType::Endpoint,
                resource.as_bytes(),
                0, // not_before: immediate
                // TODO: wire in expiry (e.g. now + ttl) for production use
                0, // expires_at: 0 = never expires (milestone A only)
            )
            .map_err(|_| IpcError::PermissionDenied)?;

        let process = self
            .processes
            .get_mut(&process_pid)
            .ok_or(IpcError::NotFound)?;
        process.capabilities.push(cap);
        Ok(())
    }

    /// Check whether `capabilities` contain a valid EndpointCap for `target_pid`.
    pub(crate) fn check_endpoint_cap(
        &self,
        capabilities: &[UcanToken],
        audience_hash: &[u8; 16],
        target_pid: u32,
        now: u64,
    ) -> Result<(), IpcError> {
        let target_resource = alloc::format!("pid:{}", target_pid);

        for cap in capabilities {
            // Must be an Endpoint capability
            if cap.capability != CapabilityType::Endpoint {
                continue;
            }
            // Must be issued to this process
            if &cap.audience != audience_hash {
                continue;
            }
            // Resource must match target pid or be wildcard
            let resource_str = match core::str::from_utf8(&cap.resource) {
                Ok(s) => s,
                Err(_) => continue, // Invalid UTF-8: skip token
            };
            if resource_str != target_resource && resource_str != "*" {
                continue;
            }
            // Cryptographic verification
            if verify_token(
                cap,
                now,
                &self.proof_store,
                &self.identity_store,
                &self.revocations,
                MAX_DELEGATION_DEPTH,
            )
            .is_ok()
            {
                return Ok(());
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

        // Resolve namespace and check capabilities while holding only
        // shared borrows. Copy scalars and remainder into locals so the
        // borrow is released before the mutable borrow on the target.
        let (target_pid, server_root_fid, remainder) = {
            let process = self.processes.get(&from_pid).ok_or(IpcError::NotFound)?;
            let (mount, rem) = process
                .namespace
                .resolve(path)
                .ok_or(IpcError::NotFound)?;
            let target_pid = mount.target_pid;
            let server_root_fid = mount.root_fid;
            let remainder = alloc::string::String::from(rem);
            // Capability check uses &self — compatible with the shared
            // borrow through `process`, so no clone needed.
            self.check_endpoint_cap(
                &process.capabilities,
                &process.address_hash,
                target_pid,
                now,
            )?;
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
        let server_fid = self.allocate_server_fid()?;
        let mut intermediate_fids = Vec::new();
        for _ in 0..components.len().saturating_sub(1) {
            intermediate_fids.push(self.allocate_server_fid()?);
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
    pub fn open(
        &mut self,
        from_pid: u32,
        fid: Fid,
        mode: OpenMode,
    ) -> Result<(), IpcError> {
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
    pub fn stat(
        &mut self,
        from_pid: u32,
        fid: Fid,
    ) -> Result<crate::FileStat, IpcError> {
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
    pub fn clunk(
        &mut self,
        from_pid: u32,
        fid: Fid,
    ) -> Result<(), IpcError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::echo::EchoServer;
    use harmony_unikernel::KernelEntropy;

    fn make_test_entropy() -> KernelEntropy<impl FnMut(&mut [u8])> {
        let mut seed = 42u64;
        KernelEntropy::new(move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
        })
    }

    #[test]
    fn spawn_process_assigns_pid() {
        let mut entropy = make_test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let mut kernel = Kernel::new(kernel_id);

        let pid = kernel.spawn_process("echo", Box::new(EchoServer::new()), &[]).unwrap();
        assert_eq!(pid, 0);

        let pid2 = kernel.spawn_process("echo2", Box::new(EchoServer::new()), &[]).unwrap();
        assert_eq!(pid2, 1);
    }

    #[test]
    fn capability_check_with_valid_cap() {
        let mut entropy = make_test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);

        // Issue the token before moving identity into the kernel.
        let process_addr = [0x01u8; 16];
        let cap = kernel_id
            .issue_root_token(
                &mut entropy,
                &process_addr,
                CapabilityType::Endpoint,
                b"pid:1",
                0,
                0,
            )
            .unwrap();

        let kernel = Kernel::new(kernel_id);

        assert!(kernel
            .check_endpoint_cap(&[cap], &process_addr, 1, 0)
            .is_ok());
    }

    #[test]
    fn capability_check_no_cap() {
        let mut entropy = make_test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let kernel = Kernel::new(kernel_id);

        let process_addr = [0x01u8; 16];
        assert_eq!(
            kernel.check_endpoint_cap(&[], &process_addr, 1, 0),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn capability_check_wrong_pid() {
        let mut entropy = make_test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);

        // Issue the token before moving identity into the kernel.
        let process_addr = [0x01u8; 16];
        let cap = kernel_id
            .issue_root_token(
                &mut entropy,
                &process_addr,
                CapabilityType::Endpoint,
                b"pid:1",
                0,
                0,
            )
            .unwrap();

        let kernel = Kernel::new(kernel_id);

        // Cap is for pid:1, trying to access pid:2
        assert_eq!(
            kernel.check_endpoint_cap(&[cap], &process_addr, 2, 0),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn capability_check_wildcard() {
        let mut entropy = make_test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);

        // Issue the token before moving identity into the kernel.
        let process_addr = [0x01u8; 16];
        let cap = kernel_id
            .issue_root_token(
                &mut entropy,
                &process_addr,
                CapabilityType::Endpoint,
                b"*",
                0,
                0,
            )
            .unwrap();

        let kernel = Kernel::new(kernel_id);

        // Wildcard should match any pid
        assert!(kernel
            .check_endpoint_cap(&[cap.clone()], &process_addr, 1, 0)
            .is_ok());
        assert!(kernel
            .check_endpoint_cap(&[cap], &process_addr, 99, 0)
            .is_ok());
    }

    // ── IPC dispatch tests ──────────────────────────────────────────

    fn setup_kernel_with_echo() -> (Kernel, u32, u32) {
        let mut entropy = make_test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let mut kernel = Kernel::new(kernel_id);

        // pid 0 = echo server
        let server_pid =
            kernel.spawn_process("echo-server", Box::new(EchoServer::new()), &[]).unwrap();

        // pid 1 = client (also an echo server, but we don't use its server)
        let client_pid = kernel.spawn_process(
            "client",
            Box::new(EchoServer::new()),
            &[("/echo", server_pid, 0)],
        ).unwrap();

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
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let mut kernel = Kernel::new(kernel_id);

        let server_pid =
            kernel.spawn_process("echo-server", Box::new(EchoServer::new()), &[]).unwrap();
        // Client has mount but NO capability
        let client_pid = kernel.spawn_process(
            "client",
            Box::new(EchoServer::new()),
            &[("/echo", server_pid, 0)],
        ).unwrap();

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
        assert_eq!(
            kernel.read(client, 1, 0, 256),
            Err(IpcError::InvalidFid)
        );
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
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let mut kernel = Kernel::new(kernel_id);

        // Shared echo server
        let server_pid =
            kernel.spawn_process("echo-server", Box::new(EchoServer::new()), &[]).unwrap();

        // Two clients, both mounting the same server
        let client_a = kernel.spawn_process(
            "client-a",
            Box::new(EchoServer::new()),
            &[("/echo", server_pid, 0)],
        ).unwrap();
        let client_b = kernel.spawn_process(
            "client-b",
            Box::new(EchoServer::new()),
            &[("/echo", server_pid, 0)],
        ).unwrap();

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
        assert_eq!(
            kernel.read(client_a, 1, 0, 256),
            Err(IpcError::InvalidFid)
        );

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
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let mut kernel = Kernel::new(kernel_id);

        let pid = kernel.spawn_process("test", Box::new(EchoServer::new()), &[]).unwrap();
        // target pid 99 doesn't exist
        assert_eq!(
            kernel.grant_endpoint_cap(&mut entropy, pid, 99, 0),
            Err(IpcError::NotFound)
        );
    }

    #[test]
    fn capability_check_expired_token_rejected() {
        let mut entropy = make_test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);

        let process_addr = [0x01u8; 16];
        // Token that expires at time 100
        let cap = kernel_id
            .issue_root_token(
                &mut entropy,
                &process_addr,
                CapabilityType::Endpoint,
                b"pid:1",
                0,   // not_before: immediate
                100, // expires_at: time 100
            )
            .unwrap();

        let kernel = Kernel::new(kernel_id);

        // At time 50 — token is valid
        assert!(kernel
            .check_endpoint_cap(&[cap.clone()], &process_addr, 1, 50)
            .is_ok());

        // At time 200 — token has expired
        assert_eq!(
            kernel.check_endpoint_cap(&[cap], &process_addr, 1, 200),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn ipc_walk_with_nonzero_now() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        // Tokens are issued with expires_at=0 (never expires),
        // so a non-zero now should still work.
        let qpath = kernel.walk(client, "/echo/hello", 0, 1, 1_000_000).unwrap();
        assert_eq!(qpath, 1);
    }

    #[test]
    fn integration_two_processes_full_ipc() {
        let mut entropy = make_test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let mut kernel = Kernel::new(kernel_id);

        // Spawn echo server as pid 0
        let server_pid = kernel.spawn_process(
            "echo-server",
            Box::new(EchoServer::new()),
            &[],
        ).unwrap();

        // Spawn client as pid 1, with echo server mounted at /svc/echo
        let client_pid = kernel.spawn_process(
            "harmony-node",
            Box::new(EchoServer::new()),  // client also serves, but we test as client
            &[("/svc/echo", server_pid, 0)],
        ).unwrap();

        // Grant client capability to access echo server
        kernel.grant_endpoint_cap(&mut entropy, client_pid, server_pid, 0).unwrap();

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
        assert_eq!(kernel.read(client_pid, 1, 0, 256), Err(IpcError::InvalidFid));
        assert_eq!(kernel.read(client_pid, 2, 0, 256), Err(IpcError::InvalidFid));
    }
}
