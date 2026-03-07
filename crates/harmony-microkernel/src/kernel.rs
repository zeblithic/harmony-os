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

/// A process in the microkernel.
pub struct Process {
    pub pid: u32,
    pub name: Arc<str>,
    pub namespace: Namespace,
    pub capabilities: Vec<UcanToken>,
    pub address_hash: [u8; 16],
    pub(crate) server: Box<dyn FileServer>,
}

/// The microkernel: process table, IPC dispatch, capability enforcement.
pub struct Kernel {
    processes: BTreeMap<u32, Process>,
    next_pid: u32,
    identity: PrivateIdentity,
    pub(crate) identity_store: MemoryIdentityStore,
    proof_store: MemoryProofStore,
    revocations: MemoryRevocationSet,
    /// Maps (client_pid, client_fid) -> target_pid for open fids.
    fid_owners: BTreeMap<(u32, Fid), u32>,
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
        }
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
    ) -> u32 {
        let pid = self.next_pid;
        self.next_pid += 1;

        // Derive a simple address hash from the pid.
        let mut address_hash = [0u8; 16];
        address_hash[..4].copy_from_slice(&pid.to_be_bytes());

        let mut namespace = Namespace::new();
        for &(path, target_pid, root_fid) in mounts {
            namespace.mount(path, target_pid, root_fid);
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

        pid
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
                0, // expires_at: 0 = never expires
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
            let resource_str = core::str::from_utf8(&cap.resource).unwrap_or("");
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
                5, // max delegation depth
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
    pub fn walk(
        &mut self,
        from_pid: u32,
        path: &str,
        _root_fid: Fid,
        new_fid: Fid,
        now: u64,
    ) -> Result<QPath, IpcError> {
        // Extract everything from the immutable borrow up front (copying
        // remainder into an owned String) so the borrow is released before
        // we take a mutable borrow on the target process.
        let (target_pid, server_root_fid, remainder, caps, addr) = {
            let process = self.processes.get(&from_pid).ok_or(IpcError::NotFound)?;
            let (mount, rem) = process
                .namespace
                .resolve(path)
                .ok_or(IpcError::NotFound)?;
            (
                mount.target_pid,
                mount.root_fid,
                alloc::string::String::from(rem),
                process.capabilities.clone(),
                process.address_hash,
            )
        };

        // Capability check
        self.check_endpoint_cap(&caps, &addr, target_pid, now)?;

        // Walk on the target server: from root fid to remainder
        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;

        let qpath = if remainder.is_empty() {
            // Walking to the mount root itself — just return its root qpath
            target.server.stat(server_root_fid).map(|st| st.qpath)?
        } else {
            target.server.walk(server_root_fid, new_fid, &remainder)?
        };

        // Record fid ownership
        self.fid_owners.insert((from_pid, new_fid), target_pid);
        Ok(qpath)
    }

    /// Open a previously walked fid.
    pub fn open(
        &mut self,
        from_pid: u32,
        fid: Fid,
        mode: OpenMode,
        _now: u64,
    ) -> Result<(), IpcError> {
        let &target_pid = self
            .fid_owners
            .get(&(from_pid, fid))
            .ok_or(IpcError::InvalidFid)?;
        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;
        target.server.open(fid, mode)
    }

    /// Read from a previously opened fid.
    pub fn read(
        &mut self,
        from_pid: u32,
        fid: Fid,
        offset: u64,
        count: u32,
        _now: u64,
    ) -> Result<Vec<u8>, IpcError> {
        let &target_pid = self
            .fid_owners
            .get(&(from_pid, fid))
            .ok_or(IpcError::InvalidFid)?;
        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;
        target.server.read(fid, offset, count)
    }

    /// Write to a previously opened fid.
    pub fn write(
        &mut self,
        from_pid: u32,
        fid: Fid,
        offset: u64,
        data: &[u8],
        _now: u64,
    ) -> Result<u32, IpcError> {
        let &target_pid = self
            .fid_owners
            .get(&(from_pid, fid))
            .ok_or(IpcError::InvalidFid)?;
        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;
        target.server.write(fid, offset, data)
    }

    /// Release a fid.
    pub fn clunk(
        &mut self,
        from_pid: u32,
        fid: Fid,
        _now: u64,
    ) -> Result<(), IpcError> {
        let target_pid = self
            .fid_owners
            .remove(&(from_pid, fid))
            .ok_or(IpcError::InvalidFid)?;
        let target = self
            .processes
            .get_mut(&target_pid)
            .ok_or(IpcError::NotFound)?;
        target.server.clunk(fid)
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

        let pid = kernel.spawn_process("echo", Box::new(EchoServer::new()), &[]);
        assert_eq!(pid, 0);

        let pid2 = kernel.spawn_process("echo2", Box::new(EchoServer::new()), &[]);
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
            kernel.spawn_process("echo-server", Box::new(EchoServer::new()), &[]);

        // pid 1 = client (also an echo server, but we don't use its server)
        let client_pid = kernel.spawn_process(
            "client",
            Box::new(EchoServer::new()),
            &[("/echo", server_pid, 0)],
        );

        // Grant client access to server
        kernel
            .grant_endpoint_cap(&mut entropy, client_pid, server_pid, 0)
            .unwrap();

        (kernel, client_pid, server_pid)
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
        kernel.open(client, 1, OpenMode::Read, 0).unwrap();
        let data = kernel.read(client, 1, 0, 256, 0).unwrap();
        assert_eq!(data, b"Hello from echo server!");
    }

    #[test]
    fn ipc_write_and_read_echo() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        kernel.walk(client, "/echo/echo", 0, 1, 0).unwrap();
        kernel.open(client, 1, OpenMode::ReadWrite, 0).unwrap();
        kernel.write(client, 1, 0, b"round trip", 0).unwrap();
        let data = kernel.read(client, 1, 0, 256, 0).unwrap();
        assert_eq!(data, b"round trip");
    }

    #[test]
    fn ipc_denied_without_capability() {
        let mut entropy = make_test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let mut kernel = Kernel::new(kernel_id);

        let server_pid =
            kernel.spawn_process("echo-server", Box::new(EchoServer::new()), &[]);
        // Client has mount but NO capability
        let client_pid = kernel.spawn_process(
            "client",
            Box::new(EchoServer::new()),
            &[("/echo", server_pid, 0)],
        );

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
        kernel.open(client, 1, OpenMode::Read, 0).unwrap();
        kernel.clunk(client, 1, 0).unwrap();
        assert_eq!(
            kernel.read(client, 1, 0, 256, 0),
            Err(IpcError::InvalidFid)
        );
    }
}
