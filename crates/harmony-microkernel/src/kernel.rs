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
use crate::{Fid, FileServer, IpcError};

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
}
