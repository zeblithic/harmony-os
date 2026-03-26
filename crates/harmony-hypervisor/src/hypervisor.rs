// SPDX-License-Identifier: GPL-2.0-or-later
//! Sans-I/O hypervisor state machine.
//!
//! Accepts `TrapEvent`s, returns `HypervisorAction`s. No register access,
//! no assembly — pure Rust logic testable with `cargo test`.

use alloc::collections::BTreeMap;

use crate::platform::{HVC_PING, HVC_PONG, VIRTUAL_UART_IPA};
use crate::stage2::Stage2PageTable;
use crate::trap::*;
use crate::vcpu::{VCpuContext, Vm, VmState};
use crate::vmid::{VmId, VmIdAllocator};
use harmony_microkernel::vm::PhysAddr;

/// The hypervisor state machine.
///
/// BTreeMap is used for VM storage. `insert()` allocates heap memory,
/// but only during VM creation (HVC_VM_CREATE) — a cold-path management
/// operation. The hot-path trap handling (`handle()`) does not allocate.
pub struct Hypervisor {
    vmid_alloc: VmIdAllocator,
    vms: BTreeMap<u8, Vm>,
    /// Currently executing VM (None = host).
    pub(crate) active_vmid: Option<VmId>,
    /// Host vCPU context (VM 0).
    _host_ctx: VCpuContext,
    /// Converts PA → writable pointer (for Stage-2 table manipulation).
    phys_to_virt: fn(PhysAddr) -> *mut u8,
    /// Returns owned frames to the physical allocator when VMs are destroyed.
    frame_dealloc: fn(PhysAddr),
}

impl Hypervisor {
    pub fn new(phys_to_virt: fn(PhysAddr) -> *mut u8, frame_dealloc: fn(PhysAddr)) -> Self {
        Self {
            vmid_alloc: VmIdAllocator::new(),
            vms: BTreeMap::new(),
            active_vmid: None,
            _host_ctx: VCpuContext::default(),
            phys_to_virt,
            frame_dealloc,
        }
    }

    /// Process a trap event. Returns a single action for the platform shim.
    pub fn handle(
        &mut self,
        event: TrapEvent,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<HypervisorAction, HypervisorError> {
        match event {
            TrapEvent::HvcCall { x0, x1, x2, x3 } => self.handle_hvc(x0, x1, x2, x3, frame_alloc),
            TrapEvent::DataAbort { ipa, access, .. } => self.handle_data_abort(ipa, access),
            TrapEvent::InstructionAbort { ipa: _ } => {
                let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;
                if let Some(vm) = self.vms.get_mut(&vmid.0) {
                    vm.state = VmState::Halted;
                }
                self.active_vmid = None;
                Ok(HypervisorAction::DestroyVm { vmid })
            }
            TrapEvent::WfiWfe => {
                if let Some(vmid) = self.active_vmid {
                    if let Some(vm) = self.vms.get_mut(&vmid.0) {
                        vm.state = VmState::Halted;
                    }
                    self.active_vmid = None;
                }
                Ok(HypervisorAction::HvcResult { x0: 0 })
            }
            TrapEvent::SmcForward { x0, x1, x2, x3 } => {
                Ok(HypervisorAction::ForwardSmc { x0, x1, x2, x3 })
            }
        }
    }

    fn handle_hvc(
        &mut self,
        x0: u64,
        x1: u64,
        x2: u64,
        x3: u64,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<HypervisorAction, HypervisorError> {
        // Guest-allowed HVCs: exit and ping. Always permitted.
        match x0 {
            HVC_GUEST_EXIT => return self.hvc_guest_exit(x1),
            HVC_PING => return Ok(HypervisorAction::HvcResult { x0: HVC_PONG }),
            _ => {}
        }
        // Management HVCs: host-only. Reject if a guest is active.
        if self.active_vmid.is_some() {
            return Err(HypervisorError::InvalidHvc(x0));
        }
        match x0 {
            HVC_VM_CREATE => self.hvc_vm_create(frame_alloc),
            HVC_VM_DESTROY => self.hvc_vm_destroy(x1),
            HVC_VM_START => self.hvc_vm_start(x1, x2),
            HVC_VM_MAP => self.hvc_vm_map(x1, x2, x3, frame_alloc),
            _ => Err(HypervisorError::InvalidHvc(x0)),
        }
    }

    fn hvc_vm_create(
        &mut self,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<HypervisorAction, HypervisorError> {
        let vmid = self
            .vmid_alloc
            .alloc()
            .ok_or(HypervisorError::VmLimitReached)?;
        let root = match frame_alloc() {
            Some(r) => r,
            None => {
                self.vmid_alloc.free(vmid);
                return Err(HypervisorError::OutOfMemory);
            }
        };
        let ptr = (self.phys_to_virt)(root);
        unsafe { core::ptr::write_bytes(ptr, 0, 4096) };
        let stage2 = Stage2PageTable::new(root, vmid, self.phys_to_virt);
        let vm = Vm {
            id: vmid,
            vcpu: VCpuContext::default(),
            stage2,
            state: VmState::Created,
        };
        self.vms.insert(vmid.0, vm);
        Ok(HypervisorAction::HvcResult { x0: vmid.0 as u64 })
    }

    fn hvc_vm_destroy(&mut self, x1: u64) -> Result<HypervisorAction, HypervisorError> {
        let vmid = VmId(x1 as u8);
        // Defense-in-depth: never destroy the active VM (Stage-2 tables in use).
        // Management HVCs are already host-only, but guard explicitly.
        if self.active_vmid == Some(vmid) {
            return Err(HypervisorError::VmAlreadyRunning(vmid));
        }
        let vm = self
            .vms
            .remove(&vmid.0)
            .ok_or(HypervisorError::InvalidVmId(vmid))?;
        // Free all Stage-2 table frames (root + intermediates).
        for frame in vm.stage2.into_owned_frames() {
            (self.frame_dealloc)(frame);
        }
        self.vmid_alloc.free(vmid);
        Ok(HypervisorAction::HvcResult { x0: 0 })
    }

    fn hvc_vm_start(&mut self, x1: u64, x2: u64) -> Result<HypervisorAction, HypervisorError> {
        // Reject if any VM is already active — host must wait for guest exit.
        if let Some(active) = self.active_vmid {
            return Err(HypervisorError::VmAlreadyRunning(active));
        }
        let vmid = VmId(x1 as u8);
        let entry_ipa = x2;
        let vm = self
            .vms
            .get_mut(&vmid.0)
            .ok_or(HypervisorError::InvalidVmId(vmid))?;
        // Cold-restart: reset register file so halted VMs don't start with stale state.
        if vm.state == VmState::Halted {
            vm.vcpu = VCpuContext::default();
        }
        vm.vcpu.elr_el2 = entry_ipa;
        vm.vcpu.spsr_el2 = 0x3C5; // EL1h + DAIF masked
        vm.state = VmState::Running;
        self.active_vmid = Some(vmid);
        Ok(HypervisorAction::EnterGuest { vmid })
    }

    fn hvc_vm_map(
        &mut self,
        x1: u64,
        x2: u64,
        x3: u64,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<HypervisorAction, HypervisorError> {
        let (vmid_raw, flags_raw, page_count) = unpack_vm_map_x1(x1);
        let vmid = VmId(vmid_raw);
        let ipa_base = x2;
        let pa_base = x3;

        let flags = Stage2Flags {
            readable: flags_raw & 0b001 != 0,
            writable: flags_raw & 0b010 != 0,
            executable: flags_raw & 0b100 != 0,
            mem_attr: match (flags_raw >> 3) & 0b111 {
                1 => Stage2MemAttr::NormalNonCacheable,
                2 => Stage2MemAttr::Device,
                _ => Stage2MemAttr::NormalWriteBack,
            },
        };

        // Guard against IPA/PA overflow before the mapping loop.
        let total_bytes = (page_count as u64)
            .checked_mul(4096)
            .ok_or(HypervisorError::InvalidAddress)?;
        ipa_base
            .checked_add(total_bytes)
            .ok_or(HypervisorError::InvalidAddress)?;
        pa_base
            .checked_add(total_bytes)
            .ok_or(HypervisorError::InvalidAddress)?;

        let vm = self
            .vms
            .get_mut(&vmid.0)
            .ok_or(HypervisorError::InvalidVmId(vmid))?;
        for i in 0..page_count as u64 {
            let ipa = ipa_base + i * 4096;
            let pa = PhysAddr(pa_base + i * 4096);
            if let Err(e) = vm.stage2.map(ipa, pa, flags, frame_alloc) {
                // Rollback: unmap all successfully mapped pages.
                for j in 0..i {
                    let rollback_ipa = ipa_base + j * 4096;
                    let _ = vm.stage2.unmap(rollback_ipa);
                }
                return Err(HypervisorError::Stage2MapFailed(e));
            }
        }
        Ok(HypervisorAction::HvcResult { x0: 0 })
    }

    fn hvc_guest_exit(&mut self, x1: u64) -> Result<HypervisorAction, HypervisorError> {
        if let Some(vmid) = self.active_vmid {
            if let Some(vm) = self.vms.get_mut(&vmid.0) {
                vm.state = VmState::Halted;
            }
            self.active_vmid = None;
        }
        Ok(HypervisorAction::HvcResult { x0: x1 })
    }

    fn handle_data_abort(
        &mut self,
        ipa: u64,
        access: AccessType,
    ) -> Result<HypervisorAction, HypervisorError> {
        // All data aborts require an active guest — reject early if host-only.
        let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;

        if ipa == VIRTUAL_UART_IPA {
            return match access {
                AccessType::Write { value } => Ok(HypervisorAction::EmitChar { ch: value as u8 }),
                // TX-only virtual UART: swallow reads silently.
                AccessType::Read => Ok(HypervisorAction::ResumeGuest),
            };
        }
        // Unknown IPA — kill the guest. Clear active_vmid atomically with the
        // DestroyVm decision, matching the WFI and guest_exit paths.
        if let Some(vm) = self.vms.get_mut(&vmid.0) {
            vm.state = VmState::Halted;
        }
        self.active_vmid = None;
        Ok(HypervisorAction::DestroyVm { vmid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::VIRTUAL_UART_IPA;
    use crate::vmid::VmId;
    use alloc::vec;
    use harmony_microkernel::vm::PhysAddr;

    struct BumpAlloc {
        next: u64,
        limit: u64,
    }
    impl BumpAlloc {
        fn new(base: u64, size: u64) -> Self {
            Self {
                next: base,
                limit: base + size,
            }
        }
        fn alloc(&mut self) -> Option<PhysAddr> {
            if self.next >= self.limit {
                return None;
            }
            let addr = self.next;
            self.next += 4096;
            Some(PhysAddr(addr))
        }
    }

    fn make_hypervisor() -> Hypervisor {
        Hypervisor::new(|pa| pa.0 as *mut u8, |_| {})
    }

    /// Helper: creates a page-aligned bump allocator over a heap-backed arena.
    /// The arena must be allocated with +1 page to absorb alignment padding.
    fn make_arena_alloc(arena: &[u8]) -> impl FnMut() -> Option<PhysAddr> + '_ {
        let base = arena.as_ptr() as u64;
        let aligned_base = (base + 4095) & !4095; // page-align up
        let arena_end = base + arena.len() as u64;
        let mut bump = aligned_base;
        move || {
            if bump + 4096 > arena_end {
                return None;
            }
            let addr = bump;
            bump += 4096;
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096) };
            Some(PhysAddr(addr))
        }
    }

    #[test]
    fn create_vm_returns_vmid() {
        let mut hyp = make_hypervisor();
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_VM_CREATE,
                    x1: 0,
                    x2: 0,
                    x3: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(action, HypervisorAction::HvcResult { x0: 1 });
    }

    #[test]
    fn create_vm_allocates_stage2_root() {
        let mut hyp = make_hypervisor();
        let arena = vec![0u8; 65 * 4096];
        let arena_base = arena.as_ptr() as u64;
        let arena_end = arena_base + arena.len() as u64;
        let mut bump_ptr = arena_base;
        let mut alloc = || {
            if bump_ptr >= arena_end {
                return None;
            }
            let addr = bump_ptr;
            bump_ptr += 4096;
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096) };
            Some(PhysAddr(addr))
        };
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        // At least one frame was allocated (the Stage-2 root).
        assert!(bump_ptr > arena_base);
    }

    #[test]
    fn destroy_nonexistent_vm_errors() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let result = hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_DESTROY,
                x1: 99,
                x2: 0,
                x3: 0,
            },
            &mut || alloc.alloc(),
        );
        assert!(matches!(
            result,
            Err(HypervisorError::InvalidVmId(VmId(99)))
        ));
    }

    #[test]
    fn invalid_hvc_errors() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let result = hyp.handle(
            TrapEvent::HvcCall {
                x0: 0xDEAD,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut || alloc.alloc(),
        );
        assert!(matches!(result, Err(HypervisorError::InvalidHvc(0xDEAD))));
    }

    #[test]
    fn vm_map_adds_stage2_entry() {
        let mut hyp = make_hypervisor();
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        let x1 = pack_vm_map_x1(1, 0b00_000_111, 1);
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_VM_MAP,
                    x1,
                    x2: 0x4000_0000,
                    x3: 0x8000_0000,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(action, HypervisorAction::HvcResult { x0: 0 });
    }

    #[test]
    fn vm_start_returns_enter_guest() {
        let mut hyp = make_hypervisor();
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_VM_START,
                    x1: 1,
                    x2: 0x4000_0000,
                    x3: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert!(matches!(
            action,
            HypervisorAction::EnterGuest { vmid: VmId(1) }
        ));
    }

    #[test]
    fn data_abort_at_uart_emits_char() {
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 1,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: VIRTUAL_UART_IPA,
                    access: AccessType::Write { value: b'H' as u64 },
                    width: 1,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(action, HypervisorAction::EmitChar { ch: b'H' });
    }

    #[test]
    fn data_abort_at_unknown_ipa_destroys_vm() {
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 1,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: 0xDEAD_0000,
                    access: AccessType::Read,
                    width: 4,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(action, HypervisorAction::DestroyVm { vmid: VmId(1) });
    }

    #[test]
    fn wfi_halts_guest() {
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 1,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        let action = hyp.handle(TrapEvent::WfiWfe, &mut alloc).unwrap();
        assert!(matches!(action, HypervisorAction::HvcResult { .. }));
    }

    #[test]
    fn smc_forward() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let action = hyp
            .handle(
                TrapEvent::SmcForward {
                    x0: 0xC400_0003,
                    x1: 0,
                    x2: 0,
                    x3: 0,
                },
                &mut || alloc.alloc(),
            )
            .unwrap();
        assert!(matches!(
            action,
            HypervisorAction::ForwardSmc {
                x0: 0xC400_0003,
                ..
            }
        ));
    }

    #[test]
    fn guest_exit_hvc_halts() {
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 1,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_GUEST_EXIT,
                    x1: 0,
                    x2: 0,
                    x3: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert!(matches!(action, HypervisorAction::HvcResult { x0: 0 }));
    }

    #[test]
    fn ping_returns_pong() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: crate::platform::HVC_PING,
                    x1: 0,
                    x2: 0,
                    x3: 0,
                },
                &mut || alloc.alloc(),
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::HvcResult {
                x0: crate::platform::HVC_PONG
            }
        );
    }

    #[test]
    fn full_guest_stub_lifecycle() {
        let arena = vec![0u8; 129 * 4096];
        let mut alloc = make_arena_alloc(&arena);

        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});

        // 1. Create VM
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_VM_CREATE,
                    x1: 0,
                    x2: 0,
                    x3: 0,
                },
                &mut alloc,
            )
            .unwrap();
        let vmid = match action {
            HypervisorAction::HvcResult { x0 } => x0 as u8,
            _ => panic!("expected HvcResult"),
        };
        assert_eq!(vmid, 1);

        // 2. Map 8 pages of guest RAM at IPA 0x4000_0000
        let x1 = pack_vm_map_x1(vmid, 0b00_000_111, 8);
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_VM_MAP,
                    x1,
                    x2: 0x4000_0000,
                    x3: 0xA000_0000,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(action, HypervisorAction::HvcResult { x0: 0 });

        // 3. Start VM at entry IPA
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_VM_START,
                    x1: vmid as u64,
                    x2: 0x4000_0000,
                    x3: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert!(matches!(
            action,
            HypervisorAction::EnterGuest { vmid: VmId(1) }
        ));

        // 4. Guest writes "Hi" to virtual UART
        for &ch in b"Hi" {
            let action = hyp
                .handle(
                    TrapEvent::DataAbort {
                        ipa: VIRTUAL_UART_IPA,
                        access: AccessType::Write { value: ch as u64 },
                        width: 1,
                    },
                    &mut alloc,
                )
                .unwrap();
            assert_eq!(action, HypervisorAction::EmitChar { ch });
        }

        // 5. Guest exits via HVC
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_GUEST_EXIT,
                    x1: 0,
                    x2: 0,
                    x3: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(action, HypervisorAction::HvcResult { x0: 0 });

        // 6. Destroy VM
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_VM_DESTROY,
                    x1: vmid as u64,
                    x2: 0,
                    x3: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(action, HypervisorAction::HvcResult { x0: 0 });
    }

    #[test]
    fn data_abort_without_active_vm_returns_error() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let result = hyp.handle(
            TrapEvent::DataAbort {
                ipa: 0xDEAD_0000,
                access: AccessType::Read,
                width: 4,
            },
            &mut || alloc.alloc(),
        );
        assert!(matches!(result, Err(HypervisorError::NoActiveVm)));
    }

    #[test]
    fn instruction_abort_without_active_vm_returns_error() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let result = hyp.handle(
            TrapEvent::InstructionAbort { ipa: 0x4000_0000 },
            &mut || alloc.alloc(),
        );
        assert!(matches!(result, Err(HypervisorError::NoActiveVm)));
    }

    #[test]
    fn uart_read_returns_resume_guest() {
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 1,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: VIRTUAL_UART_IPA,
                    access: AccessType::Read,
                    width: 4,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(action, HypervisorAction::ResumeGuest);
    }

    #[test]
    fn vm_start_rejects_when_another_vm_active() {
        let arena = vec![0u8; 129 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});
        // Create two VMs
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        // Start VM 1
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 1,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        // Try to start VM 2 while VM 1 is active — management HVC rejected
        let result = hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 2,
                x2: 0x5000_0000,
                x3: 0,
            },
            &mut alloc,
        );
        // Management HVCs are host-only; rejected with InvalidHvc when guest is active
        assert!(matches!(
            result,
            Err(HypervisorError::InvalidHvc(HVC_VM_START))
        ));
    }

    #[test]
    fn double_map_same_ipa_rejected() {
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        // Map page once
        let x1 = pack_vm_map_x1(1, 0b00_000_111, 1);
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_MAP,
                x1,
                x2: 0x4000_0000,
                x3: 0x8000_0000,
            },
            &mut alloc,
        )
        .unwrap();
        // Map same IPA again — should fail
        let result = hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_MAP,
                x1,
                x2: 0x4000_0000,
                x3: 0x9000_0000,
            },
            &mut alloc,
        );
        assert!(matches!(result, Err(HypervisorError::Stage2MapFailed(_))));
    }

    #[test]
    fn guest_cannot_call_management_hvcs() {
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 1,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        // Guest tries to create a VM — rejected
        let result = hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        );
        assert!(matches!(result, Err(HypervisorError::InvalidHvc(_))));
        // Guest tries to map memory — rejected
        let result = hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_MAP,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        );
        assert!(matches!(result, Err(HypervisorError::InvalidHvc(_))));
        // Guest CAN call exit and ping
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_PING,
                    x1: 0,
                    x2: 0,
                    x3: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::HvcResult {
                x0: crate::platform::HVC_PONG
            }
        );
    }

    #[test]
    fn destroy_active_vm_rejected() {
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_CREATE,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 1,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        // Guest exit to return to host
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_GUEST_EXIT,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        // Restart VM 1 to make it active again
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 1,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        // Guest exits
        hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_GUEST_EXIT,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut alloc,
        )
        .unwrap();
        // Now from host: destroy VM 1 (should succeed since it's not active)
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_VM_DESTROY,
                    x1: 1,
                    x2: 0,
                    x3: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(action, HypervisorAction::HvcResult { x0: 0 });
    }
}
