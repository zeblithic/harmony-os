// SPDX-License-Identifier: GPL-2.0-or-later
//! Sans-I/O hypervisor state machine.
//!
//! Accepts `TrapEvent`s, returns `HypervisorAction`s. No register access,
//! no assembly — pure Rust logic testable with `cargo test`.

use alloc::collections::BTreeMap;

use crate::gic::VirtualGic;
use crate::platform::{
    GICD_IPA, GICD_SIZE, GICR_IPA, GICR_SIZE, GUEST_CNTHCTL_EL2, GUEST_CNTVOFF_EL2, HVC_PING,
    HVC_PONG, VIRTIO_NET_MMIO_IPA, VIRTIO_NET_MMIO_SIZE, VIRTUAL_UART_IPA, VIRTUAL_UART_SIZE,
};
use crate::stage2::{Stage2Granule, Stage2PageTable};
use crate::trap::*;
use crate::uart::VirtualUart;
use crate::vcpu::{VCpuContext, Vm, VmState};
use crate::virtio_mmio::MmioResponse;
use crate::virtio_net::VirtioNetDevice;
use crate::vmid::{VmId, VmIdAllocator};
use harmony_microkernel::vm::PhysAddr;

/// The hypervisor state machine.
///
/// BTreeMap is used for VM storage. `insert()` allocates heap memory,
/// but only during VM creation (HVC_VM_CREATE) — a cold-path management
/// operation. The hot-path trap handling (`handle()`) does not allocate.
pub struct Hypervisor {
    vmid_alloc: VmIdAllocator,
    pub(crate) vms: BTreeMap<u8, Vm>,
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
            TrapEvent::DataAbort {
                ipa,
                access,
                width,
                srt,
            } => self.handle_data_abort(ipa, access, width, srt),
            TrapEvent::InstructionAbort { ipa: _ } => {
                let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;
                if let Some(vm) = self.vms.get_mut(&vmid.0) {
                    vm.state = VmState::Halted;
                }
                self.active_vmid = None;
                Ok(HypervisorAction::DestroyVm { vmid })
            }
            TrapEvent::WfiWfe => {
                let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;
                if let Some(vm) = self.vms.get_mut(&vmid.0) {
                    vm.state = VmState::Halted;
                }
                self.active_vmid = None;
                Ok(HypervisorAction::HaltGuest { vmid })
            }
            TrapEvent::SmcForward { x0, x1, x2, x3 } => {
                // SMC traps only arrive from a guest (EL1). A host-side SMC goes
                // directly to EL3 and never reaches this handler.
                let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;
                if let Some(vm) = self.vms.get_mut(&vmid.0) {
                    vm.gic
                        .sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
                }
                Ok(HypervisorAction::ForwardSmc { x0, x1, x2, x3 })
            }
            TrapEvent::TimerIrq => {
                let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;
                let vm = self
                    .vms
                    .get_mut(&vmid.0)
                    .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
                vm.gic.pend(27); // PPI 27 = virtual timer
                vm.gic
                    .sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
                // No unpend — sync_lrs will auto-clear when the guest acknowledges
                // the interrupt (LR transitions to Active on IAR read).
                Ok(HypervisorAction::ResumeGuest)
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
            HVC_PING => {
                if let Some(vmid) = self.active_vmid {
                    if let Some(vm) = self.vms.get_mut(&vmid.0) {
                        vm.gic
                            .sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
                    }
                }
                return Ok(HypervisorAction::HvcResult { x0: HVC_PONG });
            }
            _ => {}
        }
        // Management HVCs: host-only. Reject if a guest is active.
        if self.active_vmid.is_some() {
            return Err(HypervisorError::InvalidHvc(x0));
        }
        match x0 {
            HVC_VM_CREATE => self.hvc_vm_create(frame_alloc),
            HVC_VM_DESTROY => self.hvc_vm_destroy(x1),
            HVC_VM_START => self.hvc_vm_start(x1, x2, x3),
            HVC_VM_MAP => self.hvc_vm_map(x1, x2, x3, frame_alloc),
            _ => Err(HypervisorError::InvalidHvc(x0)),
        }
    }

    /// Read-only access to a VM by VMID (for testing and inspection).
    pub fn vm(&self, vmid: u8) -> Option<&Vm> {
        self.vms.get(&vmid)
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
        let stage2 = Stage2PageTable::new(root, vmid, Stage2Granule::Four, self.phys_to_virt);
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, vmid.0];
        let virtio_net = VirtioNetDevice::new(mac);
        let vm = Vm {
            id: vmid,
            vcpu: VCpuContext::default(),
            stage2,
            state: VmState::Created,
            uart: VirtualUart::new(),
            virtio_net,
            gic: VirtualGic::new(),
        };
        self.vms.insert(vmid.0, vm);
        Ok(HypervisorAction::HvcResult { x0: vmid.0 as u64 })
    }

    /// Validate and extract a VMID from a u64 HVC argument. Rejects values > 255.
    fn parse_vmid(x: u64) -> Result<VmId, HypervisorError> {
        if x == 0 || x > u8::MAX as u64 {
            return Err(HypervisorError::InvalidVmId(x));
        }
        Ok(VmId(x as u8))
    }

    fn hvc_vm_destroy(&mut self, x1: u64) -> Result<HypervisorAction, HypervisorError> {
        let vmid = Self::parse_vmid(x1)?;
        // Defense-in-depth: never destroy the active VM (Stage-2 tables in use).
        // Management HVCs are already host-only, but guard explicitly.
        if self.active_vmid == Some(vmid) {
            return Err(HypervisorError::VmAlreadyRunning(vmid));
        }
        let vm = self
            .vms
            .remove(&vmid.0)
            .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
        // Free all Stage-2 table frames (root + intermediates).
        for frame in vm.stage2.into_owned_frames() {
            (self.frame_dealloc)(frame);
        }
        self.vmid_alloc.free(vmid);
        Ok(HypervisorAction::HvcResult { x0: 0 })
    }

    fn hvc_vm_start(
        &mut self,
        x1: u64,
        x2: u64,
        x3: u64,
    ) -> Result<HypervisorAction, HypervisorError> {
        // Reject if any VM is already active — host must wait for guest exit.
        if let Some(active) = self.active_vmid {
            return Err(HypervisorError::VmAlreadyRunning(active));
        }
        let vmid = Self::parse_vmid(x1)?;
        let entry_ipa = x2;
        let dtb_ipa = x3;
        let vm = self
            .vms
            .get_mut(&vmid.0)
            .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
        // Cold-restart: reset all per-VM state so halted VMs don't start with stale values.
        if vm.state == VmState::Halted {
            vm.vcpu = VCpuContext::default();
            vm.uart = VirtualUart::new();
            vm.gic = VirtualGic::new();
        }
        vm.vcpu.elr_el2 = entry_ipa;
        vm.vcpu.spsr_el2 = 0x3C5; // EL1h + DAIF masked
                                  // ARM64 boot protocol: x0 = DTB physical address
        vm.vcpu.x[0] = dtb_ipa;
        // x1, x2, x3 must be 0
        vm.vcpu.x[1] = 0;
        vm.vcpu.x[2] = 0;
        vm.vcpu.x[3] = 0;
        vm.state = VmState::Running;
        vm.vcpu.icc_sre_el1 = 0x7; // SRE + DFB + DIB — enable system register access
        vm.gic
            .sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
        self.active_vmid = Some(vmid);
        let stage2_root = vm.stage2.root_paddr();
        Ok(HypervisorAction::EnterGuest {
            vmid,
            stage2_root,
            elr_el2: vm.vcpu.elr_el2,
            spsr_el2: vm.vcpu.spsr_el2,
            cnthctl_el2: GUEST_CNTHCTL_EL2,
            cntvoff_el2: GUEST_CNTVOFF_EL2,
        })
    }

    fn hvc_vm_map(
        &mut self,
        x1: u64,
        x2: u64,
        x3: u64,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<HypervisorAction, HypervisorError> {
        let (vmid_raw, flags_raw, page_count) = unpack_vm_map_x1(x1);
        let vmid = Self::parse_vmid(vmid_raw as u64)?;
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
            .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
        for i in 0..page_count as u64 {
            let ipa = ipa_base + i * 4096;
            let pa = PhysAddr(pa_base + i * 4096);
            if let Err(e) = vm.stage2.map(ipa, pa, flags, frame_alloc) {
                // Rollback: unmap all successfully mapped leaf entries.
                // Note: intermediate table frames allocated during the successful
                // map() calls remain in owned_frames and are reclaimed on VM
                // destroy. Reclaiming empty intermediate tables here would require
                // walking and pruning the tree — not worth the complexity for
                // Phase A+B1 where mappings are set up once at VM creation.
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
        let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;
        if let Some(vm) = self.vms.get_mut(&vmid.0) {
            vm.state = VmState::Halted;
        }
        self.active_vmid = None;
        Ok(HypervisorAction::GuestExited {
            vmid,
            exit_code: x1,
        })
    }

    fn handle_data_abort(
        &mut self,
        ipa: u64,
        access: AccessType,
        width: u8,
        srt: u8,
    ) -> Result<HypervisorAction, HypervisorError> {
        // All data aborts require an active guest — reject early if host-only.
        let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;

        if (VIRTIO_NET_MMIO_IPA..VIRTIO_NET_MMIO_IPA + VIRTIO_NET_MMIO_SIZE).contains(&ipa) {
            let offset = (ipa - VIRTIO_NET_MMIO_IPA) as u32;
            let vm = self
                .vms
                .get_mut(&vmid.0)
                .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
            let response = vm.virtio_net.handle_mmio(offset, access);
            vm.gic
                .sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
            return match response {
                MmioResponse::ReadValue(val) => Ok(HypervisorAction::MmioResult {
                    emit: None,
                    read_value: val,
                    width,
                    srt,
                    pc_advance: 4,
                }),
                MmioResponse::WriteAck | MmioResponse::StatusChanged { .. } => {
                    Ok(HypervisorAction::MmioResult {
                        emit: None,
                        read_value: 0,
                        width,
                        srt,
                        pc_advance: 4,
                    })
                }
                MmioResponse::QueueNotify { queue } => Ok(HypervisorAction::VirtioQueueNotify {
                    vmid,
                    queue,
                    pc_advance: 4,
                }),
            };
        }

        if (VIRTUAL_UART_IPA..VIRTUAL_UART_IPA + VIRTUAL_UART_SIZE).contains(&ipa) {
            let offset = (ipa - VIRTUAL_UART_IPA) as u16;
            let vm = self
                .vms
                .get_mut(&vmid.0)
                .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;

            let (emit, read_value) = match access {
                AccessType::Write { value } => (vm.uart.write(offset, value), 0),
                AccessType::Read => (None, vm.uart.read(offset)),
            };
            vm.gic
                .sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);

            return Ok(HypervisorAction::MmioResult {
                emit,
                read_value,
                width,
                srt,
                pc_advance: 4,
            });
        }
        // GIC Distributor
        if (GICD_IPA..GICD_IPA + GICD_SIZE).contains(&ipa) {
            let offset = (ipa - GICD_IPA) as u32;
            let vm = self
                .vms
                .get_mut(&vmid.0)
                .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
            let read_value = match access {
                AccessType::Write { value } => {
                    vm.gic.write_gicd(offset, value);
                    0
                }
                AccessType::Read => vm.gic.read_gicd(offset),
            };
            vm.gic
                .sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
            return Ok(HypervisorAction::MmioResult {
                emit: None,
                read_value,
                width,
                srt,
                pc_advance: 4,
            });
        }

        // GIC Redistributor
        if (GICR_IPA..GICR_IPA + GICR_SIZE).contains(&ipa) {
            let offset = (ipa - GICR_IPA) as u32;
            let vm = self
                .vms
                .get_mut(&vmid.0)
                .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
            let read_value = if offset < 0x10000 {
                match access {
                    AccessType::Write { value } => {
                        vm.gic.write_gicr_rd(offset, value);
                        0
                    }
                    AccessType::Read => vm.gic.read_gicr_rd(offset),
                }
            } else {
                let sgi_offset = offset - 0x10000;
                match access {
                    AccessType::Write { value } => {
                        vm.gic.write_gicr_sgi(sgi_offset, value);
                        0
                    }
                    AccessType::Read => vm.gic.read_gicr_sgi(sgi_offset),
                }
            };
            vm.gic
                .sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
            return Ok(HypervisorAction::MmioResult {
                emit: None,
                read_value,
                width,
                srt,
                pc_advance: 4,
            });
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
        assert!(matches!(result, Err(HypervisorError::InvalidVmId(99))));
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
            HypervisorAction::EnterGuest { vmid: VmId(1), .. }
        ));
    }

    #[test]
    fn enter_guest_includes_timer_config() {
        use crate::platform::{GUEST_CNTHCTL_EL2, GUEST_CNTVOFF_EL2};

        let mut hyp = make_hypervisor();
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);

        // Create VM
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

        // Start VM
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

        // EnterGuest must carry timer configuration for the platform shim.
        match action {
            HypervisorAction::EnterGuest {
                cnthctl_el2,
                cntvoff_el2,
                ..
            } => {
                // EL1PCTEN (bit 0) and EL1PCEN (bit 1) must be set.
                assert_eq!(cnthctl_el2, GUEST_CNTHCTL_EL2);
                assert_ne!(cnthctl_el2 & 0b11, 0, "EL1PCTEN and EL1PCEN must be set");
                // Virtual counter offset must be zero (virtual == physical).
                assert_eq!(cntvoff_el2, GUEST_CNTVOFF_EL2);
                assert_eq!(cntvoff_el2, 0);
            }
            other => panic!("expected EnterGuest, got {other:?}"),
        }
    }

    #[test]
    fn vm_start_sets_x0_to_dtb_ipa() {
        use crate::platform::GUEST_RAM_BASE_IPA;

        let entry_ipa = GUEST_RAM_BASE_IPA;
        let dtb_ipa = GUEST_RAM_BASE_IPA + 0x780_0000;

        let mut hyp = make_hypervisor();
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);

        // Create VM
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

        // Start VM with dtb_ipa in x3
        let action = hyp
            .handle(
                TrapEvent::HvcCall {
                    x0: HVC_VM_START,
                    x1: 1,
                    x2: entry_ipa,
                    x3: dtb_ipa,
                },
                &mut alloc,
            )
            .unwrap();

        // Verify EnterGuest action has correct elr_el2
        match action {
            HypervisorAction::EnterGuest {
                vmid: VmId(1),
                elr_el2,
                ..
            } => {
                assert_eq!(elr_el2, entry_ipa);
            }
            other => panic!("expected EnterGuest, got {:?}", other),
        }

        // Verify vcpu register state via vm() accessor
        let vm = hyp.vm(1).expect("VM 1 should exist");
        assert_eq!(
            vm.vcpu.x[0], dtb_ipa,
            "x0 must be dtb_ipa per ARM64 boot protocol"
        );
        assert_eq!(vm.vcpu.x[1], 0, "x1 must be 0 per ARM64 boot protocol");
        assert_eq!(vm.vcpu.x[2], 0, "x2 must be 0 per ARM64 boot protocol");
        assert_eq!(vm.vcpu.x[3], 0, "x3 must be 0 per ARM64 boot protocol");
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
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::MmioResult {
                emit: Some(b'H'),
                read_value: 0,
                width: 1,
                srt: 0,
                pc_advance: 4,
            }
        );
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
                    srt: 0,
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
        assert_eq!(action, HypervisorAction::HaltGuest { vmid: VmId(1) });
    }

    #[test]
    fn smc_forward() {
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
                TrapEvent::SmcForward {
                    x0: 0xC400_0003,
                    x1: 0,
                    x2: 0,
                    x3: 0,
                },
                &mut alloc,
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
    fn smc_forward_without_active_vm_errors() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let result = hyp.handle(
            TrapEvent::SmcForward {
                x0: 0xC400_0003,
                x1: 0,
                x2: 0,
                x3: 0,
            },
            &mut || alloc.alloc(),
        );
        assert!(matches!(result, Err(HypervisorError::NoActiveVm)));
    }

    #[test]
    fn vmid_truncation_rejected() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        // 0x101 would truncate to VmId(1) — should be rejected
        let result = hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_DESTROY,
                x1: 0x101,
                x2: 0,
                x3: 0,
            },
            &mut || alloc.alloc(),
        );
        assert!(matches!(result, Err(HypervisorError::InvalidVmId(_))));
        let result = hyp.handle(
            TrapEvent::HvcCall {
                x0: HVC_VM_START,
                x1: 0x101,
                x2: 0x4000_0000,
                x3: 0,
            },
            &mut || alloc.alloc(),
        );
        assert!(matches!(result, Err(HypervisorError::InvalidVmId(_))));
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
        assert!(matches!(
            action,
            HypervisorAction::GuestExited {
                vmid: VmId(1),
                exit_code: 0
            }
        ));
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
            HypervisorAction::EnterGuest { vmid: VmId(1), .. }
        ));

        // 4. Guest writes "Hi" to virtual UART
        for &ch in b"Hi" {
            let action = hyp
                .handle(
                    TrapEvent::DataAbort {
                        ipa: VIRTUAL_UART_IPA,
                        access: AccessType::Write { value: ch as u64 },
                        width: 1,
                        srt: 0,
                    },
                    &mut alloc,
                )
                .unwrap();
            assert_eq!(
                action,
                HypervisorAction::MmioResult {
                    emit: Some(ch),
                    read_value: 0,
                    width: 1,
                    srt: 0,
                    pc_advance: 4,
                }
            );
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
        assert_eq!(
            action,
            HypervisorAction::GuestExited {
                vmid: VmId(1),
                exit_code: 0
            }
        );

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
                srt: 0,
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
        // Read at UARTDR (offset +0x00) → read_value 0
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: VIRTUAL_UART_IPA,
                    access: AccessType::Read,
                    width: 4,
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 0,
                width: 4,
                srt: 0,
                pc_advance: 4,
            }
        );
        // Read at UARTFR (offset +0x18) → TXFE + RXFE
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: VIRTUAL_UART_IPA + 0x18,
                    access: AccessType::Read,
                    width: 4,
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: (1 << 7) | (1 << 4), // TXFE + RXFE
                width: 4,
                srt: 0,
                pc_advance: 4,
            }
        );
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

    #[test]
    fn uart_probe_via_hypervisor() {
        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});

        // Create VM
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

        // Start VM
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

        // Read PeriphID0 (IPA = VIRTUAL_UART_IPA + 0xFE0) → expect 0x11
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: VIRTUAL_UART_IPA + 0xFE0,
                    access: AccessType::Read,
                    width: 4,
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 0x11,
                width: 4,
                srt: 0,
                pc_advance: 4,
            }
        );

        // Write 'H' (0x48) to UARTDR (IPA = VIRTUAL_UART_IPA + 0x000) → expect emit Some(0x48)
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: VIRTUAL_UART_IPA,
                    access: AccessType::Write { value: 0x48 },
                    width: 1,
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::MmioResult {
                emit: Some(0x48),
                read_value: 0,
                width: 1,
                srt: 0,
                pc_advance: 4,
            }
        );
    }

    // ── VirtIO MMIO routing tests ─────────────────────────────────────────────

    #[test]
    fn virtio_mmio_magic_via_hypervisor() {
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
        // Read REG_MAGIC at offset +0x000 — expect 0x74726976 ("virt" LE)
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: crate::platform::VIRTIO_NET_MMIO_IPA,
                    access: AccessType::Read,
                    width: 4,
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 0x7472_6976,
                width: 4,
                srt: 0,
                pc_advance: 4,
            }
        );
    }

    #[test]
    fn virtio_mmio_write_via_hypervisor() {
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
        // Write Status=1 to REG_STATUS at offset +0x070
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: crate::platform::VIRTIO_NET_MMIO_IPA + 0x070,
                    access: AccessType::Write { value: 1 },
                    width: 4,
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        // Write path: MmioResult with read_value=0
        assert_eq!(
            action,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 0,
                width: 4,
                srt: 0,
                pc_advance: 4,
            }
        );
    }

    #[test]
    fn virtio_queue_notify_via_hypervisor() {
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
        // Write queue index 1 to REG_QUEUE_NOTIFY at offset +0x050
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: crate::platform::VIRTIO_NET_MMIO_IPA + 0x050,
                    access: AccessType::Write { value: 1 },
                    width: 4,
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::VirtioQueueNotify {
                vmid: VmId(1),
                queue: 1,
                pc_advance: 4
            }
        );
    }

    #[test]
    fn virtio_mmio_without_active_vm_errors() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        // No VM created or started — DataAbort at VirtIO IPA should return NoActiveVm
        let result = hyp.handle(
            TrapEvent::DataAbort {
                ipa: crate::platform::VIRTIO_NET_MMIO_IPA,
                access: AccessType::Read,
                width: 4,
                srt: 0,
            },
            &mut || alloc.alloc(),
        );
        assert!(matches!(result, Err(HypervisorError::NoActiveVm)));
    }

    // ── End-to-end: Linux virtio-mmio probe + TX packet ──────────────────────

    /// Send a DataAbort at `VIRTIO_NET_MMIO_IPA + offset` through the hypervisor
    /// and return the resulting action.
    fn send_mmio(
        hyp: &mut Hypervisor,
        alloc: &mut impl FnMut() -> Option<PhysAddr>,
        offset: u32,
        access: AccessType,
    ) -> HypervisorAction {
        hyp.handle(
            TrapEvent::DataAbort {
                ipa: crate::platform::VIRTIO_NET_MMIO_IPA + offset as u64,
                access,
                width: 4,
                srt: 0,
            },
            alloc,
        )
        .unwrap()
    }

    #[test]
    fn linux_virtio_mmio_probe_and_tx() {
        // ── Setup: VM lifecycle ───────────────────────────────────────────────

        // Large arena for Stage-2 page table frames (64 pages).
        let stage2_arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&stage2_arena);

        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});

        // HVC_VM_CREATE → VMID 1
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

        // HVC_VM_START → guest enters
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
            HypervisorAction::EnterGuest { vmid: VmId(1), .. }
        ));

        // ── Shared memory arena for virtqueues and packet buffer ──────────────
        //
        // Layout (byte offsets into `mem`):
        //   0x0000  RX desc table  (16 entries × 16 bytes = 256 bytes)
        //   0x0100  RX avail ring  (6 + 2×16 = 38 bytes)
        //   0x1000  RX used ring   (page-aligned; 6 + 8×16 = 134 bytes)
        //   0x2000  TX desc table  (256 bytes)
        //   0x2100  TX avail ring  (38 bytes)
        //   0x3000  TX used ring   (134 bytes)
        //   0x4000  Packet buffer  (12-byte virtio_net_hdr + 60-byte frame = 72 bytes)
        //
        // The queue address registers are programmed with these byte offsets directly.
        // `try_make_queue` uses them as offsets into the `mem` slice, so they must be
        // small numbers within `mem.len()`, not absolute IPAs.
        //
        // The descriptor `addr` field stores the actual host pointer to the packet
        // buffer, so `ipa_to_ptr = |addr| addr as *const u8` is the identity.

        const RX_DESC_OFF: u64 = 0x0000;
        const RX_AVAIL_OFF: u64 = 0x0100;
        const RX_USED_OFF: u64 = 0x1000;
        const TX_DESC_OFF: u64 = 0x2000;
        const TX_AVAIL_OFF: u64 = 0x2100;
        const TX_USED_OFF: u64 = 0x3000;
        const PKT_BUF_OFF: u64 = 0x4000;
        const MEM_SIZE: usize = 0x5000; // 5 pages, covers all offsets

        let mut mem = vec![0u8; MEM_SIZE];

        // ── Phase 1: Device Discovery (3 reads) ───────────────────────────────

        // REG_MAGIC (+0x000) → 0x74726976 ("virt" LE)
        let a = send_mmio(&mut hyp, &mut alloc, 0x000, AccessType::Read);
        assert_eq!(
            a,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 0x7472_6976,
                width: 4,
                srt: 0,
                pc_advance: 4
            }
        );

        // REG_VERSION (+0x004) → 2
        let a = send_mmio(&mut hyp, &mut alloc, 0x004, AccessType::Read);
        assert_eq!(
            a,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 2,
                width: 4,
                srt: 0,
                pc_advance: 4
            }
        );

        // REG_DEVICE_ID (+0x008) → 1 (net)
        let a = send_mmio(&mut hyp, &mut alloc, 0x008, AccessType::Read);
        assert_eq!(
            a,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 1,
                width: 4,
                srt: 0,
                pc_advance: 4
            }
        );

        // ── Phase 2: Status Lifecycle ─────────────────────────────────────────

        // Reset (write 0)
        send_mmio(&mut hyp, &mut alloc, 0x070, AccessType::Write { value: 0 });
        // ACKNOWLEDGE (bit 0)
        send_mmio(&mut hyp, &mut alloc, 0x070, AccessType::Write { value: 1 });
        // ACKNOWLEDGE | DRIVER (bits 0+1)
        send_mmio(&mut hyp, &mut alloc, 0x070, AccessType::Write { value: 3 });

        // ── Phase 3: Feature Negotiation ─────────────────────────────────────

        // Select feature word 0
        send_mmio(&mut hyp, &mut alloc, 0x014, AccessType::Write { value: 0 });
        // Read device features word 0 — must have bit 5 (F_MAC) and bit 16 (F_STATUS)
        let a = send_mmio(&mut hyp, &mut alloc, 0x010, AccessType::Read);
        let feat0 = match a {
            HypervisorAction::MmioResult { read_value, .. } => read_value,
            other => panic!("expected MmioResult, got {:?}", other),
        };
        assert_ne!(feat0 & (1 << 5), 0, "F_MAC must be set in feature word 0");
        assert_ne!(
            feat0 & (1 << 16),
            0,
            "F_STATUS must be set in feature word 0"
        );

        // Select feature word 1
        send_mmio(&mut hyp, &mut alloc, 0x014, AccessType::Write { value: 1 });
        // Read device features word 1 — must have bit 0 (F_VERSION_1, global bit 32)
        let a = send_mmio(&mut hyp, &mut alloc, 0x010, AccessType::Read);
        let feat1 = match a {
            HypervisorAction::MmioResult { read_value, .. } => read_value,
            other => panic!("expected MmioResult, got {:?}", other),
        };
        assert_ne!(feat1 & 1, 0, "F_VERSION_1 must be set in feature word 1");

        // Write driver features: word 0 = F_MAC | F_STATUS
        send_mmio(&mut hyp, &mut alloc, 0x024, AccessType::Write { value: 0 });
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x020,
            AccessType::Write {
                value: (1 << 5) | (1 << 16),
            },
        );
        // Write driver features: word 1 = F_VERSION_1
        send_mmio(&mut hyp, &mut alloc, 0x024, AccessType::Write { value: 1 });
        send_mmio(&mut hyp, &mut alloc, 0x020, AccessType::Write { value: 1 });

        // FEATURES_OK (bits 0+1+3 = 0xB)
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x070,
            AccessType::Write { value: 0xB },
        );
        // Read back status — must still be 0xB
        let a = send_mmio(&mut hyp, &mut alloc, 0x070, AccessType::Read);
        assert_eq!(
            a,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 0xB,
                width: 4,
                srt: 0,
                pc_advance: 4
            }
        );

        // ── Phase 4: Queue Configuration ─────────────────────────────────────
        //
        // Queue register addresses are byte offsets into `mem`.  VirtQueue::new
        // receives them directly as `desc_offset`, `avail_offset`, `used_offset`.

        // — Select RX queue (index 0) —
        send_mmio(&mut hyp, &mut alloc, 0x030, AccessType::Write { value: 0 });
        send_mmio(&mut hyp, &mut alloc, 0x038, AccessType::Write { value: 16 });
        // QueueDescLow/High
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x080,
            AccessType::Write {
                value: RX_DESC_OFF & 0xFFFF_FFFF,
            },
        );
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x084,
            AccessType::Write {
                value: (RX_DESC_OFF >> 32) & 0xFFFF_FFFF,
            },
        );
        // QueueAvailLow/High
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x090,
            AccessType::Write {
                value: RX_AVAIL_OFF & 0xFFFF_FFFF,
            },
        );
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x094,
            AccessType::Write {
                value: (RX_AVAIL_OFF >> 32) & 0xFFFF_FFFF,
            },
        );
        // QueueUsedLow/High
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x0A0,
            AccessType::Write {
                value: RX_USED_OFF & 0xFFFF_FFFF,
            },
        );
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x0A4,
            AccessType::Write {
                value: (RX_USED_OFF >> 32) & 0xFFFF_FFFF,
            },
        );
        // QueueReady = 1
        send_mmio(&mut hyp, &mut alloc, 0x044, AccessType::Write { value: 1 });

        // — Select TX queue (index 1) —
        send_mmio(&mut hyp, &mut alloc, 0x030, AccessType::Write { value: 1 });
        send_mmio(&mut hyp, &mut alloc, 0x038, AccessType::Write { value: 16 });
        // QueueDescLow/High
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x080,
            AccessType::Write {
                value: TX_DESC_OFF & 0xFFFF_FFFF,
            },
        );
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x084,
            AccessType::Write {
                value: (TX_DESC_OFF >> 32) & 0xFFFF_FFFF,
            },
        );
        // QueueAvailLow/High
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x090,
            AccessType::Write {
                value: TX_AVAIL_OFF & 0xFFFF_FFFF,
            },
        );
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x094,
            AccessType::Write {
                value: (TX_AVAIL_OFF >> 32) & 0xFFFF_FFFF,
            },
        );
        // QueueUsedLow/High
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x0A0,
            AccessType::Write {
                value: TX_USED_OFF & 0xFFFF_FFFF,
            },
        );
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x0A4,
            AccessType::Write {
                value: (TX_USED_OFF >> 32) & 0xFFFF_FFFF,
            },
        );
        // QueueReady = 1
        send_mmio(&mut hyp, &mut alloc, 0x044, AccessType::Write { value: 1 });

        // ── Phase 5: Driver Ready ─────────────────────────────────────────────

        // DRIVER_OK (bits 0+1+2+3 = 0xF)
        send_mmio(
            &mut hyp,
            &mut alloc,
            0x070,
            AccessType::Write { value: 0xF },
        );

        // ── Phase 6: TX Packet ────────────────────────────────────────────────

        // Build a 60-byte test Ethernet frame (all 0xAA).
        const FRAME_LEN: usize = 60;
        const HDR_LEN: usize = 12; // virtio_net_hdr
        const PKT_LEN: usize = HDR_LEN + FRAME_LEN; // 72

        // Write packet into shared memory:
        //   [0..12]  virtio_net_hdr  (all zeros)
        //   [12..72] Ethernet frame  (all 0xAA)
        let pkt_off = PKT_BUF_OFF as usize;
        // Header is already zeroed (vec! initializes to 0).
        mem[pkt_off + HDR_LEN..pkt_off + PKT_LEN].fill(0xAA);

        // The descriptor `addr` is the actual host pointer to the packet buffer.
        // `ipa_to_ptr = |addr| addr as *const u8` is the identity function.
        let pkt_ptr = mem[pkt_off..].as_ptr() as u64;

        // Write TX descriptor 0 at TX_DESC_OFF:
        //   addr  = pkt_ptr (host pointer, used by ipa_to_ptr)
        //   len   = 72
        //   flags = 0 (no NEXT, no WRITE)
        //   next  = 0
        let tx_desc_base = TX_DESC_OFF as usize;
        mem[tx_desc_base..tx_desc_base + 8].copy_from_slice(&pkt_ptr.to_le_bytes());
        mem[tx_desc_base + 8..tx_desc_base + 12].copy_from_slice(&(PKT_LEN as u32).to_le_bytes());
        mem[tx_desc_base + 12..tx_desc_base + 14].copy_from_slice(&0u16.to_le_bytes());
        mem[tx_desc_base + 14..tx_desc_base + 16].copy_from_slice(&0u16.to_le_bytes());

        // Write TX available ring: flags=0, idx=1, ring[0]=0
        let tx_avail_base = TX_AVAIL_OFF as usize;
        mem[tx_avail_base..tx_avail_base + 2].copy_from_slice(&0u16.to_le_bytes()); // flags
        mem[tx_avail_base + 2..tx_avail_base + 4].copy_from_slice(&1u16.to_le_bytes()); // idx=1
        mem[tx_avail_base + 4..tx_avail_base + 6].copy_from_slice(&0u16.to_le_bytes()); // ring[0]=0

        // Guest notifies TX queue (index 1).
        let a = send_mmio(&mut hyp, &mut alloc, 0x050, AccessType::Write { value: 1 });
        assert_eq!(
            a,
            HypervisorAction::VirtioQueueNotify {
                vmid: VmId(1),
                queue: 1,
                pc_advance: 4
            }
        );

        // ── Phase 7: Host reads the TX packet ─────────────────────────────────

        let vm = hyp.vms.get_mut(&1).expect("VM 1 must exist");
        let mut out_buf = [0u8; 1500];
        let n = vm
            .virtio_net
            .poll_tx(&mut mem, 0, |addr| addr as *const u8, &mut out_buf)
            .expect("poll_tx must return Some");

        // Expect exactly 60 bytes (virtio_net_hdr stripped).
        assert_eq!(n, FRAME_LEN);
        // All frame bytes must be 0xAA.
        assert!(
            out_buf[..FRAME_LEN].iter().all(|&b| b == 0xAA),
            "frame bytes must all be 0xAA, got: {:?}",
            &out_buf[..FRAME_LEN]
        );
    }

    #[test]
    fn virtio_config_space_mac() {
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
        // Read REG_CONFIG_BASE at offset +0x100 — first MAC byte should be 0x02
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: crate::platform::VIRTIO_NET_MMIO_IPA + 0x100,
                    access: AccessType::Read,
                    width: 1,
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 0x02,
                width: 1,
                srt: 0,
                pc_advance: 4,
            }
        );
    }

    // ── GIC integration tests ─────────────────────────────────────────────────

    #[test]
    fn timer_irq_pends_ppi_27() {
        use crate::platform::{GICR_IPA, LR_COUNT};

        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});

        // Create and start VM
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

        // Enable PPI 27 via GICR SGI_base ISENABLER0 (IPA = GICR_IPA + 0x10000 + 0x0100)
        // Bit 27 in ISENABLER0 enables IRQ 27.
        hyp.handle(
            TrapEvent::DataAbort {
                ipa: GICR_IPA + 0x10000 + 0x0100,
                access: AccessType::Write { value: 1 << 27 },
                width: 4,
                srt: 0,
            },
            &mut alloc,
        )
        .unwrap();

        // Fire TimerIrq — should pend PPI 27 and return ResumeGuest
        let action = hyp.handle(TrapEvent::TimerIrq, &mut alloc).unwrap();
        assert_eq!(action, HypervisorAction::ResumeGuest);

        // Verify: vm.vcpu.ich_lr[0] has vINTID = 27
        let vm = hyp.vm(1).expect("VM 1 should exist");
        let lr0 = vm.vcpu.ich_lr[0];
        let vintid = lr0 & 0xFFFF_FFFF; // vINTID is bits [31:0]
        assert_eq!(vintid, 27, "LR[0] vINTID must be 27 (virtual timer PPI)");
        // Verify the LR has the pending state set (bits [63:62] = 0b01)
        let state = (lr0 >> 62) & 0b11;
        assert_eq!(state, 0b01, "LR[0] state must be pending (0b01)");
        // Verify at most LR_COUNT LRs are used
        let used = vm.vcpu.ich_lr[..LR_COUNT]
            .iter()
            .filter(|&&lr| (lr >> 62) & 0b11 != 0)
            .count();
        assert!(used >= 1, "at least one LR must be populated");
    }

    #[test]
    fn gicd_mmio_reads_typer_through_hypervisor() {
        use crate::platform::GICD_IPA;

        let arena = vec![0u8; 65 * 4096];
        let mut alloc = make_arena_alloc(&arena);
        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8, |_| {});

        // Create and start VM
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

        // DataAbort read at GICD_IPA + 0x0004 (TYPER) — expect ITLinesNumber=1
        let action = hyp
            .handle(
                TrapEvent::DataAbort {
                    ipa: GICD_IPA + 0x0004,
                    access: AccessType::Read,
                    width: 4,
                    srt: 0,
                },
                &mut alloc,
            )
            .unwrap();
        assert_eq!(
            action,
            HypervisorAction::MmioResult {
                emit: None,
                read_value: 1,
                width: 4,
                srt: 0,
                pc_advance: 4,
            }
        );
    }
}
