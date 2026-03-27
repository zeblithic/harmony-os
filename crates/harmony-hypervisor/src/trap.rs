// SPDX-License-Identifier: GPL-2.0-or-later
//! Trap event/action types, HVC constants, and error enum.

use crate::vmid::VmId;
use harmony_microkernel::vm::{PhysAddr, VmError};

// ── HVC Function IDs ─────────────────────────────────────────────────

/// "HV" prefix (0x4856) places these in the vendor-specific HVC range.
pub const HVC_VM_CREATE: u64 = 0x4856_0001;
pub const HVC_VM_DESTROY: u64 = 0x4856_0002;
pub const HVC_VM_START: u64 = 0x4856_0003;
pub const HVC_VM_MAP: u64 = 0x4856_0010;
pub const HVC_GUEST_EXIT: u64 = 0x4856_0099;

// ── VM_MAP x1 packing ───────────────────────────────────────────────

/// Pack VMID, flags, and page_count into a single u64 for HVC_VM_MAP x1.
/// Layout: bits [7:0]=VMID, [15:8]=flags, [31:16]=page_count.
pub fn pack_vm_map_x1(vmid: u8, flags: u8, page_count: u16) -> u64 {
    (vmid as u64) | ((flags as u64) << 8) | ((page_count as u64) << 16)
}

/// Unpack HVC_VM_MAP x1 into (vmid, flags, page_count).
pub fn unpack_vm_map_x1(x1: u64) -> (u8, u8, u16) {
    let vmid = (x1 & 0xFF) as u8;
    let flags = ((x1 >> 8) & 0xFF) as u8;
    let page_count = ((x1 >> 16) & 0xFFFF) as u16;
    (vmid, flags, page_count)
}

// ── Events ───────────────────────────────────────────────────────────

/// Events fed into the hypervisor by the platform shim after parsing ESR_EL2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrapEvent {
    HvcCall {
        x0: u64,
        x1: u64,
        x2: u64,
        x3: u64,
    },
    DataAbort {
        ipa: u64,
        access: AccessType,
        width: u8,
    },
    InstructionAbort {
        ipa: u64,
    },
    WfiWfe,
    SmcForward {
        x0: u64,
        x1: u64,
        x2: u64,
        x3: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessType {
    Read,
    Write { value: u64 },
}

// ── Actions ──────────────────────────────────────────────────────────

/// Actions the hypervisor returns for the platform shim to execute.
///
/// Note: Stage-2 page table manipulation happens inside `handle()` via
/// pure memory writes through `phys_to_virt`. The platform shim must
/// perform TLB invalidation (TLBI IPAS2E1IS + TLBI VMALLE1IS + DSB ISH
/// + ISB) after any `HvcResult` returned from `HVC_VM_MAP`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HypervisorAction {
    DestroyVm {
        vmid: VmId,
    },
    /// Result of a trapped MMIO access (Stage-2 data abort).
    /// The platform shim must:
    /// 1. If `emit` is Some(ch), write `ch` to the host console (virtual UART TX).
    /// 2. If the original access was a read, inject `read_value` into the guest
    ///    register indicated by ESR_EL2.ISS.SRT.
    /// 3. Advance ELR_EL2 by `pc_advance` bytes (typically 4) to skip the
    ///    faulting instruction.
    /// 4. Resume the guest.
    MmioResult {
        /// Character to emit to host console, if any (virtual UART TX at offset +0x00).
        emit: Option<u8>,
        /// Value to inject into the guest's target register on a read trap.
        /// For writes and TX-only UART, this is 0.
        read_value: u64,
        /// Access width in bytes (1/2/4/8) from ESR_EL2.ISS.SAS.
        /// The shim uses this to zero/sign-extend `read_value` when
        /// injecting into the guest's target register.
        width: u8,
        /// Bytes to advance ELR_EL2 (4 for A64, 2 for T32).
        pc_advance: u8,
    },
    /// Guest executed WFI/WFE and has been descheduled. The platform shim
    /// should switch to host context (restore host vCPU, clear VTTBR_EL2).
    /// This is NOT an HVC — do not attempt to return a value to the guest.
    HaltGuest {
        vmid: VmId,
    },
    /// Forward an SMC to EL3 (PSCI). The platform shim must advance
    /// ELR_EL2 by 4 after the SMC completes, then resume the guest.
    ForwardSmc {
        x0: u64,
        x1: u64,
        x2: u64,
        x3: u64,
    },
    /// Switch to guest context and eret. The platform shim must:
    /// 1. Load `VTTBR_EL2 = (vmid << 48) | stage2_root`.
    /// 2. Set `ELR_EL2 = elr_el2`, `SPSR_EL2 = spsr_el2`.
    /// 3. Restore guest GPRs from VCpuContext.
    /// 4. Issue `eret`.
    EnterGuest {
        vmid: VmId,
        stage2_root: PhysAddr,
        elr_el2: u64,
        spsr_el2: u64,
    },
    /// Return x0 to the HVC caller and resume at EL1.
    HvcResult {
        x0: u64,
    },
}

// ── Stage-2 flags ────────────────────────────────────────────────────

/// Stage-2 permission and memory attribute flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage2Flags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub mem_attr: Stage2MemAttr,
}

/// Stage-2 memory attribute (encoded directly in descriptor, no MAIR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage2MemAttr {
    NormalWriteBack,
    NormalNonCacheable,
    Device,
}

impl Stage2Flags {
    /// RWX normal write-back — the common case for guest RAM.
    pub const GUEST_RAM: Self = Self {
        readable: true,
        writable: true,
        executable: true,
        mem_attr: Stage2MemAttr::NormalWriteBack,
    };
}

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HypervisorError {
    VmLimitReached,
    /// The VMID argument is out of range or does not refer to a known VM.
    /// Carries the raw u64 so diagnostics can report the actual bad input.
    InvalidVmId(u64),
    InvalidHvc(u64),
    Stage2MapFailed(VmError),
    VmAlreadyRunning(VmId),
    OutOfMemory,
    /// A trap arrived but no guest VM is active (active_vmid is None).
    NoActiveVm,
    /// IPA or PA range overflows u64 address space.
    InvalidAddress,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmid::VmId;

    #[test]
    fn hvc_constants_have_hv_prefix() {
        assert_eq!(HVC_VM_CREATE >> 16, 0x4856);
        assert_eq!(HVC_VM_DESTROY >> 16, 0x4856);
        assert_eq!(HVC_VM_START >> 16, 0x4856);
        assert_eq!(HVC_VM_MAP >> 16, 0x4856);
        assert_eq!(HVC_GUEST_EXIT >> 16, 0x4856);
    }

    #[test]
    fn hvc_constants_are_unique() {
        let ids = [
            HVC_VM_CREATE,
            HVC_VM_DESTROY,
            HVC_VM_START,
            HVC_VM_MAP,
            HVC_GUEST_EXIT,
        ];
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn trap_event_variants_constructible() {
        let _hvc = TrapEvent::HvcCall {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
        };
        let _da = TrapEvent::DataAbort {
            ipa: 0x0900_0000,
            access: AccessType::Write { value: b'H' as u64 },
            width: 1,
        };
        let _ia = TrapEvent::InstructionAbort { ipa: 0x4000_0000 };
        let _wfi = TrapEvent::WfiWfe;
        let _smc = TrapEvent::SmcForward {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
        };
    }

    #[test]
    fn hypervisor_error_variants_constructible() {
        let _a = HypervisorError::VmLimitReached;
        let _b = HypervisorError::InvalidVmId(42);
        let _c = HypervisorError::InvalidHvc(0xDEAD);
        let _d = HypervisorError::VmAlreadyRunning(VmId(1));
        let _e = HypervisorError::OutOfMemory;
    }

    #[test]
    fn vm_map_pack_unpack_round_trips() {
        let vmid = 5u8;
        let flags_bits = 0b00_111u8;
        let page_count = 8u16;
        let packed = pack_vm_map_x1(vmid, flags_bits, page_count);
        let (v, f, p) = unpack_vm_map_x1(packed);
        assert_eq!(v, vmid);
        assert_eq!(f, flags_bits);
        assert_eq!(p, page_count);
    }
}
