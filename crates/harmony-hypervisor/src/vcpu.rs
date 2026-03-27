// SPDX-License-Identifier: GPL-2.0-or-later
//! vCPU context and VM state.

use crate::stage2::Stage2PageTable;
use crate::virtio_net::VirtioNetDevice;
use crate::vmid::VmId;

/// Saved register state for a virtual CPU.
#[derive(Debug, Clone, Default)]
pub struct VCpuContext {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub sp_el1: u64,
    pub elr_el2: u64,
    pub spsr_el2: u64,
    pub sctlr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
    pub vbar_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub contextidr_el1: u64,
    pub cntv_ctl_el0: u64,
    pub cntv_cval_el0: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Created,
    Running,
    Halted,
}

pub struct Vm {
    pub id: VmId,
    pub vcpu: VCpuContext,
    pub stage2: Stage2PageTable,
    pub state: VmState,
    pub virtio_net: VirtioNetDevice,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpu_context_default_is_zeroed() {
        let ctx = VCpuContext::default();
        assert_eq!(ctx.x, [0u64; 31]);
        assert_eq!(ctx.sp_el0, 0);
        assert_eq!(ctx.sp_el1, 0);
        assert_eq!(ctx.elr_el2, 0);
        assert_eq!(ctx.spsr_el2, 0);
        assert_eq!(ctx.sctlr_el1, 0);
    }

    #[test]
    fn vm_state_transitions() {
        assert_eq!(VmState::Created, VmState::Created);
        assert_ne!(VmState::Created, VmState::Running);
        assert_ne!(VmState::Running, VmState::Halted);
    }

    #[test]
    fn vcpu_context_set_entry_point() {
        let ctx = VCpuContext {
            elr_el2: 0x4000_0000,
            spsr_el2: 0x3C5, // EL1h + DAIF masked
            ..Default::default()
        };
        assert_eq!(ctx.elr_el2, 0x4000_0000);
        assert_eq!(ctx.spsr_el2, 0x3C5);
    }
}
