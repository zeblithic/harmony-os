// SPDX-License-Identifier: GPL-2.0-or-later
//! Platform constants for the hypervisor.

pub mod qemu_virt;
pub mod rpi5;

/// Virtual UART base IPA — the full PL011 register page (4KiB).
/// Guest accesses anywhere in [base, base+size) are trapped.
pub const VIRTUAL_UART_IPA: u64 = 0x0900_0000;
/// Size of the virtual UART MMIO region (one 4KiB page covers all PL011 registers).
pub const VIRTUAL_UART_SIZE: u64 = 0x1000;

/// VirtIO-net MMIO base IPA.
pub const VIRTIO_NET_MMIO_IPA: u64 = 0x0A00_0000;
/// Size of the VirtIO-net MMIO region (one 4KiB page).
pub const VIRTIO_NET_MMIO_SIZE: u64 = 0x1000;

/// Default guest RAM base IPA. Re-exported from the guest loader layout
/// to ensure a single source of truth across crate boundaries.
pub const GUEST_RAM_BASE_IPA: u64 = harmony_microkernel::guest_loader::layout::RAM_BASE;

/// HVC ping function ID for EL2→EL1 drop validation.
pub const HVC_PING: u64 = 0x4856_FFFF;
/// Expected HVC ping response.
pub const HVC_PONG: u64 = 0x4856_FFFE;

/// CNTHCTL_EL2 value for guest entry: EL1PCTEN (bit 0) + EL1PCEN (bit 1).
pub const GUEST_CNTHCTL_EL2: u64 = 0b11;
/// CNTVOFF_EL2 value: zero offset (virtual == physical counter).
pub const GUEST_CNTVOFF_EL2: u64 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_uart_ipa_is_consistent() {
        assert_eq!(VIRTUAL_UART_IPA, 0x0900_0000);
    }

    #[test]
    fn guest_ram_base_is_page_aligned() {
        assert_eq!(GUEST_RAM_BASE_IPA & 0xFFF, 0);
    }
}
