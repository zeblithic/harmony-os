// SPDX-License-Identifier: GPL-2.0-or-later
//! Platform constants for the hypervisor.

pub mod qemu_virt;
pub mod rpi5;

/// Virtual UART IPA — guest writes here trigger Stage-2 data abort.
pub const VIRTUAL_UART_IPA: u64 = 0x0900_0000;

/// Default guest RAM base IPA.
pub const GUEST_RAM_BASE_IPA: u64 = 0x4000_0000;

/// HVC ping function ID for EL2→EL1 drop validation.
pub const HVC_PING: u64 = 0x4856_FFFF;
/// Expected HVC ping response.
pub const HVC_PONG: u64 = 0x4856_FFFE;

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
