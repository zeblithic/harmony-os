// SPDX-License-Identifier: GPL-2.0-or-later
//! Parse VirtIO PCI capabilities to locate MMIO register regions.
//!
//! VirtIO 1.0 §4.1.4: vendor-specific PCI capabilities (cap ID 0x09)
//! with `cfg_type` identifying the structure type.

use crate::pci::{pci_config_read32, pci_config_read8, PciDevice};

/// PCI capability ID for vendor-specific capabilities.
const PCI_CAP_ID_VENDOR: u8 = 0x09;

/// Common configuration structure (§4.1.4.3).
pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
/// Notification structure (§4.1.4.4).
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
/// ISR status structure (§4.1.4.5).
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
/// Device-specific configuration structure (§4.1.4.6).
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
/// PCI configuration access structure (§4.1.4.7).
pub const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;

/// Parsed VirtIO PCI capability addresses for MMIO register access.
pub struct VirtioPciCaps {
    /// Virtual address of the common configuration registers.
    pub common_cfg: usize,
    /// Virtual address of the notification region base.
    pub notify_base: usize,
    /// Bytes per queue index for notification writes.
    pub notify_off_multiplier: u32,
    /// Virtual address of the device-specific configuration registers.
    pub device_cfg: usize,
    /// Virtual address of the ISR status register.
    pub isr_cfg: usize,
}

/// Walk the PCI capability list for a VirtIO device and resolve MMIO
/// virtual addresses for each required capability structure.
///
/// # Arguments
///
/// * `dev` — The PCI device whose capabilities to parse.
/// * `phys_offset` — The kernel's physical-to-virtual memory offset
///   (from the bootloader's physical memory mapping).
///
/// # Returns
///
/// `Some(VirtioPciCaps)` if all required capabilities (common, notify,
/// ISR, device) were found; `None` otherwise.
pub fn parse_capabilities(dev: &PciDevice, phys_offset: u64) -> Option<VirtioPciCaps> {
    let mut common_cfg: Option<usize> = None;
    let mut notify_base: Option<usize> = None;
    let mut notify_off_multiplier: u32 = 0;
    let mut device_cfg: Option<usize> = None;
    let mut isr_cfg: Option<usize> = None;

    let mut cap_ptr = dev.capabilities_ptr();

    // Walk the capability linked list.
    while cap_ptr != 0 {
        let cap_id = pci_config_read8(dev.bus, dev.device, dev.function, cap_ptr);
        let cap_next = pci_config_read8(dev.bus, dev.device, dev.function, cap_ptr + 1);

        if cap_id == PCI_CAP_ID_VENDOR {
            let cfg_type = pci_config_read8(dev.bus, dev.device, dev.function, cap_ptr + 3);
            let bar_index = pci_config_read8(dev.bus, dev.device, dev.function, cap_ptr + 4);
            let offset = pci_config_read32(dev.bus, dev.device, dev.function, cap_ptr + 8);
            let _length = pci_config_read32(dev.bus, dev.device, dev.function, cap_ptr + 12);

            // Read the BAR value and resolve the physical base address.
            // 64-bit BARs (type bits [2:1] == 0b10) span two consecutive BARs.
            let bar_val = dev.bars[bar_index as usize];
            let is_64bit = (bar_val >> 1) & 0x3 == 0x2;
            let bar_base = if is_64bit {
                let lo = (bar_val & 0xFFFF_FFF0) as u64;
                let hi = dev.bars[bar_index as usize + 1] as u64;
                lo | (hi << 32)
            } else {
                (bar_val & 0xFFFF_FFF0) as u64
            };
            let virt_addr = (bar_base + phys_offset + offset as u64) as usize;

            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => {
                    common_cfg = Some(virt_addr);
                }
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    notify_base = Some(virt_addr);
                    // The notify_off_multiplier is at cap_ptr + 16 for notify caps.
                    notify_off_multiplier =
                        pci_config_read32(dev.bus, dev.device, dev.function, cap_ptr + 16);
                }
                VIRTIO_PCI_CAP_ISR_CFG => {
                    isr_cfg = Some(virt_addr);
                }
                VIRTIO_PCI_CAP_DEVICE_CFG => {
                    device_cfg = Some(virt_addr);
                }
                _ => {}
            }
        }

        cap_ptr = cap_next;
    }

    Some(VirtioPciCaps {
        common_cfg: common_cfg?,
        notify_base: notify_base?,
        notify_off_multiplier,
        device_cfg: device_cfg?,
        isr_cfg: isr_cfg?,
    })
}
