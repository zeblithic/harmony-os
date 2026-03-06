// SPDX-License-Identifier: GPL-2.0-or-later
//! Minimal PCI bus 0 scanner using x86 I/O ports 0xCF8 / 0xCFC.

use x86_64::instructions::port::Port;

const CONFIG_ADDRESS: u16 = 0x0CF8;
const CONFIG_DATA: u16 = 0x0CFC;

pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_NET_DEVICE_ID_MODERN: u16 = 0x1041;
pub const VIRTIO_NET_DEVICE_ID_TRANSITIONAL: u16 = 0x1000;

fn config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

pub fn pci_config_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    unsafe {
        Port::new(CONFIG_ADDRESS).write(config_address(bus, device, function, offset));
        Port::new(CONFIG_DATA).read()
    }
}

pub fn pci_config_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let val = pci_config_read32(bus, device, function, offset);
    ((val >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

pub fn pci_config_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let val = pci_config_read32(bus, device, function, offset);
    ((val >> ((offset & 3) * 8)) & 0xFF) as u8
}

pub fn pci_config_write32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    unsafe {
        Port::new(CONFIG_ADDRESS).write(config_address(bus, device, function, offset));
        Port::new(CONFIG_DATA).write(value);
    }
}

pub fn pci_config_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let current = pci_config_read32(bus, device, function, offset);
    let shift = (offset & 2) * 8;
    let mask = !(0xFFFF_u32 << shift);
    let new_val = (current & mask) | ((value as u32) << shift);
    pci_config_write32(bus, device, function, offset, new_val);
}

pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub bars: [u32; 6],
}

impl PciDevice {
    pub fn capabilities_ptr(&self) -> u8 {
        pci_config_read8(self.bus, self.device, self.function, 0x34)
    }

    pub fn enable_bus_master(&self) {
        // Read full 32-bit register at offset 0x04: [Status(15:0) | Command(15:0)].
        // Write back with status bits zeroed to avoid clearing W1C status bits
        // (writing 0 to a W1C bit is a no-op; writing 1 would clear it).
        let word = pci_config_read32(self.bus, self.device, self.function, 0x04);
        let cmd = (word as u16) | 0b0000_0110; // Memory Space + Bus Master
        pci_config_write32(self.bus, self.device, self.function, 0x04, cmd as u32);
    }
}

pub fn find_virtio_net() -> Option<PciDevice> {
    // NOTE: Only scans bus 0, function 0. Multi-function devices and
    // secondary buses are not enumerated — sufficient for QEMU virtio-net.
    for device in 0..32u8 {
        let reg0 = pci_config_read32(0, device, 0, 0);
        let vendor_id = (reg0 & 0xFFFF) as u16;
        if vendor_id == 0xFFFF {
            continue;
        }
        let device_id = ((reg0 >> 16) & 0xFFFF) as u16;

        // Transitional (0x1000) devices are included; the modern VirtIO 1.0
        // init in virtio/net.rs requires FEATURES_OK acceptance — legacy-only
        // transitional devices will fail gracefully there.
        if vendor_id == VIRTIO_VENDOR_ID
            && (device_id == VIRTIO_NET_DEVICE_ID_MODERN
                || device_id == VIRTIO_NET_DEVICE_ID_TRANSITIONAL)
        {
            let mut bars = [0u32; 6];
            for (i, bar) in bars.iter_mut().enumerate() {
                *bar = pci_config_read32(0, device, 0, 0x10 + (i as u8) * 4);
            }
            return Some(PciDevice {
                bus: 0,
                device,
                function: 0,
                vendor_id,
                device_id,
                bars,
            });
        }
    }
    None
}
