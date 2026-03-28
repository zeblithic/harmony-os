// SPDX-License-Identifier: GPL-2.0-or-later

//! Hardware platform descriptor types.
//!
//! `HardwareConfig` is populated at boot from FDT device trees, UEFI tables,
//! or compile-time constants, and describes the physical peripherals available
//! to the microkernel.  It is the first step toward dynamic hardware discovery
//! for Apple Silicon and other platforms.

use alloc::string::String;
use alloc::vec::Vec;

// ── Memory ────────────────────────────────────────────────────────────────────

/// A contiguous physical memory region.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
}

// ── Serial ────────────────────────────────────────────────────────────────────

/// MMIO-mapped serial / UART controller.
#[derive(Debug, Clone)]
pub struct SerialConfig {
    pub base: u64,
    pub size: u64,
    /// DT `compatible` string (e.g. `"arm,pl011"`, `"apple,s5l-uart"`).
    pub compatible: String,
}

// ── Interrupt controller ──────────────────────────────────────────────────────

/// Supported interrupt-controller hardware variants.
#[derive(Debug, Clone)]
pub enum InterruptControllerVariant {
    /// ARM GICv3 (Generic Interrupt Controller, revision 3).
    GicV3,
    /// Apple AIC (Apple Interrupt Controller).
    AppleAic,
}

/// MMIO-mapped interrupt controller.
#[derive(Debug, Clone)]
pub struct InterruptControllerConfig {
    pub base: u64,
    pub size: u64,
    pub variant: InterruptControllerVariant,
}

// ── Network device ────────────────────────────────────────────────────────────

/// MMIO-mapped network device.
#[derive(Debug, Clone)]
pub struct NetworkDeviceConfig {
    pub base: u64,
    pub size: u64,
    pub irq: u32,
    /// DT `compatible` string (e.g. `"virtio,mmio"`, `"apple,t8103-dwi"`).
    pub compatible: String,
}

// ── Block device ──────────────────────────────────────────────────────────────

/// MMIO-mapped block device.
#[derive(Debug, Clone)]
pub struct BlockDeviceConfig {
    pub base: u64,
    pub size: u64,
    pub irq: u32,
    /// DT `compatible` string (e.g. `"virtio,mmio"`).
    pub compatible: String,
}

// ── Chosen / bootloader parameters ───────────────────────────────────────────

/// Parameters supplied by the bootloader via `/chosen` (FDT or UEFI vars).
#[derive(Debug, Clone, Default)]
pub struct ChosenConfig {
    pub bootargs: Option<String>,
    pub stdout_path: Option<String>,
    pub initrd_start: Option<u64>,
    pub initrd_end: Option<u64>,
}

// ── Top-level platform descriptor ────────────────────────────────────────────

/// Complete platform hardware descriptor, built at boot.
#[derive(Debug, Clone)]
pub struct HardwareConfig {
    pub memory_regions: Vec<MemoryRegion>,
    pub serial: Option<SerialConfig>,
    pub interrupt_controller: Option<InterruptControllerConfig>,
    pub network_devices: Vec<NetworkDeviceConfig>,
    pub block_devices: Vec<BlockDeviceConfig>,
    pub chosen: ChosenConfig,
    /// Page granule in bytes (4096 for 4 KiB, 16384 for 16 KiB, 65536 for 64 KiB).
    pub page_granule: usize,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            memory_regions: Vec::new(),
            serial: None,
            interrupt_controller: None,
            network_devices: Vec::new(),
            block_devices: Vec::new(),
            chosen: ChosenConfig::default(),
            page_granule: 4096,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a DTB blob into HardwareConfig (test-only, mirrors fdt_parse.rs).
    fn parse_fdt_for_test(dtb: &[u8]) -> HardwareConfig {
        let fdt = fdt::Fdt::new(dtb).expect("invalid FDT");
        let mut config = HardwareConfig::default();

        for node in fdt.all_nodes() {
            if node.name.starts_with("memory") {
                if let Some(reg) = node.reg() {
                    for region in reg {
                        config.memory_regions.push(MemoryRegion {
                            base: region.starting_address as u64,
                            size: region.size.unwrap_or(0) as u64,
                        });
                    }
                }
            }
        }

        // In fdt 0.1.x, chosen() returns Chosen directly (panics if missing).
        let chosen = fdt.chosen();
        config.chosen.bootargs = chosen.bootargs().map(|s| s.to_string());

        for node in fdt.all_nodes() {
            if let Some(compat) = node.compatible() {
                for c in compat.all() {
                    match c {
                        "arm,pl011" => {
                            if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                                config.serial = Some(SerialConfig {
                                    base: reg.starting_address as u64,
                                    size: reg.size.unwrap_or(0x1000) as u64,
                                    compatible: c.to_string(),
                                });
                            }
                        }
                        "arm,gic-v3" | "arm,cortex-a15-gic" => {
                            if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                                config.interrupt_controller = Some(InterruptControllerConfig {
                                    base: reg.starting_address as u64,
                                    size: reg.size.unwrap_or(0x10000) as u64,
                                    variant: InterruptControllerVariant::GicV3,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        config
    }

    #[test]
    fn fdt_parse_qemu_virt() {
        let dtb = include_bytes!("../tests/fixtures/qemu-virt.dtb");
        let cfg = parse_fdt_for_test(dtb);
        assert!(!cfg.memory_regions.is_empty(), "should find /memory");
        assert!(cfg.serial.is_some(), "should find PL011 UART");
        assert!(cfg.interrupt_controller.is_some(), "should find GIC");
    }

    #[test]
    fn fdt_serial_compatible_is_pl011() {
        let dtb = include_bytes!("../tests/fixtures/qemu-virt.dtb");
        let cfg = parse_fdt_for_test(dtb);
        assert_eq!(cfg.serial.unwrap().compatible, "arm,pl011");
    }

    #[test]
    fn hardware_config_default() {
        let cfg = HardwareConfig::default();
        assert!(cfg.memory_regions.is_empty());
        assert!(cfg.serial.is_none());
        assert!(cfg.interrupt_controller.is_none());
        assert!(cfg.network_devices.is_empty());
        assert!(cfg.block_devices.is_empty());
        assert!(cfg.chosen.bootargs.is_none());
        assert_eq!(cfg.page_granule, 4096);
    }

    #[test]
    fn memory_region_stores_bytes() {
        let region = MemoryRegion {
            base: 0x4000_0000,
            size: 0x8000_0000,
        };
        assert_eq!(region.base, 0x4000_0000);
        assert_eq!(region.size, 0x8000_0000);
    }

    #[test]
    fn interrupt_controller_variant_matching() {
        let gic = InterruptControllerVariant::GicV3;
        let aic = InterruptControllerVariant::AppleAic;

        assert!(matches!(gic, InterruptControllerVariant::GicV3));
        assert!(matches!(aic, InterruptControllerVariant::AppleAic));
        // Ensure both variants are distinct
        assert!(!matches!(gic, InterruptControllerVariant::AppleAic));
    }
}
