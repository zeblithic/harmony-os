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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterruptControllerVariant {
    /// ARM GICv2 (e.g. GIC-400, `arm,cortex-a15-gic`).
    GicV2,
    /// ARM GICv3 (e.g. GIC-600, `arm,gic-v3`).
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
    /// GICv3 redistributor base address. `None` for GICv2/AIC.
    pub redistributor_base: Option<u64>,
    /// GICv3 redistributor region size in bytes. `None` for GICv2/AIC.
    pub redistributor_size: Option<u64>,
}

// ── VirtIO MMIO device ───────────────────────────────────────────────────────

/// A VirtIO MMIO transport discovered from the device tree.
///
/// `virtio,mmio` is the generic transport compatible — the actual device sub-type
/// (net, blk, rng, gpu, etc.) requires probing the MMIO DeviceID register at
/// runtime. FDT parsing only discovers the transport; callers classify after probe.
#[derive(Debug, Clone)]
pub struct VirtioMmioConfig {
    pub base: u64,
    pub size: u64,
    pub irq: u32,
}

// ── Block device ──────────────────────────────────────────────────────────────

/// MMIO-mapped block device (NVMe, Apple ANS2, etc.).
#[derive(Debug, Clone)]
pub struct BlockDeviceConfig {
    pub base: u64,
    pub size: u64,
    pub irq: u32,
    /// DT `compatible` string (e.g. `"nvme"`, `"apple,ans2"`).
    pub compatible: String,
}

// ── Network device ───────────────────────────────────────────────────────────

/// MMIO-mapped network controller with MAC address from device tree.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub base: u64,
    pub size: u64,
    /// Factory MAC address from the DTB `local-mac-address` property.
    pub mac_address: [u8; 6],
    /// DT `compatible` string (e.g. `"brcm,bcm2711-genet-v5"`).
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
    /// VirtIO MMIO transports — device sub-type determined after MMIO probe.
    pub virtio_devices: Vec<VirtioMmioConfig>,
    pub block_devices: Vec<BlockDeviceConfig>,
    pub network: Option<NetworkConfig>,
    pub chosen: ChosenConfig,
    /// Page granule in bytes (4096 for 4 KiB, 16384 for 16 KiB).
    pub page_granule: usize,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            memory_regions: Vec::new(),
            serial: None,
            interrupt_controller: None,
            virtio_devices: Vec::new(),
            block_devices: Vec::new(),
            network: None,
            chosen: ChosenConfig::default(),
            page_granule: crate::vm::PAGE_SIZE as usize,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a DTB blob into HardwareConfig (test-only, superset of fdt_parse.rs).
    /// Includes GENET parsing for NetworkConfig tests; the boot path reads
    /// the DTB inline (zero-alloc) instead of calling parse_fdt().
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
                        "arm,gic-v3" => {
                            if let Some(mut regs) = node.reg() {
                                if let Some(gicd_reg) = regs.next() {
                                    let gicr_reg = regs.next();
                                    config.interrupt_controller = Some(InterruptControllerConfig {
                                        base: gicd_reg.starting_address as u64,
                                        size: gicd_reg.size.unwrap_or(0x10000) as u64,
                                        variant: InterruptControllerVariant::GicV3,
                                        redistributor_base: gicr_reg
                                            .map(|r| r.starting_address as u64),
                                        redistributor_size: gicr_reg
                                            .map(|r| r.size.unwrap_or(0xF60000) as u64),
                                    });
                                }
                            }
                        }
                        "arm,cortex-a15-gic" | "arm,gic-400" => {
                            if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                                config.interrupt_controller = Some(InterruptControllerConfig {
                                    base: reg.starting_address as u64,
                                    size: reg.size.unwrap_or(0x10000) as u64,
                                    variant: InterruptControllerVariant::GicV2,
                                    redistributor_base: None,
                                    redistributor_size: None,
                                });
                            }
                        }
                        "brcm,bcm2711-genet-v5" => {
                            if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                                if let Some(mac_prop) = node.property("local-mac-address") {
                                    if mac_prop.value.len() >= 6 {
                                        let mut mac = [0u8; 6];
                                        mac.copy_from_slice(&mac_prop.value[..6]);
                                        config.network = Some(NetworkConfig {
                                            base: reg.starting_address as u64,
                                            size: reg.size.unwrap_or(0x10000) as u64,
                                            mac_address: mac,
                                            compatible: c.to_string(),
                                        });
                                    }
                                }
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
        assert!(cfg.virtio_devices.is_empty());
        assert!(cfg.block_devices.is_empty());
        assert!(cfg.chosen.bootargs.is_none());
        assert_eq!(cfg.page_granule, crate::vm::PAGE_SIZE as usize);
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
        let gicv2 = InterruptControllerVariant::GicV2;
        let gicv3 = InterruptControllerVariant::GicV3;
        let aic = InterruptControllerVariant::AppleAic;

        assert_eq!(gicv2, InterruptControllerVariant::GicV2);
        assert_eq!(gicv3, InterruptControllerVariant::GicV3);
        assert_eq!(aic, InterruptControllerVariant::AppleAic);
        assert_ne!(gicv2, gicv3);
        assert_ne!(gicv3, aic);
    }

    #[test]
    fn gicv3_redistributor_fields() {
        let config = InterruptControllerConfig {
            base: 0x0800_0000,
            size: 0x1_0000,
            variant: InterruptControllerVariant::GicV3,
            redistributor_base: Some(0x080A_0000),
            redistributor_size: Some(0xF6_0000),
        };
        assert_eq!(config.redistributor_base, Some(0x080A_0000));
        assert_eq!(config.redistributor_size, Some(0xF6_0000));
    }

    #[test]
    fn gicv2_redistributor_fields_are_none() {
        let config = InterruptControllerConfig {
            base: 0x0800_0000,
            size: 0x1_0000,
            variant: InterruptControllerVariant::GicV2,
            redistributor_base: None,
            redistributor_size: None,
        };
        assert_eq!(config.redistributor_base, None);
    }

    #[test]
    fn network_config_construction() {
        let net = NetworkConfig {
            base: 0x1F_0058_0000,
            size: 0x10000,
            mac_address: [0xDC, 0xA6, 0x32, 0x12, 0x34, 0x56],
            compatible: "brcm,bcm2711-genet-v5".to_string(),
        };
        assert_eq!(net.base, 0x1F_0058_0000);
        assert_eq!(net.size, 0x10000);
        assert_eq!(net.mac_address, [0xDC, 0xA6, 0x32, 0x12, 0x34, 0x56]);
        assert_eq!(net.compatible, "brcm,bcm2711-genet-v5");
    }

    #[test]
    fn hardware_config_default_network_is_none() {
        let cfg = HardwareConfig::default();
        assert!(cfg.network.is_none());
    }

    #[test]
    fn fdt_parse_genet_mac_and_base() {
        let dtb = include_bytes!("../tests/fixtures/rpi5-genet.dtb");
        let cfg = parse_fdt_for_test(dtb);
        let net = cfg.network.expect("should find GENET network config");
        assert_eq!(net.mac_address, [0xDC, 0xA6, 0x32, 0x12, 0x34, 0x56]);
        assert_eq!(net.compatible, "brcm,bcm2711-genet-v5");
        // Base address: 0x1f << 32 | 0x00580000 = 0x1F_0058_0000
        assert_eq!(net.base, 0x1F_0058_0000);
        assert_eq!(net.size, 0x10000);
    }

    #[test]
    fn fdt_parse_genet_missing_mac() {
        let dtb = include_bytes!("../tests/fixtures/rpi5-genet-no-mac.dtb");
        let cfg = parse_fdt_for_test(dtb);
        assert!(
            cfg.network.is_none(),
            "GENET without local-mac-address should not populate network"
        );
    }

    #[test]
    fn fdt_parse_no_genet_node() {
        let dtb = include_bytes!("../tests/fixtures/qemu-virt.dtb");
        let cfg = parse_fdt_for_test(dtb);
        assert!(cfg.network.is_none(), "QEMU virt has no GENET node");
    }
}
