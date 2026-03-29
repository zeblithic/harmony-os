// SPDX-License-Identifier: GPL-2.0-or-later
//! FDT (Flattened Device Tree) parsing → HardwareConfig conversion.
//!
//! Uses the `fdt` 0.1.x crate API (`Fdt::from_ptr`, `all_nodes`, etc.).

use alloc::string::ToString;
use alloc::vec::Vec;

use harmony_microkernel::hardware_config::*;

/// Parse a Flattened Device Tree blob into a `HardwareConfig`.
///
/// # Safety
/// `dtb_ptr` must point to a valid FDT blob.
///
/// # Panics
/// Panics if the blob has an invalid magic value, or if no `/memory` node is
/// found.
pub unsafe fn parse_fdt(dtb_ptr: *const u8) -> HardwareConfig {
    let fdt = fdt::Fdt::from_ptr(dtb_ptr).expect("invalid FDT blob");
    let mut config = HardwareConfig::default();

    // ── Memory regions ────────────────────────────────────────────────────────
    let mut found_memory = false;
    for node in fdt.all_nodes() {
        if node.name.starts_with("memory") {
            if let Some(reg) = node.reg() {
                for region in reg {
                    config.memory_regions.push(MemoryRegion {
                        base: region.starting_address as u64,
                        size: region.size.unwrap_or(0) as u64,
                    });
                    found_memory = true;
                }
            }
        }
    }
    assert!(found_memory, "FDT: no /memory node found — cannot boot");

    // ── /chosen ───────────────────────────────────────────────────────────────
    // In fdt 0.1.x, `chosen()` panics if `/chosen` is absent.
    // Guard with find_node to avoid boot panics on DTBs missing /chosen.
    if fdt.find_node("/chosen").is_some() {
        let chosen = fdt.chosen();
        config.chosen.bootargs = chosen.bootargs().map(|s| s.to_string());
        config.chosen.stdout_path = chosen.stdout().map(|n| n.name.to_string());
    }

    // ── Peripheral nodes ──────────────────────────────────────────────────────
    for node in fdt.all_nodes() {
        let compat_list: Vec<&str> = node
            .compatible()
            .map(|c| c.all().collect())
            .unwrap_or_default();

        for compat in &compat_list {
            match *compat {
                "arm,pl011" | "apple,uart" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.serial = Some(SerialConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x1000) as u64,
                            compatible: compat.to_string(),
                        });
                    }
                }
                "arm,gic-v3" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.interrupt_controller = Some(InterruptControllerConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x10000) as u64,
                            variant: InterruptControllerVariant::GicV3,
                        });
                    }
                }
                "arm,cortex-a15-gic" | "arm,gic-400" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.interrupt_controller = Some(InterruptControllerConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x10000) as u64,
                            variant: InterruptControllerVariant::GicV2,
                        });
                    }
                }
                "apple,aic" | "apple,aic2" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.interrupt_controller = Some(InterruptControllerConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0xC000) as u64,
                            variant: InterruptControllerVariant::AppleAic,
                        });
                    }
                }
                "virtio,mmio" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.virtio_devices.push(VirtioMmioConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x200) as u64,
                            irq: first_irq(&node),
                        });
                    }
                }
                "nvme" | "apple,ans2" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.block_devices.push(BlockDeviceConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x40000) as u64,
                            irq: first_irq(&node),
                            compatible: compat.to_string(),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    config
}

/// Extract the IRQ number from a GIC 3-cell `interrupts` property.
/// Format: `<type irq_number flags>`, each cell is 4 bytes (big-endian).
/// Cell 0 (bytes [0..4]) = type (0=SPI, 1=PPI). Cell 1 (bytes [4..8]) = IRQ number.
///
/// **Limitation:** This assumes GIC encoding. Apple AIC uses a different cell
/// layout — AIC IRQ parsing is deferred to Phase B (harmony-os-1hc).
fn first_irq(node: &fdt::node::FdtNode) -> u32 {
    node.property("interrupts")
        .and_then(|p| {
            let bytes = p.value;
            // GIC 3-cell format: need at least 8 bytes for type + irq_number.
            if bytes.len() >= 8 {
                Some(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
            } else {
                None
            }
        })
        .unwrap_or(0)
}
