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
    // In fdt 0.1.x, `chosen()` returns `Chosen` directly and panics if the
    // node is missing.  QEMU virt and most real platforms always include it.
    let chosen = fdt.chosen();
    config.chosen.bootargs = chosen.bootargs().map(|s| s.to_string());
    config.chosen.stdout_path = chosen.stdout().map(|n| n.name.to_string());

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
                "arm,gic-v3" | "arm,cortex-a15-gic" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.interrupt_controller = Some(InterruptControllerConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x10000) as u64,
                            variant: InterruptControllerVariant::GicV3,
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
                        config.network_devices.push(NetworkDeviceConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x200) as u64,
                            irq: first_irq(&node),
                            compatible: compat.to_string(),
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

fn first_irq(node: &fdt::node::FdtNode) -> u32 {
    node.property("interrupts")
        .and_then(|p| {
            let bytes = p.value;
            if bytes.len() >= 4 {
                Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else {
                None
            }
        })
        .unwrap_or(0)
}
