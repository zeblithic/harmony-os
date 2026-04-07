# RPi5 Real MAC Address Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read the real factory MAC address and GENET base address from the RPi5 device tree instead of using hardcoded constants.

**Architecture:** Extend the existing FDT→HardwareConfig pipeline with a `NetworkConfig` struct. Parse the GENET node's `local-mac-address` and `reg` properties from the DTB. Wire up DTB access in the UEFI boot path, falling back to hardcoded platform constants when no DTB/GENET node is present.

**Tech Stack:** Rust, `fdt` 0.1 crate, `uefi` 0.36 crate, `dtc` (device tree compiler for test fixtures)

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/harmony-microkernel/src/hardware_config.rs` | Modify | Add `NetworkConfig` struct + field on `HardwareConfig` + update `Default` + tests |
| `crates/harmony-boot-aarch64/src/fdt_parse.rs` | Modify | Add `"brcm,bcm2711-genet-v5"` match arm to parse `reg` + `local-mac-address` |
| `crates/harmony-boot-aarch64/src/main.rs` | Modify | Get DTB pointer from UEFI config table, call `parse_fdt()`, use result for GENET init |
| `crates/harmony-microkernel/tests/fixtures/rpi5-genet.dts` | Create | DTS source for test fixture (GENET node with MAC) |
| `crates/harmony-microkernel/tests/fixtures/rpi5-genet.dtb` | Create | Compiled DTB fixture |
| `crates/harmony-microkernel/tests/fixtures/rpi5-genet-no-mac.dts` | Create | DTS source for test fixture (GENET node without MAC) |
| `crates/harmony-microkernel/tests/fixtures/rpi5-genet-no-mac.dtb` | Create | Compiled DTB fixture |

---

### Task 1: NetworkConfig + FDT Parsing + Tests

**Files:**
- Modify: `crates/harmony-microkernel/src/hardware_config.rs`
- Modify: `crates/harmony-boot-aarch64/src/fdt_parse.rs`
- Create: `crates/harmony-microkernel/tests/fixtures/rpi5-genet.dts`
- Create: `crates/harmony-microkernel/tests/fixtures/rpi5-genet.dtb`
- Create: `crates/harmony-microkernel/tests/fixtures/rpi5-genet-no-mac.dts`
- Create: `crates/harmony-microkernel/tests/fixtures/rpi5-genet-no-mac.dtb`

**Context:** The `hardware_config.rs` file defines `HardwareConfig` and peripheral config structs (`SerialConfig`, `BlockDeviceConfig`, etc.). It also has a `parse_fdt_for_test()` function that mirrors the real `fdt_parse.rs` logic but uses `Fdt::new(dtb)` instead of `Fdt::from_ptr(dtb_ptr)` for safe testing. The existing test DTB fixture is at `crates/harmony-microkernel/tests/fixtures/qemu-virt.dtb`. The `fdt_parse.rs` file in `harmony-boot-aarch64` is the real parser used at boot.

- [ ] **Step 1: Create the GENET DTB test fixtures**

Create the DTS source for a minimal RPi5-like DTB with a GENET node including `local-mac-address`:

File: `crates/harmony-microkernel/tests/fixtures/rpi5-genet.dts`
```dts
/dts-v1/;

/ {
	#address-cells = <2>;
	#size-cells = <2>;
	compatible = "test,rpi5-genet";

	memory@40000000 {
		device_type = "memory";
		reg = <0x00 0x40000000 0x00 0x8000000>;
	};

	chosen {
	};

	ethernet@1f00580000 {
		compatible = "brcm,bcm2711-genet-v5";
		reg = <0x1f 0x00580000 0x00 0x10000>;
		local-mac-address = [dc a6 32 12 34 56];
	};
};
```

Create the DTS source for a GENET node *without* `local-mac-address`:

File: `crates/harmony-microkernel/tests/fixtures/rpi5-genet-no-mac.dts`
```dts
/dts-v1/;

/ {
	#address-cells = <2>;
	#size-cells = <2>;
	compatible = "test,rpi5-genet-no-mac";

	memory@40000000 {
		device_type = "memory";
		reg = <0x00 0x40000000 0x00 0x8000000>;
	};

	chosen {
	};

	ethernet@1f00580000 {
		compatible = "brcm,bcm2711-genet-v5";
		reg = <0x1f 0x00580000 0x00 0x10000>;
	};
};
```

Compile both:
```bash
dtc -I dts -O dtb -o crates/harmony-microkernel/tests/fixtures/rpi5-genet.dtb \
    crates/harmony-microkernel/tests/fixtures/rpi5-genet.dts
dtc -I dts -O dtb -o crates/harmony-microkernel/tests/fixtures/rpi5-genet-no-mac.dtb \
    crates/harmony-microkernel/tests/fixtures/rpi5-genet-no-mac.dts
```

Verify both compile without errors.

- [ ] **Step 2: Write the failing tests**

Add the following to the `#[cfg(test)] mod tests` block in `crates/harmony-microkernel/src/hardware_config.rs`, after the existing tests:

```rust
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
        assert!(cfg.network.is_none(), "GENET without local-mac-address should not populate network");
    }

    #[test]
    fn fdt_parse_no_genet_node() {
        let dtb = include_bytes!("../tests/fixtures/qemu-virt.dtb");
        let cfg = parse_fdt_for_test(dtb);
        assert!(cfg.network.is_none(), "QEMU virt has no GENET node");
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel network_config_construction fdt_parse_genet hardware_config_default_network`

Expected: compilation error — `NetworkConfig` type does not exist, `HardwareConfig` has no `network` field.

- [ ] **Step 4: Add NetworkConfig struct and HardwareConfig field**

In `crates/harmony-microkernel/src/hardware_config.rs`:

Add after the `BlockDeviceConfig` struct (after line 82):

```rust
// ── Network device ───────────────────────────────────────────────────────

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
```

Add the `network` field to `HardwareConfig` (after `block_devices`):

```rust
    pub network: Option<NetworkConfig>,
```

Add to `Default` impl (after `block_devices: Vec::new(),`):

```rust
            network: None,
```

- [ ] **Step 5: Add GENET parsing to the test-only parser**

In the `parse_fdt_for_test()` function in `hardware_config.rs`, add a match arm inside the `for c in compat.all()` block, after the GIC arms (after the `"arm,cortex-a15-gic" | "arm,gic-400"` arm):

```rust
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
```

- [ ] **Step 6: Add GENET parsing to the real fdt_parse.rs**

In `crates/harmony-boot-aarch64/src/fdt_parse.rs`, add the same match arm in the `for compat in &compat_list` block, before the `_ => {}` catch-all:

```rust
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
                                    compatible: compat.to_string(),
                                });
                            }
                        }
                    }
                }
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel`

Expected: all tests pass, including the 5 new ones. Zero clippy warnings.

- [ ] **Step 8: Run clippy**

Run: `cargo clippy --workspace`

Expected: no new warnings.

- [ ] **Step 9: Commit**

```bash
git add crates/harmony-microkernel/src/hardware_config.rs \
       crates/harmony-microkernel/tests/fixtures/rpi5-genet.dts \
       crates/harmony-microkernel/tests/fixtures/rpi5-genet.dtb \
       crates/harmony-microkernel/tests/fixtures/rpi5-genet-no-mac.dts \
       crates/harmony-microkernel/tests/fixtures/rpi5-genet-no-mac.dtb \
       crates/harmony-boot-aarch64/src/fdt_parse.rs
git commit -m "feat: add NetworkConfig and GENET FDT parsing for RPi5 MAC address"
```

---

### Task 2: Boot Path Integration

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/main.rs`

**Context:** The UEFI boot entry point is `fn main() -> Status` in `crates/harmony-boot-aarch64/src/main.rs` (line 184). It performs PE section parsing before `exit_boot_services()` (line 235), then initializes PL011 serial (line 254), then initializes GENET at line 884 (inside `#[cfg(feature = "rpi5")]` block). The GENET init currently uses `platform::GENET_BASE` (line 890) and `platform::NODE_MAC` (line 891). The `fdt_parse` module is declared (`mod fdt_parse;` at line 10) but `parse_fdt()` is never called. The `uefi` 0.36 crate provides `uefi::system::with_config_table()` to access UEFI configuration tables, but does not define the DTB GUID — it must be defined manually. `with_config_table` reads the raw system table pointer and works both before and after ExitBootServices.

- [ ] **Step 1: Get DTB pointer from UEFI configuration table**

In `crates/harmony-boot-aarch64/src/main.rs`, add the DTB pointer lookup after the PE section parsing block (after the closing `};` at line 231) and before the `exit_boot_services` call (line 235):

```rust
    // ── Find DTB in UEFI configuration table ──
    // RPi5 UEFI (EDK2) exposes the device tree here. The DTB blob
    // remains in memory after ExitBootServices; we just save the pointer.
    let dtb_ptr: Option<*const u8> = {
        use uefi::table::cfg::ConfigTableEntry;
        // EFI_DTB_TABLE_GUID per UEFI spec 2.10, Table 4-6.
        // Not defined in the uefi crate as of 0.36.
        const DTB_GUID: uefi::Guid = uefi::guid!("b1b621d5-f19c-41a5-830b-d9152c69aae0");
        uefi::system::with_config_table(|entries: &[ConfigTableEntry]| {
            entries
                .iter()
                .find(|e| e.guid == DTB_GUID)
                .map(|e| e.address as *const u8)
        })
    };
```

- [ ] **Step 2: Parse FDT after serial init**

After the PL011 serial initialization (after `let _ = writeln!(serial, "[PL011] Serial initialized: 115200 8N1");` around line 258), add:

```rust
    // ── Parse device tree (if present) ──
    let hw_config = dtb_ptr.map(|ptr| {
        let _ = writeln!(serial, "[FDT] Parsing device tree at {:p}", ptr);
        unsafe { fdt_parse::parse_fdt(ptr) }
    });
    if hw_config.is_none() {
        let _ = writeln!(serial, "[FDT] No device tree found, using platform defaults");
    }
```

- [ ] **Step 3: Use HardwareConfig for GENET init**

In the `#[cfg(feature = "rpi5")]` GENET initialization block (starting at line 886), replace lines 890-902:

```rust
        let mut bank = unsafe { mmio::MmioRegisterBank::new(platform::GENET_BASE) };
        let mac = platform::NODE_MAC;
        let _ = writeln!(
            serial,
            "[GENET] Initializing at {:#x}, MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            platform::GENET_BASE,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
        );
```

With:

```rust
        let (mac, genet_base) = match hw_config.as_ref().and_then(|c| c.network.as_ref()) {
            Some(net) => (net.mac_address, net.base as usize),
            None => (platform::NODE_MAC, platform::GENET_BASE),
        };
        let mut bank = unsafe { mmio::MmioRegisterBank::new(genet_base) };
        let _ = writeln!(
            serial,
            "[GENET] Initializing at {:#x}, MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            genet_base,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
        );
```

- [ ] **Step 4: Build and verify**

Run: `cargo clippy --workspace`

Expected: no warnings. The `#[cfg(feature = "rpi5")]` block compiles only for RPi5 builds, but clippy should still check it.

Also run: `cargo test --workspace`

Expected: all existing + new tests pass. The boot path changes are `#[cfg(target_os = "uefi")]` gated so they don't affect test builds.

- [ ] **Step 5: Run nightly rustfmt**

Run: `cargo +nightly fmt --all`

Expected: clean formatting.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat: read MAC and GENET base from DTB at boot, fall back to platform defaults"
```
