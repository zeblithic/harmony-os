# RPi5 Real MAC Address from DTB

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-429

**Goal:** Read the real factory MAC address and GENET base address from the RPi5 device tree instead of using hardcoded constants, enabling multi-RPi5 deployments without MAC collisions.

**Prerequisite:** None (GENET driver already merged).

---

## Architecture

No new files. Two existing files modified, plus boot path plumbing.

The RPi5 UEFI firmware (EDK2) reads the factory MAC from BCM2712 OTP fuses and injects it into the Flattened Device Tree as a `local-mac-address` property on the GENET ethernet node. The FDT parsing infrastructure already exists (`fdt_parse.rs` → `HardwareConfig`). This feature extends that pipeline to extract network device configuration.

**Data flow:**

```
DTB blob (from UEFI)
  → fdt_parse.rs: match "brcm,bcm2711-genet-v5", extract reg + local-mac-address
  → HardwareConfig.network: Option<NetworkConfig>
  → main.rs: use NetworkConfig values, fall back to platform:: constants if absent
  → GenetDriver::init(mac, ...)
```

### What changes

- **`hardware_config.rs`** — Add `NetworkConfig` struct (base, size, mac_address, compatible) and `network: Option<NetworkConfig>` field on `HardwareConfig`. Follows the existing `SerialConfig` / `BlockDeviceConfig` pattern.

- **`fdt_parse.rs`** — Match `"brcm,bcm2711-genet-v5"` compatible string, extract `reg` property (base + size) and `local-mac-address` property (6-byte MAC). Populate `config.network`.

- **`main.rs`** (boot path) — Replace `platform::NODE_MAC` and `platform::GENET_BASE` usage with values from `HardwareConfig.network`, falling back to the platform constants when the DTB has no GENET node (e.g., QEMU virt).

### What stays the same

- `platform.rs` — `NODE_MAC` and `GENET_BASE` constants kept as fallback defaults
- `GenetDriver` (Ring 1) — unchanged, still takes `mac: [u8; 6]` parameter
- `GenetServer` (Ring 2) — unchanged
- `hv_server.rs` — VM MAC stays hardcoded (VMs need unique MACs, not the host's)
- All existing tests — unchanged
- QEMU virt platform — no GENET node in its DTB, falls back to constants

---

## NetworkConfig

```rust
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub base: u64,
    pub size: u64,
    pub mac_address: [u8; 6],
    pub compatible: String,
}
```

Follows the same pattern as `SerialConfig` and `BlockDeviceConfig`. The `mac_address` field stores the 6-byte MAC from the DTB's `local-mac-address` property.

Added to `HardwareConfig`:

```rust
pub struct HardwareConfig {
    // ... existing fields ...
    pub network: Option<NetworkConfig>,
}
```

Default: `None` (no network device in DTB).

---

## FDT Parsing

In the peripheral node loop in `fdt_parse.rs`, add a match arm:

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

Key behaviors:
- Only populates `network` if BOTH `reg` and `local-mac-address` are present with valid length
- `local-mac-address` must be at least 6 bytes (standard DTB property format)
- If `local-mac-address` is missing or short, the GENET node is skipped entirely — caller falls back to platform constants

---

## Boot Path Integration

In `main.rs`, the GENET init block changes from:

```rust
let mac = platform::NODE_MAC;
let mut bank = unsafe { mmio::MmioRegisterBank::new(platform::GENET_BASE) };
```

To:

```rust
let (mac, genet_base) = match config.network {
    Some(ref net) => (net.mac_address, net.base as usize),
    None => (platform::NODE_MAC, platform::GENET_BASE),
};
let mut bank = unsafe { mmio::MmioRegisterBank::new(genet_base) };
```

Silent fallback. The existing boot log that prints the MAC during GENET init makes the active MAC visible without additional logging.

---

## Testing

All tests use the existing `fdt` crate and DTB fixture patterns. No hardware needed.

### HardwareConfig tests (in `hardware_config.rs`)

1. **network_config_construction** — Create a `NetworkConfig`, verify all fields
2. **hardware_config_default_network_is_none** — `HardwareConfig::default().network` is `None`

### FDT parsing tests (in `hardware_config.rs` using test DTB fixtures)

3. **fdt_parse_genet_mac_and_base** — DTB with `brcm,bcm2711-genet-v5` node including `local-mac-address` and `reg` → `config.network` is `Some` with correct MAC and base
4. **fdt_parse_genet_missing_mac** — DTB with GENET node but no `local-mac-address` property → `config.network` is `None`
5. **fdt_parse_no_genet_node** — DTB without any GENET node (existing QEMU fixture) → `config.network` is `None`

### DTB Test Fixture

A minimal DTB binary containing a GENET-compatible node with `local-mac-address` property. Built offline (e.g., from a `.dts` source compiled with `dtc`) and checked in as `tests/fixtures/rpi5-genet.dtb`. This is the same approach used for the existing `qemu-virt.dtb` fixture.

---

## Scope Boundary

**In scope:**
- `NetworkConfig` struct in `hardware_config.rs`
- `network: Option<NetworkConfig>` field on `HardwareConfig`
- FDT parsing of `brcm,bcm2711-genet-v5` node (`reg` + `local-mac-address`)
- `main.rs` boot path uses `HardwareConfig.network` with fallback to `platform::` constants
- DTB test fixture with GENET node
- 5 tests listed above

**Out of scope:**
- VideoCore mailbox interface
- VM MAC derivation in `hv_server.rs`
- Removing `platform::NODE_MAC` / `platform::GENET_BASE` (kept as fallbacks)
- Dynamic GENET IRQ from DTB (currently not used — GENET is polled)
- Other network device types (VirtIO-net, CDC-ECM)
- `qemu-virt` platform changes (no GENET on QEMU)
- MMIO_REGIONS update (GENET_BASE already in the static list; dynamic MMIO mapping is a larger change)
