# RPi5: RP1 PCIe BAR → GENET Ethernet Integration

**Bead:** harmony-os-7ng
**Date:** 2026-03-23
**Status:** Draft

## Problem

The GENET Ethernet driver, DMA pool, and event loop are all implemented, but
GENET registers at `0x1F_0058_0000` are inaccessible because the MMU doesn't
map that MMIO region. The RPi5's UEFI firmware already initializes PCIe and
assigns BARs (preserved via `pciex4_reset=0` in config.txt), so no PCIe
enumeration is needed — we just need to map the address and wire the driver.

## Solution

Add a platform-provided MMIO region list so the MMU maps all device memory
pages at boot. Create an `MmioRegisterBank` for GENET, initialize the driver
with DMA pools, and wire it into the event loop's existing TODO slots for
RX polling and TX dispatch.

## Design Decisions

### No PCIe driver needed — UEFI already did it

RPi5 UEFI (EDK2) performs full PCIe enumeration and BAR assignment before
`ExitBootServices()`. With `pciex4_reset=0` in config.txt (already set in
our build script), the BAR mappings are preserved. We access GENET registers
directly at the pre-configured address `0x1F_0058_0000`.

### Platform MMIO region list instead of hardcoded mappings

Currently only PL011 is mapped as Device memory. Rather than adding GENET
as another hardcoded mapping, `platform.rs` exports a `const` array of
MMIO regions. `mmu::init_and_enable()` maps all of them. This scales to
GPIO, SDHCI, and other future drivers without MMU code changes.

### Hardcoded test MAC address

Use `[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]` (locally administered unicast).
Reading the real MAC from OTP/firmware is separate work. The `0x02` prefix
indicates locally administered, avoiding conflicts on the LAN.

### GENET init gated on `#[cfg(feature = "rpi5")]`

GENET only exists on RPi5. QEMU-virt builds skip GENET initialization
entirely. The event loop structure is the same — the GENET RX/TX code is
inside `#[cfg(feature = "rpi5")]` blocks.

## Architecture

### Platform MMIO Regions

```rust
// crates/harmony-boot-aarch64/src/platform.rs

/// MMIO regions to map as Device memory (NO_CACHE) during MMU init.
/// Each entry: (base_address, page_count).
pub const MMIO_REGIONS: &[(usize, usize)] = &[
    (PL011_BASE, 1),         // UART
    #[cfg(feature = "rpi5")]
    (GENET_BASE, 16),        // GENET register blocks (SYS through TDMA + descriptors)
];
```

QEMU-virt gets PL011 only. RPi5 gets PL011 + GENET.

### MMU Changes

Replace the hardcoded PL011 MMIO mapping in `mmu::init_and_enable()` with
a loop over `platform::MMIO_REGIONS`:

```rust
for &(base, pages) in platform::MMIO_REGIONS {
    for i in 0..pages {
        let addr = base as u64 + i as u64 * PAGE_SIZE;
        let _ = pt.map(VirtAddr(addr), PhysAddr(addr), mmio_flags, &mut alloc);
    }
}
```

### GENET Initialization (RPi5 only)

After heap setup and runtime creation, inside `#[cfg(feature = "rpi5")]`:

```rust
let mut genet_bank = unsafe { MmioRegisterBank::new(platform::GENET_BASE) };
let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]; // locally administered
let mut genet = GenetDriver::<256, 256>::init(&mut genet_bank, mac, 1000)?;

// Allocate DMA pools from bump allocator (identity-mapped: phys == virt)
let mut tx_pool = DmaPool::new(tx_buffers, 2048);
let mut rx_pool = DmaPool::new(rx_buffers, 2048);

genet.arm_rx_descriptors(&mut genet_bank, &mut rx_pool)?;
```

### Event Loop Wiring (RPi5 only)

Replace the TODO comments in the event loop:

**RX polling:**
```rust
#[cfg(feature = "rpi5")]
while let Some(frame) = genet.poll_rx(&mut genet_bank, &mut rx_pool) {
    unsafe { cache::invalidate_range(/* buffer virt */, frame.data.len()) };
    if frame.data.len() >= 14 {
        let ethertype = u16::from_be_bytes([frame.data[12], frame.data[13]]);
        if ethertype == 0x88B5 {
            let payload = frame.data[14..].to_vec();
            let rx_actions = runtime.handle_packet("eth0", payload, now);
            for action in &rx_actions { dispatch_action(action, &mut serial); }
        }
    }
}
```

**TX dispatch:**
```rust
RuntimeAction::SendOnInterface { interface_name, raw } => {
    #[cfg(feature = "rpi5")]
    {
        // Wrap in Ethernet frame: dst_broadcast + src_mac + ethertype 0x88B5 + payload
        let mut frame = Vec::with_capacity(14 + raw.len());
        frame.extend_from_slice(&[0xFF; 6]); // broadcast dst
        frame.extend_from_slice(&mac);        // src
        frame.extend_from_slice(&0x88B5u16.to_be_bytes()); // Harmony ethertype
        frame.extend_from_slice(raw);
        unsafe { cache::clean_range(/* buffer virt after copy */, frame.len()) };
        genet.reclaim_tx(&genet_bank, &mut tx_pool);
        let _ = genet.send(&mut genet_bank, &frame, &mut tx_pool);
    }
    let _ = writeln!(serial, "[TX] {} bytes on {}", raw.len(), interface_name);
}
```

**Periodic reclaim (before tick):**
```rust
#[cfg(feature = "rpi5")]
genet.reclaim_tx(&genet_bank, &mut tx_pool);
```

### DMA Pool Construction

Allocate 256 pages for TX pool and 256 pages for RX pool from the bump
allocator. Each page is 4 KiB, providing one 2048-byte DMA buffer per page.

```rust
let mut tx_buffers = [DmaBuffer { virt: core::ptr::null_mut(), phys: 0 }; 256];
for buf in tx_buffers.iter_mut() {
    let frame = alloc.alloc_frame().expect("TX DMA buffer allocation failed");
    *buf = DmaBuffer { virt: frame.as_u64() as *mut u8, phys: frame.as_u64() };
}
```

## File Changes

| File | Change |
|------|--------|
| `crates/harmony-boot-aarch64/src/platform.rs` | Add `MMIO_REGIONS` const array |
| `crates/harmony-boot-aarch64/src/mmu.rs` | Replace hardcoded PL011 mapping with MMIO_REGIONS loop |
| `crates/harmony-boot-aarch64/src/main.rs` | GENET init + DMA pool allocation + event loop wiring (rpi5 feature-gated) |

## What is NOT in Scope

- No PCIe controller driver (UEFI handles it)
- No PCIe enumeration or BAR assignment
- No real MAC address from OTP/firmware (hardcoded test MAC)
- No IP/ARP stack (raw Harmony frames via EtherType 0x88B5 only)
- No GENET interrupt handling (polling only)
- No link status monitoring in the event loop (future work)

## Testing

- QEMU boot test continues to pass (GENET is rpi5-only, QEMU has no GENET)
- `platform_mmio_regions` — verify region list is non-empty for each platform
- Existing GENET + DmaPool unit tests cover driver logic
- Real hardware: flash SD card, observe on serial:
  - `[GENET] Initialized, MAC=02:00:00:00:00:01`
  - `[GENET] RX armed: 256 descriptors`
  - `[TX] N bytes on eth0` (now actually sent via GENET)
  - Network peer discovery if another Harmony node is on the LAN
