# RP1 PCIe BAR → GENET Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Map GENET MMIO via UEFI-configured PCIe BAR, initialize the Ethernet driver with DMA pools, and wire frame TX/RX into the event loop for real RPi5 networking.

**Architecture:** Platform MMIO region list replaces hardcoded PL011 mapping in MMU. GENET init + DMA pool allocation after heap setup. Event loop TODO slots filled with actual GENET RX polling and TX dispatch. All GENET code is `#[cfg(feature = "rpi5")]`.

**Tech Stack:** Rust (no_std, aarch64-unknown-uefi), harmony-unikernel (GenetDriver, DmaPool, RegisterBank)

**Spec:** `docs/superpowers/specs/2026-03-23-pcie-rp1-genet-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `crates/harmony-boot-aarch64/src/platform.rs` | Add `MMIO_REGIONS` const array, remove `#[allow(dead_code)]` from `GENET_BASE` |
| `crates/harmony-boot-aarch64/src/mmu.rs` | Replace hardcoded PL011 mapping with MMIO_REGIONS loop |
| `crates/harmony-boot-aarch64/src/main.rs` | GENET init, DMA pool allocation, event loop wiring (rpi5 feature-gated) |

---

### Task 1: Platform MMIO region list + MMU refactor

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/platform.rs`
- Modify: `crates/harmony-boot-aarch64/src/mmu.rs`

- [ ] **Step 1: Add MMIO_REGIONS to platform.rs**

In `crates/harmony-boot-aarch64/src/platform.rs`, after `GENET_BASE` (line 42), add:

```rust
/// MMIO regions to map as Device memory (NO_CACHE) during MMU init.
/// Each entry: (base_address, page_count).
#[cfg(feature = "qemu-virt")]
pub const MMIO_REGIONS: &[(usize, usize)] = &[
    (PL011_BASE, 1),
];

#[cfg(feature = "rpi5")]
pub const MMIO_REGIONS: &[(usize, usize)] = &[
    (PL011_BASE, 1),
    (GENET_BASE, 16), // SYS through TDMA + descriptor RAM (~64KB)
];
```

Also remove `#[allow(dead_code)]` from `GENET_BASE` since it's now used.

Update the comment above GENET_BASE: remove "Not usable without PCIe initialization" — it IS usable now (UEFI did PCIe init, preserved via `pciex4_reset=0`).

- [ ] **Step 2: Replace hardcoded PL011 mapping in mmu.rs**

In `crates/harmony-boot-aarch64/src/mmu.rs`, find the hardcoded PL011 MMIO mapping (around line 167):

```rust
const PL011_MMIO_BASE: u64 = 0x0900_0000;
// ... later ...
let mmio_flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::NO_CACHE;
let mmio_result = pt.map(
    VirtAddr(PL011_MMIO_BASE),
    PhysAddr(PL011_MMIO_BASE),
    mmio_flags,
    &mut || alloc_zeroed_frame(alloc),
);
```

Replace with a loop over platform MMIO regions. Remove the `PL011_MMIO_BASE` constant. Add `use crate::platform;` if not already imported.

```rust
    // 4. Map platform MMIO regions as Device memory (NO_CACHE).
    let mmio_flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::NO_CACHE;
    for &(base, pages) in platform::MMIO_REGIONS {
        for page_idx in 0..pages {
            let addr = base as u64 + page_idx as u64 * PAGE_SIZE;
            let mmio_result = pt.map(
                VirtAddr(addr),
                PhysAddr(addr),
                mmio_flags,
                &mut || alloc_zeroed_frame(alloc),
            );
            match mmio_result {
                Ok(()) => mapped_pages += 1,
                Err(VmError::RegionConflict(_)) => {}
                Err(e) => {
                    let _ = writeln!(serial, "[MMU] MMIO map error at {:#x}: {:?}", addr, e);
                }
            }
        }
    }
```

Remove the old PL011-specific mapping code and the UART conflict warning (the generic loop handles it).

- [ ] **Step 3: Run tests**

Run: `cargo test --workspace`
Expected: all tests pass. QEMU boot test still works (PL011 mapping now comes from MMIO_REGIONS instead of hardcoded constant — same address, different source).

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot-aarch64/src/platform.rs crates/harmony-boot-aarch64/src/mmu.rs
git commit -m "feat(boot): platform MMIO region list, map GENET pages on RPi5

Replace hardcoded PL011 MMIO mapping with platform::MMIO_REGIONS loop.
RPi5 maps PL011 + GENET (16 pages). QEMU maps PL011 only.
UEFI preserves PCIe BAR via pciex4_reset=0.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: GENET initialization + DMA pools

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/main.rs`

- [ ] **Step 1: Add GENET initialization after runtime creation (rpi5 only)**

In `crates/harmony-boot-aarch64/src/main.rs`, after the announcing destination registration (search for `register_announcing_destination`), add GENET init inside a `#[cfg(feature = "rpi5")]` block.

**Important:** The `bump` allocator is still available at this point (used earlier for MMU page tables). Use it to allocate DMA buffer pages.

```rust
    // ── GENET Ethernet initialization (RPi5 only) ──
    #[cfg(feature = "rpi5")]
    let (mut genet_driver, mut genet_bank, mut tx_pool, mut rx_pool) = {
        use harmony_unikernel::drivers::dma_pool::{DmaBuffer, DmaPool};
        use harmony_unikernel::drivers::genet::GenetDriver;

        let mut bank = unsafe { mmio::MmioRegisterBank::new(platform::GENET_BASE) };
        let mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let _ = writeln!(
            serial,
            "[GENET] Initializing at {:#x}, MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            platform::GENET_BASE, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        );

        let driver = match GenetDriver::<256, 256>::init(&mut bank, mac, 1000) {
            Ok(d) => {
                let _ = writeln!(serial, "[GENET] Driver initialized");
                d
            }
            Err(e) => {
                let _ = writeln!(serial, "[GENET] FATAL: init failed: {:?}", e);
                panic!("GENET init failed");
            }
        };

        // Allocate DMA buffer pools from bump allocator.
        // Each page = 4 KiB, one 2048-byte DMA buffer per page.
        let mut tx_bufs = [DmaBuffer { virt: core::ptr::null_mut(), phys: 0 }; 256];
        for buf in tx_bufs.iter_mut() {
            let frame = bump.alloc_frame().expect("TX DMA buffer alloc failed");
            *buf = DmaBuffer { virt: frame.as_u64() as *mut u8, phys: frame.as_u64() };
        }
        let tx_pool = DmaPool::new(tx_bufs, 2048);

        let mut rx_bufs = [DmaBuffer { virt: core::ptr::null_mut(), phys: 0 }; 256];
        for buf in rx_bufs.iter_mut() {
            let frame = bump.alloc_frame().expect("RX DMA buffer alloc failed");
            *buf = DmaBuffer { virt: frame.as_u64() as *mut u8, phys: frame.as_u64() };
        }
        let mut rx_pool = DmaPool::new(rx_bufs, 2048);

        (driver, bank, tx_pool, rx_pool)
    };

    // Arm RX descriptors with DMA buffer addresses.
    #[cfg(feature = "rpi5")]
    {
        if let Err(e) = genet_driver.arm_rx_descriptors(&mut genet_bank, &mut rx_pool) {
            let _ = writeln!(serial, "[GENET] FATAL: arm RX failed: {:?}", e);
            panic!("GENET arm_rx_descriptors failed");
        }
        let _ = writeln!(serial, "[GENET] RX armed: 256 descriptors");
    }
```

**Note:** `bump` is a `BumpAllocator` with `alloc_frame() -> Option<PhysAddr>`. Since we're identity-mapped, `phys == virt`. The `alloc_frame()` returns `PhysAddr` — use `.as_u64()` to get the raw address. Check the actual type; the bump allocator might return `Option<PhysAddr>` where `PhysAddr` has `.as_u64()`, or it might return a raw u64. Read the code and adapt.

- [ ] **Step 2: Run tests**

Run: `cargo test --workspace`
Expected: all tests pass. GENET init code is `#[cfg(feature = "rpi5")]` — QEMU builds skip it entirely.

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(boot): GENET init + DMA pool allocation on RPi5

Initialize GenetDriver at GENET_BASE with hardcoded test MAC.
Allocate 256 TX + 256 RX DMA buffers from bump allocator.
Arm all RX descriptors. Feature-gated to rpi5.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire GENET into event loop

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/main.rs`

- [ ] **Step 1: Replace RX TODO with actual GENET polling**

Find the `TODO(harmony-os-7ng)` for RX polling in the event loop (around line 627). Replace the entire comment block with:

```rust
        // ── Network RX (RPi5 GENET) ──
        #[cfg(feature = "rpi5")]
        {
            while let Some(frame) = genet_driver.poll_rx(&mut genet_bank, &mut rx_pool) {
                // Cache invalidate: ensure CPU sees DMA-written data.
                // In identity map, buf.virt == phys; we need the virt addr of the
                // buffer that was just consumed. Since poll_rx already copied the data
                // into frame.data (a Vec), the DMA buffer is freed. Cache invalidation
                // should happen inside the MMIO integration layer before the copy.
                // For now, frame.data is already a CPU-side copy.

                if frame.data.len() >= 14 {
                    let ethertype =
                        u16::from_be_bytes([frame.data[12], frame.data[13]]);
                    if ethertype == 0x88B5 {
                        // Raw Harmony frame — strip Ethernet header
                        let payload = frame.data[14..].to_vec();
                        let rx_actions =
                            runtime.handle_packet("eth0", payload, now);
                        for action in &rx_actions {
                            dispatch_action(action, &mut serial);
                        }
                    }
                    // Other EtherTypes (IP, ARP) dropped for now — no netstack.
                }
            }
        }
```

- [ ] **Step 2: Replace TX TODO with actual GENET send**

Find the `RuntimeAction::SendOnInterface` match arm (around line 654). Replace the TODO with actual TX:

```rust
        RuntimeAction::SendOnInterface {
            interface_name,
            raw,
        } => {
            #[cfg(feature = "rpi5")]
            {
                // Wrap payload in Ethernet frame: broadcast dst + src MAC + EtherType 0x88B5
                let mac = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x01];
                let mut frame = alloc::vec::Vec::with_capacity(14 + raw.len());
                frame.extend_from_slice(&[0xFF; 6]); // broadcast destination
                frame.extend_from_slice(&mac);
                frame.extend_from_slice(&0x88B5u16.to_be_bytes());
                frame.extend_from_slice(raw);

                genet_driver.reclaim_tx(&genet_bank, &mut tx_pool);
                match genet_driver.send(&mut genet_bank, &frame, &mut tx_pool) {
                    Ok(()) => {}
                    Err(e) => {
                        let _ = writeln!(serial, "[TX] send error: {:?}", e);
                    }
                }
            }
            let _ = writeln!(serial, "[TX] {} bytes on {}", raw.len(), interface_name);
        }
```

- [ ] **Step 3: Add periodic TX reclaim before tick**

Before the `runtime.tick(now)` call in the event loop, add:

```rust
        // Reclaim completed TX buffers.
        #[cfg(feature = "rpi5")]
        genet_driver.reclaim_tx(&genet_bank, &mut tx_pool);
```

- [ ] **Step 4: Run tests**

Run: `cargo test --workspace`
Expected: all tests pass. Event loop changes are `#[cfg(feature = "rpi5")]` — QEMU builds unaffected.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(boot): wire GENET RX/TX into RPi5 event loop

Poll GENET RX each iteration, route 0x88B5 frames to runtime.
Dispatch SendOnInterface by wrapping in Ethernet frame and sending
via GENET. Periodic TX reclaim before timer tick.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Full verification

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace`

- [ ] **Step 3: Run fmt**

Run: `cargo fmt --all -- --check`

- [ ] **Step 4: Verify QEMU boot test**

The QEMU boot test must still pass — all GENET code is behind `#[cfg(feature = "rpi5")]`. The `qemu-virt` build compiles without GENET dependencies.
