# RPi5 Boot Loop Integration

**Bead:** harmony-os-7af
**Date:** 2026-03-23
**Status:** Draft

## Problem

The aarch64 boot path initializes PL011 UART, MMU, heap, timer, and
UnikernelRuntime, but the main loop is a minimal `wfe` idle that only calls
`runtime.tick()` and logs actions. There is no proper event loop structure,
no MMIO RegisterBank implementation for real hardware drivers, and no dispatch
of RuntimeAction variants. The RPi5 can't be used as a Harmony node.

## Solution

Replace the idle loop with a structured event loop following the proven x86_64
pattern. Add a concrete `MmioRegisterBank` for volatile MMIO access. Register
a placeholder network interface. Dispatch RuntimeAction variants to serial
output. GENET networking is deferred until RP1 PCIe initialization is
available (harmony-os-7ng).

## Design Decisions

### Event loop without GENET (PCIe blocker)

GENET on RPi5 requires RP1 PCIe BAR initialization which is not yet
implemented. Rather than block the entire boot loop on PCIe, we deliver a
working event loop with serial console, timer ticks, and runtime action
dispatch. The loop structure has a clearly marked placeholder for network
polling that will be wired when PCIe lands.

### MmioRegisterBank in the boot crate

The RegisterBank trait lives in harmony-unikernel. The MMIO implementation
wraps `core::ptr::{read,write}_volatile` and lives in the boot crate because
it needs the physical base address which is platform-specific. It implements
the trait from harmony-unikernel so it can be passed to any sans-I/O driver.

### Announce-only interface registration

The runtime registers an "eth0" interface at boot even though GENET can't
send yet. This allows the Reticulum node to generate announces (which will
be queued but not transmitted). When GENET becomes available, the event loop
simply starts polling RX and dispatching TX — no runtime reconfiguration
needed.

## Architecture

### MmioRegisterBank

```rust
// crates/harmony-boot-aarch64/src/mmio.rs

use harmony_unikernel::drivers::register_bank::RegisterBank;

pub struct MmioRegisterBank {
    base: usize,
}

impl MmioRegisterBank {
    pub const fn new(base: usize) -> Self { Self { base } }
    pub fn base(&self) -> usize { self.base }
}

impl RegisterBank for MmioRegisterBank {
    fn read(&self, offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }
    fn write(&mut self, offset: usize, value: u32) {
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }
}
```

### Event Loop

Replace the current idle loop (`wfe` + `runtime.tick()` + log) with:

```rust
runtime.register_interface("eth0");

loop {
    let now = timer::now_ms();

    // TODO(harmony-os-7ng): Poll GENET RX here when PCIe is ready.
    // Pattern: while let Some(frame) = genet.poll_rx(&mut bank, &mut rx_pool) {
    //     match ethertype(&frame.data) {
    //         0x88B5 => { runtime.handle_packet("eth0", payload, now); }
    //         _ => {}
    //     }
    // }

    let actions = runtime.tick(now);
    for action in &actions {
        match action {
            RuntimeAction::SendOnInterface { interface_name, raw } => {
                // TODO(harmony-os-7ng): Send via GENET when PCIe is ready.
                let _ = writeln!(serial, "[TX] {} bytes on {}", raw.len(), interface_name);
            }
            other => {
                let _ = writeln!(serial, "[Runtime] {:?}", other);
            }
        }
    }

    unsafe { core::arch::asm!("wfe") };
}
```

### Boot Sequence Addition

After the existing runtime creation and before the event loop:

1. Register "eth0" interface with runtime
2. Register an announcing destination for the node identity
3. Log boot complete message with identity address hash

## File Changes

| File | Change |
|------|--------|
| `crates/harmony-boot-aarch64/src/mmio.rs` | New: MmioRegisterBank struct |
| `crates/harmony-boot-aarch64/src/main.rs` | Add `mod mmio;`, replace idle loop with event loop, register interface + destination |

## What is NOT in Scope

- No GENET initialization (requires RP1 PCIe — harmony-os-7ng)
- No network frame reception or transmission
- No IP/ARP stack (smoltcp integration is future work)
- No GPIO LED control (nice-to-have, not blocking)
- No SDHCI config persistence (separate concern)

## Testing

- `mmio_register_bank_read_write` — test with heap buffer as mock MMIO region
- Real hardware: flash SD card, observe serial output showing:
  - Boot messages (MMU, timer, identity)
  - Runtime tick actions (announces generated)
  - "[TX] N bytes on eth0" messages (queued but not sent)
- Existing workspace tests unaffected (boot crate excluded from workspace)
