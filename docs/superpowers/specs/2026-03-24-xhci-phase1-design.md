# xHCI USB Driver — Phase 1: Controller Init + Port Detection

## Goal

Implement a sans-I/O xHCI driver that initializes the DesignWare USB controller on RPi5, detects connected USB devices by port, and reports their negotiated speed. This proves the xHCI hardware interface works and establishes the driver foundation for Phase 2 (device slot assignment) and Phase 3 (full enumeration).

## Scope

**In scope:**
- xHCI controller halt + reset sequence
- Capability register parsing (port count, slot count, offsets)
- Port status register scanning (connected, enabled, speed)
- USB speed detection: Low Speed, Full Speed, High Speed, SuperSpeed, SuperSpeedPlus
- Platform MMIO constant for RPi5 xHCI base address
- Unit tests using `MockRegisterBank`

**Out of scope:**
- TRB ring infrastructure (command, event, transfer rings) — Phase 2
- Device slot assignment / SET_ADDRESS — Phase 2
- Device descriptor reads / GET_DESCRIPTOR — Phase 2
- Configuration / interface / endpoint enumeration — Phase 3
- Class drivers (mass storage, HID, network) — separate beads
- QEMU support (QEMU virt has no RP1 xHCI emulation)
- Hot-plug detection (requires interrupt/event ring — Phase 2)
- Boot loop integration (separate bead)

## Architecture

### Sans-I/O Pattern

Follows the established driver pattern (GENET, SDHCI, PL011): the `XhciDriver` struct is a pure state machine generic over `RegisterBank`. All register access goes through the trait. No embedded I/O, no async, no interrupts. The caller (boot code) provides register access and calls methods in sequence.

### State Machine

```
Uninit ──init()──→ Resetting ──(halt+reset)──→ Ready
                       │                         │
                       ▼                         ▼
                    Error              detect_ports() → Vec<PortStatus>
```

States:
- **Uninit** — constructed, no hardware interaction yet
- **Resetting** — transient during `init()` (halt → reset sequence)
- **Ready** — controller initialized, ports can be scanned
- **Error** — unrecoverable failure (timeout during halt/reset)

### Register Layout

xHCI registers are split into three regions, all relative to the MMIO base:

1. **Capability registers** (offset 0x00): Read-only, describe hardware capabilities
2. **Operational registers** (offset = `cap_length` read from CAPLENGTH): Control and status
3. **Port registers** (operational base + 0x400 + 0x10 * port_index): Per-port status/control

The `cap_length` value is read from hardware during `init()` and stored in the driver struct. All subsequent operational and port register accesses are offset by this value.

## Types

### XhciDriver

```rust
pub struct XhciDriver {
    /// Number of downstream ports (from HCSPARAMS1 bits 31:24).
    max_ports: u8,
    /// Maximum device slots (from HCSPARAMS1 bits 7:0).
    max_slots: u8,
    /// Capability register length — offset to operational registers.
    cap_length: u8,
    /// Runtime register offset from base (from RTSOFF, stored for Phase 2+).
    rts_offset: u32,
    /// Doorbell register offset from base (from DBOFF, stored for Phase 2+).
    db_offset: u32,
    /// Current driver state.
    state: XhciState,
}
```

### XhciState

```rust
enum XhciState {
    /// Not yet initialized — no hardware interaction.
    Uninit,
    /// Controller halted and reset, ready for port detection.
    Ready,
    /// Unrecoverable error.
    Error(XhciError),
}
```

Note: `Resetting` is a transient state within `init()`, not a persistent state — the method either transitions to `Ready` or `Error` before returning.

### XhciError

```rust
pub enum XhciError {
    /// Controller did not halt (USBSTS.HCH not set) within poll limit.
    HaltTimeout,
    /// Reset did not complete (USBCMD.HCRST not cleared) within poll limit.
    ResetTimeout,
    /// Controller Not Ready (USBSTS.CNR still set) after reset.
    NotReady,
    /// Operation attempted in wrong state.
    InvalidState,
}
```

### UsbSpeed

```rust
pub enum UsbSpeed {
    /// 1.5 Mbps — speed ID 2
    LowSpeed,
    /// 12 Mbps — speed ID 1
    FullSpeed,
    /// 480 Mbps — speed ID 3
    HighSpeed,
    /// 5 Gbps — speed ID 4
    SuperSpeed,
    /// 10 Gbps — speed ID 5
    SuperSpeedPlus,
    /// Unrecognized speed ID from hardware.
    Unknown(u8),
}
```

### PortStatus

```rust
pub struct PortStatus {
    /// Zero-based port index.
    pub port: u8,
    /// Device connected (PORTSC bit 0: CCS).
    pub connected: bool,
    /// Port enabled (PORTSC bit 1: PED).
    pub enabled: bool,
    /// Negotiated link speed (PORTSC bits 13:10).
    pub speed: UsbSpeed,
}
```

## Init Sequence

`XhciDriver::init(regs: &mut impl RegisterBank) -> Result<(), XhciError>`

1. **Read capability registers** (at fixed offsets from MMIO base):
   - `CAPLENGTH_HCIVERSION` (0x00): extract `cap_length = value & 0xFF`
   - `HCSPARAMS1` (0x04): extract `max_slots = value & 0xFF`, `max_ports = (value >> 24) & 0xFF`
   - `DBOFF` (0x14): `db_offset = value`
   - `RTSOFF` (0x18): `rts_offset = value`

2. **Halt the controller**:
   - Read `USBCMD` at `cap_length + 0x00`, clear `RUN` bit, write back
   - Poll `USBSTS` at `cap_length + 0x04` until `HCH` bit (bit 0) is set
   - Fail with `HaltTimeout` if not set within `MAX_POLL_ITERATIONS` (1000)

3. **Reset the controller**:
   - Read `USBCMD`, set `HCRST` bit, write back
   - Poll `USBCMD` until `HCRST` bit clears (controller self-clears when done)
   - Fail with `ResetTimeout` if not cleared within `MAX_POLL_ITERATIONS`
   - Poll `USBSTS` until `CNR` bit (bit 11) clears (controller ready)
   - Fail with `NotReady` if not cleared within `MAX_POLL_ITERATIONS`

4. Transition to `Ready` state.

## Port Detection

`XhciDriver::detect_ports(regs: &impl RegisterBank) -> Result<Vec<PortStatus>, XhciError>`

- Requires state `Ready`, returns `InvalidState` otherwise
- For each port `0..max_ports`:
  - Compute PORTSC offset: `cap_length + PORTSC_BASE + PORTSC_STRIDE * port`
  - Read PORTSC register
  - Extract CCS (bit 0), PED (bit 1), speed (bits 13:10)
  - Map speed ID to `UsbSpeed` variant
- Return `Vec<PortStatus>` for all ports

## Register Constants

### New constants (add to existing stub)

```rust
// ── PORTSC registers ────────────────────────────────────────────
/// First PORTSC relative to operational base.
const PORTSC_BASE: usize = 0x400;
/// Byte spacing between successive PORTSC registers.
const PORTSC_STRIDE: usize = 0x10;

// ── PORTSC bits ─────────────────────────────────────────────────
const PORTSC_CCS: u32 = 1 << 0;       // Current Connect Status
const PORTSC_PED: u32 = 1 << 1;       // Port Enabled/Disabled
const PORTSC_SPEED_SHIFT: u32 = 10;
const PORTSC_SPEED_MASK: u32 = 0xF << 10;

// ── xHCI speed IDs ──────────────────────────────────────────────
const SPEED_FULL: u8 = 1;
const SPEED_LOW: u8 = 2;
const SPEED_HIGH: u8 = 3;
const SPEED_SUPER: u8 = 4;
const SPEED_SUPER_PLUS: u8 = 5;

// ── Polling limit ───────────────────────────────────────────────
const MAX_POLL_ITERATIONS: u32 = 1000;
```

### HCSPARAMS1 field extraction

```rust
// HCSPARAMS1 bit layout:
// Bits  7:0  — MaxSlots (max device slots)
// Bits 15:8  — MaxIntrs (max interrupters, not used in Phase 1)
// Bits 31:24 — MaxPorts (max downstream ports)
```

## Platform Integration

### RPi5 MMIO Constant

In `crates/harmony-boot-aarch64/src/platform.rs`:

```rust
#[cfg(feature = "rpi5")]
pub const XHCI_BASE: usize = 0x1F00D_0000;
```

The DesignWare xHCI controller is at RP1 offset `0xD0000` from the RP1 PCIe BAR base (`0x1F000_0000`), same mechanism as GENET at `0x1F005_8000`.

### MMIO Region Entry

Add `XHCI_BASE` to the `MMIO_REGIONS` array (RPi5 variant) so the MMU maps it as device memory.

### Boot Code (future integration)

The boot event loop in `main.rs` will conditionally call `XhciDriver::init()` and `detect_ports()` under `#[cfg(feature = "rpi5")]`. This is analogous to the existing GENET init. **Boot integration is not part of this bead** — it's Phase 2+ work when the driver does something actionable with the detected devices.

## File Map

| File | Change |
|------|--------|
| `crates/harmony-unikernel/src/drivers/dwc_usb.rs` | Expand: PORTSC constants, `XhciDriver`, `XhciState`, `XhciError`, `UsbSpeed`, `PortStatus`, `init()`, `detect_ports()`, 10 unit tests |
| `crates/harmony-boot-aarch64/src/platform.rs` | Add `XHCI_BASE` constant + MMIO region entry (rpi5 only) |

## Testing Strategy

All tests use `MockRegisterBank` with pre-configured register values. The mock already supports sequential reads (for polling loops where a register transitions between values).

1. **`init_reads_capability_registers`** — Verify `init` reads CAPLENGTH, HCSPARAMS1, RTSOFF, DBOFF and extracts correct values.
2. **`init_halts_then_resets`** — Mock: USBSTS transitions HCH 0→1, then USBCMD HCRST self-clears, CNR clears. Verify correct write sequence.
3. **`init_halt_timeout`** — USBSTS.HCH never set → `HaltTimeout`.
4. **`init_reset_timeout`** — USBCMD.HCRST never clears → `ResetTimeout`.
5. **`detect_ports_empty`** — No CCS bits set → all ports `connected: false`.
6. **`detect_ports_one_usb2_device`** — Port 0 CCS + PED + speed=HighSpeed.
7. **`detect_ports_mixed_speeds`** — Multiple ports with FS, HS, SS speeds.
8. **`detect_ports_unknown_speed`** — Speed field = 15 → `UsbSpeed::Unknown(15)`.
9. **`detect_ports_before_init_fails`** — `Uninit` state → `InvalidState`.
10. **`init_after_error_fails`** — After timeout → `InvalidState` on retry.

## Future Work (Explicitly Deferred)

- **Phase 2 (harmony-os-vof):** TRB ring infrastructure, command/event rings, device slot assignment, SET_ADDRESS, GET_DESCRIPTOR
- **Phase 3 (harmony-os-e4v):** Configuration selection, interface/endpoint enumeration
- **Class drivers:** Mass storage, HID, network — separate beads after Phase 3
- **QEMU emulation:** No RP1 xHCI in QEMU virt; test via MockRegisterBank only
- **Hot-plug:** Requires interrupt/event ring from Phase 2
- **Boot integration:** Wire into main.rs event loop after Phase 2 makes it useful
