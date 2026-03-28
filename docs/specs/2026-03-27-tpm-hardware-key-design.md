# TPM 2.0 Hardware Key Derivation — Design Spec

## Goal

Add a sans-I/O TPM 2.0 driver that derives a 32-byte hardware root
key deterministically from the physical TPM chip and current firmware
measurements (PCR values). The key is unique per device and changes
if firmware is modified — binding the post-quantum key hierarchy to
specific hardware and boot state without persistent sealed blobs.

## Background

The four-tier key hierarchy (owner/hardware/session/user) in
`key_hierarchy.rs` currently generates the hardware identity from a
software-only random keypair. This bead replaces that with a
TPM-derived key, providing true hardware binding.

The target hardware is the LetsTrust TPM module (Infineon SLB9672)
on Raspberry Pi 5, attached via SPI0/CE1. The driver is designed for
any TPM 2.0 SPI-attached module, not just the SLB9672.

## Design Decisions

- **HMAC derivation, not PCR sealing**: Uses `TPM2_HMAC` with a
  platform-unique primary key and PCR digests as input. Eliminates
  the complexity of policy sessions, sealed blob storage, and PCR
  fragility on firmware updates. The key is derived fresh each boot
  — deterministically identical if firmware hasn't changed.
- **`tpm2-protocol` crate for marshaling**: External dependency
  (no_std, zero-dep, MIT/Apache-2.0, maintained by Linux kernel TPM
  maintainer). Provides type-safe command/response marshaling for all
  TPM 2.0 commands. Avoids hand-rolling complex nested parameter
  structures.
- **New `SpiBus` trait**: Minimal SPI abstraction (`transfer`,
  `assert_cs`, `deassert_cs`). The TPM driver handles SPI PTP
  protocol internally. `MockSpiBus` for testing.
- **Single file**: `tpm.rs` in `drivers/`, following GENET/NVMe
  pattern. Three logical layers (SPI transport, command engine, key
  derivation) in one file.
- **Not fully sans-I/O internally**: The SPI wait-state polling loop
  must execute within the driver (clock MISO until ACK). The `SpiBus`
  trait is the I/O boundary. From the caller's perspective, the API
  is synchronous: `derive_hardware_key()` returns a 32-byte key.

## SpiBus Trait

```rust
pub trait SpiBus {
    /// Full-duplex SPI transfer: simultaneously send `tx` and
    /// receive into `rx`. Both slices must have the same length.
    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]);
    /// Assert chip select (drive CS# low).
    fn assert_cs(&mut self);
    /// Deassert chip select (drive CS# high).
    fn deassert_cs(&mut self);
}
```

Located in a new `spi_bus.rs` in `drivers/`, alongside
`register_bank.rs`. Includes `MockSpiBus` under `#[cfg(test)]`.

## TpmDriver Struct

```rust
pub struct TpmDriver<S: SpiBus> {
    bus: S,
    locality: u8,       // always 0
    state: TpmState,
}

pub enum TpmState {
    Uninitialized,
    Ready,       // after Startup + SelfTest
    KeyDerived,  // primary key created, HMAC completed
}
```

## SPI PTP Transport (Layer 1)

Every TPM register access uses a 4-byte SPI header:

| Byte | Field | Description |
|------|-------|-------------|
| 0 | Direction + Size | Bit 7: 1=read, 0=write. Bits 5:0: byte count |
| 1 | Address [23:16] | High byte of 24-bit register address |
| 2 | Address [15:8] | Middle byte |
| 3 | Address [7:0] | Low byte |

After the header, the driver polls MISO for wait-state ACK: clock
single bytes until bit 0 is set. Timeout after `MAX_WAIT_CYCLES`
iterations (configurable, default 10000).

### TPM Registers (Locality 0)

| Register | Address | Purpose |
|----------|---------|---------|
| TPM_ACCESS_0 | 0xD40000 | Locality request, validity check |
| TPM_STS_0 | 0xD40018 | commandReady, dataAvail, burstCount, tpmGo |
| TPM_DATA_FIFO_0 | 0xD40024 | Command/response data portal |
| TPM_DID_VID | 0xD40F00 | Device/Vendor ID (probe) |

### Private Methods

```rust
fn read_register(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), TpmError>
fn write_register(&mut self, addr: u32, data: &[u8]) -> Result<(), TpmError>
fn poll_wait_state(&mut self) -> Result<(), TpmError>
```

## TPM Command Engine (Layer 2)

Sequences FIFO-based command execution:

1. Read `TPM_ACCESS_0` — verify `tpmRegValidSts` (bit 7) and
   `activeLocality` (bit 5). Request locality if needed.
2. Write `TPM_STS_0` with `commandReady` (bit 6)
3. Poll `TPM_STS_0` until `commandReady` is set
4. Read `burstCount` (bits 23:8 of TPM_STS_0)
5. Write command to `TPM_DATA_FIFO_0` in chunks ≤ burstCount
6. Write `TPM_STS_0` with `tpmGo` (bit 5)
7. Poll `TPM_STS_0` until `dataAvail` (bit 4)
8. Read burstCount, read response from FIFO in chunks

```rust
fn execute_command(
    &mut self,
    command: &[u8],
    response: &mut [u8],
) -> Result<usize, TpmError>
```

Response buffer is caller-provided (stack-allocated). Largest
expected response is ~600 bytes (CreatePrimary). A 1024-byte buffer
covers all commands.

## Hardware Key Derivation (Layer 3)

### Public API

```rust
pub fn init(bus: S) -> Result<Self, TpmError>
pub fn derive_hardware_key(
    &mut self,
    pcr_indices: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], TpmError>
```

### init() Sequence

1. Probe `TPM_DID_VID` to verify SPI connectivity
2. `TPM2_Startup(TPM_SU_CLEAR)` (command code 0x00000144)
3. `TPM2_SelfTest(fullTest=yes)` (command code 0x00000143)
4. Transition to `TpmState::Ready`

### derive_hardware_key() Sequence

1. **TPM2_CreatePrimary** (0x00000131) — derive HMAC key under
   `TPM_RH_OWNER` (0x40000001). Algorithm: `TPM_ALG_KEYEDHASH`
   with `TPM_ALG_SHA256`. Returns transient object handle. The key
   is derived from the TPM's internal unique seed — hardware-bound.
2. **TPM2_PCR_Read** (0x0000017E) — read SHA-256 digests for the
   requested PCR indices (e.g., `[0, 4]` for firmware + kernel).
   Concatenate digests into a single buffer.
3. **TPM2_HMAC** (0x00000155) — HMAC the concatenated PCR digests +
   caller salt using the primary key handle. SHA-256 output = 32
   bytes.
4. **TPM2_FlushContext** (0x00000165) — release transient handle.
5. Return the 32-byte HMAC digest.

### Why TPM_RH_OWNER?

Platform hierarchy (`TPM_RH_PLATFORM`) is locked after boot on many
TPMs. Owner hierarchy is available throughout the OS lifecycle and
still derives from a hardware-unique seed.

### PCR Index Flexibility

The caller chooses which PCRs to bind to. Typical policy:
- PCR 0: firmware/CRTM (immutable per firmware release)
- PCR 4: OS bootloader/kernel (changes on OS update)

This lets the key hierarchy code decide binding policy without
hard-coding it in the driver.

### Firmware Update Handling

Because the key is derived via HMAC (not sealed), firmware updates
simply produce a different key on next boot. The key hierarchy's
rotation mechanism (KERI pre-rotation, harmony-os-s9t) handles the
identity transition. No resealing, no fragility.

## Error Type

```rust
pub enum TpmError {
    /// SPI wait-state or status polling exceeded iteration limit.
    Timeout,
    /// TPM_ACCESS validity check failed.
    LocalityUnavailable,
    /// TPM returned non-zero response code.
    CommandFailed { rc: u32 },
    /// Response exceeds caller-provided buffer.
    BufferTooSmall,
    /// TPM driver is in the wrong state for the operation.
    InvalidState,
}
```

## New Files

- `crates/harmony-unikernel/src/drivers/spi_bus.rs` — `SpiBus`
  trait + `MockSpiBus`
- `crates/harmony-unikernel/src/drivers/tpm.rs` — `TpmDriver`
  (all three layers)

## Modified Files

- `crates/harmony-unikernel/src/drivers/mod.rs` — add `pub mod
  spi_bus;` and `pub mod tpm;`
- `crates/harmony-unikernel/Cargo.toml` — add `tpm2-protocol`
  dependency

## Testing

All tests use `MockSpiBus` — no hardware needed.

### MockSpiBus Design

More sophisticated than MockRegisterBank:
- Records outgoing SPI frames for assertion
- Plays back pre-configured response sequences per register address
- Simulates configurable wait-state count (N bytes of 0x00 before
  ACK)

### SPI PTP transport tests
- Probe reads TPM_DID_VID: correct SPI header format
- Read register: correct 4-byte header (direction=read, size, addr)
- Write register: correct header + payload bytes
- Wait-state polling: mock returns 0x00 twice then ACK, verify retry
- Wait-state timeout: mock never ACKs, verify TpmError::Timeout

### Command engine tests
- Execute command writes FIFO in burstCount-sized chunks
- Execute command polls dataAvail before reading response
- Command failed: mock non-zero RC, verify TpmError::CommandFailed
- Buffer too small: verify TpmError::BufferTooSmall

### Init tests
- Startup + SelfTest sequence: correct command codes sent
- Locality check: valid bits → success
- Locality unavailable: missing valid bits → error

### Key derivation tests
- Full HMAC workflow: mock all 4 responses, verify 32-byte output
- CreatePrimary uses KEYEDHASH + SHA256
- PCR_Read requests correct indices
- HMAC input includes PCR digests + salt
- FlushContext called after derivation
- Same PCR values + salt → same key (deterministic)
- Different PCR values → different key

### Integration test
- Full lifecycle: init → derive_hardware_key → verify 32-byte output

## Out of Scope

- Full PCR sealing / TPM2_Unseal workflow (alternative approach)
- Policy sessions (TPM2_StartAuthSession, TPM2_PolicyPCR)
- Persistent key storage on TPM
- Remote attestation
- Multi-locality support
- Interrupt-driven completion (PIRQ#)
- PCR extension (TPM2_PCR_Extend) — measured boot is a follow-up
- Real SPI hardware driver for RPi5 RP1 controller
- Integration with key_hierarchy.rs (follow-up bead)
