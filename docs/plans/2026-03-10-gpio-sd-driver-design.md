# GPIO + SD/eMMC Driver Design

## Goal

Add GPIO (RP1) and SD/eMMC (SDHCI) sans-I/O drivers to harmony-unikernel,
with 9P FileServer wrappers in harmony-microkernel. Same pattern as PL011:
RegisterBank trait for testability, no unsafe in driver code.

## GPIO Architecture

### Hardware: RP1 South-Bridge (RPi5)

The RPi5 routes GPIO through the RP1 chip (Cortex-M3 on PCIe). Three
register blocks per GPIO bank:

| Block        | Base (bank 0)  | Purpose                                   |
|--------------|----------------|-------------------------------------------|
| `io_bank0`   | `0x400d_0000`  | Per-pin function select + status           |
| `pads_bank0` | `0x400f_0000`  | Per-pin electrical config                  |
| `sys_rio0`   | `0x400e_0000`  | Registered I/O — direction, output, input  |

### Per-Pin Registers (io_bank)

8 bytes per pin:

- `STATUS` at `pin * 8 + 0x00` — read-only pin state
- `CTRL` at `pin * 8 + 0x04` — funcsel (bits 4:0), output/input/OE overrides

### Pad Control Registers (pads_bank)

4 bytes per pin at `pin * 4 + 0x04`:

- Drive strength (bits 5:4)
- Pull-up enable (bit 3)
- Pull-down enable (bit 2)
- Schmitt trigger (bit 1)
- Slew rate (bit 0)

### RIO Registers (sys_rio)

Bit-per-pin, atomic set/clear via offset:

- `RIO_OUT` (0x00) — output value
- `RIO_OE` (0x04) — output enable
- `RIO_IN` (0x08) — input value (read-only)
- `+0x2000` — SET (atomic OR)
- `+0x3000` — CLR (atomic AND-NOT)

### Driver Design

Abstract trait with RP1 implementation:

```rust
pub trait GpioController {
    fn set_function(&mut self, pin: u8, func: PinFunction) -> Result<(), GpioError>;
    fn set_direction(&mut self, pin: u8, dir: PinDirection) -> Result<(), GpioError>;
    fn set_pull(&mut self, pin: u8, pull: Pull) -> Result<(), GpioError>;
    fn read_pin(&self, pin: u8) -> Result<bool, GpioError>;
    fn write_pin(&mut self, pin: u8, value: bool) -> Result<(), GpioError>;
}
```

`Rp1Gpio` takes three `RegisterBank` instances (io, pads, rio) since
RP1 splits GPIO across three address spaces. Bank 0 covers 28 pins
(GPIO 0-27), which are the pins exposed on the 40-pin header.

### GpioServer (9P FileServer)

```
/dev/gpio/
  ├── 0         (pin 0)
  ├── 1         (pin 1)
  ├── ...
  └── 27        (pin 27)
```

- **read** returns ASCII `"0\n"` or `"1\n"` (Linux sysfs convention)
- **write** accepts `"0"`, `"1"` for output value, or configuration
  strings: `"in"`, `"out"`, `"alt0"`-`"alt5"`, `"pull_up"`,
  `"pull_down"`, `"pull_none"`

One file per pin. Configuration via write keeps the interface simple.

## SD/eMMC Architecture

### Hardware: SDHCI-Compatible Controller

The RPi5's EMMC2 is SDHCI-compatible. We target the standard SDHCI
register spec for portability.

### Key Registers

| Offset | Name             | Purpose                              |
|--------|------------------|--------------------------------------|
| `0x04` | Block Size/Count | Transfer block configuration         |
| `0x08` | Argument         | Command argument                     |
| `0x0C` | Transfer Mode    | DMA, direction, multi-block          |
| `0x0E` | Command          | Command index + response type        |
| `0x10` | Response 0-3     | 4x32-bit response (16 bytes)         |
| `0x20` | Buffer Data Port | PIO data transfer                    |
| `0x24` | Present State    | Card inserted, cmd/data inhibit      |
| `0x28` | Host Control     | Bus width, speed, DMA select         |
| `0x2C` | Clock Control    | SDCLK frequency, enable, stable      |
| `0x2E` | Timeout Control  | Data timeout counter                 |
| `0x2F` | Software Reset   | Reset all/cmd/data lines             |
| `0x30` | Interrupt Status | Command complete, transfer complete   |
| `0x34` | Interrupt Enable | Interrupt signal masks               |
| `0x38` | Error Interrupt  | CRC, timeout, index errors           |

### Driver Design

```rust
pub struct SdhciDriver {
    // No internal buffer — block transfers go through caller's slice
}
```

Sans-I/O methods:

- `reset(bank)` — software reset, wait for completion
- `set_clock(bank, freq_khz)` — configure SDCLK divider, enable
- `send_command(bank, cmd, arg) -> Result<Response, SdError>` — poll
  for completion or error
- `read_block(bank, buf)` — PIO read 512 bytes from buffer data port
- `write_block(bank, buf)` — PIO write 512 bytes to buffer data port

### Card Initialization State Machine

Returns `SdAction` variants so the caller drives timing:

```rust
pub enum SdAction {
    Wait { microseconds: u32 },
    SendCommand { cmd: u8, arg: u32 },
    ReadyForTransfer,
    Error(SdError),
}
```

Command sequence:

```
CMD0 (GO_IDLE) → CMD8 (SEND_IF_COND) → ACMD41 loop (SD_SEND_OP_COND)
→ CMD2 (ALL_SEND_CID) → CMD3 (SEND_RELATIVE_ADDR) → CMD7 (SELECT_CARD)
→ CMD16 (SET_BLOCKLEN) → ready for CMD17/CMD18/CMD24/CMD25
```

PIO only — no DMA. Sufficient for boot and initial use.

### SdServer (9P FileServer)

```
/dev/sd/
  └── sd0       (block device)
```

- **read(fid, offset, count)** — offset honored (block device). Rounds
  to 512-byte block boundaries. CMD17/CMD18.
- **write(fid, offset, data)** — same alignment. CMD24/CMD25.
- **stat** — returns card capacity in size field
- Unaligned offset rejected with `IpcError::InvalidArgument`

## Testing Strategy

### GPIO Tests

Driver:
- `set_function` writes correct funcsel bits to CTRL register
- `set_direction` writes OE via RIO SET/CLR
- `set_pull` writes correct pad register bits
- `read_pin` extracts correct bit from RIO_IN
- `write_pin` uses RIO_OUT SET/CLR
- Invalid pin (>= 28) returns `GpioError::InvalidPin`

Server:
- Walk to `"14"` succeeds, `"28"` and `"foo"` fail
- Read returns `"0\n"` or `"1\n"`
- Write `"1"`/`"0"` sets output
- Write `"in"`/`"out"`/`"alt0"`-`"alt5"` configures function
- Write `"pull_up"`/`"pull_down"`/`"pull_none"` sets pull
- Mode enforcement (read-only fid can't write)

### SD Tests

Driver:
- `reset` writes software reset, polls until clear
- `set_clock` writes divider, enables, waits for stable
- `send_command` writes argument + command, polls interrupt status
- `send_command` returns error on CRC/timeout/index bits
- `read_block` polls buffer ready, reads 128x u32 into 512 bytes
- Card init: correct command sequence (CMD0→CMD8→ACMD41→CMD2→CMD3→CMD7→CMD16)
- ACMD41 retry loop (polls until card ready)

Server:
- Walk/open/read/write lifecycle
- Read at offset 0 returns first block
- Read at offset 512 returns second block
- Unaligned offset rejected
- Stat returns card capacity

## Design Constraints

- No `unsafe` in drivers — all unsafety in RegisterBank impl
- No allocation in GPIO driver — fixed 28-pin limit
- No DMA — PIO transfers only
- No interrupts — polled I/O

## Scope

**In scope:** Rp1Gpio (bank 0, 28 pins), SdhciDriver (PIO, card init),
GpioServer, SdServer, full test suites.

**Not in scope:** GPIO interrupts, GPIO banks 1-2 (pins 28-53), DMA,
SD partitioning/filesystems, SDIO, eMMC extensions, hot-plug detection.

## File Layout

```
harmony-unikernel/src/drivers/
  ├── mod.rs              (add pub mod gpio, sdhci)
  ├── register_bank.rs    (existing)
  ├── pl011.rs            (existing)
  ├── gpio.rs             (GpioController trait + Rp1Gpio)
  └── sdhci.rs            (SdhciDriver + SdError + SdAction)

harmony-microkernel/src/
  ├── gpio_server.rs      (GpioServer)
  └── sd_server.rs        (SdServer)
```
