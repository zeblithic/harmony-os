# PL011 UART Driver Design

## Goal

Extract the existing PL011 UART code into a sans-I/O driver with a testable
register abstraction, then expose it as a 9P FileServer for the microkernel
namespace.

## Architecture

Three layers, one per ring:

```
harmony-unikernel (Ring 1)
  └── drivers::pl011::Pl011Driver<const N: usize>
      Sans-I/O driver with RegisterBank trait.
      Fixed ring buffer for RX. Pure logic: init, tx, rx, poll.

harmony-microkernel (Ring 2)
  └── uart_server::UartServer<D>
      9P FileServer wrapping a Pl011Driver.
      Stream semantics (offset ignored).
      Walk to "uart0", open, read/write.

harmony-boot-aarch64 (boot crate)
  └── MmioRegisterBank
      Real volatile MMIO impl of RegisterBank.
      Hardcoded base address (0x0900_0000 for QEMU).
```

## RegisterBank trait

```rust
pub trait RegisterBank {
    fn read(&self, offset: usize) -> u32;
    fn write(&mut self, offset: usize, value: u32);
}
```

Lives in `harmony-unikernel::drivers`. Implementations:

- **MmioRegisterBank** (boot crate) — volatile pointer reads/writes at a
  base address. Contains all `unsafe`.
- **MockRegisterBank** (test) — records writes, returns pre-configured
  read values. Enables full unit testing of register sequences.

## Pl011Driver

Generic over `const N: usize` for ring buffer size (default 4096).

### Methods

- `init(bank, clock_hz, baud)` — configure baud divisors, enable FIFO, TX/RX
- `poll_rx(bank)` — drain RX FIFO into internal ring buffer
- `read_buffered(buf) -> usize` — copy from ring buffer to caller's slice
- `write_bytes(bank, data)` — block on TXFF flag, send each byte
- `tx_ready(bank) -> bool` — check TXFF flag without blocking

### Register offsets (PL011)

| Offset | Name     | Purpose                          |
|--------|----------|----------------------------------|
| 0x000  | UARTDR   | Data (read RX, write TX)         |
| 0x018  | UARTFR   | Flags (TXFF bit 5, RXFE bit 4)  |
| 0x024  | UARTIBRD | Integer baud rate divisor        |
| 0x028  | UARTFBRD | Fractional baud rate divisor     |
| 0x02C  | UARTLCR_H| Line control (word len, FIFO)    |
| 0x030  | UARTCR   | Control (enable, TX/RX enable)   |

### Design constraints

- No `unsafe` in the driver — all unsafety lives in the RegisterBank impl.
- No allocation — the ring buffer is `[u8; N]` on the struct.
- No I/O assumptions — works identically on QEMU and real hardware.

## UartServer (9P FileServer)

Wraps a `Pl011Driver` and a `RegisterBank` to serve UART I/O over 9P.

### Namespace

```
/dev/uart/
  └── uart0    (character device)
```

### 9P operations

- **walk** — root fid (0) is `/dev/uart/` directory; walk to `"uart0"`
- **open** — supports `OpenMode::Read`, `Write`, and `ReadWrite`
- **read** — calls `poll_rx()` then `read_buffered()`, ignores offset
- **write** — calls `write_bytes()`, ignores offset, returns bytes written
- **stat** — size 0 (stream device), `FileType::Regular`
- **clunk** — releases fid (root fid permanent, like LibraryServer)
- **clone_fid** — duplicates fid state

## Testing strategy

### Unit tests (Pl011Driver)

- Init sequence produces correct register writes in correct order
- TX blocks when TXFF is set, resumes when cleared
- RX drains FIFO into ring buffer; read_buffered returns correct data
- Ring buffer wraps correctly; overflow drops oldest bytes
- Baud divisor calculation matches known values (e.g. 48 MHz / 115200)

### Unit tests (UartServer)

- Walk/open/read/write/clunk lifecycle
- Read returns empty vec when no RX data buffered
- Write delegates to driver write_bytes
- Stat returns stream device metadata
- Write-only and read-only open modes respected

## Scope

This design covers the PL011 UART only. GPIO, SD, USB, and Ethernet
drivers will follow the same RegisterBank pattern established here.
