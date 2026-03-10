# PL011 UART Driver Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extract the existing PL011 UART into a testable sans-I/O driver with a RegisterBank trait, then expose it as a 9P FileServer.

**Architecture:** Three layers: (1) `RegisterBank` trait + `Pl011Driver` in harmony-unikernel for sans-I/O driver logic, (2) `UartServer` in harmony-microkernel as a 9P FileServer wrapper, (3) `MmioRegisterBank` in harmony-boot-aarch64 for real hardware. The driver owns a fixed-size ring buffer for RX data.

**Tech Stack:** Rust, no_std, no unsafe in driver logic, volatile MMIO in boot crate only.

---

### Task 1: RegisterBank trait and MockRegisterBank

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/mod.rs`
- Create: `crates/harmony-unikernel/src/drivers/register_bank.rs`
- Modify: `crates/harmony-unikernel/src/lib.rs`

**Step 1: Create the drivers module and RegisterBank trait**

Create `crates/harmony-unikernel/src/drivers/mod.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Hardware driver abstractions and implementations.
//!
//! All drivers use the [`RegisterBank`] trait for MMIO access,
//! enabling full unit testing without hardware.

pub mod pl011;
pub mod register_bank;

pub use register_bank::RegisterBank;
```

Create `crates/harmony-unikernel/src/drivers/register_bank.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Hardware register abstraction for sans-I/O drivers.

/// Abstraction over memory-mapped I/O registers.
///
/// Implementations provide read/write access to a peripheral's
/// register space.  The real implementation uses volatile pointer
/// access; the mock records all operations for testing.
pub trait RegisterBank {
    /// Read a 32-bit register at `offset` bytes from the peripheral base.
    fn read(&self, offset: usize) -> u32;

    /// Write a 32-bit value to the register at `offset` bytes from the
    /// peripheral base.
    fn write(&mut self, offset: usize, value: u32);
}
```

Add to `crates/harmony-unikernel/src/lib.rs`:

```rust
pub mod drivers;
```

**Step 2: Write failing test for MockRegisterBank**

Add to `crates/harmony-unikernel/src/drivers/register_bank.rs`:

```rust
#[cfg(test)]
pub mod mock {
    use super::RegisterBank;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    /// Mock register bank that records writes and returns pre-configured reads.
    pub struct MockRegisterBank {
        /// Pre-configured values returned by `read()`.
        reads: BTreeMap<usize, Vec<u32>>,
        /// Read cursor per offset (which value to return next).
        read_cursor: BTreeMap<usize, usize>,
        /// Recorded (offset, value) pairs from `write()` calls.
        pub writes: Vec<(usize, u32)>,
    }

    impl MockRegisterBank {
        pub fn new() -> Self {
            Self {
                reads: BTreeMap::new(),
                read_cursor: BTreeMap::new(),
                writes: Vec::new(),
            }
        }

        /// Queue a sequence of values that `read(offset)` will return.
        /// Each call to `read(offset)` pops the next value. If exhausted,
        /// returns 0.
        pub fn on_read(&mut self, offset: usize, values: Vec<u32>) {
            self.reads.insert(offset, values);
            self.read_cursor.insert(offset, 0);
        }
    }

    impl RegisterBank for MockRegisterBank {
        fn read(&self, offset: usize) -> u32 {
            // Note: we need interior mutability for the cursor.
            // For test simplicity, reads without pre-configured values
            // return 0.  The cursor advancement requires &mut self
            // which we don't have.  We'll address this in the impl.
            0
        }

        fn write(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
        }
    }
}
```

Actually — `read(&self)` can't advance a cursor without interior mutability. Let's use `Cell` for the cursor:

```rust
#[cfg(test)]
pub mod mock {
    use super::RegisterBank;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::Cell;

    pub struct MockRegisterBank {
        reads: BTreeMap<usize, Vec<u32>>,
        read_cursor: BTreeMap<usize, Cell<usize>>,
        pub writes: Vec<(usize, u32)>,
    }

    impl MockRegisterBank {
        pub fn new() -> Self {
            Self {
                reads: BTreeMap::new(),
                read_cursor: BTreeMap::new(),
                writes: Vec::new(),
            }
        }

        pub fn on_read(&mut self, offset: usize, values: Vec<u32>) {
            self.reads.insert(offset, values);
            self.read_cursor.insert(offset, Cell::new(0));
        }
    }

    impl RegisterBank for MockRegisterBank {
        fn read(&self, offset: usize) -> u32 {
            let values = match self.reads.get(&offset) {
                Some(v) => v,
                None => return 0,
            };
            let cursor = match self.read_cursor.get(&offset) {
                Some(c) => c,
                None => return 0,
            };
            let idx = cursor.get();
            if idx < values.len() {
                cursor.set(idx + 1);
                values[idx]
            } else {
                // Exhausted: return last value (sticky).
                values.last().copied().unwrap_or(0)
            }
        }

        fn write(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
        }
    }
}
```

**Step 3: Write tests for MockRegisterBank**

```rust
#[cfg(test)]
mod tests {
    use super::mock::MockRegisterBank;
    use super::RegisterBank;
    use alloc::vec;

    #[test]
    fn mock_records_writes() {
        let mut bank = MockRegisterBank::new();
        bank.write(0x030, 0x301);
        bank.write(0x024, 13);
        assert_eq!(bank.writes, vec![(0x030, 0x301), (0x024, 13)]);
    }

    #[test]
    fn mock_returns_preconfigured_reads() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(0x018, vec![0x20, 0x00]); // TXFF then clear
        assert_eq!(bank.read(0x018), 0x20);
        assert_eq!(bank.read(0x018), 0x00);
    }

    #[test]
    fn mock_read_unconfigured_returns_zero() {
        let bank = MockRegisterBank::new();
        assert_eq!(bank.read(0x000), 0);
    }

    #[test]
    fn mock_read_exhausted_returns_last() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(0x018, vec![0x20]);
        assert_eq!(bank.read(0x018), 0x20);
        // Exhausted: sticky on last value
        assert_eq!(bank.read(0x018), 0x20);
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- register_bank`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/ crates/harmony-unikernel/src/lib.rs
git commit -m "feat(unikernel): add RegisterBank trait and MockRegisterBank for sans-I/O drivers"
```

---

### Task 2: Pl011Driver — init and baud rate

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/pl011.rs`

**Step 1: Write failing test for init sequence**

Create `crates/harmony-unikernel/src/drivers/pl011.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O PL011 UART driver.
//!
//! Uses the [`RegisterBank`] trait for all register access, enabling
//! full unit testing without hardware.

use super::register_bank::RegisterBank;

// ── Register offsets ──────────────────────────────────────────────
const UARTDR: usize = 0x000;
const UARTFR: usize = 0x018;
const UARTIBRD: usize = 0x024;
const UARTFBRD: usize = 0x028;
const UARTLCR_H: usize = 0x02C;
const UARTCR: usize = 0x030;

// ── Flag register bits ──────────────────────────────────────────
const UARTFR_TXFF: u32 = 1 << 5; // TX FIFO full
const UARTFR_RXFE: u32 = 1 << 4; // RX FIFO empty

/// Compute integer and fractional baud-rate divisors for the PL011.
///
/// Formula (PL011 TRM):
///   BRD  = clock_hz / (16 * baud)
///   IBRD = integer part of BRD
///   FBRD = integer(fractional_part * 64 + 0.5)
///
/// Avoids floating-point by working in 128ths then rounding to 64ths.
pub fn baud_divisors(clock_hz: u32, baud: u32) -> (u16, u8) {
    if baud == 0 {
        return (0, 0);
    }
    let div_x128 = (clock_hz as u64 * 8) / baud as u64;
    let div_x64 = (div_x128 + 1) / 2;
    let ibrd = (div_x64 / 64) as u16;
    let fbrd = (div_x64 % 64) as u8;
    (ibrd, fbrd)
}

/// Sans-I/O PL011 UART driver.
///
/// Generic over `N`: the RX ring buffer capacity in bytes.
pub struct Pl011Driver<const N: usize> {
    rx_buf: [u8; N],
    rx_head: usize,
    rx_tail: usize,
    rx_count: usize,
}

impl<const N: usize> Pl011Driver<N> {
    /// Create a new driver with an empty RX ring buffer.
    pub fn new() -> Self {
        Self {
            rx_buf: [0u8; N],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
        }
    }

    /// Initialise the PL011: set baud rate, 8N1, FIFO, enable TX+RX.
    pub fn init(&self, bank: &mut impl RegisterBank, clock_hz: u32, baud: u32) {
        // 1. Disable UART
        bank.write(UARTCR, 0);

        // 2. Baud-rate divisors
        let (ibrd, fbrd) = baud_divisors(clock_hz, baud);
        bank.write(UARTIBRD, ibrd as u32);
        bank.write(UARTFBRD, fbrd as u32);

        // 3. 8-bit word length (WLEN=0b11 << 5) + FIFO enable (bit 4) = 0x70
        bank.write(UARTLCR_H, 0x70);

        // 4. Enable UART (bit 0) + TX (bit 8) + RX (bit 9) = 0x301
        bank.write(UARTCR, 0x301);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;

    #[test]
    fn init_writes_correct_registers() {
        let driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        driver.init(&mut bank, 24_000_000, 115_200);

        assert_eq!(
            bank.writes,
            vec![
                (UARTCR, 0),       // disable
                (UARTIBRD, 13),    // baud integer
                (UARTFBRD, 1),     // baud fractional
                (UARTLCR_H, 0x70), // 8N1 + FIFO
                (UARTCR, 0x301),   // enable TX+RX
            ]
        );
    }

    #[test]
    fn baud_115200_at_24mhz() {
        assert_eq!(baud_divisors(24_000_000, 115_200), (13, 1));
    }

    #[test]
    fn baud_9600_at_24mhz() {
        assert_eq!(baud_divisors(24_000_000, 9_600), (156, 16));
    }

    #[test]
    fn baud_zero_does_not_panic() {
        assert_eq!(baud_divisors(24_000_000, 0), (0, 0));
        assert_eq!(baud_divisors(0, 115_200), (0, 0));
    }

    #[test]
    fn baud_48mhz_rounds_correctly() {
        assert_eq!(baud_divisors(48_000_000, 115_200), (26, 3));
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- pl011`
Expected: PASS (5 tests)

**Step 3: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/pl011.rs
git commit -m "feat(unikernel): add Pl011Driver with init sequence and baud rate calc"
```

---

### Task 3: Pl011Driver — TX (write_bytes)

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/pl011.rs`

**Step 1: Write failing test for write_bytes**

Add to `impl<const N: usize> Pl011Driver<N>`:

```rust
    /// Check whether the TX FIFO has space.
    pub fn tx_ready(&self, bank: &impl RegisterBank) -> bool {
        bank.read(UARTFR) & UARTFR_TXFF == 0
    }

    /// Transmit bytes, spinning while the TX FIFO is full.
    pub fn write_bytes(&self, bank: &mut impl RegisterBank, data: &[u8]) {
        for &byte in data {
            while !self.tx_ready(bank) {
                core::hint::spin_loop();
            }
            bank.write(UARTDR, byte as u32);
        }
    }
```

Add tests:

```rust
    #[test]
    fn write_bytes_sends_to_data_register() {
        let driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        // FR returns 0 (FIFO not full) for every read.
        bank.on_read(UARTFR, vec![0]);

        driver.write_bytes(&mut bank, b"Hi");
        // Should read FR twice (once per byte) and write DR twice.
        let data_writes: Vec<(usize, u32)> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UARTDR)
            .copied()
            .collect();
        assert_eq!(data_writes, vec![(UARTDR, b'H' as u32), (UARTDR, b'i' as u32)]);
    }

    #[test]
    fn write_bytes_spins_on_txff() {
        let driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        // First read: TXFF set, second read: clear, third read: clear.
        bank.on_read(UARTFR, vec![UARTFR_TXFF, 0]);

        driver.write_bytes(&mut bank, b"A");
        // Should have read FR twice (spin + success) then written DR once.
        let data_writes: Vec<(usize, u32)> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UARTDR)
            .copied()
            .collect();
        assert_eq!(data_writes, vec![(UARTDR, b'A' as u32)]);
    }
```

**Step 2: Run tests**

Run: `cargo test -p harmony-unikernel -- pl011`
Expected: PASS

**Step 3: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/pl011.rs
git commit -m "feat(unikernel): add Pl011Driver TX — write_bytes with TXFF spin"
```

---

### Task 4: Pl011Driver — RX ring buffer

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/pl011.rs`

**Step 1: Implement poll_rx and read_buffered**

Add to `impl<const N: usize> Pl011Driver<N>`:

```rust
    /// Poll the RX FIFO and drain available bytes into the ring buffer.
    ///
    /// Call this periodically (e.g. in the event loop or before reads).
    /// If the ring buffer is full, incoming bytes are dropped.
    pub fn poll_rx(&mut self, bank: &impl RegisterBank) {
        while bank.read(UARTFR) & UARTFR_RXFE == 0 {
            let byte = (bank.read(UARTDR) & 0xFF) as u8;
            if self.rx_count < N {
                self.rx_buf[self.rx_head] = byte;
                self.rx_head = (self.rx_head + 1) % N;
                self.rx_count += 1;
            }
            // If full, drop the byte.
        }
    }

    /// Read buffered RX data into `buf`. Returns the number of bytes copied.
    pub fn read_buffered(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.rx_count);
        for slot in buf[..n].iter_mut() {
            *slot = self.rx_buf[self.rx_tail];
            self.rx_tail = (self.rx_tail + 1) % N;
            self.rx_count -= 1;
        }
        n
    }

    /// Number of bytes available in the RX ring buffer.
    pub fn rx_available(&self) -> usize {
        self.rx_count
    }
```

**Step 2: Write tests**

```rust
    #[test]
    fn poll_rx_drains_fifo_into_ring() {
        let mut driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        // FR: not empty, not empty, empty (stop)
        bank.on_read(UARTFR, vec![0, 0, UARTFR_RXFE]);
        // DR: two bytes available
        bank.on_read(UARTDR, vec![b'A' as u32, b'B' as u32]);

        driver.poll_rx(&bank);
        assert_eq!(driver.rx_available(), 2);

        let mut buf = [0u8; 4];
        let n = driver.read_buffered(&mut buf);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"AB");
    }

    #[test]
    fn ring_buffer_wraps() {
        let mut driver: Pl011Driver<4> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();

        // Fill ring with 3 bytes
        bank.on_read(UARTFR, vec![0, 0, 0, UARTFR_RXFE]);
        bank.on_read(UARTDR, vec![1, 2, 3]);
        driver.poll_rx(&bank);

        // Drain 2
        let mut buf = [0u8; 2];
        driver.read_buffered(&mut buf);
        assert_eq!(buf, [1, 2]);
        assert_eq!(driver.rx_available(), 1);

        // Add 3 more (wraps around)
        let mut bank2 = MockRegisterBank::new();
        bank2.on_read(UARTFR, vec![0, 0, 0, UARTFR_RXFE]);
        bank2.on_read(UARTDR, vec![4, 5, 6]);
        driver.poll_rx(&bank2);
        assert_eq!(driver.rx_available(), 4); // full

        let mut out = [0u8; 4];
        let n = driver.read_buffered(&mut out);
        assert_eq!(n, 4);
        assert_eq!(out, [3, 4, 5, 6]);
    }

    #[test]
    fn ring_buffer_overflow_drops_bytes() {
        let mut driver: Pl011Driver<2> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        // 3 bytes available but ring is only 2
        bank.on_read(UARTFR, vec![0, 0, 0, UARTFR_RXFE]);
        bank.on_read(UARTDR, vec![b'X' as u32, b'Y' as u32, b'Z' as u32]);

        driver.poll_rx(&bank);
        assert_eq!(driver.rx_available(), 2);

        let mut buf = [0u8; 2];
        driver.read_buffered(&mut buf);
        assert_eq!(&buf, b"XY"); // Z was dropped
    }

    #[test]
    fn read_buffered_empty() {
        let mut driver: Pl011Driver<256> = Pl011Driver::new();
        let mut buf = [0u8; 4];
        let n = driver.read_buffered(&mut buf);
        assert_eq!(n, 0);
    }
```

**Step 3: Run tests**

Run: `cargo test -p harmony-unikernel -- pl011`
Expected: PASS

**Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/pl011.rs
git commit -m "feat(unikernel): add Pl011Driver RX — poll_rx ring buffer with overflow drop"
```

---

### Task 5: UartServer — 9P FileServer

**Files:**
- Create: `crates/harmony-microkernel/src/uart_server.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

**Step 1: Implement UartServer**

Create `crates/harmony-microkernel/src/uart_server.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! UartServer — 9P file server for a PL011 UART.
//!
//! Exposes a single character device file `uart0` with stream semantics
//! (offset ignored on both read and write).

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_unikernel::drivers::pl011::Pl011Driver;
use harmony_unikernel::drivers::RegisterBank;

use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

const QPATH_ROOT: QPath = 0;
const QPATH_UART0: QPath = 1;

struct FidState {
    qpath: QPath,
    is_open: bool,
    mode: Option<OpenMode>,
}

/// A 9P file server wrapping a [`Pl011Driver`] and [`RegisterBank`].
///
/// Walk to `"uart0"` to get a character device fid.
/// Read polls the RX FIFO and returns buffered data (offset ignored).
/// Write sends bytes to the TX FIFO (offset ignored).
pub struct UartServer<B: RegisterBank, const N: usize> {
    driver: Pl011Driver<N>,
    bank: B,
    fids: BTreeMap<Fid, FidState>,
}

impl<B: RegisterBank, const N: usize> UartServer<B, N> {
    /// Create a new UartServer with the given driver and register bank.
    ///
    /// The caller should have already called `driver.init()` before
    /// constructing the server.
    pub fn new(driver: Pl011Driver<N>, bank: B) -> Self {
        let mut fids = BTreeMap::new();
        fids.insert(
            0,
            FidState {
                qpath: QPATH_ROOT,
                is_open: false,
                mode: None,
            },
        );
        Self { driver, bank, fids }
    }
}

impl<B: RegisterBank, const N: usize> FileServer for UartServer<B, N> {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if state.qpath != QPATH_ROOT {
            return Err(IpcError::NotDirectory);
        }
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        if name != "uart0" {
            return Err(IpcError::NotFound);
        }
        self.fids.insert(
            new_fid,
            FidState {
                qpath: QPATH_UART0,
                is_open: false,
                mode: None,
            },
        );
        Ok(QPATH_UART0)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let state = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if state.is_open {
            return Err(IpcError::PermissionDenied);
        }
        if state.qpath == QPATH_ROOT && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::IsDirectory);
        }
        state.is_open = true;
        state.mode = Some(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, _offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if state.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(state.mode, Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }
        // Poll hardware, then drain ring buffer.
        self.driver.poll_rx(&self.bank);
        let max = count as usize;
        let mut buf = alloc::vec![0u8; max.min(self.driver.rx_available())];
        let n = self.driver.read_buffered(&mut buf);
        buf.truncate(n);
        Ok(buf)
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if state.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(state.mode, Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }
        let len = u32::try_from(data.len()).map_err(|_| IpcError::ResourceExhausted)?;
        self.driver.write_bytes(&mut self.bank, data);
        Ok(len)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Ok(()); // Root fid is permanent.
        }
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let (name, file_type) = match state.qpath {
            QPATH_ROOT => ("uart", FileType::Directory),
            QPATH_UART0 => ("uart0", FileType::Regular),
            _ => return Err(IpcError::NotFound),
        };
        Ok(FileStat {
            qpath: state.qpath,
            name: Arc::from(name),
            size: 0, // stream device
            file_type,
        })
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let qpath = state.qpath;
        self.fids.insert(
            new_fid,
            FidState {
                qpath,
                is_open: false,
                mode: None,
            },
        );
        Ok(qpath)
    }
}
```

Add to `crates/harmony-microkernel/src/lib.rs`:

```rust
pub mod uart_server;
```

**Step 2: Write tests**

Add to `crates/harmony-microkernel/src/uart_server.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use harmony_unikernel::drivers::register_bank::mock::MockRegisterBank;

    const UARTFR: usize = 0x018;
    const UARTDR: usize = 0x000;
    const UARTFR_RXFE: u32 = 1 << 4;

    fn test_server() -> UartServer<MockRegisterBank, 256> {
        let driver = Pl011Driver::new();
        let bank = MockRegisterBank::new();
        UartServer::new(driver, bank)
    }

    #[test]
    fn walk_to_uart0() {
        let mut srv = test_server();
        let qpath = srv.walk(0, 1, "uart0").unwrap();
        assert_eq!(qpath, QPATH_UART0);
    }

    #[test]
    fn walk_invalid_name() {
        let mut srv = test_server();
        assert_eq!(srv.walk(0, 1, "nonexistent"), Err(IpcError::NotFound));
    }

    #[test]
    fn write_sends_to_driver() {
        let mut srv = test_server();
        // Configure FR to return 0 (FIFO not full) for TX.
        srv.bank.on_read(UARTFR, vec![0]);

        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        let n = srv.write(1, 0, b"Hi").unwrap();
        assert_eq!(n, 2);

        let data_writes: Vec<u32> = srv
            .bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UARTDR)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(data_writes, vec![b'H' as u32, b'i' as u32]);
    }

    #[test]
    fn read_returns_rx_data() {
        let mut srv = test_server();
        // Pre-load RX FIFO with data.
        srv.bank.on_read(UARTFR, vec![0, 0, UARTFR_RXFE]);
        srv.bank.on_read(UARTDR, vec![b'X' as u32, b'Y' as u32]);

        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 256).unwrap();
        assert_eq!(data, b"XY");
    }

    #[test]
    fn read_empty_returns_empty_vec() {
        let mut srv = test_server();
        // RX FIFO is empty.
        srv.bank.on_read(UARTFR, vec![UARTFR_RXFE]);

        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 256).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn write_denied_in_read_mode() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        assert_eq!(srv.write(1, 0, b"nope"), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn read_denied_in_write_mode() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        assert_eq!(srv.read(1, 0, 256), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn stat_root() {
        let mut srv = test_server();
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "uart");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_uart0() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "uart0");
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.size, 0); // stream device
    }

    #[test]
    fn clunk_root_is_noop() {
        let mut srv = test_server();
        srv.clunk(0).unwrap();
        // Root should still work.
        srv.walk(0, 1, "uart0").unwrap();
    }

    #[test]
    fn clunk_releases_fid() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        srv.clunk(1).unwrap();
        assert_eq!(srv.stat(1), Err(IpcError::InvalidFid));
    }
}
```

**Step 3: Run tests**

Run: `cargo test --workspace`
Expected: PASS

**Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/uart_server.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(microkernel): add UartServer — 9P FileServer for PL011 UART"
```

---

### Task 6: Wire UartServer into harmony-microkernel Cargo.toml

**Files:**
- Modify: `crates/harmony-microkernel/Cargo.toml`

**Step 1: Add harmony-unikernel dependency**

The `UartServer` imports from `harmony_unikernel`, so the microkernel crate needs it as a dependency. Check the existing Cargo.toml and add:

```toml
[dependencies]
harmony-unikernel = { path = "../harmony-unikernel" }
```

This may already be present. If so, just verify it works.

**Step 2: Run workspace tests**

Run: `cargo test --workspace`
Expected: PASS (all existing + new tests)

**Step 3: Run clippy and fmt**

Run: `cargo clippy --workspace` and `cargo fmt --all -- --check`
Expected: Zero warnings, formatting clean

**Step 4: Commit (if Cargo.toml changed)**

```bash
git add crates/harmony-microkernel/Cargo.toml
git commit -m "build: add harmony-unikernel dep to harmony-microkernel for UartServer"
```

---

### Task 7: Final verification and cleanup

**Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All tests pass (existing + new driver + server tests)

**Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: Zero warnings

**Step 3: Run fmt check**

Run: `cargo fmt --all -- --check`
Expected: Clean

**Step 4: Verify test count increased**

Run: `cargo test --workspace 2>&1 | grep "test result"`
Expected: Test count increased from previous baseline (was 31 workspace tests).

**Step 5: Commit any fixups**

If clippy or fmt required changes, commit them:
```bash
git commit -m "style: clippy and fmt cleanup for PL011 driver"
```
