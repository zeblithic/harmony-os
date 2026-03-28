# TPM 2.0 Hardware Key Derivation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a TPM 2.0 driver that derives a 32-byte hardware-bound root key via HMAC with PCR digests.

**Architecture:** Three layers in `tpm.rs`: SPI PTP transport (register I/O over `SpiBus` trait), TPM command engine (FIFO state machine using `tpm2-protocol` for marshaling), and HMAC key derivation (Startup → CreatePrimary → PCR_Read → HMAC → FlushContext). `MockSpiBus` for all testing.

**Tech Stack:** Rust (no_std), `tpm2-protocol` crate (marshaling), `SpiBus` trait (SPI abstraction).

**Spec:** `docs/specs/2026-03-27-tpm-hardware-key-design.md`

**Test command:** `cargo test -p harmony-unikernel -- tpm`

**CI parity:** `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`

---

## File Structure

- **Create:** `crates/harmony-unikernel/src/drivers/spi_bus.rs` — `SpiBus` trait + `MockSpiBus`
- **Create:** `crates/harmony-unikernel/src/drivers/tpm.rs` — `TpmDriver` (all three layers + tests)
- **Modify:** `crates/harmony-unikernel/src/drivers/mod.rs` — add module declarations
- **Modify:** `Cargo.toml` (workspace root) — add `tpm2-protocol` workspace dep
- **Modify:** `crates/harmony-unikernel/Cargo.toml` — add `tpm2-protocol` dep

---

### Task 1: SpiBus trait and MockSpiBus

Create the SPI abstraction trait and the mock implementation used by all subsequent tasks.

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/spi_bus.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs`

**Context for implementer:** This follows the pattern of `register_bank.rs` (same directory). The `RegisterBank` trait has `read`/`write` methods; `SpiBus` has `transfer`/`assert_cs`/`deassert_cs`. The mock is under `#[cfg(any(test, feature = "test-utils"))]` (same guard as `mock::MockRegisterBank`). The mock is more complex than `MockRegisterBank` because it needs to parse 4-byte SPI PTP headers to determine which TPM register is being accessed, then play back per-register responses. Uses `alloc` collections (`BTreeMap`, `VecDeque`, `Vec`) — `alloc` is available in the crate (check `register_bank.rs` imports).

- [ ] **Step 1: Write the SpiBus trait and MockSpiBus**

Create `crates/harmony-unikernel/src/drivers/spi_bus.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! SPI bus abstraction for sans-I/O drivers.

/// Abstraction over an SPI bus.
///
/// Implementations provide full-duplex transfers and chip-select
/// control. The real implementation drives RP1 SPI hardware; the
/// mock records all transactions for testing.
pub trait SpiBus {
    /// Full-duplex SPI transfer: simultaneously send `tx` and
    /// receive into `rx`. Both slices must have the same length.
    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]);
    /// Assert chip select (drive CS# low).
    fn assert_cs(&mut self);
    /// Deassert chip select (drive CS# high).
    fn deassert_cs(&mut self);
}

#[cfg(any(test, feature = "test-utils"))]
pub mod mock {
    use super::SpiBus;
    use alloc::collections::BTreeMap;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Mock SPI bus that plays back pre-configured responses keyed by
    /// TPM register address (parsed from the 4-byte SPI PTP header).
    ///
    /// Two response modes:
    /// - **Register mode** (`on_register`): Each CS cycle gets the next
    ///   queued response. Used for TPM_ACCESS, TPM_STS, TPM_DID_VID.
    /// - **FIFO mode** (`on_fifo`): A single long response is consumed
    ///   across multiple CS cycles. Used for TPM_DATA_FIFO where the
    ///   command engine reads the header (6 bytes) and payload in
    ///   separate read_register calls.
    pub struct MockSpiBus {
        /// Register responses: each CS cycle pops the next entry.
        responses: BTreeMap<u32, Vec<Vec<u8>>>,
        response_cursors: BTreeMap<u32, usize>,
        /// FIFO responses: consumed across CS cycles, byte offset persists.
        fifo_responses: BTreeMap<u32, Vec<u8>>,
        fifo_offsets: BTreeMap<u32, usize>,
        /// Number of 0x00 wait-state bytes before ACK per register.
        wait_states: BTreeMap<u32, usize>,
        /// Current transaction state (within one CS cycle).
        header_buf: Vec<u8>,
        current_addr: Option<u32>,
        wait_states_remaining: usize,
        ack_sent: bool,
        payload_cursor: usize,
        cs_active: bool,
        /// Recorded transactions: (addr, is_read, payload_bytes).
        pub transactions: Vec<(u32, bool, Vec<u8>)>,
    }

    impl Default for MockSpiBus {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockSpiBus {
        pub fn new() -> Self {
            Self {
                responses: BTreeMap::new(),
                response_cursors: BTreeMap::new(),
                fifo_responses: BTreeMap::new(),
                fifo_offsets: BTreeMap::new(),
                wait_states: BTreeMap::new(),
                header_buf: Vec::new(),
                current_addr: None,
                wait_states_remaining: 0,
                ack_sent: false,
                payload_cursor: 0,
                cs_active: false,
                transactions: Vec::new(),
            }
        }

        /// Queue a response for a normal register (one per CS cycle).
        pub fn on_register(&mut self, addr: u32, response: Vec<u8>) {
            self.responses
                .entry(addr)
                .or_insert_with(Vec::new)
                .push(response);
            self.response_cursors.entry(addr).or_insert(0);
        }

        /// Append data to a FIFO response consumed across multiple CS
        /// cycles. Byte offset persists between reads. Call multiple
        /// times to queue responses for sequential commands that all
        /// read from the same FIFO address.
        pub fn on_fifo(&mut self, addr: u32, mut response: Vec<u8>) {
            self.fifo_responses
                .entry(addr)
                .or_insert_with(Vec::new)
                .append(&mut response);
            self.fifo_offsets.entry(addr).or_insert(0);
        }

        /// Set wait-state count for `addr` (default 0).
        pub fn set_wait_states(&mut self, addr: u32, count: usize) {
            self.wait_states.insert(addr, count);
        }

        /// Get the next response byte for the current address.
        fn next_response_byte(&mut self) -> u8 {
            let addr = match self.current_addr {
                Some(a) => a,
                None => return 0,
            };

            // Check FIFO mode first
            if let Some(fifo) = self.fifo_responses.get(&addr) {
                let offset = self.fifo_offsets.get(&addr).copied().unwrap_or(0);
                let byte = if offset < fifo.len() { fifo[offset] } else { 0 };
                self.fifo_offsets.insert(addr, offset + 1);
                return byte;
            }

            // Register mode: use payload_cursor within this CS cycle
            let cursor = self.response_cursors.get(&addr).copied().unwrap_or(0);
            if let Some(responses) = self.responses.get(&addr) {
                let idx = cursor.min(responses.len().saturating_sub(1));
                let resp = &responses[idx];
                let byte = if self.payload_cursor < resp.len() {
                    resp[self.payload_cursor]
                } else {
                    0
                };
                self.payload_cursor += 1;
                return byte;
            }
            0
        }
    }

    impl SpiBus for MockSpiBus {
        fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) {
            for i in 0..tx.len().min(rx.len()) {
                if self.current_addr.is_none() {
                    // Collecting 4-byte header
                    self.header_buf.push(tx[i]);
                    rx[i] = 0xFF;
                    if self.header_buf.len() == 4 {
                        let addr = ((self.header_buf[1] as u32) << 16)
                            | ((self.header_buf[2] as u32) << 8)
                            | (self.header_buf[3] as u32);
                        let is_read = (self.header_buf[0] & 0x80) != 0;
                        self.current_addr = Some(addr);
                        self.wait_states_remaining =
                            self.wait_states.get(&addr).copied().unwrap_or(0);
                        self.ack_sent = false;
                        self.payload_cursor = 0;
                        self.transactions.push((addr, is_read, Vec::new()));
                    }
                } else if !self.ack_sent {
                    if self.wait_states_remaining > 0 {
                        rx[i] = 0x00;
                        self.wait_states_remaining -= 1;
                    } else {
                        rx[i] = 0x01;
                        self.ack_sent = true;
                    }
                } else {
                    rx[i] = self.next_response_byte();
                    if let Some(last) = self.transactions.last_mut() {
                        last.2.push(tx[i]);
                    }
                }
            }
        }

        fn assert_cs(&mut self) {
            self.cs_active = true;
            self.header_buf.clear();
            self.current_addr = None;
            self.ack_sent = false;
            self.payload_cursor = 0;
            // Note: fifo_offsets NOT reset — persists across CS cycles
        }

        fn deassert_cs(&mut self) {
            // Advance register response cursor (not FIFO)
            if let Some(addr) = self.current_addr.take() {
                if self.fifo_responses.contains_key(&addr) {
                    // FIFO: offset persists, don't advance cursor
                } else if let Some(cursor) = self.response_cursors.get_mut(&addr) {
                    let max = self.responses.get(&addr).map(|r| r.len()).unwrap_or(0);
                    if *cursor < max.saturating_sub(1) {
                        *cursor += 1;
                    }
                }
            }
            self.cs_active = false;
            self.header_buf.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockSpiBus;
    use super::SpiBus;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn mock_plays_back_register_response() {
        let mut bus = MockSpiBus::new();
        bus.on_register(0xD40F00, vec![0x15, 0xD1, 0x00, 0x1A]); // fake DID_VID

        bus.assert_cs();
        // Send read header: direction=read(0x80)|size=3, addr=0xD40F00
        let tx_header = [0x80 | 3, 0xD4, 0x0F, 0x00];
        let mut rx = [0u8; 4];
        bus.transfer(&tx_header, &mut rx);

        // Wait-state ACK (0 wait states configured = immediate ACK)
        let mut ack = [0u8; 1];
        bus.transfer(&[0x00], &mut ack);
        assert_eq!(ack[0], 0x01, "immediate ACK");

        // Read 4 payload bytes
        let mut payload = [0u8; 4];
        bus.transfer(&[0x00; 4], &mut payload);
        assert_eq!(payload, [0x15, 0xD1, 0x00, 0x1A]);

        bus.deassert_cs();
    }

    #[test]
    fn mock_simulates_wait_states() {
        let mut bus = MockSpiBus::new();
        bus.on_register(0xD40018, vec![0x42]);
        bus.set_wait_states(0xD40018, 3);

        bus.assert_cs();
        let tx_header = [0x80 | 0, 0xD4, 0x00, 0x18]; // read 1 byte from STS
        let mut rx = [0u8; 4];
        bus.transfer(&tx_header, &mut rx);

        // 3 wait states then ACK
        for _ in 0..3 {
            let mut ws = [0u8; 1];
            bus.transfer(&[0x00], &mut ws);
            assert_eq!(ws[0], 0x00, "wait state");
        }
        let mut ack = [0u8; 1];
        bus.transfer(&[0x00], &mut ack);
        assert_eq!(ack[0], 0x01, "ACK after wait states");

        let mut payload = [0u8; 1];
        bus.transfer(&[0x00], &mut payload);
        assert_eq!(payload[0], 0x42);

        bus.deassert_cs();
    }

    #[test]
    fn mock_records_write_transactions() {
        let mut bus = MockSpiBus::new();

        bus.assert_cs();
        // Write header: direction=write(0x00)|size=1, addr=0xD40018
        let tx_header = [0x00 | 1, 0xD4, 0x00, 0x18];
        let mut rx = [0u8; 4];
        bus.transfer(&tx_header, &mut rx);

        // ACK
        let mut ack = [0u8; 1];
        bus.transfer(&[0x00], &mut ack);

        // Write payload byte
        let mut rx_payload = [0u8; 1];
        bus.transfer(&[0x40], &mut rx_payload); // commandReady = bit 6

        bus.deassert_cs();

        assert_eq!(bus.transactions.len(), 1);
        assert_eq!(bus.transactions[0].0, 0xD40018); // addr
        assert!(!bus.transactions[0].1); // is_read = false
        assert_eq!(bus.transactions[0].2, vec![0x40]); // payload written
    }
}
```

- [ ] **Step 2: Add module declarations to mod.rs**

Add to `crates/harmony-unikernel/src/drivers/mod.rs` (after the `pub mod sdhci;` line):

```rust
pub mod spi_bus;
pub mod tpm;
```

Note: `tpm.rs` doesn't exist yet — this will cause a compilation error until Task 2 creates it. To keep Task 1 self-contained, add only `pub mod spi_bus;` now. Add `pub mod tpm;` in Task 2.

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel -- spi_bus`
Expected: 3 tests pass.

- [ ] **Step 4: Run CI parity**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/spi_bus.rs crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(drivers): add SpiBus trait and MockSpiBus

SPI abstraction for TPM and future SPI peripherals. MockSpiBus
parses SPI PTP headers, plays back per-register responses, and
simulates configurable wait states."
```

---

### Task 2: TpmDriver scaffold, SPI PTP transport, and tpm2-protocol dependency

Create `tpm.rs` with the driver struct, error type, SPI PTP register read/write, and the `tpm2-protocol` dependency wiring.

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/tpm.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs` — add `pub mod tpm;`
- Modify: `Cargo.toml` (workspace root) — add `tpm2-protocol`
- Modify: `crates/harmony-unikernel/Cargo.toml` — add `tpm2-protocol`

**Context for implementer:** The SPI PTP protocol uses 4-byte headers. Byte 0: bit 7 = read(1)/write(0), bits 5:0 = transfer_size - 1. Bytes 1-3: 24-bit register address. After the header, poll MISO byte-by-byte until bit 0 is set (ACK). Then transfer payload bytes.

Register addresses for Locality 0: TPM_ACCESS_0 = 0xD40000, TPM_STS_0 = 0xD40018, TPM_DATA_FIFO_0 = 0xD40024, TPM_DID_VID = 0xD40F00.

The `tpm2-protocol` crate is no_std, zero-dep, provides `TpmMarshal`/`TpmUnmarshal` traits. Add it as `default-features = false` to ensure no_std.

**IMPORTANT:** Check if `tpm2-protocol` actually compiles in the workspace before writing driver code. The crate may need specific feature flags or may have compatibility issues. Run `cargo check -p harmony-unikernel` after adding the dependency to verify.

- [ ] **Step 1: Add tpm2-protocol dependency**

Add to `Cargo.toml` (workspace root), in the `[workspace.dependencies]` section:
```toml
tpm2-protocol = { version = "0.16", default-features = false }
```

Also update `rust-version` in the workspace root `Cargo.toml` from `"1.75"` to `"1.81"` — `tpm2-protocol` requires Rust 1.81+.

Add to `crates/harmony-unikernel/Cargo.toml`, in the `[dependencies]` section:
```toml
tpm2-protocol = { workspace = true }
```

Run: `cargo check -p harmony-unikernel` to verify the dependency resolves and compiles.

- [ ] **Step 2: Write TpmDriver scaffold with SPI PTP tests**

Create `crates/harmony-unikernel/src/drivers/tpm.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! TPM 2.0 driver for hardware key derivation.
//!
//! Three-layer architecture:
//! 1. **SPI PTP transport** — register read/write over [`SpiBus`]
//! 2. **Command engine** — FIFO-based command execution
//! 3. **Key derivation** — HMAC workflow for hardware-bound keys
//!
//! Uses the [`tpm2_protocol`] crate for command marshaling.

use super::spi_bus::SpiBus;

// ── TPM register addresses (Locality 0) ──────────────────────────────

const TPM_ACCESS: u32 = 0xD4_0000;
const TPM_STS: u32 = 0xD4_0018;
const TPM_DATA_FIFO: u32 = 0xD4_0024;
const TPM_DID_VID: u32 = 0xD4_0F00;

// ── TPM_ACCESS bit masks ─────────────────────────────────────────────

const ACCESS_VALID: u8 = 1 << 7;       // tpmRegValidSts
const ACCESS_ACTIVE: u8 = 1 << 4;      // activeLocality
const ACCESS_REQUEST: u8 = 1 << 1;     // requestUse

// ── TPM_STS bit masks ────────────────────────────────────────────────

const STS_COMMAND_READY: u32 = 1 << 6;
const STS_TPM_GO: u32 = 1 << 5;
const STS_DATA_AVAIL: u32 = 1 << 4;

/// Maximum wait-state polling iterations before timeout.
const MAX_WAIT_CYCLES: usize = 10_000;
/// Maximum status register polling iterations.
const MAX_POLL_CYCLES: usize = 100_000;
/// Maximum bytes per SPI register transfer (stack buffer size).
const MAX_BURST: usize = 64;

// ── Error type ───────────────────────────────────────────────────────

/// Errors returned by TPM driver operations.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// tpm2-protocol marshaling/unmarshaling failed.
    ProtocolError,
}

// ── Driver state ─────────────────────────────────────────────────────

/// Lifecycle state of a [`TpmDriver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmState {
    /// Driver created but init() not yet called.
    Uninitialized,
    /// TPM2_Startup + SelfTest completed.
    Ready,
}

// ── Driver struct ────────────────────────────────────────────────────

/// TPM 2.0 driver for hardware key derivation via HMAC.
pub struct TpmDriver<S: SpiBus> {
    bus: S,
    state: TpmState,
}

// ── SPI PTP transport (Layer 1) ──────────────────────────────────────

impl<S: SpiBus> TpmDriver<S> {
    /// Build a 4-byte SPI PTP header.
    ///
    /// `is_read`: true for read, false for write.
    /// `size`: number of bytes to transfer (1-64).
    /// `addr`: 24-bit TPM register address.
    fn spi_header(is_read: bool, size: u8, addr: u32) -> [u8; 4] {
        let dir = if is_read { 0x80 } else { 0x00 };
        [
            dir | (size - 1),
            ((addr >> 16) & 0xFF) as u8,
            ((addr >> 8) & 0xFF) as u8,
            (addr & 0xFF) as u8,
        ]
    }

    /// Poll MISO for wait-state ACK (bit 0 set).
    fn poll_wait_state(&mut self) -> Result<(), TpmError> {
        for _ in 0..MAX_WAIT_CYCLES {
            let mut rx = [0u8; 1];
            self.bus.transfer(&[0x00], &mut rx);
            if rx[0] & 0x01 != 0 {
                return Ok(());
            }
        }
        Err(TpmError::Timeout)
    }

    /// Read `buf.len()` bytes from TPM register at `addr`.
    /// Capped at `MAX_BURST` bytes per call.
    fn read_register(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), TpmError> {
        let len = buf.len().min(MAX_BURST);
        let header = Self::spi_header(true, len as u8, addr);

        self.bus.assert_cs();
        let mut rx_header = [0u8; 4];
        self.bus.transfer(&header, &mut rx_header);
        self.poll_wait_state()?;

        let tx_zeros = [0u8; MAX_BURST];
        self.bus.transfer(&tx_zeros[..len], &mut buf[..len]);
        self.bus.deassert_cs();

        Ok(())
    }

    /// Write `data` to TPM register at `addr`.
    /// Capped at `MAX_BURST` bytes per call.
    fn write_register(&mut self, addr: u32, data: &[u8]) -> Result<(), TpmError> {
        let len = data.len().min(MAX_BURST);
        let header = Self::spi_header(false, len as u8, addr);

        self.bus.assert_cs();
        let mut rx_header = [0u8; 4];
        self.bus.transfer(&header, &mut rx_header);
        self.poll_wait_state()?;

        let mut rx_payload = [0u8; MAX_BURST];
        self.bus.transfer(&data[..len], &mut rx_payload[..len]);
        self.bus.deassert_cs();

        Ok(())
    }

    /// Return the current driver state.
    pub fn state(&self) -> TpmState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::spi_bus::mock::MockSpiBus;
    use alloc::vec;

    fn make_driver() -> TpmDriver<MockSpiBus> {
        TpmDriver {
            bus: MockSpiBus::new(),
            state: TpmState::Uninitialized,
        }
    }

    // ── SPI PTP transport tests ──────────────────────────────────────

    #[test]
    fn spi_header_read_format() {
        // Read 4 bytes from TPM_DID_VID (0xD40F00)
        let hdr = TpmDriver::<MockSpiBus>::spi_header(true, 4, 0xD40F00);
        assert_eq!(hdr[0], 0x80 | 3); // read bit + size-1
        assert_eq!(hdr[1], 0xD4);
        assert_eq!(hdr[2], 0x0F);
        assert_eq!(hdr[3], 0x00);
    }

    #[test]
    fn spi_header_write_format() {
        // Write 1 byte to TPM_STS (0xD40018)
        let hdr = TpmDriver::<MockSpiBus>::spi_header(false, 1, 0xD40018);
        assert_eq!(hdr[0], 0x00); // write bit + size-1=0
        assert_eq!(hdr[1], 0xD4);
        assert_eq!(hdr[2], 0x00);
        assert_eq!(hdr[3], 0x18);
    }

    #[test]
    fn read_register_returns_mock_data() {
        let mut driver = make_driver();
        driver
            .bus
            .on_register(TPM_DID_VID, vec![0x15, 0xD1, 0x00, 0x1A]);

        let mut buf = [0u8; 4];
        driver.read_register(TPM_DID_VID, &mut buf).unwrap();
        assert_eq!(buf, [0x15, 0xD1, 0x00, 0x1A]);
    }

    #[test]
    fn read_register_with_wait_states() {
        let mut driver = make_driver();
        driver
            .bus
            .on_register(TPM_DID_VID, vec![0xAB, 0xCD, 0xEF, 0x01]);
        driver.bus.set_wait_states(TPM_DID_VID, 5);

        let mut buf = [0u8; 4];
        driver.read_register(TPM_DID_VID, &mut buf).unwrap();
        assert_eq!(buf, [0xAB, 0xCD, 0xEF, 0x01]);
    }

    #[test]
    fn wait_state_timeout() {
        let mut driver = make_driver();
        // Set wait states higher than MAX_WAIT_CYCLES
        driver
            .bus
            .on_register(TPM_DID_VID, vec![0x00]);
        driver.bus.set_wait_states(TPM_DID_VID, MAX_WAIT_CYCLES + 100);

        let mut buf = [0u8; 4];
        assert_eq!(
            driver.read_register(TPM_DID_VID, &mut buf).unwrap_err(),
            TpmError::Timeout
        );
    }
}
```

- [ ] **Step 3: Add `pub mod tpm;` to mod.rs**

Add after the `pub mod spi_bus;` line in `crates/harmony-unikernel/src/drivers/mod.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-unikernel -- tpm`
Expected: 5 tests pass (2 header format + 2 register read + 1 timeout).

- [ ] **Step 5: Run CI parity**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/harmony-unikernel/Cargo.toml crates/harmony-unikernel/src/drivers/tpm.rs crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(tpm): add TpmDriver scaffold with SPI PTP transport

Register read/write over SpiBus with wait-state polling. Adds
tpm2-protocol dependency (no_std, zero-dep) for future command
marshaling."
```

---

### Task 3: TPM command engine (FIFO state machine)

Add the `execute_command` method that sends a pre-marshaled command through the FIFO protocol and reads the response.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/tpm.rs`

**Context for implementer:** The command engine sequences: (1) check TPM_ACCESS for validity + active locality, request if needed, (2) write commandReady to TPM_STS, (3) poll commandReady, (4) read burstCount from TPM_STS bits 23:8, (5) write command to DATA_FIFO in chunks ≤ burstCount, (6) write tpmGo to TPM_STS, (7) poll dataAvail, (8) read response from DATA_FIFO.

TPM_STS is a 4-byte register. burstCount is bits 23:8 (a 16-bit value). dataAvail is bit 4. commandReady is bit 6. tpmGo is bit 5.

TPM_ACCESS is a 1-byte register. tpmRegValidSts is bit 7, activeLocality is bit 4, requestUse is bit 1.

The `read_register` and `write_register` methods from Task 2 are available.

- [ ] **Step 1: Write failing tests**

Add to the test module in `tpm.rs`:

```rust
    // ── Command engine tests ─────────────────────────────────────────

    /// Helper: configure MockSpiBus for a successful command execution.
    /// Sets up TPM_ACCESS (valid + active), TPM_STS (commandReady,
    /// burstCount=64, dataAvail), and a canned response on DATA_FIFO.
    fn mock_command_flow(bus: &mut MockSpiBus, response: &[u8]) {
        // TPM_ACCESS: valid (bit 7) + active (bit 4) = 0x90
        bus.on_register(TPM_ACCESS, vec![0x90]);
        // TPM_STS reads: first = commandReady (bit 6) = 0x40,
        // then burstCount=64 in bits 23:8 → bytes [0x40, 0x00, 0x40, 0x00]
        // (little-endian 4-byte register: 0x00_0040_40)
        // commandReady (0x40) then burstCount=64+dataAvail (0x00004010)
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]); // commandReady
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]); // burstCount=64 for write
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]); // dataAvail + burstCount=64
        // DATA_FIFO: the canned response
        bus.on_fifo(TPM_DATA_FIFO, response.to_vec());
    }

    #[test]
    fn execute_command_returns_response() {
        let mut driver = make_driver();
        // A minimal TPM response: 10-byte header with success RC
        let response_bytes = [
            0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0A, // size: 10
            0x00, 0x00, 0x00, 0x00, // RC: success
        ];
        mock_command_flow(&mut driver.bus, &response_bytes);

        // A minimal command: 10-byte header
        let command = [
            0x80, 0x01, // tag
            0x00, 0x00, 0x00, 0x0A, // size: 10
            0x00, 0x00, 0x01, 0x44, // TPM2_Startup
        ];
        let mut resp = [0u8; 64];
        let len = driver.execute_command(&command, &mut resp).unwrap();
        assert_eq!(len, 10);
        assert_eq!(&resp[..10], &response_bytes);
    }

    #[test]
    fn execute_command_failed_rc() {
        let mut driver = make_driver();
        let response_bytes = [
            0x80, 0x01,
            0x00, 0x00, 0x00, 0x0A,
            0x00, 0x00, 0x01, 0x00, // RC: TPM_RC_INITIALIZE
        ];
        mock_command_flow(&mut driver.bus, &response_bytes);

        let command = [
            0x80, 0x01,
            0x00, 0x00, 0x00, 0x0A,
            0x00, 0x00, 0x01, 0x44,
        ];
        let mut resp = [0u8; 64];
        let err = driver.execute_command(&command, &mut resp).unwrap_err();
        assert_eq!(err, TpmError::CommandFailed { rc: 0x100 });
    }

    #[test]
    fn execute_command_locality_unavailable() {
        let mut driver = make_driver();
        // TPM_ACCESS without valid bit
        driver.bus.on_register(TPM_ACCESS, vec![0x00]);

        let command = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x44];
        let mut resp = [0u8; 64];
        let err = driver.execute_command(&command, &mut resp).unwrap_err();
        assert_eq!(err, TpmError::LocalityUnavailable);
    }
```

- [ ] **Step 2: Implement execute_command**

Add to the `impl<S: SpiBus> TpmDriver<S>` block, after the SPI PTP methods:

```rust
    // ── TPM command engine (Layer 2) ─────────────────────────────────

    /// Ensure locality 0 is active. Request if needed.
    fn ensure_locality(&mut self) -> Result<(), TpmError> {
        let mut access = [0u8; 1];
        self.read_register(TPM_ACCESS, &mut access)?;

        if access[0] & ACCESS_VALID == 0 {
            return Err(TpmError::LocalityUnavailable);
        }

        if access[0] & ACCESS_ACTIVE == 0 {
            // Request locality
            self.write_register(TPM_ACCESS, &[ACCESS_REQUEST])?;
            // Poll until active
            for _ in 0..MAX_POLL_CYCLES {
                self.read_register(TPM_ACCESS, &mut access)?;
                if access[0] & ACCESS_ACTIVE != 0 {
                    return Ok(());
                }
            }
            return Err(TpmError::Timeout);
        }

        Ok(())
    }

    /// Read TPM_STS as a 4-byte little-endian u32.
    fn read_sts(&mut self) -> Result<u32, TpmError> {
        let mut buf = [0u8; 4];
        self.read_register(TPM_STS, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Extract burstCount from TPM_STS (bits 23:8).
    fn burst_count(sts: u32) -> u16 {
        ((sts >> 8) & 0xFFFF) as u16
    }

    /// Execute a pre-marshaled TPM command and read the response.
    ///
    /// Returns the number of response bytes written to `response`.
    fn execute_command(
        &mut self,
        command: &[u8],
        response: &mut [u8],
    ) -> Result<usize, TpmError> {
        // Step 1: Ensure locality is active
        self.ensure_locality()?;

        // Step 2: Set commandReady
        self.write_register(TPM_STS, &(STS_COMMAND_READY as u32).to_le_bytes())?;

        // Step 3: Poll commandReady
        for _ in 0..MAX_POLL_CYCLES {
            let sts = self.read_sts()?;
            if sts & STS_COMMAND_READY != 0 {
                break;
            }
        }

        // Step 4-5: Write command to FIFO in chunks
        let mut offset = 0;
        while offset < command.len() {
            let sts = self.read_sts()?;
            let burst = (Self::burst_count(sts) as usize).min(MAX_BURST);
            if burst == 0 {
                continue; // TPM not ready for more data yet
            }
            let chunk = (command.len() - offset).min(burst);
            self.write_register(TPM_DATA_FIFO, &command[offset..offset + chunk])?;
            offset += chunk;
        }

        // Step 6: Assert tpmGo
        self.write_register(TPM_STS, &(STS_TPM_GO as u32).to_le_bytes())?;

        // Step 7: Poll dataAvail
        for _ in 0..MAX_POLL_CYCLES {
            let sts = self.read_sts()?;
            if sts & STS_DATA_AVAIL != 0 {
                break;
            }
        }

        // Step 8: Read response header (first 6 bytes to get size)
        let mut header = [0u8; 6];
        self.read_register(TPM_DATA_FIFO, &mut header)?;

        let resp_size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if resp_size > response.len() {
            return Err(TpmError::BufferTooSmall);
        }

        // Copy header into response
        response[..6].copy_from_slice(&header);

        // Read remaining bytes
        if resp_size > 6 {
            let remaining = resp_size - 6;
            let mut read_offset = 0;
            while read_offset < remaining {
                let sts = self.read_sts()?;
                let burst = (Self::burst_count(sts) as usize).min(MAX_BURST);
                if burst == 0 {
                    continue;
                }
                let chunk = (remaining - read_offset).min(burst);
                self.read_register(
                    TPM_DATA_FIFO,
                    &mut response[6 + read_offset..6 + read_offset + chunk],
                )?;
                read_offset += chunk;
            }
        }

        // Check response code (bytes 6-9, big-endian u32)
        let rc = u32::from_be_bytes([
            response[6], response[7], response[8], response[9],
        ]);
        if rc != 0 {
            return Err(TpmError::CommandFailed { rc });
        }

        Ok(resp_size)
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel -- tpm`
Expected: 8 tests pass (5 from Task 2 + 3 new).

- [ ] **Step 4: Run CI parity**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/tpm.rs
git commit -m "feat(tpm): add command engine with FIFO state machine

Locality management, burstCount-chunked FIFO writes, tpmGo/dataAvail
polling, and response code checking."
```

---

### Task 4: init() — Startup, SelfTest, and DID/VID probe

Add the public `init()` constructor that probes the TPM, runs Startup + SelfTest, and transitions to Ready.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/tpm.rs`

**Context for implementer:** `init()` uses `execute_command` from Task 3 to send TPM2_Startup and TPM2_SelfTest. Commands are marshaled using `tpm2-protocol` types. `TPM2_Startup` uses tag `TPM_ST_NO_SESSIONS` (0x8001), command code 0x00000144, with a 2-byte startup type parameter (`TPM_SU_CLEAR` = 0x0000). `TPM2_SelfTest` uses tag 0x8001, command code 0x00000143, with a 1-byte `fullTest` parameter (0x01 = yes).

**IMPORTANT:** If `TPM2_Startup` returns `TPM_RC_INITIALIZE` (0x00000100), that means firmware already called Startup — treat it as success. The `execute_command` method returns `Err(CommandFailed { rc: 0x100 })` in this case, so `init()` must catch and accept that specific RC.

Use `tpm2_protocol` for marshaling if the API is straightforward. If the API is too complex or unclear, hand-build the simple 12-byte Startup and 11-byte SelfTest commands — they're small enough. Document whichever approach you choose.

- [ ] **Step 1: Write failing tests**

```rust
    // ── Init tests ───────────────────────────────────────────────────

    /// Helper: configure mock for a successful init sequence.
    fn mock_init_flow(bus: &mut MockSpiBus) {
        // DID_VID probe
        bus.on_register(TPM_DID_VID, vec![0x15, 0xD1, 0x00, 0x1A]);

        // Startup command flow
        bus.on_register(TPM_ACCESS, vec![0x90]); // valid + active
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]); // commandReady
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]); // burstCount=64
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]); // dataAvail
        // Startup success response (FIFO — consumed across CS cycles)
        bus.on_fifo(TPM_DATA_FIFO, vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0A,
            0x00, 0x00, 0x00, 0x00,
        ]);

        // SelfTest command flow
        bus.on_register(TPM_ACCESS, vec![0x90]);
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        // SelfTest response (appended to same FIFO)
        bus.on_fifo(TPM_DATA_FIFO, vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0A,
            0x00, 0x00, 0x00, 0x00,
        ]);
    }

    #[test]
    fn init_succeeds_and_transitions_to_ready() {
        let mut bus = MockSpiBus::new();
        mock_init_flow(&mut bus);

        let driver = TpmDriver::init(bus).unwrap();
        assert_eq!(driver.state(), TpmState::Ready);
    }

    #[test]
    fn init_accepts_tpm_rc_initialize() {
        let mut bus = MockSpiBus::new();
        // DID_VID probe
        bus.on_register(TPM_DID_VID, vec![0x15, 0xD1, 0x00, 0x1A]);

        // Startup returns TPM_RC_INITIALIZE (0x100) — firmware already started
        bus.on_register(TPM_ACCESS, vec![0x90]);
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_fifo(TPM_DATA_FIFO, vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0A,
            0x00, 0x00, 0x01, 0x00, // RC = 0x100
        ]);

        // SelfTest succeeds
        bus.on_register(TPM_ACCESS, vec![0x90]);
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_fifo(TPM_DATA_FIFO, vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0A,
            0x00, 0x00, 0x00, 0x00,
        ]);

        let driver = TpmDriver::init(bus).unwrap();
        assert_eq!(driver.state(), TpmState::Ready);
    }

    #[test]
    fn init_locality_unavailable() {
        let mut bus = MockSpiBus::new();
        bus.on_register(TPM_DID_VID, vec![0x15, 0xD1, 0x00, 0x1A]);
        // TPM_ACCESS without valid bit
        bus.on_register(TPM_ACCESS, vec![0x00]);

        let err = TpmDriver::init(bus).unwrap_err();
        assert_eq!(err, TpmError::LocalityUnavailable);
    }
```

- [ ] **Step 2: Implement init()**

Add a new impl block:

```rust
// ── Initialization (Layer 3) ─────────────────────────────────────────

/// TPM_RC_INITIALIZE — returned when Startup was already called by firmware.
const TPM_RC_INITIALIZE: u32 = 0x00000100;

impl<S: SpiBus> TpmDriver<S> {
    /// Initialize the TPM: probe DID/VID, run Startup + SelfTest.
    pub fn init(bus: S) -> Result<Self, TpmError> {
        let mut driver = Self {
            bus,
            state: TpmState::Uninitialized,
        };

        // Step 1: Probe DID/VID
        let mut did_vid = [0u8; 4];
        driver.read_register(TPM_DID_VID, &mut did_vid)?;
        // Don't hard-reject unknown vendors — just verify SPI works

        // Step 2: TPM2_Startup(TPM_SU_CLEAR)
        // Tag=0x8001 (NO_SESSIONS), Size=12, CC=0x00000144, SU=0x0000
        let startup_cmd = [
            0x80, 0x01,
            0x00, 0x00, 0x00, 0x0C,
            0x00, 0x00, 0x01, 0x44,
            0x00, 0x00,
        ];
        let mut resp = [0u8; 64];
        match driver.execute_command(&startup_cmd, &mut resp) {
            Ok(_) => {}
            Err(TpmError::CommandFailed { rc }) if rc == TPM_RC_INITIALIZE => {
                // Firmware already called Startup — that's fine
            }
            Err(e) => return Err(e),
        }

        // Step 3: TPM2_SelfTest(fullTest=yes)
        // Tag=0x8001, Size=11, CC=0x00000143, fullTest=0x01
        let selftest_cmd = [
            0x80, 0x01,
            0x00, 0x00, 0x00, 0x0B,
            0x00, 0x00, 0x01, 0x43,
            0x01,
        ];
        driver.execute_command(&selftest_cmd, &mut resp)?;

        driver.state = TpmState::Ready;
        Ok(driver)
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel -- tpm`
Expected: 11 tests pass (8 from Tasks 2-3 + 3 new).

- [ ] **Step 4: Run CI parity**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/tpm.rs
git commit -m "feat(tpm): add init() with Startup + SelfTest

Probes DID/VID, sends TPM2_Startup (accepts TPM_RC_INITIALIZE if
firmware already started), runs TPM2_SelfTest. Transitions to Ready."
```

---

### Task 5: derive_hardware_key() — HMAC workflow

Add the public `derive_hardware_key()` that executes the 4-command HMAC workflow.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/tpm.rs`

**Context for implementer:** This is the most complex task. The 4 commands are:

1. **TPM2_CreatePrimary** — tag=0x8002 (SESSIONS), CC=0x00000131, handle=TPM_RH_OWNER (0x40000001). Requires PWAP auth session: sessionHandle=TPM_RS_PW (0x40000009), nonceCaller=empty, sessionAttributes=0x01, hmac=empty. The template specifies TPM_ALG_KEYEDHASH (0x0008) with SHA256 (0x000B). Response includes a 4-byte object handle at bytes 10-13.

2. **TPM2_PCR_Read** — tag=0x8001, CC=0x0000017E. Parameter: TPML_PCR_SELECTION with count=1, hash=SHA256, sizeOfSelect=3, PCR bitmask. Response includes TPML_DIGEST with the PCR values.

3. **TPM2_HMAC** — tag=0x8002 (SESSIONS), CC=0x00000155, handle=object from CreatePrimary. PWAP auth. Input: concatenated PCR digests + salt. hashAlg=SHA256. Response includes 32-byte HMAC.

4. **TPM2_FlushContext** — tag=0x8001, CC=0x00000165, handle=object from CreatePrimary. No auth.

Given the complexity of TPM2_CreatePrimary's template structure, hand-building the command bytes is the pragmatic approach for this first implementation. The commands are fixed (same template every time), so we can use pre-built byte arrays with only the variable parts (handle, PCR indices, HMAC input) patched in.

**NOTE:** The spec's `TpmState::KeyDerived` variant is intentionally omitted — the driver allows multiple calls to `derive_hardware_key` with different PCR sets. Only `Uninitialized` and `Ready` states are needed.

**NOTE:** The exact byte sequences for these commands are complex. The implementer should consult the TPM 2.0 spec Part 3 for exact field layouts, or use `tpm2-protocol` if the API is clear enough. If blocked on marshaling complexity, report NEEDS_CONTEXT — the controller can provide exact byte sequences.

- [ ] **Step 1: Write failing tests**

```rust
    // ── Key derivation tests ─────────────────────────────────────────

    #[test]
    fn derive_hardware_key_requires_ready_state() {
        let mut driver = make_driver(); // Uninitialized
        let err = driver.derive_hardware_key(&[0, 4], b"test-salt");
        assert_eq!(err.unwrap_err(), TpmError::InvalidState);
    }
```

Start with the state guard test. The full HMAC workflow tests require complex mock setup — implement the method first, then add comprehensive tests.

- [ ] **Step 2: Implement derive_hardware_key with state guard**

Add to the init impl block (or a new one):

```rust
    /// Derive a 32-byte hardware-bound key via TPM2 HMAC.
    ///
    /// Creates a primary HMAC key under the owner hierarchy, reads
    /// the specified PCR digests, HMACs them with the salt, and
    /// returns the 32-byte result.
    pub fn derive_hardware_key(
        &mut self,
        pcr_indices: &[u8],
        salt: &[u8],
    ) -> Result<[u8; 32], TpmError> {
        if self.state != TpmState::Ready {
            return Err(TpmError::InvalidState);
        }

        let mut resp = [0u8; 1024];

        // Step 1: TPM2_CreatePrimary — HMAC key under TPM_RH_OWNER
        let primary_handle = self.create_primary_hmac_key(&mut resp)?;

        // Step 2: TPM2_PCR_Read
        let pcr_digest = self.read_pcr_digests(pcr_indices, &mut resp)?;

        // Step 3: TPM2_HMAC — HMAC(primary_key, pcr_digest || salt)
        let mut hmac_input = [0u8; 512];
        let input_len = pcr_digest.len() + salt.len();
        hmac_input[..pcr_digest.len()].copy_from_slice(&pcr_digest);
        hmac_input[pcr_digest.len()..input_len].copy_from_slice(salt);
        let key = self.hmac_with_key(primary_handle, &hmac_input[..input_len], &mut resp)?;

        // Step 4: TPM2_FlushContext
        self.flush_context(primary_handle, &mut resp)?;

        Ok(key)
    }
```

Then implement each helper method (`create_primary_hmac_key`, `read_pcr_digests`, `hmac_with_key`, `flush_context`). These build the raw command bytes and call `execute_command`. The exact byte layouts depend on the TPM 2.0 spec — the implementer should hand-build minimal commands.

**If the implementer is blocked on the exact byte sequences for CreatePrimary's complex template, they should report NEEDS_CONTEXT.** The controller will provide the exact pre-built byte arrays.

- [ ] **Step 3: Add comprehensive tests once implementation compiles**

After the helper methods are implemented, add tests that mock all 4 command responses and verify the 32-byte output. Also add:
- Same PCR values + salt → same key (deterministic)
- Different PCR values → different key

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-unikernel -- tpm`
Expected: all tests pass.

- [ ] **Step 5: Run CI parity**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/tpm.rs
git commit -m "feat(tpm): add derive_hardware_key HMAC workflow

CreatePrimary → PCR_Read → HMAC → FlushContext. Derives a 32-byte
hardware-bound key from TPM primary seed + PCR digests + caller salt."
```

---

### Task 6: Integration test — full lifecycle

Verify the complete init → derive_hardware_key pipeline.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/tpm.rs`

- [ ] **Step 1: Write integration test**

```rust
    // ── Integration test ─────────────────────────────────────────────

    #[test]
    fn full_tpm_lifecycle() {
        // This test exercises: init → derive_hardware_key → verify output
        // Uses the mock helpers from previous tasks to set up the full
        // command flow for init (Startup + SelfTest) followed by
        // derive_hardware_key (CreatePrimary + PCR_Read + HMAC + FlushContext).
        //
        // The exact mock setup depends on the command byte layouts from Task 5.
        // Verify:
        // - init succeeds (Ready state)
        // - derive_hardware_key returns a 32-byte key
        // - The key is non-zero (not all zeros)
    }
```

The implementer should fill in the mock setup based on the command formats from Task 5.

- [ ] **Step 2: Run full suite + CI parity**

Run: `cargo test -p harmony-unikernel -- tpm && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 3: Run full workspace tests**

Run: `cargo test --workspace`

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/tpm.rs
git commit -m "test(tpm): add full lifecycle integration test

init → derive_hardware_key → verify 32-byte hardware-bound key output."
```
