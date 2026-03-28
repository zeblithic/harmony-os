// SPDX-License-Identifier: GPL-2.0-or-later

//! TPM 2.0 driver for hardware key derivation.
//!
//! Three-layer architecture:
//! 1. **SPI PTP transport** — register read/write over [`SpiBus`]
//! 2. **Command engine** — FIFO-based command execution
//! 3. **Key derivation** — HMAC workflow for hardware-bound keys
//!
//! Uses the [`tpm2_protocol`] crate for command marshaling.

#[allow(unused_imports)]
use tpm2_protocol as tpm2;

use super::spi_bus::SpiBus;

// ── TPM register addresses (Locality 0) ──────────────────────────────

#[allow(dead_code)]
const TPM_ACCESS: u32 = 0xD4_0000;
#[allow(dead_code)]
const TPM_STS: u32 = 0xD4_0018;
#[allow(dead_code)]
const TPM_DATA_FIFO: u32 = 0xD4_0024;
#[allow(dead_code)]
const TPM_DID_VID: u32 = 0xD4_0F00;

// ── TPM_ACCESS bit masks ─────────────────────────────────────────────

#[allow(dead_code)]
const ACCESS_VALID: u8 = 1 << 7; // tpmRegValidSts
#[allow(dead_code)]
const ACCESS_ACTIVE: u8 = 1 << 4; // activeLocality
#[allow(dead_code)]
const ACCESS_REQUEST: u8 = 1 << 1; // requestUse

// ── TPM_STS bit masks ────────────────────────────────────────────────

#[allow(dead_code)]
const STS_COMMAND_READY: u32 = 1 << 6;
#[allow(dead_code)]
const STS_TPM_GO: u32 = 1 << 5;
#[allow(dead_code)]
const STS_DATA_AVAIL: u32 = 1 << 4;

/// Maximum wait-state polling iterations before timeout.
#[allow(dead_code)]
const MAX_WAIT_CYCLES: usize = 10_000;
/// Maximum status register polling iterations.
#[allow(dead_code)]
const MAX_POLL_CYCLES: usize = 100_000;
/// Maximum bytes per SPI register transfer (stack buffer size).
#[allow(dead_code)]
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
    #[allow(dead_code)]
    bus: S,
    state: TpmState,
}

// ── SPI PTP transport (Layer 1) ──────────────────────────────────────

#[allow(dead_code)]
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
        driver.bus.on_register(TPM_DID_VID, vec![0x00]);
        driver
            .bus
            .set_wait_states(TPM_DID_VID, MAX_WAIT_CYCLES + 100);

        let mut buf = [0u8; 4];
        assert_eq!(
            driver.read_register(TPM_DID_VID, &mut buf).unwrap_err(),
            TpmError::Timeout
        );
    }
}
