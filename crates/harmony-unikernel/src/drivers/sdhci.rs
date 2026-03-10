// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O SDHCI SD card driver.
//!
//! Implements the standard SDHCI register interface for PIO-mode
//! SD card access. Uses [`RegisterBank`] for all register access,
//! enabling full unit testing without hardware.

use super::register_bank::RegisterBank;

// ── SDHCI register offsets ──────────────────────────────────────
const SDHCI_ARGUMENT: usize = 0x08;
const SDHCI_COMMAND: usize = 0x0E;
const SDHCI_RESPONSE_0: usize = 0x10;
const SDHCI_RESPONSE_1: usize = 0x14;
const SDHCI_RESPONSE_2: usize = 0x18;
const SDHCI_RESPONSE_3: usize = 0x1C;
const SDHCI_BUFFER_DATA: usize = 0x20;
const SDHCI_PRESENT_STATE: usize = 0x24;
const SDHCI_CLOCK_CONTROL: usize = 0x2C;
const SDHCI_SOFTWARE_RESET: usize = 0x2F;
const SDHCI_INT_STATUS: usize = 0x30;
const SDHCI_ERR_INT_STATUS: usize = 0x38;

// ── Present state bits ──────────────────────────────────────────
const STATE_CMD_INHIBIT: u32 = 1 << 0;

// ── Interrupt status bits ───────────────────────────────────────
const INT_CMD_COMPLETE: u32 = 1 << 0;
const INT_BUFFER_WRITE_READY: u32 = 1 << 4;
const INT_BUFFER_READ_READY: u32 = 1 << 5;
const INT_ERROR: u32 = 1 << 15;

// ── Error interrupt bits ────────────────────────────────────────
const ERR_CMD_TIMEOUT: u32 = 1 << 0;
const ERR_CMD_CRC: u32 = 1 << 1;
const ERR_CMD_INDEX: u32 = 1 << 3;
const ERR_DATA_TIMEOUT: u32 = 1 << 4;

// ── Clock control bits ──────────────────────────────────────────
const CLOCK_INTERNAL_EN: u32 = 1 << 0;
const CLOCK_INTERNAL_STABLE: u32 = 1 << 1;
const CLOCK_SD_EN: u32 = 1 << 2;
const CLOCK_DIVIDER_SHIFT: u32 = 8;

// ── Software reset bits ─────────────────────────────────────────
const RESET_ALL: u32 = 1 << 0;

// ── Command register encoding ───────────────────────────────────
const CMD_INDEX_SHIFT: u32 = 8;
const CMD_RESP_NONE: u32 = 0x00;
const CMD_RESP_136: u32 = 0x01; // R2
const CMD_RESP_48: u32 = 0x02; // R1, R3, R6, R7
const CMD_RESP_48_BUSY: u32 = 0x03; // R1b
const CMD_CRC_CHECK: u32 = 1 << 3;
const CMD_INDEX_CHECK: u32 = 1 << 4;

// ── SD command numbers ──────────────────────────────────────────
const CMD0_GO_IDLE: u8 = 0;
const CMD2_ALL_SEND_CID: u8 = 2;
const CMD3_SEND_RCA: u8 = 3;
const CMD7_SELECT_CARD: u8 = 7;
const CMD8_SEND_IF_COND: u8 = 8;
const CMD16_SET_BLOCKLEN: u8 = 16;
const CMD55_APP_CMD: u8 = 55;
const ACMD41_SD_SEND_OP_COND: u8 = 41;

const SD_BLOCK_SIZE: usize = 512;

/// Errors returned by SD/eMMC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdError {
    /// Card not inserted or not detected.
    NoCard,
    /// Command timed out.
    Timeout,
    /// CRC check failed.
    CrcError,
    /// Command index mismatch.
    IndexError,
    /// Data transfer error.
    DataError,
    /// Controller is busy (command or data inhibit set).
    Busy,
    /// Software reset did not complete.
    ResetFailed,
    /// Clock did not stabilize.
    ClockUnstable,
    /// Card initialization failed (ACMD41 never ready).
    InitFailed,
}

/// Response from an SD command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    None,
    Short(u32),
    Long([u32; 4]),
}

/// Card state after initialization.
#[derive(Debug, Clone, Copy)]
pub struct CardInfo {
    /// Relative Card Address (from CMD3).
    pub rca: u16,
    /// Card capacity in blocks (512 bytes each).
    pub capacity_blocks: u32,
}

/// Sans-I/O SDHCI driver.
///
/// All operations take a `&mut impl RegisterBank` for register access.
/// No internal state beyond the card info learned during init.
pub struct SdhciDriver {
    card: Option<CardInfo>,
}

impl SdhciDriver {
    pub fn new() -> Self {
        Self { card: None }
    }

    /// Get card info (available after successful init_card).
    pub fn card_info(&self) -> Option<&CardInfo> {
        self.card.as_ref()
    }

    /// Software reset. Writes RESET_ALL and polls until the bit clears.
    /// Uses a bounded poll loop (max 1000 iterations) to avoid infinite spin.
    pub fn reset(&mut self, bank: &mut impl RegisterBank) -> Result<(), SdError> {
        bank.write(SDHCI_SOFTWARE_RESET, RESET_ALL);
        for _ in 0..1000 {
            if bank.read(SDHCI_SOFTWARE_RESET) & RESET_ALL == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SdError::ResetFailed)
    }

    /// Configure SD clock. Sets divider, enables internal clock,
    /// waits for stability, then enables SD clock output.
    pub fn set_clock(
        &mut self,
        bank: &mut impl RegisterBank,
        freq_khz: u32,
    ) -> Result<(), SdError> {
        // Disable SD clock first
        bank.write(SDHCI_CLOCK_CONTROL, 0);

        // Calculate divider (base clock assumed 200 MHz)
        // Divider = base_clock / (2 * target_freq)
        // For 400 kHz: 200_000 / (2 * 400) = 250
        let divider = if freq_khz > 0 {
            200_000 / (2 * freq_khz)
        } else {
            250
        };
        let clock_val = (divider << CLOCK_DIVIDER_SHIFT) | CLOCK_INTERNAL_EN;
        bank.write(SDHCI_CLOCK_CONTROL, clock_val);

        // Wait for internal clock stable
        for _ in 0..1000 {
            if bank.read(SDHCI_CLOCK_CONTROL) & CLOCK_INTERNAL_STABLE != 0 {
                // Enable SD clock
                let current = bank.read(SDHCI_CLOCK_CONTROL);
                bank.write(SDHCI_CLOCK_CONTROL, current | CLOCK_SD_EN);
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SdError::ClockUnstable)
    }

    /// Send an SD command and wait for completion.
    ///
    /// `cmd_flags` encodes response type, CRC check, and index check bits.
    pub fn send_command(
        &mut self,
        bank: &mut impl RegisterBank,
        cmd: u8,
        arg: u32,
        cmd_flags: u32,
    ) -> Result<Response, SdError> {
        // Check command inhibit
        if bank.read(SDHCI_PRESENT_STATE) & STATE_CMD_INHIBIT != 0 {
            return Err(SdError::Busy);
        }

        // Clear interrupt status
        bank.write(SDHCI_INT_STATUS, 0xFFFF_FFFF);

        // Write argument
        bank.write(SDHCI_ARGUMENT, arg);

        // Write command (index + flags)
        let cmd_reg = ((cmd as u32) << CMD_INDEX_SHIFT) | cmd_flags;
        bank.write(SDHCI_COMMAND, cmd_reg);

        // Poll for completion
        for _ in 0..100_000 {
            let status = bank.read(SDHCI_INT_STATUS);
            if status & INT_ERROR != 0 {
                let err = bank.read(SDHCI_ERR_INT_STATUS);
                // Clear status
                bank.write(SDHCI_INT_STATUS, status);
                return Err(Self::decode_error(err));
            }
            if status & INT_CMD_COMPLETE != 0 {
                // Clear command complete
                bank.write(SDHCI_INT_STATUS, INT_CMD_COMPLETE);
                return Ok(self.read_response(bank, cmd_flags));
            }
            core::hint::spin_loop();
        }
        Err(SdError::Timeout)
    }

    fn decode_error(err_bits: u32) -> SdError {
        if err_bits & ERR_CMD_TIMEOUT != 0 {
            SdError::Timeout
        } else if err_bits & ERR_CMD_CRC != 0 {
            SdError::CrcError
        } else if err_bits & ERR_CMD_INDEX != 0 {
            SdError::IndexError
        } else if err_bits & ERR_DATA_TIMEOUT != 0 {
            SdError::Timeout
        } else {
            // Covers ERR_DATA_CRC and any other unrecognized error bits.
            SdError::DataError
        }
    }

    fn read_response(&self, bank: &impl RegisterBank, cmd_flags: u32) -> Response {
        let resp_type = cmd_flags & 0x03;
        match resp_type {
            0x00 => Response::None, // CMD_RESP_NONE
            0x01 => Response::Long([
                // CMD_RESP_136 (R2)
                bank.read(SDHCI_RESPONSE_0),
                bank.read(SDHCI_RESPONSE_1),
                bank.read(SDHCI_RESPONSE_2),
                bank.read(SDHCI_RESPONSE_3),
            ]),
            _ => Response::Short(bank.read(SDHCI_RESPONSE_0)), // CMD_RESP_48, CMD_RESP_48_BUSY
        }
    }

    /// Read a single 512-byte block via PIO.
    /// Polls BUFFER_READ_READY then reads 128 u32 words from the data port.
    pub fn read_block(
        &mut self,
        bank: &mut impl RegisterBank,
        buf: &mut [u8; 512],
    ) -> Result<(), SdError> {
        // Wait for buffer read ready
        for _ in 0..100_000 {
            let status = bank.read(SDHCI_INT_STATUS);
            if status & INT_ERROR != 0 {
                return Err(SdError::DataError);
            }
            if status & INT_BUFFER_READ_READY != 0 {
                bank.write(SDHCI_INT_STATUS, INT_BUFFER_READ_READY);
                // Read 128 x u32 = 512 bytes
                for i in 0..128 {
                    let word = bank.read(SDHCI_BUFFER_DATA);
                    let offset = i * 4;
                    buf[offset] = word as u8;
                    buf[offset + 1] = (word >> 8) as u8;
                    buf[offset + 2] = (word >> 16) as u8;
                    buf[offset + 3] = (word >> 24) as u8;
                }
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SdError::Timeout)
    }

    /// Write a single 512-byte block via PIO.
    /// Polls BUFFER_WRITE_READY then writes 128 u32 words to the data port.
    pub fn write_block(
        &mut self,
        bank: &mut impl RegisterBank,
        buf: &[u8; 512],
    ) -> Result<(), SdError> {
        // Wait for buffer write ready
        for _ in 0..100_000 {
            let status = bank.read(SDHCI_INT_STATUS);
            if status & INT_ERROR != 0 {
                return Err(SdError::DataError);
            }
            if status & INT_BUFFER_WRITE_READY != 0 {
                bank.write(SDHCI_INT_STATUS, INT_BUFFER_WRITE_READY);
                // Write 128 x u32 = 512 bytes
                for i in 0..128 {
                    let offset = i * 4;
                    let word = buf[offset] as u32
                        | (buf[offset + 1] as u32) << 8
                        | (buf[offset + 2] as u32) << 16
                        | (buf[offset + 3] as u32) << 24;
                    bank.write(SDHCI_BUFFER_DATA, word);
                }
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SdError::Timeout)
    }

    /// Initialize the SD card.
    ///
    /// Performs the standard SD card init sequence:
    /// CMD0 -> CMD8 -> ACMD41 loop -> CMD2 -> CMD3 -> CMD7 -> CMD16
    pub fn init_card(&mut self, bank: &mut impl RegisterBank) -> Result<CardInfo, SdError> {
        // CMD0: GO_IDLE_STATE (no response)
        self.send_command(bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE)?;

        // CMD8: SEND_IF_COND (voltage check, 0x1AA pattern)
        self.send_command(
            bank,
            CMD8_SEND_IF_COND,
            0x1AA,
            CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK,
        )?;

        // ACMD41 loop: wait for card to become ready
        // Must send CMD55 (APP_CMD) before each ACMD41
        let mut ocr = 0u32;
        for _ in 0..100 {
            // CMD55: APP_CMD (next command is application-specific)
            self.send_command(
                bank,
                CMD55_APP_CMD,
                0,
                CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK,
            )?;

            // ACMD41: SD_SEND_OP_COND
            // Arg: HCS (bit 30) + voltage window (3.2-3.4V = bit 20)
            let resp = self.send_command(bank, ACMD41_SD_SEND_OP_COND, 0x40100000, CMD_RESP_48)?;

            if let Response::Short(r) = resp {
                if r & (1 << 31) != 0 {
                    // Card is ready (busy bit cleared)
                    ocr = r;
                    break;
                }
            }
        }
        if ocr == 0 {
            return Err(SdError::InitFailed);
        }

        // CMD2: ALL_SEND_CID (get card identification)
        self.send_command(bank, CMD2_ALL_SEND_CID, 0, CMD_RESP_136)?;

        // CMD3: SEND_RELATIVE_ADDR (get RCA)
        let rca = match self.send_command(
            bank,
            CMD3_SEND_RCA,
            0,
            CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK,
        )? {
            Response::Short(r) => (r >> 16) as u16,
            _ => return Err(SdError::InitFailed),
        };

        // CMD7: SELECT_CARD
        self.send_command(
            bank,
            CMD7_SELECT_CARD,
            (rca as u32) << 16,
            CMD_RESP_48_BUSY | CMD_CRC_CHECK | CMD_INDEX_CHECK,
        )?;

        // CMD16: SET_BLOCKLEN (512 bytes)
        self.send_command(
            bank,
            CMD16_SET_BLOCKLEN,
            SD_BLOCK_SIZE as u32,
            CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK,
        )?;

        // Determine capacity (simplified: use OCR to check SDHC)
        // SDHC cards (CCS bit set in OCR) use block addressing
        let capacity_blocks = if ocr & (1 << 30) != 0 {
            // SDHC/SDXC: capacity would come from CSD, use placeholder
            // Real implementation would send CMD9 to read CSD
            0
        } else {
            // SDSC: capacity would come from CSD
            0
        };

        let info = CardInfo {
            rca,
            capacity_blocks,
        };
        self.card = Some(info);
        Ok(info)
    }
}

impl Default for SdhciDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;

    #[test]
    fn reset_writes_reset_all_and_polls() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // First read: RESET_ALL still set, second read: cleared
        bank.on_read(SDHCI_SOFTWARE_RESET, vec![RESET_ALL, 0]);
        driver.reset(&mut bank).unwrap();
        assert!(bank.writes.contains(&(SDHCI_SOFTWARE_RESET, RESET_ALL)));
    }

    #[test]
    fn reset_fails_if_never_clears() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Always returns RESET_ALL (never clears) — sticky last value
        bank.on_read(SDHCI_SOFTWARE_RESET, vec![RESET_ALL]);
        assert_eq!(driver.reset(&mut bank), Err(SdError::ResetFailed));
    }

    #[test]
    fn set_clock_enables_internal_then_sd_clock() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Clock stable on first poll
        bank.on_read(
            SDHCI_CLOCK_CONTROL,
            vec![CLOCK_INTERNAL_STABLE, CLOCK_INTERNAL_STABLE],
        );
        // 400 kHz for init
        driver.set_clock(&mut bank, 400).unwrap();
        // Should write: disable, then divider+internal_en, then after stable check, SD enable
        let clock_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_CLOCK_CONTROL)
            .map(|(_, v)| *v)
            .collect();
        assert!(clock_writes.len() >= 2);
        // First write should be 0 (disable)
        assert_eq!(clock_writes[0], 0);
    }

    #[test]
    fn set_clock_fails_if_not_stable() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Never stable — sticky 0
        bank.on_read(SDHCI_CLOCK_CONTROL, vec![0]);
        assert_eq!(
            driver.set_clock(&mut bank, 400),
            Err(SdError::ClockUnstable)
        );
    }

    #[test]
    fn send_command_writes_arg_and_cmd() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Not inhibited
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        // Command completes immediately
        bank.on_read(SDHCI_INT_STATUS, vec![INT_CMD_COMPLETE]);
        // Response
        bank.on_read(SDHCI_RESPONSE_0, vec![0x1234]);

        let resp = driver
            .send_command(
                &mut bank,
                CMD8_SEND_IF_COND,
                0x1AA,
                CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK,
            )
            .unwrap();
        assert_eq!(resp, Response::Short(0x1234));
        assert!(bank.writes.contains(&(SDHCI_ARGUMENT, 0x1AA)));
    }

    #[test]
    fn send_command_returns_timeout_on_error() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        bank.on_read(SDHCI_INT_STATUS, vec![INT_ERROR]);
        bank.on_read(SDHCI_ERR_INT_STATUS, vec![ERR_CMD_TIMEOUT]);

        let result = driver.send_command(&mut bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE);
        assert_eq!(result, Err(SdError::Timeout));
    }

    #[test]
    fn send_command_returns_crc_error() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        bank.on_read(SDHCI_INT_STATUS, vec![INT_ERROR]);
        bank.on_read(SDHCI_ERR_INT_STATUS, vec![ERR_CMD_CRC]);

        let result = driver.send_command(&mut bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE);
        assert_eq!(result, Err(SdError::CrcError));
    }

    #[test]
    fn send_command_busy_returns_error() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        bank.on_read(SDHCI_PRESENT_STATE, vec![STATE_CMD_INHIBIT]);

        let result = driver.send_command(&mut bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE);
        assert_eq!(result, Err(SdError::Busy));
    }

    #[test]
    fn read_block_reads_512_bytes_from_data_port() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Buffer read ready
        bank.on_read(SDHCI_INT_STATUS, vec![INT_BUFFER_READ_READY]);
        // 128 reads of 4 bytes each = 512 bytes
        let mut data_values = Vec::new();
        for i in 0..128u32 {
            data_values.push(i);
        }
        bank.on_read(SDHCI_BUFFER_DATA, data_values);

        let mut buf = [0u8; 512];
        driver.read_block(&mut bank, &mut buf).unwrap();
        // First 4 bytes should be u32 value 0 in little-endian
        assert_eq!(buf[0..4], [0, 0, 0, 0]);
        // Bytes 4-7 should be u32 value 1
        assert_eq!(buf[4..8], [1, 0, 0, 0]);
    }

    #[test]
    fn write_block_writes_512_bytes_to_data_port() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Buffer write ready
        bank.on_read(SDHCI_INT_STATUS, vec![INT_BUFFER_WRITE_READY]);

        let mut buf = [0u8; 512];
        buf[0] = 0xAB;
        buf[1] = 0xCD;
        buf[2] = 0xEF;
        buf[3] = 0x01;
        driver.write_block(&mut bank, &buf).unwrap();

        // First data write should be 0x01EFCDAB (little-endian)
        let data_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_BUFFER_DATA)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(data_writes.len(), 128);
        assert_eq!(data_writes[0], 0x01EFCDAB);
    }

    #[test]
    fn init_card_sends_correct_command_sequence() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();

        // Set up mock for the full init sequence:
        // Each send_command reads: PRESENT_STATE (not inhibited), INT_STATUS (cmd complete),
        // RESPONSE_0. We need enough responses for: CMD0, CMD8, CMD55, ACMD41, CMD2, CMD3,
        // CMD7, CMD16. That's 8 commands.

        // Present state: never inhibited
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);

        // INT_STATUS sequence: each command completes immediately
        bank.on_read(SDHCI_INT_STATUS, vec![INT_CMD_COMPLETE]);

        // Responses:
        // CMD0: no response needed (RESP_NONE)
        // CMD8: returns 0x1AA
        bank.on_read(
            SDHCI_RESPONSE_0,
            vec![
                0x1AA,      // CMD8 response
                0x0120,     // CMD55 response (app cmd accepted)
                0x80100000, // ACMD41 response (ready, bit 31 set, CCS bit 30 set)
                0,          // CMD2 uses RESP_136, reads all 4 response regs
                0x12340000, // CMD3 response (RCA = 0x1234 in upper 16 bits)
                0,          // CMD7 response
                0,          // CMD16 response
            ],
        );
        bank.on_read(SDHCI_RESPONSE_1, vec![0]); // for CMD2 R2 response
        bank.on_read(SDHCI_RESPONSE_2, vec![0]);
        bank.on_read(SDHCI_RESPONSE_3, vec![0]);

        let info = driver.init_card(&mut bank).unwrap();
        assert_eq!(info.rca, 0x1234);

        // Verify the command sequence by checking SDHCI_COMMAND writes
        let cmd_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_COMMAND)
            .map(|(_, v)| *v)
            .collect();

        // CMD0: (0 << 8) | RESP_NONE = 0x0000
        // CMD8: (8 << 8) | RESP_48 | CRC | INDEX = 0x081A
        // CMD55: (55 << 8) | RESP_48 | CRC | INDEX = 0x371A
        // ACMD41: (41 << 8) | RESP_48 = 0x2902
        // CMD2: (2 << 8) | RESP_136 = 0x0201
        // CMD3: (3 << 8) | RESP_48 | CRC | INDEX = 0x031A
        // CMD7: (7 << 8) | RESP_48_BUSY | CRC | INDEX = 0x071B
        // CMD16: (16 << 8) | RESP_48 | CRC | INDEX = 0x101A
        assert_eq!(cmd_writes.len(), 8);
        // Verify command indices (upper byte)
        assert_eq!(cmd_writes[0] >> 8, 0); // CMD0
        assert_eq!(cmd_writes[1] >> 8, 8); // CMD8
        assert_eq!(cmd_writes[2] >> 8, 55); // CMD55
        assert_eq!(cmd_writes[3] >> 8, 41); // ACMD41
        assert_eq!(cmd_writes[4] >> 8, 2); // CMD2
        assert_eq!(cmd_writes[5] >> 8, 3); // CMD3
        assert_eq!(cmd_writes[6] >> 8, 7); // CMD7
        assert_eq!(cmd_writes[7] >> 8, 16); // CMD16
    }
}
