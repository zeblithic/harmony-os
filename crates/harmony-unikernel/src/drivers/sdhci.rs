// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O SDHCI SD card driver.
//!
//! Implements the standard SDHCI register interface for PIO-mode
//! SD card access. Uses [`RegisterBank`] for all register access,
//! enabling full unit testing without hardware.

use super::register_bank::RegisterBank;

// ── SDHCI register offsets (all 32-bit aligned) ─────────────────
//
// RegisterBank performs 32-bit accesses only.  Sub-32-bit SDHCI
// registers are accessed through the enclosing aligned word:
//   0x04: [Block Size (16) | Block Count (16)]
//   0x2C: [Clock Control (16) | Timeout Control (8) | Software Reset (8)]
//   0x30: [Normal Interrupt Status (16) | Error Interrupt Status (16)]
const SDHCI_BLOCK_SIZE: usize = 0x04; // also packs Block Count in upper 16
const SDHCI_ARGUMENT: usize = 0x08;
const SDHCI_RESPONSE_0: usize = 0x10;
const SDHCI_RESPONSE_1: usize = 0x14;
const SDHCI_RESPONSE_2: usize = 0x18;
const SDHCI_RESPONSE_3: usize = 0x1C;
const SDHCI_BUFFER_DATA: usize = 0x20;
const SDHCI_PRESENT_STATE: usize = 0x24;
const SDHCI_CLOCK_CONTROL: usize = 0x2C; // also packs Timeout Control + Software Reset
const SDHCI_INT_STATUS: usize = 0x30; // also packs Error Interrupt Status in upper 16

// ── Present state bits ──────────────────────────────────────────
const STATE_CMD_INHIBIT: u32 = 1 << 0;
const STATE_DAT_INHIBIT: u32 = 1 << 1;

// ── Interrupt status bits ───────────────────────────────────────
const INT_CMD_COMPLETE: u32 = 1 << 0;
const INT_TRANSFER_COMPLETE: u32 = 1 << 1;
const INT_BUFFER_WRITE_READY: u32 = 1 << 4;
const INT_BUFFER_READ_READY: u32 = 1 << 5;
const INT_ERROR: u32 = 1 << 15;

// ── Error interrupt bits (within Error Interrupt Status, bits [31:16] of 0x30)
const ERR_CMD_TIMEOUT: u32 = 1 << 0;
const ERR_CMD_CRC: u32 = 1 << 1;
const ERR_CMD_INDEX: u32 = 1 << 3;
const ERR_DATA_TIMEOUT: u32 = 1 << 4;

// ── Clock control bits ──────────────────────────────────────────
const CLOCK_INTERNAL_EN: u32 = 1 << 0;
const CLOCK_INTERNAL_STABLE: u32 = 1 << 1;
const CLOCK_SD_EN: u32 = 1 << 2;
const CLOCK_DIVIDER_SHIFT: u32 = 8;

// ── Software reset bits (at bits [31:24] of the 32-bit word at 0x2C)
const RESET_ALL: u32 = 1 << 0; // bit position within the Software Reset byte

// ── Command register encoding ───────────────────────────────────
// These values encode bits within the 16-bit Command register (upper
// half of the combined 32-bit write at SDHCI_TRANSFER_MODE).
const CMD_INDEX_SHIFT: u32 = 8;
const CMD_RESP_NONE: u32 = 0x00;
const CMD_RESP_136: u32 = 0x01; // R2
const CMD_RESP_48: u32 = 0x02; // R1, R3, R6, R7
const CMD_RESP_48_BUSY: u32 = 0x03; // R1b
const CMD_CRC_CHECK: u32 = 1 << 3;
const CMD_INDEX_CHECK: u32 = 1 << 4;

// ── Transfer mode / data-present bits ────────────────────────────
// SDHCI Transfer Mode (0x0C) and Command (0x0E) are adjacent 16-bit
// registers. We issue a single aligned 32-bit write at 0x0C:
//   bits 15:0  = Transfer Mode
//   bits 31:16 = Command
// Writing the Command portion triggers the command on the SD bus.
const SDHCI_TRANSFER_MODE: usize = 0x0C;
const CMD_DATA_PRESENT: u32 = 1 << 5;
const XFER_READ: u32 = 1 << 4;

// ── Timeout control ────────────────────────────────────────────
// Timeout Control is at byte 0x2E, i.e., bits [23:16] of the 0x2C word.
// 0x0E = maximum timeout (~2^27 TMCLK cycles, ~1 s at 200 MHz).
const TIMEOUT_VALUE: u32 = 0x0E;

// ── SD command numbers ──────────────────────────────────────────
const CMD0_GO_IDLE: u8 = 0;
const CMD2_ALL_SEND_CID: u8 = 2;
const CMD3_SEND_RCA: u8 = 3;
const CMD7_SELECT_CARD: u8 = 7;
const CMD8_SEND_IF_COND: u8 = 8;
const CMD16_SET_BLOCKLEN: u8 = 16;
const CMD17_READ_SINGLE: u8 = 17;
const CMD24_WRITE_SINGLE: u8 = 24;
const CMD9_SEND_CSD: u8 = 9;
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
    /// True for SDHC/SDXC (block-addressed), false for SDSC (byte-addressed).
    pub is_sdhc: bool,
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
    ///
    /// Software Reset is at byte 0x2F, i.e., bits [31:24] of the aligned
    /// 32-bit word at 0x2C. A full reset clears all controller state.
    pub fn reset(&mut self, bank: &mut impl RegisterBank) -> Result<(), SdError> {
        bank.write(SDHCI_CLOCK_CONTROL, RESET_ALL << 24);
        for _ in 0..1000 {
            if bank.read(SDHCI_CLOCK_CONTROL) & (RESET_ALL << 24) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SdError::ResetFailed)
    }

    /// Configure SD clock. Sets divider, enables internal clock,
    /// waits for stability, then enables SD clock output.
    ///
    /// The 32-bit word at 0x2C packs Clock Control (bits 15:0),
    /// Timeout Control (bits 23:16), and Software Reset (bits 31:24).
    /// Every write preserves the timeout value to avoid zeroing it.
    pub fn set_clock(
        &mut self,
        bank: &mut impl RegisterBank,
        freq_khz: u32,
    ) -> Result<(), SdError> {
        // Disable SD clock (preserve timeout in bits [23:16])
        bank.write(SDHCI_CLOCK_CONTROL, TIMEOUT_VALUE << 16);

        // Calculate divider (base clock assumed 200 MHz)
        // Divider = base_clock / (2 * target_freq)
        // For 400 kHz: 200_000 / (2 * 400) = 250
        // Clamped to 255 — the SDCLK Frequency Select field is 8 bits (bits 15:8).
        let divider = if freq_khz > 0 {
            (200_000 / (2 * freq_khz)).min(255)
        } else {
            250
        };
        let clock_val = (divider << CLOCK_DIVIDER_SHIFT) | CLOCK_INTERNAL_EN;
        bank.write(SDHCI_CLOCK_CONTROL, (TIMEOUT_VALUE << 16) | clock_val);

        // Wait for internal clock stable
        for _ in 0..1000 {
            if bank.read(SDHCI_CLOCK_CONTROL) & CLOCK_INTERNAL_STABLE != 0 {
                // Enable SD clock (read-modify-write preserves timeout + divider)
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
    /// `cmd_flags` encodes response type, CRC check, index check, and
    /// data-present bits for the 16-bit Command register.
    /// `transfer_mode` is the 16-bit Transfer Mode value (0 for non-data
    /// commands, `XFER_READ` for reads, 0 for writes).
    ///
    /// Both values are packed into a single aligned 32-bit write at 0x0C
    /// to avoid an unaligned write at 0x0E that would overlap RESPONSE_0.
    pub fn send_command(
        &mut self,
        bank: &mut impl RegisterBank,
        cmd: u8,
        arg: u32,
        cmd_flags: u32,
        transfer_mode: u16,
    ) -> Result<Response, SdError> {
        // Check inhibit bits: CMD_INHIBIT for all commands,
        // plus DAT_INHIBIT for data-bearing commands (SDHCI §3.7.4).
        let inhibit_mask = if cmd_flags & CMD_DATA_PRESENT != 0 {
            STATE_CMD_INHIBIT | STATE_DAT_INHIBIT
        } else {
            STATE_CMD_INHIBIT
        };
        if bank.read(SDHCI_PRESENT_STATE) & inhibit_mask != 0 {
            return Err(SdError::Busy);
        }

        // Clear interrupt status
        bank.write(SDHCI_INT_STATUS, 0xFFFF_FFFF);

        // Write argument
        bank.write(SDHCI_ARGUMENT, arg);

        // Combined 32-bit write at 0x0C: transfer mode (low 16) + command (high 16).
        // Writing the command portion triggers the command on the SD bus.
        let cmd_reg = ((cmd as u32) << CMD_INDEX_SHIFT) | cmd_flags;
        bank.write(
            SDHCI_TRANSFER_MODE,
            (cmd_reg << 16) | (transfer_mode as u32),
        );

        // Poll for completion.
        // The 32-bit read at 0x30 gives us Normal Interrupt Status (bits 15:0)
        // and Error Interrupt Status (bits 31:16) in one access.
        for _ in 0..100_000 {
            let status = bank.read(SDHCI_INT_STATUS);
            if status & INT_ERROR != 0 {
                // Error details are in bits [31:16] (Error Interrupt Status)
                let err = status >> 16;
                // Clear both normal and error status (write-1-to-clear)
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

    /// Read a single 512-byte block from the card at the given LBA.
    ///
    /// Issues CMD17 (READ_SINGLE_BLOCK) with the LBA as argument,
    /// then performs PIO to transfer the data.
    pub fn read_single_block(
        &mut self,
        bank: &mut impl RegisterBank,
        lba: u32,
        buf: &mut [u8; 512],
    ) -> Result<(), SdError> {
        // Block Size (lower 16) + Block Count (upper 16) in one aligned write
        bank.write(SDHCI_BLOCK_SIZE, (1u32 << 16) | SD_BLOCK_SIZE as u32);
        // SDSC cards use byte addressing; SDHC/SDXC use block addressing
        let arg = self.lba_to_arg(lba)?;
        // Issue CMD17 with address (transfer mode included in combined write)
        self.send_command(
            bank,
            CMD17_READ_SINGLE,
            arg,
            CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK | CMD_DATA_PRESENT,
            XFER_READ as u16,
        )?;
        // PIO data transfer
        self.read_block(bank, buf)
    }

    /// Write a single 512-byte block to the card at the given LBA.
    ///
    /// Issues CMD24 (WRITE_SINGLE_BLOCK) with the LBA as argument,
    /// then performs PIO to transfer the data.
    pub fn write_single_block(
        &mut self,
        bank: &mut impl RegisterBank,
        lba: u32,
        buf: &[u8; 512],
    ) -> Result<(), SdError> {
        // Block Size (lower 16) + Block Count (upper 16) in one aligned write
        bank.write(SDHCI_BLOCK_SIZE, (1u32 << 16) | SD_BLOCK_SIZE as u32);
        // SDSC cards use byte addressing; SDHC/SDXC use block addressing
        let arg = self.lba_to_arg(lba)?;
        // Issue CMD24 with address (write direction = transfer_mode 0)
        self.send_command(
            bank,
            CMD24_WRITE_SINGLE,
            arg,
            CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK | CMD_DATA_PRESENT,
            0,
        )?;
        // PIO data transfer
        self.write_block(bank, buf)
    }

    /// Convert an LBA to the command argument based on card type.
    /// SDHC/SDXC cards use block addressing (LBA directly).
    /// SDSC cards use byte addressing (LBA * 512).
    /// Returns `NoCard` if no card has been initialized.
    fn lba_to_arg(&self, lba: u32) -> Result<u32, SdError> {
        match self.card {
            None => Err(SdError::NoCard),
            Some(c) if c.is_sdhc => Ok(lba),
            Some(_) => lba
                .checked_mul(SD_BLOCK_SIZE as u32)
                .ok_or(SdError::DataError),
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
                // Wait for transfer complete — the controller must finish
                // the CRC/end-bit on the DAT lines before the bus is free.
                for _ in 0..100_000 {
                    let st = bank.read(SDHCI_INT_STATUS);
                    if st & INT_ERROR != 0 {
                        return Err(SdError::DataError);
                    }
                    if st & INT_TRANSFER_COMPLETE != 0 {
                        bank.write(SDHCI_INT_STATUS, INT_TRANSFER_COMPLETE);
                        return Ok(());
                    }
                    core::hint::spin_loop();
                }
                return Err(SdError::Timeout);
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
                // Wait for transfer complete — the controller has accepted
                // the data from the host buffer but must still clock it out
                // to the SD card. Returning early would give a false success.
                for _ in 0..100_000 {
                    let st = bank.read(SDHCI_INT_STATUS);
                    if st & INT_ERROR != 0 {
                        return Err(SdError::DataError);
                    }
                    if st & INT_TRANSFER_COMPLETE != 0 {
                        bank.write(SDHCI_INT_STATUS, INT_TRANSFER_COMPLETE);
                        return Ok(());
                    }
                    core::hint::spin_loop();
                }
                return Err(SdError::Timeout);
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
        self.send_command(bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE, 0)?;

        // CMD8: SEND_IF_COND (voltage check, 0x1AA pattern)
        self.send_command(
            bank,
            CMD8_SEND_IF_COND,
            0x1AA,
            CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK,
            0,
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
                0,
            )?;

            // ACMD41: SD_SEND_OP_COND
            // Arg: HCS (bit 30) + full voltage window 2.7-3.6V (bits 23:15)
            let resp =
                self.send_command(bank, ACMD41_SD_SEND_OP_COND, 0x40FF8000, CMD_RESP_48, 0)?;

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
        self.send_command(bank, CMD2_ALL_SEND_CID, 0, CMD_RESP_136, 0)?;

        // CMD3: SEND_RELATIVE_ADDR (get RCA)
        let rca = match self.send_command(
            bank,
            CMD3_SEND_RCA,
            0,
            CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK,
            0,
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
            0,
        )?;

        // Determine card type and capacity from OCR
        // CCS bit (30) distinguishes SDHC/SDXC (block-addressed) from SDSC (byte-addressed)
        let is_sdhc = ocr & (1 << 30) != 0;

        // CMD9: SEND_CSD — read Card-Specific Data register for capacity.
        // Must be sent with RCA in [31:16], returns R2 (136-bit) response.
        let capacity_blocks = match self.send_command(
            bank,
            CMD9_SEND_CSD,
            (rca as u32) << 16,
            CMD_RESP_136 | CMD_CRC_CHECK,
            0,
        )? {
            Response::Long(words) => parse_csd_capacity(words, is_sdhc),
            _ => 0,
        };

        // CMD16: SET_BLOCKLEN (512 bytes)
        self.send_command(
            bank,
            CMD16_SET_BLOCKLEN,
            SD_BLOCK_SIZE as u32,
            CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK,
            0,
        )?;

        let info = CardInfo {
            rca,
            capacity_blocks,
            is_sdhc,
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

/// Parse card capacity from CSD register response.
///
/// The SDHCI controller shifts R2 (128-bit) responses right by 8 bits when
/// storing them in RESPONSE_0-3. All bit positions are adjusted accordingly.
///
/// Returns capacity in 512-byte blocks.
fn parse_csd_capacity(resp: [u32; 4], is_sdhc: bool) -> u32 {
    // CSD version: CSD bits [127:126] → after 8-bit shift: RESPONSE_3 bits [23:22]
    let csd_version = (resp[3] >> 22) & 0x3;

    if is_sdhc && csd_version == 1 {
        // CSD v2.0 (SDHC/SDXC):
        // C_SIZE in CSD bits [69:48] → after 8-bit shift: bits [61:40]
        // Spans RESPONSE_1 bits [29:8] (22 bits).
        let c_size = (resp[1] >> 8) & 0x3F_FFFF;
        // Capacity = (C_SIZE + 1) * 512KB = (C_SIZE + 1) * 1024 blocks
        (c_size + 1) * 1024
    } else if csd_version == 0 {
        // CSD v1.0 (SDSC):
        // READ_BL_LEN: CSD bits [83:80] → after shift: RESPONSE_2 bits [11:8]
        let read_bl_len = ((resp[2] >> 8) & 0xF) as u32;
        // C_SIZE: CSD bits [73:62] → after shift: bits [65:54]
        //   RESPONSE_2 bits [1:0] (upper 2 bits) + RESPONSE_1 bits [31:22] (lower 10 bits)
        let c_size = (((resp[2] & 0x3) << 10) | ((resp[1] >> 22) & 0x3FF)) as u32;
        // C_SIZE_MULT: CSD bits [49:47] → after shift: RESPONSE_1 bits [9:7]
        let c_size_mult = ((resp[1] >> 7) & 0x7) as u32;

        let block_len = 1u32 << read_bl_len;
        let mult = 1u32 << (c_size_mult + 2);
        let total_bytes = (c_size + 1) as u64 * mult as u64 * block_len as u64;
        (total_bytes / 512) as u32
    } else {
        0 // Unknown CSD version
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
        // Software Reset is at bits [31:24] of the 0x2C word.
        // First read: RESET_ALL still set, second read: cleared.
        bank.on_read(SDHCI_CLOCK_CONTROL, vec![RESET_ALL << 24, 0]);
        driver.reset(&mut bank).unwrap();
        assert!(bank
            .writes
            .contains(&(SDHCI_CLOCK_CONTROL, RESET_ALL << 24)));
    }

    #[test]
    fn reset_fails_if_never_clears() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Always returns RESET_ALL set (never clears) — sticky last value
        bank.on_read(SDHCI_CLOCK_CONTROL, vec![RESET_ALL << 24]);
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
        // Should write: disable (with timeout), then divider+internal_en+timeout, then SD enable
        let clock_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_CLOCK_CONTROL)
            .map(|(_, v)| *v)
            .collect();
        assert!(clock_writes.len() >= 2);
        // First write: disable clock but preserve timeout
        assert_eq!(clock_writes[0], TIMEOUT_VALUE << 16);
        // Second write: divider + internal_en + timeout in bits [23:16]
        assert_eq!((clock_writes[1] >> 16) & 0xFF, TIMEOUT_VALUE);
    }

    #[test]
    fn set_clock_low_freq_does_not_corrupt_timeout() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Clock stable on first poll
        bank.on_read(
            SDHCI_CLOCK_CONTROL,
            vec![CLOCK_INTERNAL_STABLE, CLOCK_INTERNAL_STABLE],
        );
        // 390 kHz → raw divider = 200_000 / (2*390) = 256, must clamp to 255
        driver.set_clock(&mut bank, 390).unwrap();
        let clock_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_CLOCK_CONTROL)
            .map(|(_, v)| *v)
            .collect();
        // The divider write (second) must preserve timeout in bits [23:16]
        let divider_write = clock_writes[1];
        assert_eq!((divider_write >> 16) & 0xFF, TIMEOUT_VALUE);
        // Divider in bits [15:8] must be 255 (clamped), not 256
        assert_eq!((divider_write >> 8) & 0xFF, 255);
    }

    #[test]
    fn set_clock_fails_if_not_stable() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Never stable — returns timeout bits but no INTERNAL_STABLE
        bank.on_read(SDHCI_CLOCK_CONTROL, vec![TIMEOUT_VALUE << 16]);
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
                0,
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
        // Error bits in upper 16: ERR_CMD_TIMEOUT; INT_ERROR in lower 16
        bank.on_read(SDHCI_INT_STATUS, vec![INT_ERROR | (ERR_CMD_TIMEOUT << 16)]);

        let result = driver.send_command(&mut bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE, 0);
        assert_eq!(result, Err(SdError::Timeout));
    }

    #[test]
    fn send_command_returns_crc_error() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        // Error bits in upper 16: ERR_CMD_CRC; INT_ERROR in lower 16
        bank.on_read(SDHCI_INT_STATUS, vec![INT_ERROR | (ERR_CMD_CRC << 16)]);

        let result = driver.send_command(&mut bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE, 0);
        assert_eq!(result, Err(SdError::CrcError));
    }

    #[test]
    fn send_command_busy_returns_error() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        bank.on_read(SDHCI_PRESENT_STATE, vec![STATE_CMD_INHIBIT]);

        let result = driver.send_command(&mut bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE, 0);
        assert_eq!(result, Err(SdError::Busy));
    }

    #[test]
    fn data_command_checks_dat_inhibit() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // DAT_INHIBIT set, CMD_INHIBIT clear — should reject data commands
        bank.on_read(SDHCI_PRESENT_STATE, vec![STATE_DAT_INHIBIT]);

        let result = driver.send_command(
            &mut bank,
            CMD17_READ_SINGLE,
            0,
            CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK | CMD_DATA_PRESENT,
            XFER_READ as u16,
        );
        assert_eq!(result, Err(SdError::Busy));
    }

    #[test]
    fn non_data_command_ignores_dat_inhibit() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // DAT_INHIBIT set but CMD_INHIBIT clear — non-data commands should proceed
        bank.on_read(SDHCI_PRESENT_STATE, vec![STATE_DAT_INHIBIT]);
        bank.on_read(SDHCI_INT_STATUS, vec![INT_CMD_COMPLETE]);
        bank.on_read(SDHCI_RESPONSE_0, vec![0]);

        let result = driver.send_command(&mut bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn write_block_waits_for_transfer_complete() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Buffer write ready, then NOT yet complete, then complete
        bank.on_read(
            SDHCI_INT_STATUS,
            vec![INT_BUFFER_WRITE_READY, 0, INT_TRANSFER_COMPLETE],
        );

        let buf = [0u8; 512];
        driver.write_block(&mut bank, &buf).unwrap();

        // Verify INT_TRANSFER_COMPLETE was cleared
        assert!(bank
            .writes
            .contains(&(SDHCI_INT_STATUS, INT_TRANSFER_COMPLETE)));
    }

    #[test]
    fn read_block_reads_512_bytes_from_data_port() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Buffer read ready, then transfer complete
        bank.on_read(
            SDHCI_INT_STATUS,
            vec![INT_BUFFER_READ_READY, INT_TRANSFER_COMPLETE],
        );
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
        // Buffer write ready, then transfer complete
        bank.on_read(
            SDHCI_INT_STATUS,
            vec![INT_BUFFER_WRITE_READY, INT_TRANSFER_COMPLETE],
        );

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
        // CMD7, CMD9, CMD16. That's 9 commands.

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
                0xC0100000, // ACMD41 response (ready bit 31 + CCS bit 30 = SDHC)
                0,          // CMD2 uses RESP_136, reads all 4 response regs
                0x12340000, // CMD3 response (RCA = 0x1234 in upper 16 bits)
                0,          // CMD7 response
                0,          // CMD9 uses RESP_136, reads all 4 response regs
                0,          // CMD16 response
            ],
        );
        bank.on_read(
            SDHCI_RESPONSE_1,
            vec![
                0,         // CMD2 R2 response
                1000 << 8, // CMD9 CSD: C_SIZE = 1000 in bits [29:8]
            ],
        );
        bank.on_read(SDHCI_RESPONSE_2, vec![0]); // CMD2 and CMD9
        bank.on_read(
            SDHCI_RESPONSE_3,
            vec![
                0,       // CMD2 R2 response
                1 << 22, // CMD9 CSD: version 2.0 in bits [23:22]
            ],
        );

        let info = driver.init_card(&mut bank).unwrap();
        assert_eq!(info.rca, 0x1234);
        // ACMD41 response has CCS bit (30) set → SDHC
        assert!(info.is_sdhc);
        // CSD v2.0 with C_SIZE=1000 → (1000+1)*1024 = 1_025_024 blocks
        assert!(info.capacity_blocks > 0);

        // Verify the command sequence from the combined writes at SDHCI_TRANSFER_MODE.
        // Upper 16 bits = command register, lower 16 bits = transfer mode (0 for all init cmds).
        let cmd_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_TRANSFER_MODE)
            .map(|(_, v)| v >> 16) // extract command portion
            .collect();

        assert_eq!(cmd_writes.len(), 9);
        // Verify command indices (bits 13:8 of the command register)
        assert_eq!(cmd_writes[0] >> 8, 0); // CMD0
        assert_eq!(cmd_writes[1] >> 8, 8); // CMD8
        assert_eq!(cmd_writes[2] >> 8, 55); // CMD55
        assert_eq!(cmd_writes[3] >> 8, 41); // ACMD41
        assert_eq!(cmd_writes[4] >> 8, 2); // CMD2
        assert_eq!(cmd_writes[5] >> 8, 3); // CMD3
        assert_eq!(cmd_writes[6] >> 8, 7); // CMD7
        assert_eq!(cmd_writes[7] >> 8, 9); // CMD9
        assert_eq!(cmd_writes[8] >> 8, 16); // CMD16
    }

    /// Helper: set up mock for a successful read_single_block.
    ///
    /// Programs the mock to handle CMD17 (send_command) followed by
    /// PIO read (read_block). `data` is the 512-byte payload.
    fn setup_read_single_mock(bank: &mut MockRegisterBank, data: &[u8; 512]) {
        // send_command reads: PRESENT_STATE (not inhibited)
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        // send_command polls INT_STATUS for CMD_COMPLETE,
        // then read_block polls for BUFFER_READ_READY,
        // then waits for TRANSFER_COMPLETE after reading the buffer
        bank.on_read(
            SDHCI_INT_STATUS,
            vec![
                INT_CMD_COMPLETE,
                INT_BUFFER_READ_READY,
                INT_TRANSFER_COMPLETE,
            ],
        );
        // CMD17 R1 response
        bank.on_read(SDHCI_RESPONSE_0, vec![0]);
        // Buffer data: 128 little-endian u32 words
        let words: Vec<u32> = (0..128)
            .map(|i| {
                let off = i * 4;
                data[off] as u32
                    | (data[off + 1] as u32) << 8
                    | (data[off + 2] as u32) << 16
                    | (data[off + 3] as u32) << 24
            })
            .collect();
        bank.on_read(SDHCI_BUFFER_DATA, words);
    }

    /// Helper: set up mock for a successful write_single_block.
    fn setup_write_single_mock(bank: &mut MockRegisterBank) {
        // send_command reads: PRESENT_STATE (not inhibited)
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        // send_command polls INT_STATUS for CMD_COMPLETE,
        // then write_block polls for BUFFER_WRITE_READY,
        // then waits for TRANSFER_COMPLETE after filling the buffer
        bank.on_read(
            SDHCI_INT_STATUS,
            vec![
                INT_CMD_COMPLETE,
                INT_BUFFER_WRITE_READY,
                INT_TRANSFER_COMPLETE,
            ],
        );
        // CMD24 R1 response
        bank.on_read(SDHCI_RESPONSE_0, vec![0]);
    }

    /// Helper: create a driver with an SDHC card pre-initialized.
    fn driver_with_sdhc_card() -> SdhciDriver {
        let mut driver = SdhciDriver::new();
        driver.card = Some(CardInfo {
            rca: 0x1234,
            capacity_blocks: 0,
            is_sdhc: true,
        });
        driver
    }

    #[test]
    fn read_single_block_issues_cmd17_then_reads() {
        let mut driver = driver_with_sdhc_card();
        let mut bank = MockRegisterBank::new();

        // Fill test data with a recognizable pattern
        let mut expected = [0u8; 512];
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        setup_read_single_mock(&mut bank, &expected);

        let mut buf = [0u8; 512];
        driver.read_single_block(&mut bank, 42, &mut buf).unwrap();

        // Verify data was read correctly
        assert_eq!(buf, expected);

        // Verify CMD17 was issued with LBA=42 (default: SDHC block-addressed)
        assert!(bank.writes.contains(&(SDHCI_ARGUMENT, 42)));

        // Combined write at SDHCI_TRANSFER_MODE: command in upper 16, transfer mode in lower 16
        let combined_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_TRANSFER_MODE)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(combined_writes.len(), 1);
        assert_eq!((combined_writes[0] >> 16) >> 8, CMD17_READ_SINGLE as u32);
        // Verify transfer mode has XFER_READ set
        assert_eq!(combined_writes[0] & 0xFFFF, XFER_READ);

        // Verify block size (lower 16) + block count (upper 16) in one write
        let block_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_BLOCK_SIZE)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(block_writes.len(), 1);
        assert_eq!(block_writes[0] & 0xFFFF, SD_BLOCK_SIZE as u32);
        assert_eq!(block_writes[0] >> 16, 1); // block count
    }

    #[test]
    fn write_single_block_issues_cmd24_then_writes() {
        let mut driver = driver_with_sdhc_card();
        let mut bank = MockRegisterBank::new();

        setup_write_single_mock(&mut bank);

        let mut buf = [0u8; 512];
        buf[0] = 0xDE;
        buf[1] = 0xAD;
        buf[2] = 0xBE;
        buf[3] = 0xEF;
        driver.write_single_block(&mut bank, 7, &buf).unwrap();

        // Verify CMD24 was issued with LBA=7 (default: SDHC block-addressed)
        assert!(bank.writes.contains(&(SDHCI_ARGUMENT, 7)));

        // Combined write at SDHCI_TRANSFER_MODE: command in upper 16, transfer mode in lower 16
        let combined_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_TRANSFER_MODE)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(combined_writes.len(), 1);
        assert_eq!((combined_writes[0] >> 16) >> 8, CMD24_WRITE_SINGLE as u32);
        // Verify transfer mode does NOT have XFER_READ set (write direction)
        assert_eq!(combined_writes[0] & 0xFFFF, 0);

        // Verify block size (lower 16) + block count (upper 16) in one write
        let block_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_BLOCK_SIZE)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(block_writes.len(), 1);
        assert_eq!(block_writes[0] & 0xFFFF, SD_BLOCK_SIZE as u32);
        assert_eq!(block_writes[0] >> 16, 1); // block count

        // Verify the first data word was written correctly
        let data_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == SDHCI_BUFFER_DATA)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(data_writes.len(), 128);
        assert_eq!(data_writes[0], 0xEFBEADDE);
    }

    #[test]
    fn read_single_block_propagates_command_error() {
        let mut driver = driver_with_sdhc_card();
        let mut bank = MockRegisterBank::new();

        // CMD17 fails with a timeout (error bits in upper 16 of INT_STATUS)
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        bank.on_read(SDHCI_INT_STATUS, vec![INT_ERROR | (ERR_CMD_TIMEOUT << 16)]);

        let mut buf = [0u8; 512];
        assert_eq!(
            driver.read_single_block(&mut bank, 0, &mut buf),
            Err(SdError::Timeout)
        );
    }

    #[test]
    fn write_single_block_propagates_command_error() {
        let mut driver = driver_with_sdhc_card();
        let mut bank = MockRegisterBank::new();

        // CMD24 fails with a CRC error (error bits in upper 16 of INT_STATUS)
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        bank.on_read(SDHCI_INT_STATUS, vec![INT_ERROR | (ERR_CMD_CRC << 16)]);

        let buf = [0u8; 512];
        assert_eq!(
            driver.write_single_block(&mut bank, 0, &buf),
            Err(SdError::CrcError)
        );
    }

    #[test]
    fn sdsc_card_uses_byte_addressing() {
        let mut driver = SdhciDriver::new();
        // Simulate an SDSC card (is_sdhc = false)
        driver.card = Some(CardInfo {
            rca: 0x1234,
            capacity_blocks: 0,
            is_sdhc: false,
        });
        let mut bank = MockRegisterBank::new();
        setup_read_single_mock(&mut bank, &[0u8; 512]);

        let mut buf = [0u8; 512];
        driver.read_single_block(&mut bank, 1, &mut buf).unwrap();

        // SDSC: argument should be byte address = LBA * 512 = 512
        assert!(bank.writes.contains(&(SDHCI_ARGUMENT, 512)));
    }

    #[test]
    fn sdsc_large_lba_overflow_returns_error() {
        let mut driver = SdhciDriver::new();
        driver.card = Some(CardInfo {
            rca: 0x1234,
            capacity_blocks: 0,
            is_sdhc: false,
        });
        let mut bank = MockRegisterBank::new();
        let mut buf = [0u8; 512];
        // LBA 0x0100_0000 * 512 = 0x2_0000_0000, overflows u32
        assert_eq!(
            driver.read_single_block(&mut bank, 0x0100_0000, &mut buf),
            Err(SdError::DataError)
        );
    }

    #[test]
    fn sdhc_card_uses_block_addressing() {
        let mut driver = SdhciDriver::new();
        // Simulate an SDHC card (is_sdhc = true)
        driver.card = Some(CardInfo {
            rca: 0x1234,
            capacity_blocks: 0,
            is_sdhc: true,
        });
        let mut bank = MockRegisterBank::new();
        setup_read_single_mock(&mut bank, &[0u8; 512]);

        let mut buf = [0u8; 512];
        driver.read_single_block(&mut bank, 1, &mut buf).unwrap();

        // SDHC: argument should be LBA directly = 1
        assert!(bank.writes.contains(&(SDHCI_ARGUMENT, 1)));
    }

    #[test]
    fn read_block_waits_for_transfer_complete() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        // Buffer read ready, then NOT yet complete, then complete
        bank.on_read(
            SDHCI_INT_STATUS,
            vec![INT_BUFFER_READ_READY, 0, INT_TRANSFER_COMPLETE],
        );
        // Provide 128 data words
        bank.on_read(SDHCI_BUFFER_DATA, vec![0; 128]);

        let mut buf = [0u8; 512];
        driver.read_block(&mut bank, &mut buf).unwrap();

        // Verify INT_TRANSFER_COMPLETE was cleared
        assert!(bank
            .writes
            .contains(&(SDHCI_INT_STATUS, INT_TRANSFER_COMPLETE)));
    }

    #[test]
    fn read_single_block_without_init_returns_no_card() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        let mut buf = [0u8; 512];
        assert_eq!(
            driver.read_single_block(&mut bank, 0, &mut buf),
            Err(SdError::NoCard)
        );
    }

    #[test]
    fn write_single_block_without_init_returns_no_card() {
        let mut driver = SdhciDriver::new();
        let mut bank = MockRegisterBank::new();
        let buf = [0u8; 512];
        assert_eq!(
            driver.write_single_block(&mut bank, 0, &buf),
            Err(SdError::NoCard)
        );
    }

    #[test]
    fn parse_csd_v2_capacity() {
        // Simulate a 32GB SDHC card:
        // CSD v2.0: csd_version = 1, C_SIZE = 65535 → (65535+1)*1024 = 67_108_864 blocks = 32 GB
        //
        // CSD bits [127:126] = 0b01 (v2.0) → after shift: RESPONSE_3 bits [23:22] = 0b01
        // CSD bits [69:48] = C_SIZE = 65535 → after shift: RESPONSE_1 bits [29:8] = 65535
        let resp = [
            0u32,       // RESPONSE_0: unused for v2.0 capacity
            65535 << 8, // RESPONSE_1: C_SIZE in bits [29:8]
            0,          // RESPONSE_2
            1 << 22,    // RESPONSE_3: CSD version 1 (v2.0) in bits [23:22]
        ];
        let blocks = parse_csd_capacity(resp, true);
        assert_eq!(blocks, 67_108_864, "32GB SDHC card should have 67M blocks");
    }

    #[test]
    fn parse_csd_v2_small_card() {
        // 4GB SDHC: C_SIZE = 8191 → (8191+1)*1024 = 8_388_608 blocks = 4 GB
        let resp = [0, 8191 << 8, 0, 1 << 22];
        let blocks = parse_csd_capacity(resp, true);
        assert_eq!(blocks, 8_388_608);
    }

    #[test]
    fn parse_csd_v1_capacity() {
        // Simulate a 2GB SDSC card:
        // READ_BL_LEN = 10 (1024 bytes), C_SIZE = 4095, C_SIZE_MULT = 7
        // Capacity = (4095+1) * (1<<9) * 1024 = 4096 * 512 * 1024 = 2,147,483,648 bytes = 2GB
        // In 512-byte blocks: 2,147,483,648 / 512 = 4,194,304
        //
        // CSD bits [127:126] = 0b00 (v1.0) → RESPONSE_3 bits [23:22] = 0
        // READ_BL_LEN in CSD bits [83:80] → after shift: RESPONSE_2 bits [11:8] = 10
        // C_SIZE in CSD bits [73:62] → after shift: RESPONSE_2 bits [1:0] (upper 2) + RESPONSE_1 bits [31:22] (lower 10)
        //   C_SIZE = 4095 = 0xFFF → upper 2 bits = 0b11, lower 10 bits = 0x3FF
        // C_SIZE_MULT in CSD bits [49:47] → after shift: RESPONSE_1 bits [9:7] = 7
        let resp = [
            0,
            (0x3FF << 22) | (7 << 7), // RESPONSE_1: C_SIZE lower 10 bits [31:22] + C_SIZE_MULT [9:7]
            (10 << 8) | 0x3,          // RESPONSE_2: READ_BL_LEN [11:8] + C_SIZE upper 2 bits [1:0]
            0,                        // RESPONSE_3: CSD version 0 (v1.0)
        ];
        let blocks = parse_csd_capacity(resp, false);
        assert_eq!(blocks, 4_194_304, "2GB SDSC card should have 4M blocks");
    }

    #[test]
    fn parse_csd_unknown_version_returns_zero() {
        let resp = [0, 0, 0, 0b11 << 22]; // CSD version 3 (invalid)
        assert_eq!(parse_csd_capacity(resp, true), 0);
    }
}
