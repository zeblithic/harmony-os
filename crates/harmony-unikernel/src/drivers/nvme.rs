// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O NVMe driver.
//!
//! Implements NVMe controller initialization and queue management via the
//! [`RegisterBank`] trait for all register access, enabling full unit
//! testing without hardware.  The driver is a pure state machine: callers
//! supply a [`RegisterBank`] and drive state transitions; no I/O is
//! performed internally.

use super::register_bank::RegisterBank;

// ── NVMe register offsets (all 32-bit aligned) ───────────────────────────────
// All offsets are pre-declared per the NVMe base spec §3.1 register map.
#[allow(dead_code)]
const REG_CAP_LO: usize = 0x00;
#[allow(dead_code)]
const REG_CAP_HI: usize = 0x04;
#[allow(dead_code)]
const REG_VS: usize = 0x08;
const REG_CC: usize = 0x14;
const REG_CSTS: usize = 0x1C;
const REG_AQA: usize = 0x24;
const REG_ASQ_LO: usize = 0x28;
#[allow(dead_code)]
const REG_ASQ_HI: usize = 0x2C;
const REG_ACQ_LO: usize = 0x30;
#[allow(dead_code)]
const REG_ACQ_HI: usize = 0x34;

// ── CC / CSTS bit definitions ─────────────────────────────────────────────────
/// CC value with EN=1, CSS=0 (NVM cmd set), MPS=0, IOSQES=6, IOCQES=4.
const CC_ENABLE: u32 = 0x0046_0001;
/// CC.EN bit mask.
const CC_EN: u32 = 1;
/// CSTS.RDY bit mask.
const CSTS_RDY: u32 = 1;

/// Maximum polling iterations before returning [`NvmeError::Timeout`].
const MAX_POLL_ITERATIONS: u32 = 100_000;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by NVMe driver operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvmeError {
    /// Controller did not reach the expected ready state within the poll limit.
    Timeout,
    /// The CAP.CSS field does not advertise support for the NVM command set.
    UnsupportedCommandSet,
    /// The driver is in the wrong state for the requested operation.
    InvalidState,
    /// A submission queue command completed with a non-zero status field.
    CommandFailed {
        /// Raw 15-bit status field from the completion queue entry.
        status: u16,
    },
    /// The completion queue contained no entry to harvest.
    NoCompletion,
}

// ── Driver state ──────────────────────────────────────────────────────────────

/// Lifecycle state of an [`NvmeDriver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeState {
    /// Driver object created but `init` not yet called.
    Uninitialized,
    /// Controller has been reset (CC.EN=0, CSTS.RDY=0).
    Disabled,
    /// Controller is running (CC.EN=1, CSTS.RDY=1).
    Enabled,
}

// ── Driver struct ─────────────────────────────────────────────────────────────

/// Sans-I/O NVMe controller driver.
///
/// All state is held in this struct; the caller provides a [`RegisterBank`]
/// that implements MMIO access.
pub struct NvmeDriver<R: RegisterBank> {
    bank: R,
    /// Maximum queue entries supported by the controller (MQES+1).
    max_queue_entries: u16,
    /// Doorbell stride encoded as log2(4 << DSTRD).
    doorbell_stride: u8,
    /// Per-controller timeout in milliseconds (TO * 500 ms units).
    timeout_ms: u32,
    /// Admin submission queue tail pointer (software-maintained).
    admin_sq_tail: u16,
    /// Admin completion queue head pointer (software-maintained).
    admin_cq_head: u16,
    /// Admin completion queue phase bit.
    admin_cq_phase: bool,
    /// Physical base address of the admin submission queue.
    admin_sq_phys: u64,
    /// Physical base address of the admin completion queue.
    admin_cq_phys: u64,
    /// Number of entries in each admin queue.
    admin_queue_size: u16,
    /// Monotonically increasing command identifier.
    next_cid: u16,
    /// Current lifecycle state of the driver.
    state: NvmeState,
}

// ── Helper methods ────────────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Read a 64-bit value from two adjacent 32-bit registers.
    ///
    /// `offset_lo` is the lower-word offset; the upper word is at
    /// `offset_lo + 4`.
    fn read64(&self, offset_lo: usize) -> u64 {
        let lo = self.bank.read(offset_lo) as u64;
        let hi = self.bank.read(offset_lo + 4) as u64;
        lo | (hi << 32)
    }

    /// Write a 64-bit value to two adjacent 32-bit registers.
    ///
    /// `offset_lo` is the lower-word offset; the upper word is written to
    /// `offset_lo + 4`.
    fn write64(&mut self, offset_lo: usize, value: u64) {
        self.bank.write(offset_lo, value as u32);
        self.bank.write(offset_lo + 4, (value >> 32) as u32);
    }

    /// Compute the MMIO offset of a submission or completion queue doorbell.
    ///
    /// Per NVMe spec §3.1.12: doorbell base = 0x1000, stride = 4 << DSTRD.
    /// SQ tail doorbell for queue `qid` is at index `2*qid`;
    /// CQ head doorbell is at `2*qid + 1`.
    fn doorbell_offset(&self, qid: u16, is_cq: bool) -> usize {
        let stride = 4usize << self.doorbell_stride;
        0x1000 + (2 * qid as usize + is_cq as usize) * stride
    }

    /// Poll CSTS.RDY until it equals `expected`.
    ///
    /// Returns `Ok(())` when the bit matches or [`NvmeError::Timeout`] if
    /// [`MAX_POLL_ITERATIONS`] is exhausted without the bit settling.
    fn poll_ready(&self, expected: bool) -> Result<(), NvmeError> {
        for _ in 0..MAX_POLL_ITERATIONS {
            let csts = self.bank.read(REG_CSTS);
            let rdy = (csts & CSTS_RDY) != 0;
            if rdy == expected {
                return Ok(());
            }
        }
        Err(NvmeError::Timeout)
    }

    // ── Public accessors (used in tests / higher-level code) ──────────────────

    /// Return the current driver state.
    pub fn state(&self) -> NvmeState {
        self.state
    }

    /// Return the maximum queue entries advertised by the controller.
    pub fn max_queue_entries(&self) -> u16 {
        self.max_queue_entries
    }

    /// Return the doorbell stride exponent.
    pub fn doorbell_stride(&self) -> u8 {
        self.doorbell_stride
    }

    /// Return the controller timeout in milliseconds.
    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }
}

// ── Initialisation ────────────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Initialise an NVMe controller.
    ///
    /// Steps performed:
    /// 1. Read the 64-bit CAP register and extract MQES, TO, DSTRD, and CSS.
    /// 2. Verify that CAP.CSS bit 0 is set (NVM command set supported).
    /// 3. Read VS (informational; not validated).
    /// 4. Disable the controller: clear CC.EN and poll until CSTS.RDY=0.
    ///
    /// On success the driver is returned in [`NvmeState::Disabled`].
    pub fn init(mut bank: R) -> Result<Self, NvmeError> {
        // Step 1 — read CAP (64-bit).
        let cap_lo = bank.read(REG_CAP_LO);
        let cap_hi = bank.read(REG_CAP_HI);
        let cap = (cap_lo as u64) | ((cap_hi as u64) << 32);

        // MQES (bits 15:0) — maximum queue entries supported (0-based, add 1).
        let mqes = (cap & 0xFFFF) as u16;
        let max_queue_entries = mqes.wrapping_add(1);

        // TO (bits 31:24 of CAP, i.e., bits 31:24 of cap_lo) — timeout in
        // 500 ms units.
        let to = (cap_lo >> 24) & 0xFF;
        let timeout_ms = to * 500;

        // DSTRD (bits 35:32 of CAP, i.e., bits 3:0 of cap_hi).
        let doorbell_stride = (cap_hi & 0x0F) as u8;

        // CSS (bits 44:37 of CAP, i.e., bits 12:5 of cap_hi).
        let css = (cap_hi >> 5) & 0xFF;

        // Step 2 — verify NVM command set (CSS bit 0).
        if css & 0x01 == 0 {
            return Err(NvmeError::UnsupportedCommandSet);
        }

        // Step 3 — read VS (informational).
        let _vs = bank.read(REG_VS);

        // Step 4 — disable controller.
        // Write CC with EN=0 (preserve other fields by reading current CC, but
        // the spec allows writing zero to all other bits during reset).
        let cc = bank.read(REG_CC);
        bank.write(REG_CC, cc & !CC_EN);

        // Construct driver before polling (poll_ready borrows bank via self).
        let driver = Self {
            bank,
            max_queue_entries,
            doorbell_stride,
            timeout_ms,
            admin_sq_tail: 0,
            admin_cq_head: 0,
            admin_cq_phase: true,
            admin_sq_phys: 0,
            admin_cq_phys: 0,
            admin_queue_size: 0,
            next_cid: 0,
            state: NvmeState::Disabled,
        };

        // Poll CSTS.RDY=0.
        driver.poll_ready(false)?;

        Ok(driver)
    }
}

// ── Admin queue setup ─────────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Configure the admin submission and completion queues, then enable the
    /// controller.
    ///
    /// Steps performed:
    /// 1. Verify the driver is in [`NvmeState::Disabled`].
    /// 2. Clamp `queue_size` to [`max_queue_entries`].
    /// 3. Write AQA (offset 0x24): `(size-1) << 16 | (size-1)`.
    /// 4. Write ASQ (offset 0x28, 64-bit): `sq_phys`.
    /// 5. Write ACQ (offset 0x30, 64-bit): `cq_phys`.
    /// 6. Write CC (offset 0x14): [`CC_ENABLE`].
    /// 7. Poll `CSTS.RDY` until set.
    /// 8. Store queue addresses and size; reset tail/head/phase; transition to
    ///    [`NvmeState::Enabled`].
    ///
    /// # Errors
    ///
    /// Returns [`NvmeError::InvalidState`] if the driver is not in
    /// [`NvmeState::Disabled`].  Returns [`NvmeError::Timeout`] if the
    /// controller does not assert `CSTS.RDY` within the poll limit.
    pub fn setup_admin_queue(
        &mut self,
        sq_phys: u64,
        cq_phys: u64,
        queue_size: u16,
    ) -> Result<(), NvmeError> {
        // Step 1 — verify state.
        if self.state != NvmeState::Disabled {
            return Err(NvmeError::InvalidState);
        }

        // Step 2 — clamp queue size to what the controller supports.
        let size = queue_size.min(self.max_queue_entries);

        // Step 3 — write AQA: both ACQS and ASQS are 0-based, so subtract 1.
        let size_minus_1 = (size - 1) as u32;
        let aqa = (size_minus_1 << 16) | size_minus_1;
        self.bank.write(REG_AQA, aqa);

        // Step 4 — write ASQ (64-bit physical address).
        self.write64(REG_ASQ_LO, sq_phys);

        // Step 5 — write ACQ (64-bit physical address).
        self.write64(REG_ACQ_LO, cq_phys);

        // Step 6 — enable the controller.
        self.bank.write(REG_CC, CC_ENABLE);

        // Step 7 — poll CSTS.RDY=1.
        self.poll_ready(true)?;

        // Step 8 — update driver state.
        self.admin_sq_phys = sq_phys;
        self.admin_cq_phys = cq_phys;
        self.admin_queue_size = size;
        self.admin_sq_tail = 0;
        self.admin_cq_head = 0;
        self.admin_cq_phase = true;
        self.state = NvmeState::Enabled;

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;
    use alloc::vec;

    /// Build a [`MockRegisterBank`] pre-loaded with sensible NVMe CAP values:
    /// - CAP_LO = 0x0100_003F → MQES=63 (max_queue_entries=64), TO=1 (500 ms)
    /// - CAP_HI = 0x0000_0020 → DSTRD=0, CSS=1 (bit 0 of css = 1, since css =
    ///   (0x20 >> 5) & 0xFF = 1)
    /// - VS = 0x0001_0400 (NVMe 1.4)
    /// - CSTS = [CSTS_RDY, 0] — RDY=1 initially, then 0 after disable
    /// - CC = [CC_EN] — controller currently enabled
    fn mock_nvme_bank() -> MockRegisterBank {
        let mut bank = MockRegisterBank::new();
        bank.on_read(REG_CAP_LO, vec![0x0100_003F]); // MQES=63, TO=1
        bank.on_read(REG_CAP_HI, vec![0x0000_0020]); // CSS bit 5 of hi word
        bank.on_read(REG_VS, vec![0x0001_0400]); // NVMe 1.4
        bank.on_read(REG_CSTS, vec![CSTS_RDY, 0]); // RDY=1 then 0
        bank.on_read(REG_CC, vec![CC_EN]); // Currently enabled
        bank
    }

    #[test]
    fn init_reads_capabilities() {
        let bank = mock_nvme_bank();
        let driver = NvmeDriver::init(bank).expect("init should succeed");

        assert_eq!(
            driver.max_queue_entries(),
            64,
            "MQES=63 → max_queue_entries=64"
        );
        assert_eq!(driver.doorbell_stride(), 0, "DSTRD=0");
        assert_eq!(driver.timeout_ms(), 500, "TO=1 → 500 ms");
        assert_eq!(driver.state(), NvmeState::Disabled);
    }

    #[test]
    fn init_disables_controller() {
        let bank = mock_nvme_bank();
        let driver = NvmeDriver::init(bank).expect("init should succeed");

        // CC was written twice: once to read-modify-write EN=0.
        // Find the write to REG_CC and assert EN bit is cleared.
        let cc_writes: alloc::vec::Vec<u32> = driver
            .bank
            .writes
            .iter()
            .filter(|(offset, _)| *offset == REG_CC)
            .map(|(_, val)| *val)
            .collect();

        assert!(
            !cc_writes.is_empty(),
            "at least one write to REG_CC expected"
        );
        for val in &cc_writes {
            assert_eq!(
                val & CC_EN,
                0,
                "CC.EN must be 0 after init; got CC=0x{val:08X}"
            );
        }
    }

    #[test]
    fn init_timeout_on_disable() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(REG_CAP_LO, vec![0x0100_003F]);
        bank.on_read(REG_CAP_HI, vec![0x0000_0020]);
        bank.on_read(REG_VS, vec![0x0001_0400]);
        // CSTS.RDY never clears — always returns 1.
        bank.on_read(REG_CSTS, vec![CSTS_RDY]);
        bank.on_read(REG_CC, vec![CC_EN]);

        match NvmeDriver::init(bank) {
            Err(NvmeError::Timeout) => {}
            Err(e) => panic!("expected Timeout, got {:?}", e),
            Ok(_) => panic!("expected Timeout, got Ok"),
        }
    }

    #[test]
    fn init_rejects_unsupported_css() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(REG_CAP_LO, vec![0x0100_003F]);
        // CAP_HI with CSS bits all zero (bits 12:5 of cap_hi = 0).
        bank.on_read(REG_CAP_HI, vec![0x0000_0000]);
        bank.on_read(REG_VS, vec![0x0001_0400]);
        bank.on_read(REG_CSTS, vec![0]);
        bank.on_read(REG_CC, vec![0]);

        match NvmeDriver::init(bank) {
            Err(NvmeError::UnsupportedCommandSet) => {}
            Err(e) => panic!("expected UnsupportedCommandSet, got {:?}", e),
            Ok(_) => panic!("expected UnsupportedCommandSet, got Ok"),
        }
    }

    #[test]
    fn setup_admin_queue_writes_registers_and_enables() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
        driver.bank.writes.clear();

        driver.setup_admin_queue(0x1_0000, 0x2_0000, 32).unwrap();

        assert_eq!(driver.state, NvmeState::Enabled);
        assert_eq!(driver.admin_queue_size, 32);
        assert!(driver.bank.writes.contains(&(REG_AQA, 0x001F_001F)));
        assert!(driver.bank.writes.contains(&(REG_ASQ_LO, 0x0001_0000)));
        assert!(driver.bank.writes.contains(&(REG_ASQ_HI, 0x0000_0000)));
        assert!(driver.bank.writes.contains(&(REG_ACQ_LO, 0x0002_0000)));
        assert!(driver.bank.writes.contains(&(REG_ACQ_HI, 0x0000_0000)));
        assert!(driver.bank.writes.contains(&(REG_CC, CC_ENABLE)));
    }

    #[test]
    fn setup_admin_queue_clamps_size_to_mqes() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
        driver.bank.writes.clear();

        driver.setup_admin_queue(0x1_0000, 0x2_0000, 256).unwrap();
        assert_eq!(driver.admin_queue_size, 64); // MQES+1=64
        assert!(driver.bank.writes.contains(&(REG_AQA, 0x003F_003F)));
    }

    #[test]
    fn setup_admin_queue_rejects_wrong_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
        driver.setup_admin_queue(0x1_0000, 0x2_0000, 32).unwrap();
        // Now Enabled — second call should fail
        let result = driver.setup_admin_queue(0x3_0000, 0x4_0000, 32);
        assert_eq!(result.unwrap_err(), NvmeError::InvalidState);
    }
}
