// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O NVMe driver.
//!
//! Implements NVMe controller initialization and queue management via the
//! [`RegisterBank`] trait for all register access, enabling full unit
//! testing without hardware.  The driver is a pure state machine: callers
//! supply a [`RegisterBank`] and drive state transitions; no I/O is
//! performed internally.

use super::register_bank::RegisterBank;
use alloc::vec::Vec;

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

// ── Command / completion types ────────────────────────────────────────────────

/// An admin command ready for the caller to execute.
#[derive(Debug)]
pub struct AdminCommand {
    /// 64-byte SQE to write at `sq_phys + sq_offset`.
    pub sqe: [u8; 64],
    /// Byte offset into the submission queue buffer.
    pub sq_offset: u64,
    /// Register offset for the SQ tail doorbell.
    pub doorbell_offset: usize,
    /// Value to write to the SQ tail doorbell.
    pub doorbell_value: u32,
    /// Optional PRP list bytes for multi-block transfers.
    ///
    /// When `Some`, the caller must write these bytes to a 4 KiB-aligned
    /// physical address, then patch SQE bytes 32–39 (PRP2) with that address
    /// before submitting the command.
    pub prp_list: Option<Vec<u8>>,
}

/// A parsed completion queue entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub cid: u16,
    pub status: u16,
    pub result: u32,
}

/// Completion with doorbell info for the caller to ring.
#[derive(Debug)]
pub struct CompletionResult {
    pub completion: Completion,
    pub cq_doorbell_offset: usize,
    pub cq_doorbell_value: u32,
}

// ── Queue pair ───────────────────────────────────────────────────────────

/// A submission/completion queue pair.
///
/// Tracks the software-maintained tail, head, and phase pointers for one
/// SQ+CQ pair.  Both admin (qid=0) and I/O (qid≥1) queues use this struct.
pub struct QueuePair {
    pub(crate) qid: u16,
    pub(crate) sq_tail: u16,
    pub(crate) cq_head: u16,
    pub(crate) cq_phase: bool,
    #[allow(dead_code)]
    pub(crate) sq_phys: u64,
    #[allow(dead_code)]
    pub(crate) cq_phys: u64,
    pub(crate) size: u16,
}

impl QueuePair {
    /// Create a new queue pair with all pointers at zero and phase=true.
    pub fn new(qid: u16, sq_phys: u64, cq_phys: u64, size: u16) -> Self {
        Self {
            qid,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            sq_phys,
            cq_phys,
            size,
        }
    }

    /// Parse a 16-byte CQE and, if the phase bit matches, return the
    /// completion with CQ doorbell info.  Returns `None` on phase mismatch.
    pub fn check_completion(
        &mut self,
        cqe: &[u8; 16],
        doorbell_stride: u8,
    ) -> Option<CompletionResult> {
        let status_word = u16::from_le_bytes([cqe[14], cqe[15]]);
        let phase = (status_word & 0x0001) != 0;
        let status = status_word >> 1;

        if phase != self.cq_phase {
            return None;
        }

        let result = u32::from_le_bytes([cqe[0], cqe[1], cqe[2], cqe[3]]);
        let cid = u16::from_le_bytes([cqe[12], cqe[13]]);

        let next_head = self.cq_head + 1;
        if next_head >= self.size {
            self.cq_head = 0;
            self.cq_phase = !self.cq_phase;
        } else {
            self.cq_head = next_head;
        }

        let stride = 4usize << doorbell_stride;
        let cq_doorbell_offset = 0x1000 + (2 * self.qid as usize + 1) * stride;
        let cq_doorbell_value = self.cq_head as u32;

        Some(CompletionResult {
            completion: Completion {
                cid,
                status,
                result,
            },
            cq_doorbell_offset,
            cq_doorbell_value,
        })
    }

    /// Compute the byte offset into the SQ buffer for the current tail,
    /// advance the tail (wrapping), and return an [`AdminCommand`] with
    /// the SQE and doorbell information.
    pub fn submit(&mut self, sqe: [u8; 64], doorbell_stride: u8) -> AdminCommand {
        let sq_offset = (self.sq_tail as u64) * 64;
        self.sq_tail = (self.sq_tail + 1) % self.size;

        let stride = 4usize << doorbell_stride;
        let doorbell_offset = 0x1000 + (2 * self.qid as usize) * stride;
        let doorbell_value = self.sq_tail as u32;

        AdminCommand {
            sqe,
            sq_offset,
            doorbell_offset,
            doorbell_value,
            prp_list: None,
        }
    }
}

/// Parsed fields from the 4 KiB Identify Controller data structure.
#[derive(Debug, Clone)]
pub struct IdentifyController {
    pub serial_number: [u8; 20],
    pub model_number: [u8; 40],
    pub firmware_rev: [u8; 8],
    pub max_data_transfer: u8,
    pub num_namespaces: u32,
}

/// Parsed fields from the 4 KiB Identify Namespace data structure.
#[derive(Debug, Clone)]
pub struct IdentifyNamespace {
    /// Namespace size in logical blocks (bytes 0-7).
    pub nsze: u64,
    /// Namespace capacity in logical blocks (bytes 8-15).
    pub ncap: u64,
    /// Namespace utilization in logical blocks (bytes 16-23).
    pub nuse: u64,
    /// Formatted LBA Size — raw byte 26 (bits 3:0 = LBA format index).
    pub flbas: u8,
    /// Logical block size in bytes, derived from LBAF[flbas & 0x0F].LBADS.
    pub lba_size_bytes: u32,
}

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
    /// The requested transfer exceeds the controller's MDTS.
    TransferTooLarge,
    /// One or more PRP addresses are not 4 KiB-aligned.
    UnalignedAddress,
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
    /// I/O queues created and active.
    Ready,
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
    /// Admin submission/completion queue pair.
    admin: QueuePair,
    /// I/O submission/completion queue pair (None until created).
    io: Option<QueuePair>,
    /// Pending I/O queue params cached by create_io_queues(), consumed by
    /// activate_io_queues().  Ensures software QueuePair matches hardware.
    pending_io: Option<(u64, u64, u16)>,
    /// Monotonically increasing command identifier.
    next_cid: u16,
    /// Current lifecycle state of the driver.
    state: NvmeState,
    /// Maximum Data Transfer Size exponent from Identify Controller.
    /// 0 = no controller-imposed limit. >0 = max transfer is 2^mdts pages.
    mdts: u8,
}

// ── Helper methods ────────────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Read a 64-bit value from two adjacent 32-bit registers.
    ///
    /// `offset_lo` is the lower-word offset; the upper word is at
    /// `offset_lo + 4`.
    #[allow(dead_code)]
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

    /// Poll CSTS.RDY until it equals `expected`.
    ///
    /// Returns `Ok(())` when the bit matches or [`NvmeError::Timeout`] if
    /// [`MAX_POLL_ITERATIONS`] is exhausted without the bit settling.
    ///
    /// Note: this uses a fixed iteration count, not `timeout_ms`. Callers
    /// on real hardware should use `timeout_ms()` for wall-clock timeout;
    /// `MAX_POLL_ITERATIONS` is sized for unit-test environments.
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

    /// Set the MDTS value from Identify Controller byte 77.
    ///
    /// Call this after parsing the Identify Controller response.
    /// `mdts = 0` means no controller-imposed limit.
    pub fn set_mdts(&mut self, mdts: u8) {
        self.mdts = mdts;
    }

    /// Maximum number of 4 KiB pages per transfer, or `None` if unlimited.
    ///
    /// Derived from MDTS: when non-zero, max pages = 2^mdts.
    pub fn max_transfer_blocks(&self) -> Option<u32> {
        if self.mdts == 0 {
            None
        } else if self.mdts >= 32 {
            Some(u32::MAX)
        } else {
            Some(1u32 << self.mdts)
        }
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
        // Saturate at u16::MAX to avoid wrapping when MQES=0xFFFF (65536 entries).
        let mqes = (cap & 0xFFFF) as u16;
        let max_queue_entries = mqes.saturating_add(1);

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
            admin: QueuePair::new(0, 0, 0, 0),
            io: None,
            pending_io: None,
            next_cid: 0,
            state: NvmeState::Disabled,
            mdts: 0,
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

        // Guard: AQA fields are 0-based (size-1), so zero is illegal.
        if size == 0 {
            return Err(NvmeError::InvalidState);
        }

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
        self.admin = QueuePair::new(0, sq_phys, cq_phys, size);
        self.state = NvmeState::Enabled;

        Ok(())
    }
}

// ── Identify Controller command ───────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Build an Identify Controller admin command (opcode 0x06, CNS=1).
    ///
    /// The caller must DMA-map a 4 KiB buffer and pass its physical address as
    /// `data_phys`.  On success an [`AdminCommand`] is returned; the caller
    /// writes the SQE to host memory, updates the doorbell, and later harvests
    /// the completion with [`check_completion`].
    ///
    /// # Errors
    ///
    /// Returns [`NvmeError::InvalidState`] if the driver is not in
    /// [`NvmeState::Enabled`] or [`NvmeState::Ready`].
    pub fn identify_controller(&mut self, data_phys: u64) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        // Build 64-byte SQE (all bytes zero by default).
        let mut sqe = [0u8; 64];

        // CDW0 bytes 0-3: opcode=0x06 | (cid << 16), little-endian.
        let cdw0: u32 = 0x06 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());

        // PRP1 bytes 24-31: data_phys, little-endian u64.
        sqe[24..32].copy_from_slice(&data_phys.to_le_bytes());

        // CDW10 bytes 40-43: CNS=0x01 (Identify Controller), little-endian.
        sqe[40..44].copy_from_slice(&1u32.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }

    /// Build an Identify Namespace admin command (opcode 0x06, CNS=0).
    ///
    /// The caller must DMA-map a 4 KiB buffer and pass its physical
    /// address as `data_phys`.  `nsid` identifies the namespace (typically 1).
    pub fn identify_namespace(
        &mut self,
        nsid: u32,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];
        // CDW0: opcode=0x06, CID
        let cdw0: u32 = 0x06 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        // CDW1 (NSID): bytes 4-7
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());
        // PRP1: data_phys
        sqe[24..32].copy_from_slice(&data_phys.to_le_bytes());
        // CDW10: CNS=0x00 (Identify Namespace)
        sqe[40..44].copy_from_slice(&0u32.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }
}

// ── I/O queue creation ───────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Build a Create I/O Completion Queue admin command (opcode 0x05).
    pub fn create_io_cq(&mut self, cq_phys: u64, size: u16) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let size = size.min(self.max_queue_entries);
        if size == 0 {
            return Err(NvmeError::InvalidState);
        }

        let mut sqe = [0u8; 64];
        let cdw0: u32 = 0x05 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[24..32].copy_from_slice(&cq_phys.to_le_bytes());
        let cdw10: u32 = 1 | (((size - 1) as u32) << 16);
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());
        let cdw11: u32 = 0x0000_0003;
        sqe[44..48].copy_from_slice(&cdw11.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }

    /// Build a Create I/O Submission Queue admin command (opcode 0x01).
    pub fn create_io_sq(&mut self, sq_phys: u64, size: u16) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let size = size.min(self.max_queue_entries);
        if size == 0 {
            return Err(NvmeError::InvalidState);
        }

        let mut sqe = [0u8; 64];
        let cdw0: u32 = 0x01 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[24..32].copy_from_slice(&sq_phys.to_le_bytes());
        let cdw10: u32 = 1 | (((size - 1) as u32) << 16);
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());
        let cdw11: u32 = 0x0001_0001;
        sqe[44..48].copy_from_slice(&cdw11.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }

    /// Build admin commands to create one I/O CQ+SQ pair (qid=1).
    ///
    /// Returns `[create_cq_cmd, create_sq_cmd]`.  The caller must execute
    /// them in order, confirm both completions succeed, then call
    /// [`activate_io_queues`] to record the result.
    pub fn create_io_queues(
        &mut self,
        sq_phys: u64,
        cq_phys: u64,
        size: u16,
    ) -> Result<[AdminCommand; 2], NvmeError> {
        // Only allow in Enabled state — not Ready (queues already exist)
        // or Disabled (admin queue not active).
        if self.state != NvmeState::Enabled {
            return Err(NvmeError::InvalidState);
        }
        let size = size.min(self.max_queue_entries);
        let cq_cmd = self.create_io_cq(cq_phys, size)?;
        let sq_cmd = self.create_io_sq(sq_phys, size)?;
        // Cache the effective (post-clamp) params so activate_io_queues
        // creates a QueuePair that matches what the hardware was programmed with.
        self.pending_io = Some((sq_phys, cq_phys, size));
        Ok([cq_cmd, sq_cmd])
    }

    /// Record that the I/O queues were successfully created on the
    /// controller.
    ///
    /// Call this after executing both commands from [`create_io_queues`]
    /// and confirming successful completions.  Uses the params cached by
    /// `create_io_queues` to ensure the software QueuePair matches the
    /// hardware.  Transitions the driver to [`NvmeState::Ready`].
    pub fn activate_io_queues(&mut self) -> Result<(), NvmeError> {
        if self.state != NvmeState::Enabled {
            return Err(NvmeError::InvalidState);
        }

        let (sq_phys, cq_phys, size) = self.pending_io.take().ok_or(NvmeError::InvalidState)?;
        self.io = Some(QueuePair::new(1, sq_phys, cq_phys, size));
        self.state = NvmeState::Ready;
        Ok(())
    }
}

// ── Block I/O commands ───────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Build an NVM I/O command (Read or Write) and submit via the I/O queue.
    ///
    /// `pages` is a slice of 4 KiB-aligned physical addresses, one per logical
    /// block to transfer.  PRP1/PRP2/PRP-list are set according to the NVMe spec:
    ///
    /// | Pages | PRP1       | PRP2       | prp_list                    |
    /// |-------|------------|------------|-----------------------------|
    /// | 1     | pages[0]   | 0          | None                        |
    /// | 2     | pages[0]   | pages[1]   | None                        |
    /// | 3+    | pages[0]   | u64::MAX   | Some(pages[1..] as LE u64s) |
    ///
    /// For the 3+ case, PRP2 is set to `u64::MAX` as a sentinel.  The caller
    /// must write the `prp_list` bytes to a 4 KiB-aligned physical address, then
    /// patch SQE bytes 32–39 with that address before submitting.
    fn io_rw_command(
        &mut self,
        opcode: u8,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        if pages.is_empty() {
            return Err(NvmeError::TransferTooLarge);
        }
        for &addr in pages {
            if addr & 0xFFF != 0 {
                return Err(NvmeError::UnalignedAddress);
            }
        }
        if let Some(max) = self.max_transfer_blocks() {
            if pages.len() as u32 > max {
                return Err(NvmeError::TransferTooLarge);
            }
        }
        // Check LBA + block_count doesn't overflow u64.
        let block_count = pages.len() as u64;
        if lba.checked_add(block_count).is_none() {
            return Err(NvmeError::TransferTooLarge);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let nlb = (pages.len() as u32) - 1; // NLB is 0-based

        let mut sqe = [0u8; 64];
        let cdw0: u32 = (opcode as u32) | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());
        // PRP1 = first page
        sqe[24..32].copy_from_slice(&pages[0].to_le_bytes());
        // PRP2 depends on page count
        let prp_list = if pages.len() == 1 {
            sqe[32..40].copy_from_slice(&0u64.to_le_bytes());
            None
        } else if pages.len() == 2 {
            sqe[32..40].copy_from_slice(&pages[1].to_le_bytes());
            None
        } else {
            // 3+ pages: PRP2 = sentinel, build PRP list from pages[1..]
            sqe[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
            let mut list = Vec::with_capacity((pages.len() - 1) * 8);
            for &addr in &pages[1..] {
                list.extend_from_slice(&addr.to_le_bytes());
            }
            Some(list)
        };
        // LBA
        sqe[40..44].copy_from_slice(&(lba as u32).to_le_bytes());
        sqe[44..48].copy_from_slice(&((lba >> 32) as u32).to_le_bytes());
        // CDW12: NLB (0-based block count)
        sqe[48..52].copy_from_slice(&nlb.to_le_bytes());

        let mut cmd = self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .submit(sqe, self.doorbell_stride);
        cmd.prp_list = prp_list;
        Ok(cmd)
    }

    /// Build an NVM Read command for multiple logical blocks.
    ///
    /// `pages` contains one 4 KiB-aligned physical address per block.
    pub fn read_blocks(
        &mut self,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
        self.io_rw_command(0x02, nsid, lba, pages)
    }

    /// Build an NVM Write command for multiple logical blocks.
    ///
    /// `pages` contains one 4 KiB-aligned physical address per block.
    pub fn write_blocks(
        &mut self,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
        self.io_rw_command(0x01, nsid, lba, pages)
    }

    /// Build an NVM Read command (opcode 0x02) for one logical block.
    ///
    /// Thin wrapper around [`read_blocks`](Self::read_blocks) with a
    /// single-element page slice.
    pub fn read_block(
        &mut self,
        nsid: u32,
        lba: u64,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        self.read_blocks(nsid, lba, &[data_phys])
    }

    /// Build an NVM Write command (opcode 0x01) for one logical block.
    ///
    /// Thin wrapper around [`write_blocks`](Self::write_blocks) with a
    /// single-element page slice.
    pub fn write_block(
        &mut self,
        nsid: u32,
        lba: u64,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        self.write_blocks(nsid, lba, &[data_phys])
    }

    /// Build an NVM Flush command (opcode 0x00).
    ///
    /// Submits via the I/O queue (qid=1).  Flushes all pending writes
    /// for `nsid` to non-volatile media.  No data transfer.
    pub fn flush(&mut self, nsid: u32) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];
        let cdw0: u32 = (cid as u32) << 16;
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());

        Ok(self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .submit(sqe, self.doorbell_stride))
    }
}

// ── Completion checking ───────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Parse a raw 16-byte completion queue entry and, if the phase bit
    /// matches the expected phase, return a [`CompletionResult`].
    ///
    /// The caller reads 16 bytes from `admin_cq_phys + (admin_cq_head * 16)`
    /// and passes them here.  If the phase bit in the CQE matches the driver's
    /// current `admin_cq_phase`, the completion is valid and the head/phase
    /// are advanced.
    ///
    /// Returns `Ok(None)` when the phase does not match (no new completion).
    ///
    /// # CQE layout (NVMe spec §4.6)
    ///
    /// | Bytes | Field         |
    /// |-------|---------------|
    /// | 0-3   | DW0 (result)  |
    /// | 4-7   | DW1 (reserved)|
    /// | 8-9   | SQ head ptr   |
    /// | 10-11 | SQ identifier |
    /// | 12-13 | CID           |
    /// | 14-15 | Status (P=b0) |
    pub fn check_completion(
        &mut self,
        cqe_bytes: &[u8; 16],
    ) -> Result<Option<CompletionResult>, NvmeError> {
        Ok(self.admin.check_completion(cqe_bytes, self.doorbell_stride))
    }

    /// Parse a raw 16-byte I/O completion queue entry.
    ///
    /// Delegates to the I/O [`QueuePair`]'s completion checking.
    /// Requires [`NvmeState::Ready`].
    pub fn check_io_completion(
        &mut self,
        cqe_bytes: &[u8; 16],
    ) -> Result<Option<CompletionResult>, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        Ok(self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .check_completion(cqe_bytes, self.doorbell_stride))
    }
}

// ── Identify Controller response parser ──────────────────────────────────────

/// Parse the 4 KiB Identify Controller data structure (NVMe spec §5.15.2.1).
///
/// | Bytes   | Field              |
/// |---------|--------------------|
/// | 4-23    | Serial Number (SN) |
/// | 24-63   | Model Number (MN)  |
/// | 64-71   | Firmware Revision  |
/// | 77      | MDTS               |
/// | 516-519 | NN (num namespaces)|
pub fn parse_identify_controller(data: &[u8; 4096]) -> IdentifyController {
    let mut serial_number = [0u8; 20];
    serial_number.copy_from_slice(&data[4..24]);

    let mut model_number = [0u8; 40];
    model_number.copy_from_slice(&data[24..64]);

    let mut firmware_rev = [0u8; 8];
    firmware_rev.copy_from_slice(&data[64..72]);

    let max_data_transfer = data[77];

    let num_namespaces = u32::from_le_bytes([data[516], data[517], data[518], data[519]]);

    IdentifyController {
        serial_number,
        model_number,
        firmware_rev,
        max_data_transfer,
        num_namespaces,
    }
}

/// Parse the 4 KiB Identify Namespace data structure (NVMe spec §5.15.2.2).
///
/// | Bytes   | Field              |
/// |---------|--------------------|
/// | 0-7     | NSZE               |
/// | 8-15    | NCAP               |
/// | 16-23   | NUSE               |
/// | 26      | FLBAS              |
/// | 128+    | LBA Format table   |
pub fn parse_identify_namespace(data: &[u8; 4096]) -> IdentifyNamespace {
    let nsze = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let ncap = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let nuse = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let flbas = data[26];

    // LBA Format table starts at byte 128, 4 bytes per entry.
    // LBADS is at byte 2 of each entry.
    let fmt_index = (flbas & 0x0F) as usize;
    let lbads = data[128 + fmt_index * 4 + 2];
    // Guard against malformed LBADS values that would overflow a u32 shift.
    let lba_size_bytes = if lbads < 32 { 1u32 << lbads } else { 0 };

    IdentifyNamespace {
        nsze,
        ncap,
        nuse,
        flbas,
        lba_size_bytes,
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
        assert_eq!(driver.admin.size, 32);
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
        assert_eq!(driver.admin.size, 64); // MQES+1=64
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

    // ── Task 3 & 4 tests ──────────────────────────────────────────────────────

    /// Helper: produce an Enabled driver ready for command tests.
    fn enabled_driver() -> NvmeDriver<MockRegisterBank> {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
        driver.setup_admin_queue(0x1_0000, 0x2_0000, 32).unwrap();
        driver
    }

    #[test]
    fn identify_controller_builds_correct_sqe() {
        let mut driver = enabled_driver();
        let data_phys: u64 = 0xDEAD_BEEF_0000u64;
        let cmd = driver.identify_controller(data_phys).unwrap();

        // CDW0: opcode=0x06, CID=0 → bits 7:0 = 0x06, bits 31:16 = 0
        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x06, "opcode must be 0x06");
        assert_eq!((cdw0 >> 16) as u16, 0, "CID must be 0 for first command");

        // PRP1 at bytes 24-31
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, data_phys, "PRP1 must equal data_phys");

        // CDW10 at bytes 40-43: CNS=1
        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10, 1, "CDW10 must be 1 (CNS=Identify Controller)");

        // Doorbell offset for admin SQ (qid=0, is_cq=false, DSTRD=0): 0x1000
        assert_eq!(cmd.doorbell_offset, 0x1000, "SQ tail doorbell offset");
        // Doorbell value: new tail = 1
        assert_eq!(cmd.doorbell_value, 1, "SQ tail doorbell value must be 1");
    }

    #[test]
    fn identify_controller_increments_cid() {
        let mut driver = enabled_driver();

        let cmd0 = driver.identify_controller(0x1000).unwrap();
        let cdw0_0 = u32::from_le_bytes(cmd0.sqe[0..4].try_into().unwrap());
        assert_eq!((cdw0_0 >> 16) as u16, 0, "first CID must be 0");

        let cmd1 = driver.identify_controller(0x2000).unwrap();
        let cdw0_1 = u32::from_le_bytes(cmd1.sqe[0..4].try_into().unwrap());
        assert_eq!((cdw0_1 >> 16) as u16, 1, "second CID must be 1");
    }

    #[test]
    fn check_completion_detects_phase_match() {
        let mut driver = enabled_driver();
        // Initial phase is `true` (1), so set phase bit = 1.
        let mut cqe = [0u8; 16];
        cqe[0..4].copy_from_slice(&0x42u32.to_le_bytes()); // DW0 result
        cqe[12..14].copy_from_slice(&0u16.to_le_bytes()); // CID=0
        cqe[14..16].copy_from_slice(&0x0001u16.to_le_bytes()); // status: phase=1, code=0

        let result = driver.check_completion(&cqe).unwrap();
        let cr = result.expect("phase matches, should return Some");

        assert_eq!(cr.completion.cid, 0);
        assert_eq!(cr.completion.status, 0, "status code must be 0 (success)");
        assert_eq!(cr.completion.result, 0x42);
    }

    #[test]
    fn check_completion_rejects_phase_mismatch() {
        let mut driver = enabled_driver();
        // Initial phase is `true` (1); set phase bit = 0 → mismatch.
        let mut cqe = [0u8; 16];
        cqe[14..16].copy_from_slice(&0x0000u16.to_le_bytes()); // phase=0

        let result = driver.check_completion(&cqe).unwrap();
        assert!(result.is_none(), "phase mismatch must return None");
    }

    #[test]
    fn check_completion_advances_head_and_inverts_phase_on_wrap() {
        // Use a queue of size 2 so the wrap happens quickly.
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
        driver.setup_admin_queue(0x1_0000, 0x2_0000, 2).unwrap();

        // Build a CQE with the given result and phase bit.
        let make_cqe = |result: u32, phase: bool| -> [u8; 16] {
            let mut cqe = [0u8; 16];
            cqe[0..4].copy_from_slice(&result.to_le_bytes());
            let status_word: u16 = if phase { 0x0001 } else { 0x0000 };
            cqe[14..16].copy_from_slice(&status_word.to_le_bytes());
            cqe
        };

        // Completion 1: head=0, phase=true → valid; head advances to 1.
        let cqe1 = make_cqe(1, true);
        let r1 = driver
            .check_completion(&cqe1)
            .unwrap()
            .expect("cqe1 should match");
        assert_eq!(r1.completion.result, 1);
        assert_eq!(driver.admin.cq_head, 1);
        assert!(driver.admin.cq_phase, "phase stays true after head=0→1");

        // Completion 2: head=1, phase=true → valid; wraps to head=0, phase inverts.
        let cqe2 = make_cqe(2, true);
        let r2 = driver
            .check_completion(&cqe2)
            .unwrap()
            .expect("cqe2 should match");
        assert_eq!(r2.completion.result, 2);
        assert_eq!(driver.admin.cq_head, 0, "head wraps to 0");
        assert!(!driver.admin.cq_phase, "phase inverts on wrap");

        // Completion 3: head=0, phase=false → valid after inversion.
        let cqe3 = make_cqe(3, false);
        let r3 = driver
            .check_completion(&cqe3)
            .unwrap()
            .expect("cqe3 should match");
        assert_eq!(r3.completion.result, 3);
        assert_eq!(driver.admin.cq_head, 1);
        assert!(!driver.admin.cq_phase, "phase stays false after head=0→1");
    }

    #[test]
    fn parse_identify_controller_extracts_fields() {
        let mut data = [0u8; 4096];

        // Serial number: bytes 4-23 (20 bytes)
        let sn = b"SN1234567890123456  ";
        data[4..24].copy_from_slice(sn);

        // Model number: bytes 24-63 (40 bytes)
        let mn = b"ModelXYZ                                ";
        data[24..64].copy_from_slice(mn);

        // Firmware revision: bytes 64-71 (8 bytes)
        let fw = b"FW1.2345";
        data[64..72].copy_from_slice(fw);

        // MDTS: byte 77
        data[77] = 5;

        // NN: bytes 516-519 (LE u32)
        data[516..520].copy_from_slice(&1024u32.to_le_bytes());

        let ic = parse_identify_controller(&data);

        assert_eq!(&ic.serial_number, sn);
        assert_eq!(&ic.model_number, mn);
        assert_eq!(&ic.firmware_rev, fw);
        assert_eq!(ic.max_data_transfer, 5);
        assert_eq!(ic.num_namespaces, 1024);
    }

    // ── QueuePair unit tests ───────────────────────────────────────────────

    #[test]
    fn queue_pair_submit_computes_offset_and_advances_tail() {
        let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 32);
        let sqe = [0xABu8; 64];
        let cmd = qp.submit(sqe, 0); // doorbell_stride=0

        // sq_offset = tail(0) * 64 = 0
        assert_eq!(cmd.sq_offset, 0);
        // doorbell for SQ of qid=0, stride=0: 0x1000 + (2*0+0)*(4<<0) = 0x1000
        assert_eq!(cmd.doorbell_offset, 0x1000);
        // doorbell value = new tail = 1
        assert_eq!(cmd.doorbell_value, 1);
        // SQE bytes preserved
        assert_eq!(cmd.sqe, [0xABu8; 64]);

        // Second submit: offset = 1*64 = 64, tail advances to 2
        let cmd2 = qp.submit([0xCDu8; 64], 0);
        assert_eq!(cmd2.sq_offset, 64);
        assert_eq!(cmd2.doorbell_value, 2);
    }

    #[test]
    fn queue_pair_submit_wraps_tail() {
        let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 2);
        let _ = qp.submit([0u8; 64], 0); // tail: 0 → 1
        let cmd = qp.submit([0u8; 64], 0); // tail: 1 → 0 (wrap)
        assert_eq!(cmd.doorbell_value, 0);
        assert_eq!(cmd.sq_offset, 64); // offset was computed before wrap
    }

    #[test]
    fn queue_pair_submit_uses_io_queue_doorbell() {
        // qid=1, doorbell_stride=0: SQ doorbell = 0x1000 + (2*1+0)*(4<<0) = 0x1008
        let mut qp = QueuePair::new(1, 0x3_0000, 0x4_0000, 16);
        let cmd = qp.submit([0u8; 64], 0);
        assert_eq!(cmd.doorbell_offset, 0x1008);
    }

    #[test]
    fn queue_pair_check_completion_phase_match() {
        let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 32);
        // CQE with phase=1 (matches initial cq_phase=true), CID=5, result=0x42
        let mut cqe = [0u8; 16];
        cqe[0..4].copy_from_slice(&0x42u32.to_le_bytes());
        cqe[12..14].copy_from_slice(&5u16.to_le_bytes());
        cqe[14..16].copy_from_slice(&0x0001u16.to_le_bytes()); // phase=1, status=0

        let cr = qp.check_completion(&cqe, 0).expect("phase matches");
        assert_eq!(cr.completion.cid, 5);
        assert_eq!(cr.completion.status, 0);
        assert_eq!(cr.completion.result, 0x42);
        // CQ doorbell for qid=0: 0x1000 + (2*0+1)*(4<<0) = 0x1004
        assert_eq!(cr.cq_doorbell_offset, 0x1004);
        assert_eq!(cr.cq_doorbell_value, 1); // head advanced to 1
    }

    #[test]
    fn queue_pair_check_completion_phase_mismatch() {
        let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 32);
        // CQE with phase=0, but cq_phase=true → mismatch
        let mut cqe = [0u8; 16];
        cqe[14..16].copy_from_slice(&0x0000u16.to_le_bytes());

        assert!(qp.check_completion(&cqe, 0).is_none());
    }

    #[test]
    fn queue_pair_check_completion_wraps_and_inverts_phase() {
        let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 2); // size=2

        let make_cqe = |phase: bool| -> [u8; 16] {
            let mut cqe = [0u8; 16];
            let status_word: u16 = if phase { 0x0001 } else { 0x0000 };
            cqe[14..16].copy_from_slice(&status_word.to_le_bytes());
            cqe
        };

        // head=0, phase=true → match, head→1
        let r1 = qp.check_completion(&make_cqe(true), 0).unwrap();
        assert_eq!(r1.cq_doorbell_value, 1);

        // head=1, phase=true → match, head wraps→0, phase inverts→false
        let r2 = qp.check_completion(&make_cqe(true), 0).unwrap();
        assert_eq!(r2.cq_doorbell_value, 0);

        // head=0, phase=false → match (inverted phase)
        let r3 = qp.check_completion(&make_cqe(false), 0).unwrap();
        assert_eq!(r3.cq_doorbell_value, 1);
    }

    #[test]
    fn queue_pair_check_completion_io_queue_doorbell() {
        // qid=1, stride=0: CQ doorbell = 0x1000 + (2*1+1)*(4<<0) = 0x100C
        let mut qp = QueuePair::new(1, 0x3_0000, 0x4_0000, 16);
        let mut cqe = [0u8; 16];
        cqe[14..16].copy_from_slice(&0x0001u16.to_le_bytes());

        let cr = qp.check_completion(&cqe, 0).unwrap();
        assert_eq!(cr.cq_doorbell_offset, 0x100C);
    }

    // ── Create I/O queue tests ────────────────────────────────────────────

    #[test]
    fn create_io_cq_builds_correct_sqe() {
        let mut driver = enabled_driver();
        let cq_phys: u64 = 0xAAAA_0000;
        let cmd = driver.create_io_cq(cq_phys, 32).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x05, "opcode must be 0x05 (Create I/O CQ)");

        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, cq_phys);

        // CDW10: QID=1 | (31 << 16) = 0x001F_0001
        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFFFF, 1, "QID must be 1");
        assert_eq!(cdw10 >> 16, 31, "QSIZE must be size-1 = 31");

        // CDW11: PC=1, IEN=1, IV=0 → 0x0000_0003
        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0x0000_0003);
    }

    #[test]
    fn create_io_sq_builds_correct_sqe() {
        let mut driver = enabled_driver();
        let sq_phys: u64 = 0xBBBB_0000;
        let cmd = driver.create_io_sq(sq_phys, 32).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x01, "opcode must be 0x01 (Create I/O SQ)");

        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, sq_phys);

        // CDW10: QID=1 | (31 << 16)
        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFFFF, 1);
        assert_eq!(cdw10 >> 16, 31);

        // CDW11: PC=1, CQID=1<<16 → 0x0001_0001
        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0x0001_0001);
    }

    #[test]
    fn create_io_cq_rejects_disabled_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        // State is Disabled — should reject
        assert_eq!(
            driver.create_io_cq(0x1000, 16).unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn create_io_cq_advances_admin_doorbell() {
        let mut driver = enabled_driver();
        let cmd1 = driver.create_io_cq(0xAAAA_0000, 16).unwrap();
        let cmd2 = driver.create_io_cq(0xBBBB_0000, 16).unwrap();
        // Doorbell values should be sequential (admin SQ tail advancing)
        assert_eq!(cmd1.doorbell_value, cmd2.doorbell_value - 1);
    }

    // ── create_io_queues + activate tests ─────────────────────────────────────

    #[test]
    fn create_io_queues_returns_cq_first_sq_second() {
        let mut driver = enabled_driver();
        let cmds = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();

        // First command is Create I/O CQ (opcode 0x05)
        let cdw0_cq = u32::from_le_bytes(cmds[0].sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0_cq & 0xFF, 0x05);

        // Second command is Create I/O SQ (opcode 0x01)
        let cdw0_sq = u32::from_le_bytes(cmds[1].sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0_sq & 0xFF, 0x01);
    }

    #[test]
    fn create_io_queues_clamps_size() {
        let mut driver = enabled_driver(); // MQES+1 = 64
        let cmds = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 256)
            .unwrap();

        // CDW10 of CQ: size-1 in upper 16 bits should be 63 (clamped to 64)
        let cdw10 = u32::from_le_bytes(cmds[0].sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 >> 16, 63);
    }

    #[test]
    fn create_io_queues_rejects_disabled_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        assert_eq!(
            driver.create_io_queues(0x1000, 0x2000, 16).unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn create_io_queues_rejects_ready_state() {
        let mut driver = enabled_driver();
        let _ = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        driver.activate_io_queues().unwrap();
        assert_eq!(driver.state(), NvmeState::Ready);
        // Already has I/O queues — should reject
        assert_eq!(
            driver
                .create_io_queues(0xCCCC_0000, 0xDDDD_0000, 16)
                .unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn activate_io_queues_transitions_to_ready() {
        let mut driver = enabled_driver();
        assert_eq!(driver.state(), NvmeState::Enabled);

        let _ = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        driver.activate_io_queues().unwrap();

        assert_eq!(driver.state(), NvmeState::Ready);
        assert!(driver.io.is_some());
        let io = driver.io.as_ref().unwrap();
        assert_eq!(io.qid, 1);
        assert_eq!(io.size, 32);
    }

    #[test]
    fn activate_io_queues_rejects_double_activation() {
        let mut driver = enabled_driver();
        let _ = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        driver.activate_io_queues().unwrap();
        // Now Ready — second call should fail (state is Ready, not Enabled)
        assert_eq!(
            driver.activate_io_queues().unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn activate_io_queues_rejects_disabled_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        // Disabled state — no pending_io either
        assert_eq!(
            driver.activate_io_queues().unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn activate_io_queues_rejects_without_create() {
        let mut driver = enabled_driver();
        // Enabled but create_io_queues not called — no pending_io
        assert_eq!(
            driver.activate_io_queues().unwrap_err(),
            NvmeError::InvalidState
        );
    }

    // ── Identify Namespace tests ──────────────────────────────────────────

    #[test]
    fn identify_namespace_builds_correct_sqe() {
        let mut driver = enabled_driver();
        let data_phys: u64 = 0xFEED_0000;
        let cmd = driver.identify_namespace(1, data_phys).unwrap();

        // Opcode 0x06 (Identify)
        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x06);

        // NSID at bytes 4-7
        let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
        assert_eq!(nsid, 1);

        // PRP1
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, data_phys);

        // CDW10: CNS=0x00
        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10, 0x00);
    }

    #[test]
    fn identify_namespace_different_nsids() {
        let mut driver = enabled_driver();
        let cmd1 = driver.identify_namespace(1, 0x1000).unwrap();
        let cmd2 = driver.identify_namespace(2, 0x2000).unwrap();

        let nsid1 = u32::from_le_bytes(cmd1.sqe[4..8].try_into().unwrap());
        let nsid2 = u32::from_le_bytes(cmd2.sqe[4..8].try_into().unwrap());
        assert_ne!(nsid1, nsid2);
        assert_eq!(nsid1, 1);
        assert_eq!(nsid2, 2);
    }

    #[test]
    fn identify_namespace_rejects_disabled_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        assert_eq!(
            driver.identify_namespace(1, 0x1000).unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn identify_namespace_works_in_ready_state() {
        let mut driver = enabled_driver();
        let _ = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        driver.activate_io_queues().unwrap();
        assert_eq!(driver.state(), NvmeState::Ready);
        // Should succeed in Ready state
        driver.identify_namespace(1, 0x1000).unwrap();
    }

    // ── parse_identify_namespace tests ────────────────────────────────────────

    #[test]
    fn parse_identify_namespace_extracts_fields() {
        let mut data = [0u8; 4096];

        // NSZE: bytes 0-7
        data[0..8].copy_from_slice(&1024u64.to_le_bytes());
        // NCAP: bytes 8-15
        data[8..16].copy_from_slice(&1000u64.to_le_bytes());
        // NUSE: bytes 16-23
        data[16..24].copy_from_slice(&500u64.to_le_bytes());
        // FLBAS: byte 26 (index 0 into LBA format table)
        data[26] = 0x00;
        // LBA Format 0 at byte 128: bytes [MS(2), LBADS(1), RP(1)]
        // LBADS = byte 130 = 9 → 512 bytes
        data[130] = 9;

        let ns = parse_identify_namespace(&data);
        assert_eq!(ns.nsze, 1024);
        assert_eq!(ns.ncap, 1000);
        assert_eq!(ns.nuse, 500);
        assert_eq!(ns.flbas, 0);
        assert_eq!(ns.lba_size_bytes, 512);
    }

    #[test]
    fn parse_identify_namespace_4k_sectors() {
        let mut data = [0u8; 4096];

        data[0..8].copy_from_slice(&2048u64.to_le_bytes());
        data[8..16].copy_from_slice(&2048u64.to_le_bytes());
        data[16..24].copy_from_slice(&100u64.to_le_bytes());
        // FLBAS: index 1
        data[26] = 0x01;
        // LBA Format 1 at byte 132 (128 + 1*4): LBADS at offset 2 = byte 134
        data[134] = 12; // 2^12 = 4096

        let ns = parse_identify_namespace(&data);
        assert_eq!(ns.flbas, 1);
        assert_eq!(ns.lba_size_bytes, 4096);
    }

    #[test]
    fn parse_identify_namespace_flbas_uses_low_nibble() {
        let mut data = [0u8; 4096];
        data[0..8].copy_from_slice(&100u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        data[16..24].copy_from_slice(&50u64.to_le_bytes());
        // FLBAS byte: 0x12 — low nibble is 2, high nibble (metadata) is 1
        data[26] = 0x12;
        // LBA Format 2 at byte 136 (128 + 2*4): LBADS at byte 138
        data[138] = 9;

        let ns = parse_identify_namespace(&data);
        assert_eq!(ns.flbas, 0x12, "raw byte preserved");
        assert_eq!(ns.lba_size_bytes, 512, "uses low nibble (index 2)");
    }

    // ── Phase 2 integration tests ─────────────────────────────────────────

    #[test]
    fn identify_controller_works_in_ready_state() {
        let mut driver = enabled_driver();
        let _ = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        driver.activate_io_queues().unwrap();
        assert_eq!(driver.state(), NvmeState::Ready);

        // identify_controller should still work in Ready state
        let cmd = driver.identify_controller(0xDEAD_0000).unwrap();
        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x06);
    }

    #[test]
    fn full_phase2_lifecycle() {
        // init → admin queue → create I/O queues → activate → identify namespace
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        assert_eq!(driver.state(), NvmeState::Disabled);

        driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
        driver.setup_admin_queue(0x1_0000, 0x2_0000, 32).unwrap();
        assert_eq!(driver.state(), NvmeState::Enabled);

        let cmds = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        // Verify we got CQ and SQ commands
        let op0 = u32::from_le_bytes(cmds[0].sqe[0..4].try_into().unwrap()) & 0xFF;
        let op1 = u32::from_le_bytes(cmds[1].sqe[0..4].try_into().unwrap()) & 0xFF;
        assert_eq!(op0, 0x05); // Create I/O CQ
        assert_eq!(op1, 0x01); // Create I/O SQ

        driver.activate_io_queues().unwrap();
        assert_eq!(driver.state(), NvmeState::Ready);

        // Identify namespace should work in Ready state
        let ns_cmd = driver.identify_namespace(1, 0xFEED_0000).unwrap();
        let ns_cdw0 = u32::from_le_bytes(ns_cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(ns_cdw0 & 0xFF, 0x06);
        let ns_nsid = u32::from_le_bytes(ns_cmd.sqe[4..8].try_into().unwrap());
        assert_eq!(ns_nsid, 1);
    }

    // ── ready_driver helper ───────────────────────────────────────────────────

    /// Helper: produce a Ready driver with I/O queues active.
    fn ready_driver() -> NvmeDriver<MockRegisterBank> {
        let mut driver = enabled_driver();
        let _ = driver.create_io_queues(0x3_0000, 0x4_0000, 32).unwrap();
        driver.activate_io_queues().unwrap();
        driver
    }

    // ── Read command tests ────────────────────────────────────────────────────

    #[test]
    fn read_block_builds_correct_sqe() {
        let mut driver = ready_driver();
        let cmd = driver.read_block(1, 100, 0xBEEF_0000).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x02);

        let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
        assert_eq!(nsid, 1);

        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0xBEEF_0000);

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10, 100);

        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0);

        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 0);
    }

    #[test]
    fn read_block_uses_io_queue_doorbell() {
        let mut driver = ready_driver();
        let cmd = driver.read_block(1, 0, 0x1000).unwrap();
        assert_eq!(cmd.doorbell_offset, 0x1008);
    }

    #[test]
    fn read_block_rejects_enabled_state() {
        let mut driver = enabled_driver();
        assert_eq!(driver.state(), NvmeState::Enabled);
        assert_eq!(
            driver.read_block(1, 0, 0x1000).unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn read_block_rejects_disabled_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        assert_eq!(
            driver.read_block(1, 0, 0x1000).unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn read_block_large_lba_splits_correctly() {
        let mut driver = ready_driver();
        let lba: u64 = 0x1_ABCD_EF00;
        let cmd = driver.read_block(1, lba, 0x1000).unwrap();

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw10, 0xABCD_EF00, "LBA low 32 bits");
        assert_eq!(cdw11, 0x0000_0001, "LBA high 32 bits");
    }

    // ── Write command tests ───────────────────────────────────────────────────

    #[test]
    fn write_block_builds_correct_sqe() {
        let mut driver = ready_driver();
        let cmd = driver.write_block(1, 200, 0xCAFE_0000).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x01);

        let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
        assert_eq!(nsid, 1);

        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0xCAFE_0000);

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10, 200);
        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0);

        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 0);
    }

    #[test]
    fn write_block_uses_io_queue_doorbell() {
        let mut driver = ready_driver();
        let cmd = driver.write_block(1, 0, 0x1000).unwrap();
        assert_eq!(cmd.doorbell_offset, 0x1008);
    }

    #[test]
    fn write_block_rejects_enabled_state() {
        let mut driver = enabled_driver();
        assert_eq!(
            driver.write_block(1, 0, 0x1000).unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn write_block_rejects_disabled_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        assert_eq!(
            driver.write_block(1, 0, 0x1000).unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn write_block_large_lba_splits_correctly() {
        let mut driver = ready_driver();
        let lba: u64 = 0x1_ABCD_EF00;
        let cmd = driver.write_block(1, lba, 0x1000).unwrap();

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw10, 0xABCD_EF00, "LBA low 32 bits");
        assert_eq!(cdw11, 0x0000_0001, "LBA high 32 bits");
    }

    // ── Flush command tests ───────────────────────────────────────────────

    #[test]
    fn flush_builds_correct_sqe() {
        let mut driver = ready_driver();
        let cmd = driver.flush(1).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x00);

        let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
        assert_eq!(nsid, 1);

        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0);

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw10, 0);
        assert_eq!(cdw11, 0);
        assert_eq!(cdw12, 0);
    }

    #[test]
    fn flush_uses_io_queue_doorbell() {
        let mut driver = ready_driver();
        let cmd = driver.flush(1).unwrap();
        assert_eq!(cmd.doorbell_offset, 0x1008);
    }

    #[test]
    fn flush_rejects_enabled_state() {
        let mut driver = enabled_driver();
        assert_eq!(driver.flush(1).unwrap_err(), NvmeError::InvalidState);
    }

    #[test]
    fn flush_rejects_disabled_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        assert_eq!(driver.flush(1).unwrap_err(), NvmeError::InvalidState);
    }

    // ── I/O completion tests ──────────────────────────────────────────────

    #[test]
    fn check_io_completion_phase_match() {
        let mut driver = ready_driver();
        let _ = driver.read_block(1, 0, 0x1000).unwrap();

        let mut cqe = [0u8; 16];
        cqe[0..4].copy_from_slice(&0x42u32.to_le_bytes());
        cqe[12..14].copy_from_slice(&0u16.to_le_bytes());
        cqe[14..16].copy_from_slice(&0x0001u16.to_le_bytes());

        let cr = driver
            .check_io_completion(&cqe)
            .unwrap()
            .expect("phase matches");
        assert_eq!(cr.completion.result, 0x42);
        assert_eq!(cr.completion.status, 0);
        assert_eq!(cr.cq_doorbell_offset, 0x100C);
    }

    #[test]
    fn check_io_completion_phase_mismatch() {
        let mut driver = ready_driver();
        let mut cqe = [0u8; 16];
        cqe[14..16].copy_from_slice(&0x0000u16.to_le_bytes());

        let result = driver.check_io_completion(&cqe).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn check_io_completion_rejects_enabled_state() {
        let mut driver = enabled_driver();
        let cqe = [0u8; 16];
        assert_eq!(
            driver.check_io_completion(&cqe).unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn check_io_completion_uses_io_cq_doorbell() {
        let mut driver = ready_driver();
        let mut cqe = [0u8; 16];
        cqe[14..16].copy_from_slice(&0x0001u16.to_le_bytes());

        let cr = driver.check_io_completion(&cqe).unwrap().unwrap();
        assert_eq!(cr.cq_doorbell_offset, 0x100C);
    }

    // ── Phase 3 integration test ──────────────────────────────────────────

    #[test]
    fn full_phase3_block_io_lifecycle() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        assert_eq!(driver.state(), NvmeState::Disabled);

        driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
        driver.setup_admin_queue(0x1_0000, 0x2_0000, 32).unwrap();
        assert_eq!(driver.state(), NvmeState::Enabled);

        let _ = driver.create_io_queues(0x3_0000, 0x4_0000, 32).unwrap();
        driver.activate_io_queues().unwrap();
        assert_eq!(driver.state(), NvmeState::Ready);

        let make_cqe = |phase: bool| -> [u8; 16] {
            let mut cqe = [0u8; 16];
            let status_word: u16 = if phase { 0x0001 } else { 0x0000 };
            cqe[14..16].copy_from_slice(&status_word.to_le_bytes());
            cqe
        };

        // Read block 42
        let read_cmd = driver.read_block(1, 42, 0xBEEF_0000).unwrap();
        let cdw0 = u32::from_le_bytes(read_cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x02);
        assert_eq!(read_cmd.doorbell_offset, 0x1008);

        let read_cr = driver
            .check_io_completion(&make_cqe(true))
            .unwrap()
            .expect("read completion");
        assert_eq!(read_cr.cq_doorbell_offset, 0x100C);

        // Write block 42
        let write_cmd = driver.write_block(1, 42, 0xCAFE_0000).unwrap();
        let cdw0 = u32::from_le_bytes(write_cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x01);

        let write_cr = driver
            .check_io_completion(&make_cqe(true))
            .unwrap()
            .expect("write completion");
        assert_eq!(write_cr.completion.status, 0);

        // Flush
        let flush_cmd = driver.flush(1).unwrap();
        let cdw0 = u32::from_le_bytes(flush_cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x00);

        let flush_cr = driver
            .check_io_completion(&make_cqe(true))
            .unwrap()
            .expect("flush completion");
        assert_eq!(flush_cr.completion.status, 0);
    }

    // ── MDTS tests ───────────────────────────────────────────────────────

    #[test]
    fn mdts_defaults_to_zero() {
        let driver = ready_driver();
        assert_eq!(driver.max_transfer_blocks(), None);
    }

    #[test]
    fn set_mdts_stores_value() {
        let mut driver = ready_driver();
        driver.set_mdts(5);
        // MDTS=5 → max transfer = 2^5 = 32 pages
        assert_eq!(driver.max_transfer_blocks(), Some(32));
    }

    #[test]
    fn set_mdts_one_means_two_pages() {
        let mut driver = ready_driver();
        driver.set_mdts(1);
        assert_eq!(driver.max_transfer_blocks(), Some(2));
    }

    #[test]
    fn set_mdts_large_value_saturates() {
        let mut driver = ready_driver();
        driver.set_mdts(32);
        assert_eq!(driver.max_transfer_blocks(), Some(u32::MAX));
    }

    // ── PRP list tests ───────────────────────────────────────────────────

    #[test]
    fn read_block_has_no_prp_list() {
        let mut driver = ready_driver();
        let cmd = driver.read_block(1, 0, 0x1000).unwrap();
        assert!(cmd.prp_list.is_none());
    }

    #[test]
    fn read_blocks_two_pages_uses_prp2() {
        let mut driver = ready_driver();
        let pages = [0x1_0000u64, 0x2_0000u64];
        let cmd = driver.read_blocks(1, 0, &pages).unwrap();

        // PRP1 = pages[0]
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0x1_0000);

        // PRP2 = pages[1]
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp2, 0x2_0000);

        // NLB = 1 (0-based: 2 blocks - 1)
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 1);

        // No PRP list needed for 2 pages
        assert!(cmd.prp_list.is_none());
    }

    #[test]
    fn read_blocks_three_pages_builds_prp_list() {
        let mut driver = ready_driver();
        let pages = [0x1_0000u64, 0x2_0000u64, 0x3_0000u64];
        let cmd = driver.read_blocks(1, 0, &pages).unwrap();

        // PRP1 = pages[0]
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0x1_0000);

        // PRP2 = sentinel (u64::MAX) — caller replaces with list phys addr
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp2, u64::MAX);

        // NLB = 2 (0-based: 3 blocks - 1)
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 2);

        // PRP list contains pages[1] and pages[2] as LE u64s
        let list = cmd.prp_list.as_ref().expect("3 pages needs PRP list");
        assert_eq!(list.len(), 16); // 2 entries × 8 bytes
        let entry0 = u64::from_le_bytes(list[0..8].try_into().unwrap());
        let entry1 = u64::from_le_bytes(list[8..16].try_into().unwrap());
        assert_eq!(entry0, 0x2_0000);
        assert_eq!(entry1, 0x3_0000);
    }

    #[test]
    fn read_blocks_eight_pages_prp_list_has_seven_entries() {
        let mut driver = ready_driver();
        let pages: Vec<u64> = (0..8).map(|i| (i + 1) * 0x1000).collect();
        let cmd = driver.read_blocks(1, 0, &pages).unwrap();

        // NLB = 7 (0-based: 8 blocks - 1)
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 7);

        let list = cmd.prp_list.as_ref().expect("8 pages needs PRP list");
        // 7 entries × 8 bytes = 56 bytes
        assert_eq!(list.len(), 56);
        for i in 0..7 {
            let entry = u64::from_le_bytes(list[i * 8..(i + 1) * 8].try_into().unwrap());
            assert_eq!(entry, (i as u64 + 2) * 0x1000);
        }
    }

    #[test]
    fn write_blocks_two_pages_uses_prp2() {
        let mut driver = ready_driver();
        let pages = [0x1_0000u64, 0x2_0000u64];
        let cmd = driver.write_blocks(1, 0, &pages).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x01); // Write opcode

        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp2, 0x2_0000);

        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 1);
    }

    #[test]
    fn single_block_wrapper_still_works() {
        let mut driver = ready_driver();
        let cmd = driver.read_block(1, 100, 0xBEEF_0000).unwrap();

        // Same assertions as the existing read_block_builds_correct_sqe test
        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x02);
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0xBEEF_0000);
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp2, 0);
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 0);
        assert!(cmd.prp_list.is_none());
    }

    #[test]
    fn read_blocks_cid_increments() {
        let mut driver = ready_driver();
        let cmd1 = driver.read_blocks(1, 0, &[0x1000, 0x2000]).unwrap();
        let cmd2 = driver.read_blocks(1, 10, &[0x3000, 0x4000]).unwrap();
        let cid1 = u32::from_le_bytes(cmd1.sqe[0..4].try_into().unwrap()) >> 16;
        let cid2 = u32::from_le_bytes(cmd2.sqe[0..4].try_into().unwrap()) >> 16;
        assert_eq!(cid2, cid1 + 1);
    }
}
