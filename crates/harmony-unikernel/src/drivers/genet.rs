// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O BCM54213PE GENET Ethernet driver.
//!
//! Register map derived from Linux `drivers/net/ethernet/broadcom/genet/`.
//! Uses the [`RegisterBank`] trait for all register access, enabling
//! full unit testing without hardware.

use super::dma_pool::DmaPool;
use super::register_bank::RegisterBank;

// ── Block base offsets (GENET v5, BCM2712 / RPi5) ─────────────────
const _SYS_OFF: usize = 0x0000;
const _EXT_OFF: usize = 0x0080;
const _INTRL2_0_OFF: usize = 0x0200;
const _INTRL2_1_OFF: usize = 0x0240;
const RBUF_OFF: usize = 0x0300;
const TBUF_OFF: usize = 0x0600; // v5
const UMAC_OFF: usize = 0x0800;
const RDMA_OFF: usize = 0x2000; // v5
const TDMA_OFF: usize = 0x4000; // v5

// ── SYS registers ─────────────────────────────────────────────────
const _SYS_REV_CTRL: usize = _SYS_OFF;
const _SYS_PORT_CTRL: usize = _SYS_OFF + 0x04;
const _SYS_RBUF_FLUSH_CTRL: usize = _SYS_OFF + 0x08;
const _SYS_TBUF_FLUSH_CTRL: usize = _SYS_OFF + 0x0C;

// Port modes
const _PORT_MODE_EXT_GPHY: u32 = 3;

// ── EXT registers ─────────────────────────────────────────────────
const _EXT_PWR_MGMT: usize = _EXT_OFF;
const _EXT_RGMII_OOB_CTRL: usize = _EXT_OFF + 0x0C;
const _EXT_GPHY_CTRL: usize = _EXT_OFF + 0x1C;

// EXT_RGMII_OOB_CTRL bits
const _RGMII_LINK: u32 = 1 << 4;
const _OOB_DISABLE: u32 = 1 << 5;
const _RGMII_MODE_EN: u32 = 1 << 6;
const _ID_MODE_DIS: u32 = 1 << 16;

// ── UMAC registers ────────────────────────────────────────────────
const UMAC_CMD: usize = UMAC_OFF + 0x008;
const UMAC_MAC0: usize = UMAC_OFF + 0x00C;
const UMAC_MAC1: usize = UMAC_OFF + 0x010;
const UMAC_MAX_FRAME_LEN: usize = UMAC_OFF + 0x014;
const UMAC_TX_FLUSH: usize = UMAC_OFF + 0x334;
const UMAC_MIB_CTRL: usize = UMAC_OFF + 0x580;
const UMAC_MDIO_CMD: usize = UMAC_OFF + 0x614;

// UMAC_CMD bits
const CMD_TX_EN: u32 = 1 << 0;
const CMD_RX_EN: u32 = 1 << 1;
const _CMD_SPEED_MASK: u32 = 3 << 2;
const CMD_SPEED_1000: u32 = 2 << 2;
const _CMD_SPEED_100: u32 = 1 << 2;
const _CMD_SPEED_10: u32 = 0;
const CMD_SW_RESET: u32 = 1 << 13;
const _CMD_HD_EN: u32 = 1 << 10;

// MIB control
const MIB_RESET_RX: u32 = 1 << 0;
const MIB_RESET_RUNT: u32 = 1 << 1;
const MIB_RESET_TX: u32 = 1 << 2;

// MDIO bits
const MDIO_START_BUSY: u32 = 1 << 29;
const MDIO_READ_FAIL: u32 = 1 << 28;
const MDIO_RD: u32 = 2 << 26;
const _MDIO_WR: u32 = 1 << 26;
const MDIO_PMD_SHIFT: u32 = 21;
const MDIO_REG_SHIFT: u32 = 16;

// ── RBUF registers ────────────────────────────────────────────────
const RBUF_CTRL: usize = RBUF_OFF;
const RBUF_CHK_CTRL: usize = RBUF_OFF + 0x14;

const RBUF_64B_EN: u32 = 1 << 0; // RBUF_CTRL: enable 64-byte status block
const RBUF_ALIGN_2B: u32 = 1 << 1;
const RBUF_CHK_EN: u32 = 1 << 0; // RBUF_CHK_CTRL: enable RX checksum offload
const RBUF_SKIP_FCS: u32 = 1 << 4;

// ── TBUF registers ────────────────────────────────────────────────
const TBUF_CTRL: usize = TBUF_OFF;

const TBUF_64B_EN: u32 = 1 << 0;

// ── DMA descriptor fields ─────────────────────────────────────────
const DMA_DESC_LENGTH_STATUS: usize = 0x00;
const DMA_DESC_ADDRESS_LO: usize = 0x04;
const DMA_DESC_ADDRESS_HI: usize = 0x08;
const DMA_DESC_SIZE: usize = 12; // 3 words × 4 bytes per descriptor (v5)
const DMA_DESC_NUM_WORDS: usize = 3; // words per descriptor (for end_ptr register)

// DMA control/status bits (same bit position, different registers)
const DMA_CTRL_EN: u32 = 1 << 0; // DMA_CTRL: set to enable DMA
const DMA_STATUS_DISABLED: u32 = 1 << 0; // DMA_STATUS: set when DMA is disabled
const _DMA_DESC_RAM_INIT_BUSY: u32 = 1 << 1;

const DMA_BUFLENGTH_SHIFT: u32 = 16;
const DMA_BUFLENGTH_MASK: u32 = 0x0FFF;
const _DMA_OWN: u32 = 0x8000;
const DMA_EOP: u32 = 0x4000;
const DMA_SOP: u32 = 0x2000;
const _DMA_WRAP: u32 = 0x1000;
const DMA_TX_APPEND_CRC: u32 = 0x0040;

// RX descriptor status bits
const DMA_RX_CRC_ERROR: u32 = 0x0002;
const DMA_RX_OV: u32 = 0x0001;
const DMA_RX_RXER: u32 = 0x0004;
const DMA_RX_LG: u32 = 0x0010;
const DMA_RX_NO: u32 = 0x0008;
const DMA_RX_ERROR_MASK: u32 = DMA_RX_CRC_ERROR | DMA_RX_OV | DMA_RX_RXER | DMA_RX_LG | DMA_RX_NO;

// ── DMA ring registers (per-ring, relative to RDMA/TDMA block) ───
// Ring register offset = ring_index * DMA_RING_SIZE + register_offset
const DMA_RING_SIZE: usize = 0x40;

// Ring registers (offsets within a ring's 0x40-byte block)
const RING_WRITE_PTR: usize = 0x00;
const RING_PROD_INDEX: usize = 0x08;
const RING_CONS_INDEX: usize = 0x0C;
const RING_BUF_SIZE: usize = 0x10;
const RING_START_ADDR: usize = 0x14;
// These are within the upper half of each ring's register block:
const RING_END_ADDR: usize = 0x1C;
const RING_READ_PTR: usize = 0x24;
const RING_MBUF_DONE_THRESH: usize = 0x2C;
const _RING_FLOW_PERIOD: usize = 0x30;
const RING_XON_XOFF_THRESH: usize = 0x34;

// DMA control register (global, after all ring registers)
// Ring 16 = default ring, 17 rings total (0-15 priority + 16 default)
const DMA_RINGS_SIZE: usize = DMA_RING_SIZE * 17;
const DMA_CTRL: usize = DMA_RINGS_SIZE;
const DMA_STATUS: usize = DMA_RINGS_SIZE + 0x04;
const DMA_SCB_BURST_SIZE: usize = DMA_RINGS_SIZE + 0x0C;

// After the ring-register block, four global DMA control registers
// (CTRL / STATUS / reserved / SCB_BURST_SIZE = 4 × 4 = 16 bytes)
// precede the descriptor array.
const DMA_DESC_BASE_OFFSET: usize = 0x10;

// Default ring index
const DEFAULT_RING: usize = 16;

const DMA_P_INDEX_MASK: u32 = 0xFFFF;
const DMA_C_INDEX_MASK: u32 = 0xFFFF;

const DMA_RING_SIZE_SHIFT: u32 = 16;
const DMA_MAX_BURST_LENGTH: u32 = 0x10;

// Flow control thresholds
const DMA_FC_THRESH_LO: u32 = 5;
const DMA_XOFF_THRESHOLD_SHIFT: u32 = 16;

// ── Constants ─────────────────────────────────────────────────────
const ENET_MAX_MTU_SIZE: u32 = 1536; // ETH payload + headers + padding
const ENET_MIN_FRAME: usize = 14; // Minimum Ethernet header (dst + src + ethertype)
const DMA_BUF_LENGTH: u32 = 2048;

// ── PHY registers (standard MII) ─────────────────────────────────
const MII_BMSR: u32 = 1; // Basic Mode Status Register
const BMSR_LSTATUS: u32 = 0x0004; // Link status
const PHY_ADDR: u32 = 1; // Default internal PHY address

// ── Error types ───────────────────────────────────────────────────

/// Errors from GENET driver operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenetError {
    /// DMA failed to enter disabled state within timeout.
    DmaTimeout,
    /// TX ring is full — no free descriptors.
    TxRingFull,
    /// Frame exceeds maximum transmit size.
    FrameTooLarge,
    /// Frame is smaller than minimum Ethernet header (14 bytes).
    FrameTooSmall,
    /// MDIO operation timed out.
    MdioTimeout,
    /// MDIO read completed but PHY did not acknowledge (NACK).
    MdioReadFail,
    /// No DMA buffers available in the pool.
    NoBuffers,
}

/// Statistics counters for the GENET interface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GenetStats {
    pub rx_packets: u32,
    pub tx_packets: u32,
    pub rx_errors: u32,
    pub tx_errors: u32,
}

/// A received frame from the RX ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxFrame {
    /// Raw Ethernet frame bytes (including header).
    pub data: alloc::vec::Vec<u8>,
    /// DMA status flags from the descriptor.
    pub status: u32,
}

/// Sans-I/O BCM54213PE GENET Ethernet driver.
///
/// Generic over `RX_RING` and `TX_RING`: number of descriptors in each
/// ring. The default hardware configuration uses 256 for each.
///
/// All methods take a `RegisterBank` for MMIO access — no embedded I/O.
pub struct GenetDriver<const RX_RING: usize, const TX_RING: usize> {
    rx_cons_index: u32,
    tx_prod_index: u32,
    tx_cons_index: u32,
    mac: [u8; 6],
    link_up: bool,
    stats: GenetStats,
    /// TX descriptor → buffer index mapping for reclaim.
    tx_buf_indices: [Option<usize>; TX_RING],
}

impl<const RX_RING: usize, const TX_RING: usize> GenetDriver<RX_RING, TX_RING> {
    /// Initialize the GENET controller.
    ///
    /// Performs the full hardware init sequence:
    /// 1. Software reset (UMAC)
    /// 2. Clear MIB counters
    /// 3. Set max frame length
    /// 4. Configure RBUF (64B receive status block, 2-byte alignment)
    /// 5. Configure TBUF (64B transmit status block)
    /// 6. Write MAC address
    /// 7. Disable then re-initialize DMA rings
    /// 8. Enable DMA + TX/RX in UMAC
    ///
    /// The `poll_count` parameter controls how many times to poll
    /// for DMA disable confirmation (sans-I/O: caller decides timeout).
    pub fn init(
        bank: &mut impl RegisterBank,
        mac: [u8; 6],
        poll_count: u32,
    ) -> Result<Self, GenetError> {
        assert!(RX_RING > 0 && TX_RING > 0, "ring sizes must be non-zero");

        // 1. Software reset
        bank.write(UMAC_CMD, CMD_SW_RESET);
        bank.write(UMAC_CMD, 0);

        // 2. Clear MIB counters
        bank.write(UMAC_MIB_CTRL, MIB_RESET_RX | MIB_RESET_TX | MIB_RESET_RUNT);
        bank.write(UMAC_MIB_CTRL, 0);

        // 3. Max frame length
        bank.write(UMAC_MAX_FRAME_LEN, ENET_MAX_MTU_SIZE);

        // 4. RBUF: enable 64B status block + 2-byte alignment
        bank.write(RBUF_CTRL, RBUF_64B_EN | RBUF_ALIGN_2B);
        // Enable RX checksum + skip FCS
        bank.write(RBUF_CHK_CTRL, RBUF_CHK_EN | RBUF_SKIP_FCS);

        // 5. TBUF: enable 64B status block
        bank.write(TBUF_CTRL, TBUF_64B_EN);

        // 6. MAC address (big-endian, upper 4 bytes in MAC0, lower 2 in MAC1)
        let mac0 = u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]);
        let mac1 = u32::from_be_bytes([0, 0, mac[4], mac[5]]);
        bank.write(UMAC_MAC0, mac0);
        bank.write(UMAC_MAC1, mac1);

        // 7. TX flush
        bank.write(UMAC_TX_FLUSH, 1);
        bank.write(UMAC_TX_FLUSH, 0);

        // 8. Disable DMA before configuring rings
        let tdma_ctrl = TDMA_OFF + DMA_CTRL;
        let rdma_ctrl = RDMA_OFF + DMA_CTRL;
        bank.write(tdma_ctrl, 0);
        bank.write(rdma_ctrl, 0);

        // Poll for DMA disabled
        let tdma_status = TDMA_OFF + DMA_STATUS;
        let rdma_status = RDMA_OFF + DMA_STATUS;
        let mut dma_disabled = false;
        for _ in 0..poll_count {
            let ts = bank.read(tdma_status);
            let rs = bank.read(rdma_status);
            if ts & DMA_STATUS_DISABLED != 0 && rs & DMA_STATUS_DISABLED != 0 {
                dma_disabled = true;
                break;
            }
        }
        if !dma_disabled {
            return Err(GenetError::DmaTimeout);
        }

        // 9. Configure DMA burst size
        bank.write(TDMA_OFF + DMA_SCB_BURST_SIZE, DMA_MAX_BURST_LENGTH);
        bank.write(RDMA_OFF + DMA_SCB_BURST_SIZE, DMA_MAX_BURST_LENGTH);

        // 10. Configure default TX ring (ring 16)
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.write(tx_ring_base + RING_PROD_INDEX, 0);
        bank.write(tx_ring_base + RING_CONS_INDEX, 0);
        bank.write(tx_ring_base + RING_MBUF_DONE_THRESH, 1);
        bank.write(
            tx_ring_base + RING_BUF_SIZE,
            (TX_RING as u32) << DMA_RING_SIZE_SHIFT | DMA_BUF_LENGTH,
        );
        bank.write(tx_ring_base + RING_START_ADDR, 0);
        bank.write(
            tx_ring_base + RING_END_ADDR,
            (TX_RING * DMA_DESC_NUM_WORDS - 1) as u32,
        );
        bank.write(tx_ring_base + RING_WRITE_PTR, 0);
        bank.write(tx_ring_base + RING_READ_PTR, 0);

        // 11. Configure default RX ring (ring 16)
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.write(rx_ring_base + RING_PROD_INDEX, 0);
        bank.write(rx_ring_base + RING_CONS_INDEX, 0);
        bank.write(rx_ring_base + RING_MBUF_DONE_THRESH, 1);
        bank.write(
            rx_ring_base + RING_BUF_SIZE,
            (RX_RING as u32) << DMA_RING_SIZE_SHIFT | DMA_BUF_LENGTH,
        );
        // Flow control: XOFF (pause) threshold derived from ring size, XON (resume) low.
        // Guard: XOFF must exceed XON for valid hysteresis (matters for RX_RING < 80).
        let fc_thresh_hi = {
            let derived = (RX_RING as u32) >> 4;
            if derived <= DMA_FC_THRESH_LO {
                DMA_FC_THRESH_LO + 1
            } else {
                derived
            }
        };
        bank.write(
            rx_ring_base + RING_XON_XOFF_THRESH,
            fc_thresh_hi << DMA_XOFF_THRESHOLD_SHIFT | DMA_FC_THRESH_LO,
        );
        bank.write(rx_ring_base + RING_START_ADDR, 0);
        bank.write(
            rx_ring_base + RING_END_ADDR,
            (RX_RING * DMA_DESC_NUM_WORDS - 1) as u32,
        );
        bank.write(rx_ring_base + RING_WRITE_PTR, 0);
        bank.write(rx_ring_base + RING_READ_PTR, 0);

        // 12. Enable DMA
        bank.write(tdma_ctrl, DMA_CTRL_EN);
        bank.write(rdma_ctrl, DMA_CTRL_EN);

        // 13. Enable TX + RX in UMAC
        bank.write(UMAC_CMD, CMD_TX_EN | CMD_RX_EN | CMD_SPEED_1000);

        Ok(Self {
            rx_cons_index: 0,
            tx_prod_index: 0,
            tx_cons_index: 0,
            mac,
            link_up: false,
            stats: GenetStats::default(),
            tx_buf_indices: [None; TX_RING],
        })
    }

    /// Return the MAC address configured during init.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Check whether the TX ring has space for at least one frame.
    pub fn tx_ready(&self, bank: &impl RegisterBank) -> bool {
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let cons = bank.read(tx_ring_base + RING_CONS_INDEX) & DMA_C_INDEX_MASK;
        let used = self.tx_prod_index.wrapping_sub(cons) & DMA_P_INDEX_MASK;
        (used as usize) < TX_RING
    }

    /// Transmit an Ethernet frame.
    ///
    /// Writes the frame data to a TX descriptor and advances the
    /// producer index. The frame must include the Ethernet header
    /// but not the FCS (hardware appends CRC).
    pub fn send<const N: usize>(
        &mut self,
        bank: &mut impl RegisterBank,
        frame: &[u8],
        tx_pool: &mut DmaPool<N>,
    ) -> Result<(), GenetError> {
        if frame.len() < ENET_MIN_FRAME {
            self.stats.tx_errors += 1;
            return Err(GenetError::FrameTooSmall);
        }
        if frame.len() > ENET_MAX_MTU_SIZE as usize {
            self.stats.tx_errors += 1;
            return Err(GenetError::FrameTooLarge);
        }
        if !self.tx_ready(bank) {
            self.stats.tx_errors += 1;
            return Err(GenetError::TxRingFull);
        }

        // Allocate a DMA buffer and copy frame data.
        let buf_idx = tx_pool.alloc().ok_or_else(|| {
            self.stats.tx_errors += 1;
            GenetError::NoBuffers
        })?;
        let buf = tx_pool.get(buf_idx);
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.virt, frame.len());
        }

        let desc_idx = (self.tx_prod_index as usize) % TX_RING;

        let desc_base = TDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET + desc_idx * DMA_DESC_SIZE;

        // Write descriptor address fields (before LENGTH_STATUS for correct ordering).
        bank.write(desc_base + DMA_DESC_ADDRESS_LO, buf.phys as u32);
        bank.write(desc_base + DMA_DESC_ADDRESS_HI, (buf.phys >> 32) as u32);

        // Track buffer index for TX completion reclaim.
        self.tx_buf_indices[desc_idx] = Some(buf_idx);

        let len_status =
            ((frame.len() as u32) << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP | DMA_TX_APPEND_CRC;
        bank.write(desc_base + DMA_DESC_LENGTH_STATUS, len_status);

        // Advance write pointer (word units) and producer index.
        // WRITE_PTR is a "next slot to fill" pointer (producer head) —
        // it must point past the descriptor just written, matching Linux's
        // `ring->write_ptr += DMA_WORDS_PER_BD` before the register write.
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let next_desc = (desc_idx + 1) % TX_RING;
        let write_ptr = (next_desc * DMA_DESC_NUM_WORDS) as u32;
        bank.write(tx_ring_base + RING_WRITE_PTR, write_ptr);

        self.tx_prod_index = (self.tx_prod_index + 1) & DMA_P_INDEX_MASK;
        bank.write(tx_ring_base + RING_PROD_INDEX, self.tx_prod_index);

        self.stats.tx_packets += 1;
        Ok(())
    }

    /// Check for completed TX descriptors and reclaim them.
    ///
    /// Returns the number of descriptors freed since last call.
    pub fn reclaim_tx<const N: usize>(
        &mut self,
        bank: &impl RegisterBank,
        tx_pool: &mut DmaPool<N>,
    ) -> usize {
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let hw_cons = bank.read(tx_ring_base + RING_CONS_INDEX) & DMA_C_INDEX_MASK;
        let mut freed = 0u32;
        while self.tx_cons_index != hw_cons {
            let desc_idx = (self.tx_cons_index as usize) % TX_RING;
            if let Some(buf_idx) = self.tx_buf_indices[desc_idx].take() {
                let _ = tx_pool.free(buf_idx);
            }
            self.tx_cons_index = (self.tx_cons_index + 1) & DMA_C_INDEX_MASK;
            freed += 1;
        }
        freed as usize
    }

    /// Poll for a received frame.
    ///
    /// Reads the next RX descriptor if the hardware has produced one.
    /// Returns `Some(RxFrame)` on success, `None` if no frames are
    /// pending or if the frame had errors (which are counted in stats).
    ///
    /// Caller should call this in a loop until it returns `None`.
    pub fn poll_rx<const N: usize>(
        &mut self,
        bank: &mut impl RegisterBank,
        rx_pool: &mut DmaPool<N>,
    ) -> Option<RxFrame> {
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let prod = bank.read(rx_ring_base + RING_PROD_INDEX) & DMA_P_INDEX_MASK;

        if prod == self.rx_cons_index {
            return None; // nothing to read
        }

        let desc_idx = (self.rx_cons_index as usize) % RX_RING;
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET + desc_idx * DMA_DESC_SIZE;

        let len_status = bank.read(desc_base + DMA_DESC_LENGTH_STATUS);
        let length = ((len_status >> DMA_BUFLENGTH_SHIFT) & DMA_BUFLENGTH_MASK) as usize;
        let status = len_status & 0xFFFF;

        let addr_lo = bank.read(desc_base + DMA_DESC_ADDRESS_LO) as u64;
        let addr_hi = bank.read(desc_base + DMA_DESC_ADDRESS_HI) as u64;
        let buf_phys = addr_lo | (addr_hi << 32);

        // Advance read pointer (word units) and consumer index.
        // READ_PTR points past the consumed descriptor, matching TX WRITE_PTR
        // semantics. Both use word-unit addressing into descriptor RAM.
        let next_desc = (desc_idx + 1) % RX_RING;
        let read_ptr = (next_desc * DMA_DESC_NUM_WORDS) as u32;
        bank.write(rx_ring_base + RING_READ_PTR, read_ptr);

        self.rx_cons_index = (self.rx_cons_index + 1) & DMA_C_INDEX_MASK;
        bank.write(rx_ring_base + RING_CONS_INDEX, self.rx_cons_index);

        // Reject zero-length descriptors — no valid Ethernet frame can have
        // zero payload, and Ok(vec![]) would be indistinguishable from "ring empty".
        if length == 0 {
            self.stats.rx_errors += 1;
            return None;
        }

        // Reject fragmented frames: with DMA_BUF_LENGTH (2048) > ENET_MAX_MTU_SIZE
        // (1536), every valid frame fits in a single descriptor. Both SOP and EOP
        // must be set; a descriptor missing either indicates a multi-descriptor
        // fragment that this driver does not reassemble.
        if status & (DMA_SOP | DMA_EOP) != (DMA_SOP | DMA_EOP) {
            self.stats.rx_errors += 1;
            return None;
        }

        // Check for errors
        if status & DMA_RX_ERROR_MASK != 0 {
            self.stats.rx_errors += 1;
            return None;
        }

        // Copy frame data from DMA buffer.
        let data = if let Some(buf_idx) = rx_pool.find_by_phys(buf_phys) {
            let buf = rx_pool.get(buf_idx);
            let mut frame_data = alloc::vec![0u8; length];
            unsafe {
                core::ptr::copy_nonoverlapping(buf.virt, frame_data.as_mut_ptr(), length);
            }
            // Return consumed buffer and re-arm with a fresh one.
            let _ = rx_pool.free(buf_idx);
            if let Some(new_idx) = rx_pool.alloc() {
                let new_buf = rx_pool.get(new_idx);
                bank.write(desc_base + DMA_DESC_ADDRESS_LO, new_buf.phys as u32);
                bank.write(desc_base + DMA_DESC_ADDRESS_HI, (new_buf.phys >> 32) as u32);
            }
            frame_data
        } else {
            // Buffer not found in pool — hardware error or corruption.
            self.stats.rx_errors += 1;
            return None;
        };

        self.stats.rx_packets += 1;
        Some(RxFrame { data, status })
    }

    /// Pre-arm all RX descriptors with DMA buffer addresses.
    ///
    /// Called once after `init()`. Each descriptor gets a fresh buffer from the pool.
    pub fn arm_rx_descriptors<const N: usize>(
        &mut self,
        bank: &mut impl RegisterBank,
        rx_pool: &mut DmaPool<N>,
    ) -> Result<(), GenetError> {
        for desc_idx in 0..RX_RING {
            let buf_idx = rx_pool.alloc().ok_or(GenetError::NoBuffers)?;
            let buf = rx_pool.get(buf_idx);
            let desc_base =
                RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET + desc_idx * DMA_DESC_SIZE;
            bank.write(desc_base + DMA_DESC_ADDRESS_LO, buf.phys as u32);
            bank.write(desc_base + DMA_DESC_ADDRESS_HI, (buf.phys >> 32) as u32);
        }
        Ok(())
    }

    /// Read PHY link status via MDIO.
    ///
    /// Initiates an MDIO read of the Basic Mode Status Register (BMSR)
    /// and polls for completion up to `poll_count` iterations.
    /// Updates the cached `link_up` field and returns it.
    pub fn link_status(
        &mut self,
        bank: &mut impl RegisterBank,
        poll_count: u32,
    ) -> Result<bool, GenetError> {
        // Build MDIO read command for BMSR (reg 1) on PHY_ADDR
        let cmd =
            MDIO_START_BUSY | MDIO_RD | (PHY_ADDR << MDIO_PMD_SHIFT) | (MII_BMSR << MDIO_REG_SHIFT);
        bank.write(UMAC_MDIO_CMD, cmd);

        // Poll for completion
        let mut completed = false;
        let mut result = 0u32;
        for _ in 0..poll_count {
            result = bank.read(UMAC_MDIO_CMD);
            if result & MDIO_START_BUSY == 0 {
                completed = true;
                break;
            }
        }
        if !completed {
            return Err(GenetError::MdioTimeout);
        }

        // PHY NACK: MDIO transaction completed but no device responded.
        if result & MDIO_READ_FAIL != 0 {
            return Err(GenetError::MdioReadFail);
        }

        self.link_up = result & BMSR_LSTATUS != 0;
        Ok(self.link_up)
    }

    /// Return current interface statistics.
    pub fn stats(&self) -> GenetStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::dma_pool::{DmaBuffer, DmaPool};
    use crate::drivers::register_bank::mock::MockRegisterBank;
    use alloc::vec;

    fn make_test_pool<const N: usize>() -> DmaPool<N> {
        let mut buffers = [DmaBuffer {
            virt: core::ptr::null_mut(),
            phys: 0,
        }; N];
        for i in 0..N {
            let buf = alloc::vec![0u8; 2048].into_boxed_slice();
            let ptr = Box::into_raw(buf) as *mut u8;
            buffers[i] = DmaBuffer {
                virt: ptr,
                phys: ptr as u64,
            };
        }
        DmaPool::new(buffers, 2048)
    }

    fn init_bank() -> MockRegisterBank {
        let mut bank = MockRegisterBank::new();
        // DMA status: disabled immediately
        bank.on_read(TDMA_OFF + DMA_STATUS, vec![DMA_STATUS_DISABLED]);
        bank.on_read(RDMA_OFF + DMA_STATUS, vec![DMA_STATUS_DISABLED]);
        bank
    }

    const TEST_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    // ── Init tests ────────────────────────────────────────────────

    #[test]
    fn init_writes_mac_address() {
        let mut bank = init_bank();
        let driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // MAC0 = big-endian upper 4 bytes
        let mac0_writes: Vec<(usize, u32)> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UMAC_MAC0)
            .copied()
            .collect();
        assert_eq!(mac0_writes, vec![(UMAC_MAC0, 0xDEADBEEF)]);

        // MAC1 = big-endian lower 2 bytes
        let mac1_writes: Vec<(usize, u32)> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UMAC_MAC1)
            .copied()
            .collect();
        assert_eq!(mac1_writes, vec![(UMAC_MAC1, 0x0000CAFE)]);

        assert_eq!(driver.mac(), TEST_MAC);
    }

    #[test]
    fn init_performs_sw_reset() {
        let mut bank = init_bank();
        GenetDriver::<256, 256>::init(&mut bank, TEST_MAC, 10).unwrap();

        // First UMAC_CMD write should be SW_RESET
        let cmd_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UMAC_CMD)
            .map(|(_, v)| *v)
            .collect();
        assert!(cmd_writes.len() >= 3);
        assert_eq!(cmd_writes[0], CMD_SW_RESET);
        assert_eq!(cmd_writes[1], 0); // clear reset
    }

    #[test]
    fn init_clears_mib_counters() {
        let mut bank = init_bank();
        GenetDriver::<256, 256>::init(&mut bank, TEST_MAC, 10).unwrap();

        let mib_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UMAC_MIB_CTRL)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(
            mib_writes,
            vec![MIB_RESET_RX | MIB_RESET_TX | MIB_RESET_RUNT, 0]
        );
    }

    #[test]
    fn init_enables_dma_and_umac() {
        let mut bank = init_bank();
        GenetDriver::<256, 256>::init(&mut bank, TEST_MAC, 10).unwrap();

        // Last UMAC_CMD write should enable TX+RX
        let cmd_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UMAC_CMD)
            .map(|(_, v)| *v)
            .collect();
        let last_cmd = *cmd_writes.last().unwrap();
        assert!(last_cmd & CMD_TX_EN != 0, "TX not enabled");
        assert!(last_cmd & CMD_RX_EN != 0, "RX not enabled");

        // DMA should be enabled
        let tdma_ctrl_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == TDMA_OFF + DMA_CTRL)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(*tdma_ctrl_writes.last().unwrap(), DMA_CTRL_EN);
    }

    #[test]
    fn init_configures_default_ring() {
        let mut bank = init_bank();
        GenetDriver::<256, 256>::init(&mut bank, TEST_MAC, 10).unwrap();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;

        // TX ring prod/cons indices zeroed
        let prod_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == tx_ring_base + RING_PROD_INDEX)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(prod_writes, vec![0]);

        let cons_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == tx_ring_base + RING_CONS_INDEX)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(cons_writes, vec![0]);
    }

    #[test]
    fn init_mbuf_done_thresh_set_for_both_rings() {
        let mut bank = init_bank();
        GenetDriver::<256, 256>::init(&mut bank, TEST_MAC, 10).unwrap();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;

        let tx_thresh: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == tx_ring_base + RING_MBUF_DONE_THRESH)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(tx_thresh, vec![1]);

        let rx_thresh: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == rx_ring_base + RING_MBUF_DONE_THRESH)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(rx_thresh, vec![1]);
    }

    #[test]
    fn init_end_addr_uses_word_units() {
        let mut bank = init_bank();
        GenetDriver::<256, 256>::init(&mut bank, TEST_MAC, 10).unwrap();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;

        // end_ptr = num_descriptors × 3 words_per_descriptor - 1
        // For 256 descriptors: 256 × 3 - 1 = 767
        let expected = (256 * DMA_DESC_NUM_WORDS - 1) as u32;

        let tx_end: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == tx_ring_base + RING_END_ADDR)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(tx_end, vec![expected]);

        let rx_end: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == rx_ring_base + RING_END_ADDR)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(rx_end, vec![expected]);
    }

    // ── TX tests ──────────────────────────────────────────────────

    #[test]
    fn tx_ready_when_ring_has_space() {
        let mut bank = init_bank();
        let driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // Cons index = prod index = 0, so ring is empty (all free)
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);
        assert!(driver.tx_ready(&bank));
    }

    #[test]
    fn tx_not_ready_when_ring_full() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<4, 4> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // Advance prod_index to fill the ring
        driver.tx_prod_index = 4;
        // Cons index still 0 — ring is full
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);
        assert!(!driver.tx_ready(&bank));
    }

    #[test]
    fn send_frame_advances_prod_index() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<256>();

        // Consumer has caught up — ring is empty
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        let frame = [0u8; 64]; // minimum Ethernet frame
        driver.send(&mut bank, &frame, &mut tx_pool).unwrap();

        assert_eq!(driver.tx_prod_index, 1);
        assert_eq!(driver.stats.tx_packets, 1);
    }

    #[test]
    fn send_writes_descriptor() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<256>();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        let frame = [0xAA; 64];
        bank.writes.clear(); // clear init writes for easier assertion
        driver.send(&mut bank, &frame, &mut tx_pool).unwrap();

        // Descriptor writes: ADDRESS_LO, ADDRESS_HI, then LENGTH_STATUS last (ownership transfer).
        // Descriptor base = TDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET + desc_idx * DMA_DESC_SIZE
        let desc_base = TDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status_writes: Vec<(usize, u32)> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == desc_base + DMA_DESC_LENGTH_STATUS)
            .copied()
            .collect();
        assert!(!len_status_writes.is_empty());
        let (_, len_status) = len_status_writes[0];
        let written_len = (len_status >> DMA_BUFLENGTH_SHIFT) & DMA_BUFLENGTH_MASK;
        assert_eq!(written_len, 64);
        assert!(len_status & DMA_SOP != 0);
        assert!(len_status & DMA_EOP != 0);
        assert!(len_status & DMA_TX_APPEND_CRC != 0);
    }

    #[test]
    fn send_updates_write_ptr() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<4, 4> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<4>();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0, 0]);
        bank.writes.clear();

        // First send: desc_idx=0, write_ptr points to NEXT slot = (0+1)%4 * 3 = 3
        driver.send(&mut bank, &[0u8; 64], &mut tx_pool).unwrap();
        let wp0: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == tx_ring_base + RING_WRITE_PTR)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(wp0, vec![3]);

        bank.writes.clear();

        // Second send: desc_idx=1, write_ptr = (1+1)%4 * 3 = 6
        driver.send(&mut bank, &[0u8; 64], &mut tx_pool).unwrap();
        let wp1: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == tx_ring_base + RING_WRITE_PTR)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(wp1, vec![6]);
    }

    #[test]
    fn send_rejects_oversized_frame() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<256>();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        let frame = [0u8; 2048]; // way too big
        assert_eq!(
            driver.send(&mut bank, &frame, &mut tx_pool),
            Err(GenetError::FrameTooLarge)
        );
    }

    #[test]
    fn send_returns_error_when_ring_full() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<4, 4> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<4>();

        driver.tx_prod_index = 4;
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        let frame = [0u8; 64];
        assert_eq!(
            driver.send(&mut bank, &frame, &mut tx_pool),
            Err(GenetError::TxRingFull)
        );
    }

    #[test]
    fn tx_complete_reclaims_descriptors() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<256>();

        // Simulate: we sent 3 frames (prod=3), hardware consumed 2 (cons=2)
        driver.tx_prod_index = 3;
        driver.tx_cons_index = 0;

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![2]);

        let freed = driver.reclaim_tx(&bank, &mut tx_pool);
        assert_eq!(freed, 2);
        assert_eq!(driver.tx_cons_index, 2);
    }

    // ── RX tests ──────────────────────────────────────────────────

    #[test]
    fn poll_rx_returns_none_when_empty() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut rx_pool = make_test_pool::<256>();

        // RX prod index = cons index = 0 — nothing to read
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![0]);
        assert!(driver.poll_rx(&mut bank, &mut rx_pool).is_none());
    }

    #[test]
    fn poll_rx_returns_frame() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut rx_pool = make_test_pool::<256>();

        // Pre-allocate a buffer and set up the descriptor address reads.
        let buf_idx = rx_pool.alloc().unwrap();
        let buf_phys = rx_pool.get(buf_idx).phys;

        // Hardware has produced 1 frame (prod=1, cons=0)
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1]);

        // Descriptor: 64-byte frame, SOP|EOP set, no errors
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP;
        bank.on_read(desc_base + DMA_DESC_LENGTH_STATUS, vec![len_status]);
        bank.on_read(desc_base + DMA_DESC_ADDRESS_LO, vec![buf_phys as u32]);
        bank.on_read(
            desc_base + DMA_DESC_ADDRESS_HI,
            vec![(buf_phys >> 32) as u32],
        );

        // Mark the buffer as in-use (allocated) so poll_rx can find and free it.
        // (Already allocated above — pool tracks it as in-use.)
        let frame = driver.poll_rx(&mut bank, &mut rx_pool);
        assert!(frame.is_some());
        let frame = frame.unwrap();
        assert_eq!(frame.data.len(), 64);
        assert_eq!(driver.stats.rx_packets, 1);
        assert_eq!(driver.rx_cons_index, 1);
    }

    #[test]
    fn poll_rx_rejects_zero_length_descriptor() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut rx_pool = make_test_pool::<256>();

        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1]);

        // Descriptor with length=0, no error flags
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status = DMA_SOP | DMA_EOP; // length field = 0
        bank.on_read(desc_base + DMA_DESC_LENGTH_STATUS, vec![len_status]);
        // Addresses are read before the zero-length check — provide defaults.
        bank.on_read(desc_base + DMA_DESC_ADDRESS_LO, vec![0]);
        bank.on_read(desc_base + DMA_DESC_ADDRESS_HI, vec![0]);

        let frame = driver.poll_rx(&mut bank, &mut rx_pool);
        assert!(frame.is_none());
        assert_eq!(driver.stats.rx_errors, 1);
        assert_eq!(driver.stats.rx_packets, 0);
        assert_eq!(driver.rx_cons_index, 1); // descriptor still consumed
    }

    #[test]
    fn poll_rx_updates_read_ptr() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<4, 4> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut rx_pool = make_test_pool::<4>();

        // Pre-allocate 2 buffers and record their physical addresses.
        let buf0_idx = rx_pool.alloc().unwrap();
        let buf0_phys = rx_pool.get(buf0_idx).phys;
        let buf1_idx = rx_pool.alloc().unwrap();
        let buf1_phys = rx_pool.get(buf1_idx).phys;

        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![2, 2]);

        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP;
        bank.on_read(desc_base + DMA_DESC_LENGTH_STATUS, vec![len_status]);
        bank.on_read(desc_base + DMA_DESC_ADDRESS_LO, vec![buf0_phys as u32]);
        bank.on_read(
            desc_base + DMA_DESC_ADDRESS_HI,
            vec![(buf0_phys >> 32) as u32],
        );
        bank.on_read(
            desc_base + DMA_DESC_SIZE + DMA_DESC_LENGTH_STATUS,
            vec![len_status],
        );
        bank.on_read(
            desc_base + DMA_DESC_SIZE + DMA_DESC_ADDRESS_LO,
            vec![buf1_phys as u32],
        );
        bank.on_read(
            desc_base + DMA_DESC_SIZE + DMA_DESC_ADDRESS_HI,
            vec![(buf1_phys >> 32) as u32],
        );
        bank.writes.clear();

        // First poll: desc_idx=0, read_ptr = (0+1)%4 * 3 = 3 (word units, next slot)
        driver.poll_rx(&mut bank, &mut rx_pool);
        let rp0: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == rx_ring_base + RING_READ_PTR)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(rp0, vec![3]);

        bank.writes.clear();

        // Second poll: desc_idx=1, read_ptr = (1+1)%4 * 3 = 6
        driver.poll_rx(&mut bank, &mut rx_pool);
        let rp1: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == rx_ring_base + RING_READ_PTR)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(rp1, vec![6]);
    }

    #[test]
    fn poll_rx_rejects_fragmented_frame() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut rx_pool = make_test_pool::<256>();

        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1]);

        // Descriptor with SOP only (first fragment of a multi-descriptor frame)
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP; // missing EOP
        bank.on_read(desc_base + DMA_DESC_LENGTH_STATUS, vec![len_status]);
        // Addresses are read before the SOP|EOP check — provide defaults.
        bank.on_read(desc_base + DMA_DESC_ADDRESS_LO, vec![0]);
        bank.on_read(desc_base + DMA_DESC_ADDRESS_HI, vec![0]);

        let frame = driver.poll_rx(&mut bank, &mut rx_pool);
        assert!(frame.is_none());
        assert_eq!(driver.stats.rx_errors, 1);
        assert_eq!(driver.stats.rx_packets, 0);
        assert_eq!(driver.rx_cons_index, 1); // descriptor still consumed
    }

    #[test]
    fn poll_rx_detects_error_frames() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut rx_pool = make_test_pool::<256>();

        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1]);

        // Descriptor with CRC error flag
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP | DMA_RX_CRC_ERROR;
        bank.on_read(desc_base + DMA_DESC_LENGTH_STATUS, vec![len_status]);
        // Addresses are read before the error check — provide defaults.
        bank.on_read(desc_base + DMA_DESC_ADDRESS_LO, vec![0]);
        bank.on_read(desc_base + DMA_DESC_ADDRESS_HI, vec![0]);

        let frame = driver.poll_rx(&mut bank, &mut rx_pool);
        // Error frames are skipped (consumed but not returned)
        assert!(frame.is_none());
        assert_eq!(driver.stats.rx_errors, 1);
        assert_eq!(driver.rx_cons_index, 1); // descriptor still consumed
    }

    #[test]
    fn poll_rx_advances_cons_index() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut rx_pool = make_test_pool::<256>();

        // Pre-allocate 2 buffers for the 2 frames.
        let buf0_idx = rx_pool.alloc().unwrap();
        let buf0_phys = rx_pool.get(buf0_idx).phys;
        let buf1_idx = rx_pool.alloc().unwrap();
        let buf1_phys = rx_pool.get(buf1_idx).phys;

        // Two frames available
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1, 2]);

        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP;
        bank.on_read(desc_base + DMA_DESC_LENGTH_STATUS, vec![len_status]);
        bank.on_read(desc_base + DMA_DESC_ADDRESS_LO, vec![buf0_phys as u32]);
        bank.on_read(
            desc_base + DMA_DESC_ADDRESS_HI,
            vec![(buf0_phys >> 32) as u32],
        );
        bank.on_read(
            desc_base + DMA_DESC_SIZE + DMA_DESC_LENGTH_STATUS,
            vec![len_status],
        );
        bank.on_read(
            desc_base + DMA_DESC_SIZE + DMA_DESC_ADDRESS_LO,
            vec![buf1_phys as u32],
        );
        bank.on_read(
            desc_base + DMA_DESC_SIZE + DMA_DESC_ADDRESS_HI,
            vec![(buf1_phys >> 32) as u32],
        );

        driver.poll_rx(&mut bank, &mut rx_pool);
        assert_eq!(driver.rx_cons_index, 1);

        driver.poll_rx(&mut bank, &mut rx_pool);
        assert_eq!(driver.rx_cons_index, 2);
        assert_eq!(driver.stats.rx_packets, 2);
    }

    // ── Link status tests ─────────────────────────────────────────

    #[test]
    fn link_status_reads_phy_bmsr() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // MDIO read: first read returns BUSY, second returns result with LSTATUS
        bank.on_read(
            UMAC_MDIO_CMD,
            vec![
                MDIO_START_BUSY, // first poll: still busy
                BMSR_LSTATUS,    // second poll: done, link up
            ],
        );

        let up = driver.link_status(&mut bank, 100).unwrap();
        assert!(up);
        assert!(driver.link_up);
    }

    #[test]
    fn link_status_down() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // MDIO returns 0 (no LSTATUS bit)
        bank.on_read(UMAC_MDIO_CMD, vec![0]);

        let up = driver.link_status(&mut bank, 100).unwrap();
        assert!(!up);
        assert!(!driver.link_up);
    }

    #[test]
    fn init_returns_dma_timeout() {
        let mut bank = MockRegisterBank::new();
        // DMA never reports disabled
        bank.on_read(TDMA_OFF + DMA_STATUS, vec![0]);
        bank.on_read(RDMA_OFF + DMA_STATUS, vec![0]);
        let result = GenetDriver::<256, 256>::init(&mut bank, TEST_MAC, 5);
        assert!(matches!(result, Err(GenetError::DmaTimeout)));
    }

    #[test]
    #[should_panic(expected = "ring sizes must be non-zero")]
    fn init_panics_on_zero_ring_size() {
        let mut bank = init_bank();
        let _ = GenetDriver::<0, 0>::init(&mut bank, TEST_MAC, 10);
    }

    #[test]
    fn link_status_returns_mdio_timeout() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // MDIO always busy
        bank.on_read(UMAC_MDIO_CMD, vec![MDIO_START_BUSY]);

        let result = driver.link_status(&mut bank, 5);
        assert_eq!(result, Err(GenetError::MdioTimeout));
    }

    #[test]
    fn link_status_returns_mdio_read_fail() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // MDIO completes (START_BUSY clear) but PHY NACKed (READ_FAIL set)
        bank.on_read(UMAC_MDIO_CMD, vec![MDIO_READ_FAIL]);

        let result = driver.link_status(&mut bank, 5);
        assert_eq!(result, Err(GenetError::MdioReadFail));
    }

    // ── Stats tests ───────────────────────────────────────────────

    #[test]
    fn stats_tracks_tx_and_rx() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<256>();
        let mut rx_pool = make_test_pool::<256>();

        // Send a frame
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);
        driver.send(&mut bank, &[0u8; 64], &mut tx_pool).unwrap();

        // Pre-allocate an RX buffer and set up the address reads.
        let rx_buf_idx = rx_pool.alloc().unwrap();
        let rx_buf_phys = rx_pool.get(rx_buf_idx).phys;

        // Receive a frame
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1]);
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        bank.on_read(
            desc_base + DMA_DESC_LENGTH_STATUS,
            vec![(64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP],
        );
        bank.on_read(desc_base + DMA_DESC_ADDRESS_LO, vec![rx_buf_phys as u32]);
        bank.on_read(
            desc_base + DMA_DESC_ADDRESS_HI,
            vec![(rx_buf_phys >> 32) as u32],
        );
        driver.poll_rx(&mut bank, &mut rx_pool);

        let stats = driver.stats();
        assert_eq!(stats.tx_packets, 1);
        assert_eq!(stats.rx_packets, 1);
        assert_eq!(stats.rx_errors, 0);
        assert_eq!(stats.tx_errors, 0);
    }

    #[test]
    fn send_rejects_undersized_frame() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<256>();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        // Empty frame
        assert_eq!(
            driver.send(&mut bank, &[], &mut tx_pool),
            Err(GenetError::FrameTooSmall)
        );
        // 13 bytes — one short of minimum Ethernet header
        assert_eq!(
            driver.send(&mut bank, &[0u8; 13], &mut tx_pool),
            Err(GenetError::FrameTooSmall)
        );
        // Exactly 14 bytes — minimum valid
        assert!(driver.send(&mut bank, &[0u8; 14], &mut tx_pool).is_ok());
    }

    #[test]
    fn send_errors_increment_tx_errors() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<4, 4> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<4>();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        // FrameTooSmall
        let _ = driver.send(&mut bank, &[], &mut tx_pool);
        assert_eq!(driver.stats().tx_errors, 1);

        // FrameTooLarge
        let _ = driver.send(&mut bank, &[0u8; 2048], &mut tx_pool);
        assert_eq!(driver.stats().tx_errors, 2);

        // TxRingFull — fill the ring first
        driver.tx_prod_index = 4;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);
        let _ = driver.send(&mut bank, &[0u8; 64], &mut tx_pool);
        assert_eq!(driver.stats().tx_errors, 3);
    }

    #[test]
    fn init_flow_control_threshold_matches_ring_size() {
        // Use a small ring to verify threshold is derived from RX_RING, not hardcoded
        let mut bank = init_bank();
        GenetDriver::<64, 64>::init(&mut bank, TEST_MAC, 10).unwrap();

        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let xon_xoff_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == rx_ring_base + RING_XON_XOFF_THRESH)
            .map(|(_, v)| *v)
            .collect();

        // 64 >> 4 = 4, but guard clamps to DMA_FC_THRESH_LO + 1 = 6 (XOFF must exceed XON)
        // Expected: (6 << 16) | 5 = 0x0006_0005
        let expected = ((DMA_FC_THRESH_LO + 1) << DMA_XOFF_THRESHOLD_SHIFT) | DMA_FC_THRESH_LO;
        assert_eq!(xon_xoff_writes, vec![expected]);
    }

    #[test]
    fn init_flow_control_threshold_large_ring_uses_derived() {
        // With RX_RING=256, 256 >> 4 = 16 > DMA_FC_THRESH_LO (5), no clamping needed
        let mut bank = init_bank();
        GenetDriver::<256, 256>::init(&mut bank, TEST_MAC, 10).unwrap();

        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let xon_xoff_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == rx_ring_base + RING_XON_XOFF_THRESH)
            .map(|(_, v)| *v)
            .collect();

        // 256 >> 4 = 16, no guard needed: (16 << 16) | 5 = 0x0010_0005
        let expected = ((256u32 >> 4) << DMA_XOFF_THRESHOLD_SHIFT) | DMA_FC_THRESH_LO;
        assert_eq!(xon_xoff_writes, vec![expected]);
    }

    // ── DMA buffer tests ──────────────────────────────────────────

    #[test]
    fn send_writes_descriptor_addresses() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<256>();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        let frame = [0xAA; 64];
        driver.send(&mut bank, &frame, &mut tx_pool).unwrap();

        // Find ADDRESS_LO/HI writes for descriptor 0
        let desc_base = TDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let addr_lo_writes: Vec<u32> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == desc_base + DMA_DESC_ADDRESS_LO)
            .map(|(_, v)| *v)
            .collect();
        assert!(!addr_lo_writes.is_empty(), "ADDRESS_LO should be written");

        // LENGTH_STATUS should be written AFTER addresses
        // Verify ordering: ADDRESS_LO/HI written before LENGTH_STATUS.
        // Filter to only descriptor-field writes at desc_base.
        let desc_writes: Vec<usize> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off >= desc_base && *off < desc_base + DMA_DESC_SIZE)
            .map(|(off, _)| *off)
            .collect();
        let addr_lo_pos = desc_writes
            .iter()
            .position(|&off| off == desc_base + DMA_DESC_ADDRESS_LO)
            .unwrap();
        let ls_pos = desc_writes
            .iter()
            .position(|&off| off == desc_base + DMA_DESC_LENGTH_STATUS)
            .unwrap();
        assert!(
            addr_lo_pos < ls_pos,
            "ADDRESS_LO must be written before LENGTH_STATUS"
        );
    }

    #[test]
    fn send_no_buffers_returns_error() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<1>();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0, 0]);

        // First send succeeds
        driver.send(&mut bank, &[0xBB; 64], &mut tx_pool).unwrap();
        // Second fails — pool exhausted
        assert_eq!(
            driver.send(&mut bank, &[0xCC; 64], &mut tx_pool),
            Err(GenetError::NoBuffers)
        );
    }

    #[test]
    fn arm_rx_descriptors_fills_ring() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<4, 4> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut rx_pool = make_test_pool::<4>();

        driver.arm_rx_descriptors(&mut bank, &mut rx_pool).unwrap();

        // All 4 RX descriptors should have ADDRESS_LO written
        let rx_desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        for i in 0..4 {
            let desc_offset = rx_desc_base + i * DMA_DESC_SIZE;
            let has_addr = bank
                .writes
                .iter()
                .any(|(off, _)| *off == desc_offset + DMA_DESC_ADDRESS_LO);
            assert!(has_addr, "RX descriptor {i} should have ADDRESS_LO written");
        }
    }

    #[test]
    fn reclaim_tx_frees_completed_buffers() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        let mut tx_pool = make_test_pool::<256>();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0, 0, 0]);

        // Send 3 frames
        for _ in 0..3 {
            driver.send(&mut bank, &[0xDD; 64], &mut tx_pool).unwrap();
        }

        // Simulate hardware consuming 2 descriptors
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![2]);

        let freed = driver.reclaim_tx(&bank, &mut tx_pool);
        assert_eq!(freed, 2, "should free 2 completed TX buffers");
    }
}
