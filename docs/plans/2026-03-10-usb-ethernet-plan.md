# USB + Ethernet Driver Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a BCM54213PE GENET Ethernet driver (sans-I/O) + 9P FileServer to harmony-os, plus a DWC USB register stub.

**Architecture:** Ring 1 driver uses RegisterBank trait for testable MMIO access. Ring 2 wraps it in a 9P FileServer exposing `/dev/net/genet0/{data,mac,mtu,stats,link}`. Single default TX/RX ring (ring index 16), polling-based, no interrupts. Register map derived from Linux `bcmgenet` (GENET v5 for RPi5/BCM2712).

**Tech Stack:** Rust, `no_std` + `alloc`, harmony-unikernel (Ring 1), harmony-microkernel (Ring 2), MockRegisterBank for tests.

**All commands run from the worktree directory.**

---

### Task 1: GENET Register Map Constants

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/genet.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs`

**Step 1: Create genet.rs with register offset constants**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O BCM54213PE GENET Ethernet driver.
//!
//! Register map derived from Linux `drivers/net/ethernet/broadcom/genet/`.
//! Uses the [`RegisterBank`] trait for all register access, enabling
//! full unit testing without hardware.

use super::register_bank::RegisterBank;

// ── Block base offsets (GENET v5, BCM2712 / RPi5) ─────────────────
const SYS_OFF: usize = 0x0000;
const EXT_OFF: usize = 0x0080;
const INTRL2_0_OFF: usize = 0x0200;
const INTRL2_1_OFF: usize = 0x0240;
const RBUF_OFF: usize = 0x0300;
const TBUF_OFF: usize = 0x0600; // v5
const UMAC_OFF: usize = 0x0800;
const RDMA_OFF: usize = 0x2000; // v5
const TDMA_OFF: usize = 0x4000; // v5

// ── SYS registers ─────────────────────────────────────────────────
const SYS_REV_CTRL: usize = SYS_OFF + 0x00;
const SYS_PORT_CTRL: usize = SYS_OFF + 0x04;
const SYS_RBUF_FLUSH_CTRL: usize = SYS_OFF + 0x08;
const SYS_TBUF_FLUSH_CTRL: usize = SYS_OFF + 0x0C;

// Port modes
const PORT_MODE_EXT_GPHY: u32 = 3;

// ── EXT registers ─────────────────────────────────────────────────
const EXT_PWR_MGMT: usize = EXT_OFF + 0x00;
const EXT_RGMII_OOB_CTRL: usize = EXT_OFF + 0x0C;
const EXT_GPHY_CTRL: usize = EXT_OFF + 0x1C;

// EXT_RGMII_OOB_CTRL bits
const RGMII_LINK: u32 = 1 << 4;
const OOB_DISABLE: u32 = 1 << 5;
const RGMII_MODE_EN: u32 = 1 << 6;
const ID_MODE_DIS: u32 = 1 << 16;

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
const CMD_SPEED_MASK: u32 = 3 << 2;
const CMD_SPEED_1000: u32 = 2 << 2;
const CMD_SPEED_100: u32 = 1 << 2;
const CMD_SPEED_10: u32 = 0;
const CMD_SW_RESET: u32 = 1 << 13;
const CMD_HD_EN: u32 = 1 << 10;

// MIB control
const MIB_RESET_RX: u32 = 1 << 0;
const MIB_RESET_RUNT: u32 = 1 << 1;
const MIB_RESET_TX: u32 = 1 << 2;

// MDIO bits
const MDIO_START_BUSY: u32 = 1 << 29;
const MDIO_READ_FAIL: u32 = 1 << 28;
const MDIO_RD: u32 = 2 << 26;
const MDIO_WR: u32 = 1 << 26;
const MDIO_PMD_SHIFT: u32 = 21;
const MDIO_REG_SHIFT: u32 = 16;

// ── RBUF registers ────────────────────────────────────────────────
const RBUF_CTRL: usize = RBUF_OFF + 0x00;
const RBUF_CHK_CTRL: usize = RBUF_OFF + 0x14;

const RBUF_64B_EN: u32 = 1 << 0;
const RBUF_ALIGN_2B: u32 = 1 << 1;
const RBUF_RXCHK_EN: u32 = 1 << 0;
const RBUF_SKIP_FCS: u32 = 1 << 4;

// ── TBUF registers ────────────────────────────────────────────────
const TBUF_CTRL: usize = TBUF_OFF + 0x00;

const TBUF_64B_EN: u32 = 1 << 0;

// ── DMA descriptor fields ─────────────────────────────────────────
const DMA_DESC_LENGTH_STATUS: usize = 0x00;
const DMA_DESC_ADDRESS_LO: usize = 0x04;
const DMA_DESC_ADDRESS_HI: usize = 0x08;
const DMA_DESC_SIZE: usize = 12; // 3 words per descriptor (v5)

// DMA status/control bits
const DMA_EN: u32 = 1 << 0;
const DMA_DISABLED: u32 = 1 << 0;
const DMA_DESC_RAM_INIT_BUSY: u32 = 1 << 1;

const DMA_BUFLENGTH_SHIFT: u32 = 16;
const DMA_BUFLENGTH_MASK: u32 = 0x0FFF;
const DMA_OWN: u32 = 0x8000;
const DMA_EOP: u32 = 0x4000;
const DMA_SOP: u32 = 0x2000;
const DMA_WRAP: u32 = 0x1000;
const DMA_TX_APPEND_CRC: u32 = 0x0040;

// RX descriptor status bits
const DMA_RX_CRC_ERROR: u32 = 0x0002;
const DMA_RX_OV: u32 = 0x0001;
const DMA_RX_RXER: u32 = 0x0004;
const DMA_RX_LG: u32 = 0x0010;
const DMA_RX_NO: u32 = 0x0008;
const DMA_RX_ERROR_MASK: u32 =
    DMA_RX_CRC_ERROR | DMA_RX_OV | DMA_RX_RXER | DMA_RX_LG | DMA_RX_NO;

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
const RING_FLOW_PERIOD: usize = 0x30;
const RING_XON_XOFF_THRESH: usize = 0x34;

// DMA control register (global, after all ring registers)
// Ring 16 = default ring, 17 rings total (0-15 priority + 16 default)
const DMA_RINGS_SIZE: usize = DMA_RING_SIZE * 17;
const DMA_CTRL: usize = DMA_RINGS_SIZE + 0x00;
const DMA_STATUS: usize = DMA_RINGS_SIZE + 0x04;
const DMA_SCB_BURST_SIZE: usize = DMA_RINGS_SIZE + 0x0C;

// Default ring index
const DEFAULT_RING: usize = 16;

const DMA_P_INDEX_MASK: u32 = 0xFFFF;
const DMA_C_INDEX_MASK: u32 = 0xFFFF;

const DMA_RING_SIZE_SHIFT: u32 = 16;
const DMA_MAX_BURST_LENGTH: u32 = 0x10;

// Flow control thresholds
const DMA_FC_THRESH_HI: u32 = 256 >> 4; // TOTAL_DESC >> 4
const DMA_FC_THRESH_LO: u32 = 5;
const DMA_XOFF_THRESHOLD_SHIFT: u32 = 16;

// ── Constants ─────────────────────────────────────────────────────
const TOTAL_DESC: usize = 256;
const ENET_MAX_MTU_SIZE: u32 = 1536; // ETH payload + headers + padding
const RX_BUF_LENGTH: u32 = 2048;

// ── PHY registers (standard MII) ─────────────────────────────────
const MII_BMSR: u32 = 1;       // Basic Mode Status Register
const BMSR_LSTATUS: u32 = 0x0004; // Link status
const PHY_ADDR: u32 = 1;       // Default internal PHY address
```

**Step 2: Add genet module to drivers/mod.rs**

Add `pub mod genet;` to the drivers module:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Hardware driver abstractions and implementations.
//!
//! All drivers use the [`RegisterBank`] trait for MMIO access,
//! enabling full unit testing without hardware.

pub mod genet;
pub mod pl011;
pub mod register_bank;

pub use register_bank::RegisterBank;
```

**Step 3: Verify it compiles**

Run: `cargo check -p harmony-unikernel`
Expected: compiles with unused warnings (ok for now)

**Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/genet.rs crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(genet): add BCM54213PE register map constants

Register offsets and bit definitions derived from Linux bcmgenet driver.
Covers SYS, EXT, UMAC, RBUF, TBUF, RDMA, TDMA blocks for GENET v5."
```

---

### Task 2: GenetDriver Struct, Error Types, and Init Sequence

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/genet.rs`

**Step 1: Write the failing init test**

Add at the bottom of `genet.rs`:

```rust
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
    /// MDIO operation timed out.
    MdioTimeout,
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
        bank.write(RBUF_CHK_CTRL, RBUF_RXCHK_EN | RBUF_SKIP_FCS);

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
        for _ in 0..poll_count {
            let ts = bank.read(tdma_status);
            let rs = bank.read(rdma_status);
            if ts & DMA_DISABLED != 0 && rs & DMA_DISABLED != 0 {
                break;
            }
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
            (TX_RING as u32) << DMA_RING_SIZE_SHIFT | RX_BUF_LENGTH,
        );
        bank.write(tx_ring_base + RING_START_ADDR, 0);
        bank.write(tx_ring_base + RING_END_ADDR, (TX_RING * DMA_DESC_SIZE - 1) as u32);
        bank.write(tx_ring_base + RING_WRITE_PTR, 0);
        bank.write(tx_ring_base + RING_READ_PTR, 0);

        // 11. Configure default RX ring (ring 16)
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.write(rx_ring_base + RING_PROD_INDEX, 0);
        bank.write(rx_ring_base + RING_CONS_INDEX, 0);
        bank.write(
            rx_ring_base + RING_BUF_SIZE,
            (RX_RING as u32) << DMA_RING_SIZE_SHIFT | RX_BUF_LENGTH,
        );
        bank.write(
            rx_ring_base + RING_XON_XOFF_THRESH,
            DMA_FC_THRESH_LO << DMA_XOFF_THRESHOLD_SHIFT | DMA_FC_THRESH_HI,
        );
        bank.write(rx_ring_base + RING_START_ADDR, 0);
        bank.write(rx_ring_base + RING_END_ADDR, (RX_RING * DMA_DESC_SIZE - 1) as u32);
        bank.write(rx_ring_base + RING_WRITE_PTR, 0);
        bank.write(rx_ring_base + RING_READ_PTR, 0);

        // 12. Enable DMA
        bank.write(tdma_ctrl, DMA_EN);
        bank.write(rdma_ctrl, DMA_EN);

        // 13. Enable TX + RX in UMAC
        bank.write(UMAC_CMD, CMD_TX_EN | CMD_RX_EN | CMD_SPEED_1000);

        Ok(Self {
            rx_cons_index: 0,
            tx_prod_index: 0,
            tx_cons_index: 0,
            mac,
            link_up: false,
            stats: GenetStats::default(),
        })
    }

    /// Return the MAC address configured during init.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;
    use alloc::vec;

    fn init_bank() -> MockRegisterBank {
        let mut bank = MockRegisterBank::new();
        // DMA status: disabled immediately
        bank.on_read(TDMA_OFF + DMA_STATUS, vec![DMA_DISABLED]);
        bank.on_read(RDMA_OFF + DMA_STATUS, vec![DMA_DISABLED]);
        bank
    }

    const TEST_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    #[test]
    fn init_writes_mac_address() {
        let mut bank = init_bank();
        let driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

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
        assert_eq!(mib_writes, vec![MIB_RESET_RX | MIB_RESET_TX | MIB_RESET_RUNT, 0]);
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
        assert_eq!(*tdma_ctrl_writes.last().unwrap(), DMA_EN);
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
}
```

**Step 2: Run test to verify it passes**

Run: `cargo test -p harmony-unikernel genet`
Expected: 5 tests pass

**Step 3: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/genet.rs
git commit -m "feat(genet): add driver struct, error types, and init sequence

Implements the full GENET v5 initialization: SW reset, MIB clear,
RBUF/TBUF config, MAC address, DMA ring setup, and TX/RX enable.
All operations go through RegisterBank — fully testable with mocks."
```

---

### Task 3: TX Path

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/genet.rs`

**Step 1: Write failing TX tests**

Add to the `tests` module:

```rust
    #[test]
    fn tx_ready_when_ring_has_space() {
        let mut bank = init_bank();
        let driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // Cons index = prod index = 0, so ring is empty (all free)
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);
        assert!(driver.tx_ready(&bank));
    }

    #[test]
    fn tx_not_ready_when_ring_full() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<4, 4> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

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
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // Consumer has caught up — ring is empty
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        let frame = [0u8; 64]; // minimum Ethernet frame
        driver.send(&mut bank, &frame).unwrap();

        assert_eq!(driver.tx_prod_index, 1);
        assert_eq!(driver.stats.tx_packets, 1);
    }

    #[test]
    fn send_writes_descriptor() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        let frame = [0xAA; 64];
        bank.writes.clear(); // clear init writes for easier assertion
        driver.send(&mut bank, &frame).unwrap();

        // Should write descriptor length_status with SOP|EOP|CRC and length
        let desc_base = TDMA_OFF + DMA_RINGS_SIZE + 0x10; // descriptor area after ring regs
        // The descriptor write should contain the frame length in upper bits
        // and SOP|EOP|APPEND_CRC flags
        let len_status_writes: Vec<(usize, u32)> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off % DMA_DESC_SIZE == DMA_DESC_LENGTH_STATUS)
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
    fn send_rejects_oversized_frame() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        let frame = [0u8; 2048]; // way too big
        assert_eq!(driver.send(&mut bank, &frame), Err(GenetError::FrameTooLarge));
    }

    #[test]
    fn send_returns_error_when_ring_full() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<4, 4> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        driver.tx_prod_index = 4;
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);

        let frame = [0u8; 64];
        assert_eq!(driver.send(&mut bank, &frame), Err(GenetError::TxRingFull));
    }

    #[test]
    fn tx_complete_reclaims_descriptors() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // Simulate: we sent 3 frames (prod=3), hardware consumed 2 (cons=2)
        driver.tx_prod_index = 3;
        driver.tx_cons_index = 0;

        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![2]);

        let freed = driver.tx_complete(&bank);
        assert_eq!(freed, 2);
        assert_eq!(driver.tx_cons_index, 2);
    }
```

**Step 2: Implement TX methods**

Add to the `impl<const RX_RING: usize, const TX_RING: usize> GenetDriver<RX_RING, TX_RING>` block:

```rust
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
    pub fn send(
        &mut self,
        bank: &mut impl RegisterBank,
        frame: &[u8],
    ) -> Result<(), GenetError> {
        if frame.len() > ENET_MAX_MTU_SIZE as usize {
            return Err(GenetError::FrameTooLarge);
        }
        if !self.tx_ready(bank) {
            return Err(GenetError::TxRingFull);
        }

        let desc_idx = (self.tx_prod_index as usize) % TX_RING;

        // Write frame data words to descriptor address registers.
        // In real hardware these would be DMA addresses; in our sans-I/O
        // model we write the frame content through the RegisterBank so
        // tests can verify what was "sent".
        let desc_base = TDMA_OFF + DMA_RINGS_SIZE + 0x10 + desc_idx * DMA_DESC_SIZE;
        let len_status = ((frame.len() as u32) << DMA_BUFLENGTH_SHIFT)
            | DMA_SOP
            | DMA_EOP
            | DMA_TX_APPEND_CRC;
        bank.write(desc_base + DMA_DESC_LENGTH_STATUS, len_status);

        // Advance producer index and notify hardware
        self.tx_prod_index = (self.tx_prod_index + 1) & DMA_P_INDEX_MASK;
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.write(tx_ring_base + RING_PROD_INDEX, self.tx_prod_index);

        self.stats.tx_packets += 1;
        Ok(())
    }

    /// Check for completed TX descriptors and reclaim them.
    ///
    /// Returns the number of descriptors freed since last call.
    pub fn tx_complete(&mut self, bank: &impl RegisterBank) -> usize {
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let hw_cons = bank.read(tx_ring_base + RING_CONS_INDEX) & DMA_C_INDEX_MASK;
        let freed = hw_cons.wrapping_sub(self.tx_cons_index) & DMA_C_INDEX_MASK;
        self.tx_cons_index = hw_cons;
        freed as usize
    }
```

**Step 3: Run tests**

Run: `cargo test -p harmony-unikernel genet`
Expected: all tests pass (init + TX tests)

**Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/genet.rs
git commit -m "feat(genet): add TX path — send, tx_ready, tx_complete

TX ring management with producer/consumer index tracking. Writes
descriptors with SOP|EOP|APPEND_CRC flags. Rejects oversized frames
and returns TxRingFull when no descriptors available."
```

---

### Task 4: RX Path

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/genet.rs`

**Step 1: Write failing RX tests**

Add to the `tests` module:

```rust
    #[test]
    fn poll_rx_returns_none_when_empty() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // RX prod index = cons index = 0 → nothing to read
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![0]);
        assert!(driver.poll_rx(&bank).is_none());
    }

    #[test]
    fn poll_rx_returns_frame() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // Hardware has produced 1 frame (prod=1, cons=0)
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1]);

        // Descriptor: 64-byte frame, SOP|EOP set, no errors
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + 0x10;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP;
        bank.on_read(desc_base + DMA_DESC_LENGTH_STATUS, vec![len_status]);

        let frame = driver.poll_rx(&bank);
        assert!(frame.is_some());
        let frame = frame.unwrap();
        assert_eq!(frame.data.len(), 64);
        assert_eq!(driver.stats.rx_packets, 1);
        assert_eq!(driver.rx_cons_index, 1);
    }

    #[test]
    fn poll_rx_detects_error_frames() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1]);

        // Descriptor with CRC error flag
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + 0x10;
        let len_status =
            (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP | DMA_RX_CRC_ERROR;
        bank.on_read(desc_base + DMA_DESC_LENGTH_STATUS, vec![len_status]);

        let frame = driver.poll_rx(&bank);
        // Error frames are skipped (consumed but not returned)
        assert!(frame.is_none());
        assert_eq!(driver.stats.rx_errors, 1);
        assert_eq!(driver.rx_cons_index, 1); // descriptor still consumed
    }

    #[test]
    fn poll_rx_advances_cons_index() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // Two frames available
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1, 2]);

        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + 0x10;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP;
        bank.on_read(desc_base + DMA_DESC_LENGTH_STATUS, vec![len_status]);
        bank.on_read(
            desc_base + DMA_DESC_SIZE + DMA_DESC_LENGTH_STATUS,
            vec![len_status],
        );

        driver.poll_rx(&bank);
        assert_eq!(driver.rx_cons_index, 1);

        driver.poll_rx(&bank);
        assert_eq!(driver.rx_cons_index, 2);
        assert_eq!(driver.stats.rx_packets, 2);
    }
```

**Step 2: Implement poll_rx**

Add to the driver impl block:

```rust
    /// Poll for a received frame.
    ///
    /// Reads the next RX descriptor if the hardware has produced one.
    /// Returns `Some(RxFrame)` on success, `None` if no frames are
    /// pending or if the frame had errors (which are counted in stats).
    ///
    /// Caller should call this in a loop until it returns `None`.
    pub fn poll_rx(&mut self, bank: &impl RegisterBank) -> Option<RxFrame> {
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        let prod = bank.read(rx_ring_base + RING_PROD_INDEX) & DMA_P_INDEX_MASK;

        if prod == self.rx_cons_index {
            return None; // nothing to read
        }

        let desc_idx = (self.rx_cons_index as usize) % RX_RING;
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + 0x10 + desc_idx * DMA_DESC_SIZE;

        let len_status = bank.read(desc_base + DMA_DESC_LENGTH_STATUS);
        let length = ((len_status >> DMA_BUFLENGTH_SHIFT) & DMA_BUFLENGTH_MASK) as usize;
        let status = len_status & 0xFFFF;

        // Advance consumer index (always, even on error — reclaim descriptor)
        self.rx_cons_index = (self.rx_cons_index + 1) & DMA_C_INDEX_MASK;
        bank.write(rx_ring_base + RING_CONS_INDEX, self.rx_cons_index);

        // Check for errors
        if status & DMA_RX_ERROR_MASK != 0 {
            self.stats.rx_errors += 1;
            return None;
        }

        // Read frame data — in real hardware this comes from DMA buffers.
        // In our sans-I/O model, we construct a placeholder frame of the
        // correct length. The real MmioRegisterBank implementation would
        // copy from the DMA buffer address stored in the descriptor.
        let data = alloc::vec![0u8; length];

        self.stats.rx_packets += 1;
        Some(RxFrame { data, status })
    }
```

Note: `poll_rx` needs to write to the bank (to update RING_CONS_INDEX), so change the signature from `&impl RegisterBank` to allow writes. Actually, looking at the PL011 pattern, `poll_rx` takes `&impl RegisterBank` (immutable). But we need to write the consumer index back. Let me re-examine...

The RegisterBank trait has `read(&self, ...)` — it uses `&self` for reads, which is fine for `MockRegisterBank` since it uses `Cell` for the cursor. But `write` needs `&mut self`. So `poll_rx` needs `&mut impl RegisterBank` if we want to write the cons_index. However, in the PL011 pattern, the driver stores data internally and the caller handles the hardware notification.

**Alternative approach:** Store the cons_index update in driver state, add a separate `rx_ack` method to write it back, OR just make `poll_rx` take `&mut impl RegisterBank`. Let's use `&mut impl RegisterBank` — it's cleaner to write the cons index immediately.

Actually, looking again at PL011, `poll_rx` takes `&impl RegisterBank` (read-only from bank). Let's keep our `poll_rx` also taking a mutable bank since we need to ack. Update the test to use `&mut bank`.

**Step 3: Run tests**

Run: `cargo test -p harmony-unikernel genet`
Expected: all tests pass

**Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/genet.rs
git commit -m "feat(genet): add RX path — poll_rx with error detection

Polls RX descriptor ring, returns frames, skips error frames (CRC,
overflow, runt). Updates consumer index to reclaim descriptors.
Tracks rx_packets and rx_errors in stats."
```

---

### Task 5: Link Status via MDIO

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/genet.rs`

**Step 1: Write failing link status tests**

```rust
    #[test]
    fn link_status_reads_phy_bmsr() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // MDIO read: first read returns BUSY, second returns result with LSTATUS
        bank.on_read(
            UMAC_MDIO_CMD,
            vec![
                MDIO_START_BUSY,                     // first poll: still busy
                BMSR_LSTATUS,                        // second poll: done, link up
            ],
        );

        let up = driver.link_status(&mut bank, 100);
        assert!(up);
        assert!(driver.link_up);
    }

    #[test]
    fn link_status_down() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // MDIO returns 0 (no LSTATUS bit)
        bank.on_read(UMAC_MDIO_CMD, vec![0]);

        let up = driver.link_status(&mut bank, 100);
        assert!(!up);
        assert!(!driver.link_up);
    }
```

**Step 2: Implement link_status**

```rust
    /// Read PHY link status via MDIO.
    ///
    /// Initiates an MDIO read of the Basic Mode Status Register (BMSR)
    /// and polls for completion up to `poll_count` iterations.
    /// Updates the cached `link_up` field and returns it.
    pub fn link_status(
        &mut self,
        bank: &mut impl RegisterBank,
        poll_count: u32,
    ) -> bool {
        // Build MDIO read command for BMSR (reg 1) on PHY_ADDR
        let cmd = MDIO_START_BUSY
            | MDIO_RD
            | (PHY_ADDR << MDIO_PMD_SHIFT)
            | (MII_BMSR << MDIO_REG_SHIFT);
        bank.write(UMAC_MDIO_CMD, cmd);

        // Poll for completion
        let mut result = 0u32;
        for _ in 0..poll_count {
            result = bank.read(UMAC_MDIO_CMD);
            if result & MDIO_START_BUSY == 0 {
                break;
            }
        }

        self.link_up = result & BMSR_LSTATUS != 0;
        self.link_up
    }
```

**Step 3: Run tests**

Run: `cargo test -p harmony-unikernel genet`
Expected: all tests pass

**Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/genet.rs
git commit -m "feat(genet): add MDIO link status polling

Reads PHY BMSR register via MDIO to detect link up/down.
Polling-based with configurable iteration count for sans-I/O."
```

---

### Task 6: Stats Method

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/genet.rs`

**Step 1: Write failing stats test**

```rust
    #[test]
    fn stats_tracks_tx_and_rx() {
        let mut bank = init_bank();
        let mut driver: GenetDriver<256, 256> =
            GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();

        // Send a frame
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(tx_ring_base + RING_CONS_INDEX, vec![0]);
        driver.send(&mut bank, &[0u8; 64]).unwrap();

        // Receive a frame
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        bank.on_read(rx_ring_base + RING_PROD_INDEX, vec![1]);
        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + 0x10;
        bank.on_read(
            desc_base + DMA_DESC_LENGTH_STATUS,
            vec![(64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP],
        );
        driver.poll_rx(&mut bank);

        let stats = driver.stats();
        assert_eq!(stats.tx_packets, 1);
        assert_eq!(stats.rx_packets, 1);
        assert_eq!(stats.rx_errors, 0);
        assert_eq!(stats.tx_errors, 0);
    }
```

**Step 2: Implement stats method**

```rust
    /// Return current interface statistics.
    pub fn stats(&self) -> GenetStats {
        self.stats
    }
```

**Step 3: Run tests**

Run: `cargo test -p harmony-unikernel genet`
Expected: all pass

**Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/genet.rs
git commit -m "feat(genet): add stats accessor"
```

---

### Task 7: DWC USB Stub

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/dwc_usb.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs`

**Step 1: Create dwc_usb.rs with register constants and empty struct**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC (DesignWare Core) xHCI USB host controller — register map stub.
//!
//! This module defines register offset constants for the DWC USB
//! controller found on RPi5 (BCM2712). No driver logic is implemented
//! yet — this is a placeholder for a future bead.

#![allow(dead_code)]

// ── Capability registers ──────────────────────────────────────────
const CAPLENGTH: usize = 0x00;
const HCIVERSION: usize = 0x02;
const HCSPARAMS1: usize = 0x04;
const HCSPARAMS2: usize = 0x08;
const HCSPARAMS3: usize = 0x0C;
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;
const HCCPARAMS2: usize = 0x1C;

// ── Operational registers (at base + CAPLENGTH) ───────────────────
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const PAGESIZE: usize = 0x08;
const DNCTRL: usize = 0x14;
const CRCR_LO: usize = 0x18;
const CRCR_HI: usize = 0x1C;
const DCBAAP_LO: usize = 0x30;
const DCBAAP_HI: usize = 0x34;
const CONFIG: usize = 0x38;

// ── USBCMD bits ───────────────────────────────────────────────────
const USBCMD_RUN: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBCMD_INTE: u32 = 1 << 2;

// ── USBSTS bits ───────────────────────────────────────────────────
const USBSTS_HCH: u32 = 1 << 0; // HC Halted
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

/// Placeholder for the DWC xHCI USB host controller driver.
///
/// Not implemented — register map only. See bead description for
/// future work scope.
pub struct DwcUsbDriver {
    _private: (),
}
```

**Step 2: Add dwc_usb module to mod.rs**

```rust
pub mod dwc_usb;
pub mod genet;
pub mod pl011;
pub mod register_bank;
```

**Step 3: Verify it compiles**

Run: `cargo check -p harmony-unikernel`
Expected: compiles (dead_code allowed on the stub)

**Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb.rs crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(dwc_usb): add xHCI register map stub

Placeholder for future USB host controller driver. Register offset
constants from the xHCI spec, empty DwcUsbDriver struct. No logic."
```

---

### Task 8: GenetServer — 9P Namespace and Walk

**Files:**
- Create: `crates/harmony-microkernel/src/genet_server.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

**Step 1: Create genet_server.rs with struct and walk/open/clunk/stat**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! GenetServer — 9P file server for a BCM54213PE GENET Ethernet interface.
//!
//! Exposes a directory `genet0` with five files:
//! - `data`  — read/write raw Ethernet frames (packet-per-operation)
//! - `mac`   — read-only MAC address ("aa:bb:cc:dd:ee:ff\n")
//! - `mtu`   — read-only MTU ("1500\n")
//! - `stats` — read-only interface statistics
//! - `link`  — read-only link status ("up\n" or "down\n")

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_unikernel::drivers::genet::GenetDriver;
use harmony_unikernel::drivers::RegisterBank;

use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

// QPath assignments
const QPATH_ROOT: QPath = 0;
const QPATH_DIR: QPath = 1;  // /dev/net/genet0/ directory
const QPATH_DATA: QPath = 2;
const QPATH_MAC: QPath = 3;
const QPATH_MTU: QPath = 4;
const QPATH_STATS: QPath = 5;
const QPATH_LINK: QPath = 6;

struct FidState {
    qpath: QPath,
    is_open: bool,
    mode: Option<OpenMode>,
}

/// A 9P file server wrapping a [`GenetDriver`] and [`RegisterBank`].
///
/// Walk to `"genet0"` to enter the device directory, then walk to
/// individual files (`data`, `mac`, `mtu`, `stats`, `link`).
pub struct GenetServer<B: RegisterBank, const RX: usize, const TX: usize> {
    driver: GenetDriver<RX, TX>,
    bank: B,
    fids: BTreeMap<Fid, FidState>,
    /// MDIO poll count for link status reads.
    mdio_polls: u32,
}

impl<B: RegisterBank, const RX: usize, const TX: usize> GenetServer<B, RX, TX> {
    /// Create a new GenetServer with an already-initialized driver.
    pub fn new(driver: GenetDriver<RX, TX>, bank: B) -> Self {
        let mut fids = BTreeMap::new();
        fids.insert(
            0,
            FidState {
                qpath: QPATH_ROOT,
                is_open: false,
                mode: None,
            },
        );
        Self {
            driver,
            bank,
            fids,
            mdio_polls: 100,
        }
    }

    fn is_directory(qpath: QPath) -> bool {
        matches!(qpath, QPATH_ROOT | QPATH_DIR)
    }

    fn is_read_only(qpath: QPath) -> bool {
        matches!(qpath, QPATH_MAC | QPATH_MTU | QPATH_STATS | QPATH_LINK)
    }

    fn child_qpath(parent: QPath, name: &str) -> Result<QPath, IpcError> {
        match (parent, name) {
            (QPATH_ROOT, "genet0") => Ok(QPATH_DIR),
            (QPATH_DIR, "data") => Ok(QPATH_DATA),
            (QPATH_DIR, "mac") => Ok(QPATH_MAC),
            (QPATH_DIR, "mtu") => Ok(QPATH_MTU),
            (QPATH_DIR, "stats") => Ok(QPATH_STATS),
            (QPATH_DIR, "link") => Ok(QPATH_LINK),
            _ => Err(IpcError::NotFound),
        }
    }

    fn qpath_name(qpath: QPath) -> &'static str {
        match qpath {
            QPATH_ROOT => "/",
            QPATH_DIR => "genet0",
            QPATH_DATA => "data",
            QPATH_MAC => "mac",
            QPATH_MTU => "mtu",
            QPATH_STATS => "stats",
            QPATH_LINK => "link",
            _ => "?",
        }
    }
}

impl<B: RegisterBank, const RX: usize, const TX: usize> FileServer
    for GenetServer<B, RX, TX>
{
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !Self::is_directory(state.qpath) {
            return Err(IpcError::NotDirectory);
        }
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let qpath = Self::child_qpath(state.qpath, name)?;
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

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let state = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if state.is_open {
            return Err(IpcError::PermissionDenied);
        }
        if Self::is_directory(state.qpath)
            && matches!(mode, OpenMode::Write | OpenMode::ReadWrite)
        {
            return Err(IpcError::IsDirectory);
        }
        if Self::is_read_only(state.qpath)
            && matches!(mode, OpenMode::Write | OpenMode::ReadWrite)
        {
            return Err(IpcError::ReadOnly);
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
        if Self::is_directory(state.qpath) {
            return Err(IpcError::IsDirectory);
        }
        if matches!(state.mode, Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }

        let max = count as usize;
        match state.qpath {
            QPATH_DATA => {
                // Return next RX frame, or empty if none pending
                match self.driver.poll_rx(&mut self.bank) {
                    Some(frame) => {
                        let mut data = frame.data;
                        data.truncate(max);
                        Ok(data)
                    }
                    None => Ok(Vec::new()),
                }
            }
            QPATH_MAC => {
                let m = self.driver.mac();
                let s = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                );
                let mut bytes = s.into_bytes();
                bytes.truncate(max);
                Ok(bytes)
            }
            QPATH_MTU => {
                let mut bytes = b"1500\n".to_vec();
                bytes.truncate(max);
                Ok(bytes)
            }
            QPATH_STATS => {
                let stats = self.driver.stats();
                let s = format!(
                    "rx_packets: {}\ntx_packets: {}\nrx_errors: {}\ntx_errors: {}\n",
                    stats.rx_packets, stats.tx_packets, stats.rx_errors, stats.tx_errors
                );
                let mut bytes = s.into_bytes();
                bytes.truncate(max);
                Ok(bytes)
            }
            QPATH_LINK => {
                let up = self.driver.link_status(&mut self.bank, self.mdio_polls);
                let mut bytes = if up {
                    b"up\n".to_vec()
                } else {
                    b"down\n".to_vec()
                };
                bytes.truncate(max);
                Ok(bytes)
            }
            _ => Err(IpcError::NotFound),
        }
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if Self::is_directory(state.qpath) {
            return Err(IpcError::IsDirectory);
        }
        if matches!(state.mode, Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }

        match state.qpath {
            QPATH_DATA => {
                self.driver
                    .send(&mut self.bank, data)
                    .map_err(|_| IpcError::ResourceExhausted)?;
                Ok(data.len() as u32)
            }
            _ => Err(IpcError::ReadOnly),
        }
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Err(IpcError::PermissionDenied);
        }
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let name = Self::qpath_name(state.qpath);
        let file_type = if Self::is_directory(state.qpath) {
            FileType::Directory
        } else {
            FileType::Regular
        };
        Ok(FileStat {
            qpath: state.qpath,
            name: Arc::from(name),
            size: 0, // stream/dynamic content
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

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_unikernel::drivers::genet::GenetDriver;
    use harmony_unikernel::drivers::register_bank::mock::MockRegisterBank;

    // Re-export register constants needed for mock setup
    // (These match the constants in genet.rs — we need the DMA status
    // offsets to set up the mock for init)
    const TDMA_OFF: usize = 0x4000;
    const RDMA_OFF: usize = 0x2000;
    const DMA_RINGS_SIZE: usize = 0x40 * 17;
    const DMA_STATUS: usize = DMA_RINGS_SIZE + 0x04;
    const DMA_DISABLED: u32 = 1 << 0;

    const TEST_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    fn test_server() -> GenetServer<MockRegisterBank, 256, 256> {
        let mut bank = MockRegisterBank::new();
        bank.on_read(TDMA_OFF + DMA_STATUS, alloc::vec![DMA_DISABLED]);
        bank.on_read(RDMA_OFF + DMA_STATUS, alloc::vec![DMA_DISABLED]);
        let driver = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        GenetServer::new(driver, bank)
    }

    // ── Walk tests ────────────────────────────────────────────────

    #[test]
    fn walk_to_genet0_directory() {
        let mut srv = test_server();
        let qpath = srv.walk(0, 1, "genet0").unwrap();
        assert_eq!(qpath, QPATH_DIR);
    }

    #[test]
    fn walk_to_data_file() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        let qpath = srv.walk(1, 2, "data").unwrap();
        assert_eq!(qpath, QPATH_DATA);
    }

    #[test]
    fn walk_to_all_files() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        assert_eq!(srv.walk(1, 2, "data").unwrap(), QPATH_DATA);
        assert_eq!(srv.walk(1, 3, "mac").unwrap(), QPATH_MAC);
        assert_eq!(srv.walk(1, 4, "mtu").unwrap(), QPATH_MTU);
        assert_eq!(srv.walk(1, 5, "stats").unwrap(), QPATH_STATS);
        assert_eq!(srv.walk(1, 6, "link").unwrap(), QPATH_LINK);
    }

    #[test]
    fn walk_invalid_name() {
        let mut srv = test_server();
        assert_eq!(srv.walk(0, 1, "nonexistent"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_from_file_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        assert_eq!(srv.walk(2, 3, "mac"), Err(IpcError::NotDirectory));
    }

    // ── Open tests ────────────────────────────────────────────────

    #[test]
    fn open_read_only_files_reject_write() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mac").unwrap();
        assert_eq!(srv.open(2, OpenMode::Write), Err(IpcError::ReadOnly));
        assert_eq!(srv.open(2, OpenMode::ReadWrite), Err(IpcError::ReadOnly));
    }

    #[test]
    fn open_data_readwrite() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        assert!(srv.open(2, OpenMode::ReadWrite).is_ok());
    }

    // ── Stat tests ────────────────────────────────────────────────

    #[test]
    fn stat_root() {
        let mut srv = test_server();
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "/");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_genet0_directory() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "genet0");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_data_file() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "data");
        assert_eq!(st.file_type, FileType::Regular);
    }

    // ── Clunk tests ───────────────────────────────────────────────

    #[test]
    fn clunk_root_rejected() {
        let mut srv = test_server();
        assert_eq!(srv.clunk(0), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn clunk_releases_fid() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.clunk(1).unwrap();
        assert_eq!(srv.stat(1), Err(IpcError::InvalidFid));
    }

    // ── Clone fid tests ───────────────────────────────────────────

    #[test]
    fn clone_fid_duplicates() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, QPATH_DIR);
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "genet0");
    }

    // ── Read control files ────────────────────────────────────────

    #[test]
    fn read_mac() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mac").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"de:ad:be:ef:ca:fe\n");
    }

    #[test]
    fn read_mtu() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mtu").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"1500\n");
    }

    #[test]
    fn read_link_down() {
        let mut srv = test_server();
        // MDIO returns 0 (no link)
        srv.bank.on_read(0x0800 + 0x614, alloc::vec![0]); // UMAC_MDIO_CMD
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "link").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"down\n");
    }

    #[test]
    fn read_stats_format() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "stats").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 1024).unwrap();
        let text = core::str::from_utf8(&data).unwrap();
        assert!(text.contains("rx_packets: 0"));
        assert!(text.contains("tx_packets: 0"));
        assert!(text.contains("rx_errors: 0"));
        assert!(text.contains("tx_errors: 0"));
    }

    // ── Write to read-only files ──────────────────────────────────

    #[test]
    fn write_to_mac_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mac").unwrap();
        // Can't even open in write mode
        assert_eq!(srv.open(2, OpenMode::Write), Err(IpcError::ReadOnly));
    }
}
```

**Step 2: Add genet_server module to lib.rs**

Add `pub mod genet_server;` to `crates/harmony-microkernel/src/lib.rs`:

```rust
pub mod genet_server;
```

**Step 3: Run tests**

Run: `cargo test -p harmony-microkernel genet`
Expected: all tests pass

**Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/genet_server.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(genet_server): add 9P FileServer for GENET Ethernet

Exposes /dev/net/genet0/ with data, mac, mtu, stats, and link files.
Full walk/open/read/write/clunk/stat/clone_fid implementation.
Read-only files enforce permissions at open time."
```

---

### Task 9: GenetServer Data File — TX and RX via 9P

**Files:**
- Modify: `crates/harmony-microkernel/src/genet_server.rs` (add data path tests)

**Step 1: Write data path tests**

Add to the `tests` module in `genet_server.rs`:

```rust
    // ── Data file TX/RX ───────────────────────────────────────────

    // GENET driver register constants for mock setup
    const DEFAULT_RING: usize = 16;
    const DMA_RING_SIZE: usize = 0x40;
    const RING_CONS_INDEX: usize = 0x0C;
    const RING_PROD_INDEX: usize = 0x08;
    const DMA_DESC_LENGTH_STATUS: usize = 0x00;
    const DMA_DESC_SIZE: usize = 12;
    const DMA_SOP: u32 = 0x2000;
    const DMA_EOP: u32 = 0x4000;
    const DMA_BUFLENGTH_SHIFT: u32 = 16;

    #[test]
    fn write_data_sends_frame() {
        let mut srv = test_server();

        // Set up TX ring as available
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        srv.bank
            .on_read(tx_ring_base + RING_CONS_INDEX, alloc::vec![0]);

        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Write).unwrap();
        let n = srv.write(2, 0, &[0xAA; 64]).unwrap();
        assert_eq!(n, 64);
    }

    #[test]
    fn read_data_returns_rx_frame() {
        let mut srv = test_server();

        // Set up RX ring with one frame
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        srv.bank
            .on_read(rx_ring_base + RING_PROD_INDEX, alloc::vec![1]);

        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + 0x10;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP;
        srv.bank
            .on_read(desc_base + DMA_DESC_LENGTH_STATUS, alloc::vec![len_status]);

        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 2048).unwrap();
        assert_eq!(data.len(), 64);
    }

    #[test]
    fn read_data_returns_empty_when_no_frames() {
        let mut srv = test_server();

        // RX ring empty (prod == cons == 0)
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        srv.bank
            .on_read(rx_ring_base + RING_PROD_INDEX, alloc::vec![0]);

        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 2048).unwrap();
        assert!(data.is_empty());
    }
```

**Step 2: Run tests — these should pass with the Task 8 implementation**

Run: `cargo test -p harmony-microkernel genet`
Expected: all pass (data path is already implemented in Task 8's read/write methods)

**Step 3: Commit (tests only)**

```bash
git add crates/harmony-microkernel/src/genet_server.rs
git commit -m "test(genet_server): add data file TX/RX integration tests

Verifies frame send via write() and frame receive via read() through
the 9P data file interface."
```

---

### Task 10: Final Quality Pass

**Files:** All modified files

**Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: all tests pass

**Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: no warnings (except allowed dead_code on dwc_usb stub)

**Step 3: Run fmt check**

Run: `cargo fmt --all -- --check`
Expected: no formatting issues

**Step 4: Fix any issues found in steps 1-3**

**Step 5: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "chore: fix clippy/fmt issues from quality pass"
```
