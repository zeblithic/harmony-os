// SPDX-License-Identifier: GPL-2.0-or-later

//! VirtIO MMIO transport register emulation (VirtIO 1.2 §4.2.2).
//!
//! Implements the MMIO register map for a VirtIO-net device. All state lives in
//! `VirtioMmio`; the caller passes MMIO offset + access type and receives an
//! `MmioResponse` — no I/O is performed here.

use crate::trap::AccessType;

// ── Register offsets ─────────────────────────────────────────────────────────

const REG_MAGIC: u32 = 0x000;
const REG_VERSION: u32 = 0x004;
const REG_DEVICE_ID: u32 = 0x008;
const REG_VENDOR_ID: u32 = 0x00C;
const REG_DEVICE_FEATURES: u32 = 0x010;
const REG_DEVICE_FEATURES_SEL: u32 = 0x014;
const REG_DRIVER_FEATURES: u32 = 0x020;
const REG_DRIVER_FEATURES_SEL: u32 = 0x024;
const REG_QUEUE_SEL: u32 = 0x030;
const REG_QUEUE_NUM_MAX: u32 = 0x034;
const REG_QUEUE_NUM: u32 = 0x038;
const REG_QUEUE_READY: u32 = 0x044;
const REG_QUEUE_NOTIFY: u32 = 0x050;
const REG_INTERRUPT_STATUS: u32 = 0x060;
const REG_INTERRUPT_ACK: u32 = 0x064;
const REG_STATUS: u32 = 0x070;
const REG_QUEUE_DESC_LOW: u32 = 0x080;
const REG_QUEUE_DESC_HIGH: u32 = 0x084;
const REG_QUEUE_AVAIL_LOW: u32 = 0x090;
const REG_QUEUE_AVAIL_HIGH: u32 = 0x094;
const REG_QUEUE_USED_LOW: u32 = 0x0A0;
const REG_QUEUE_USED_HIGH: u32 = 0x0A4;
const REG_CONFIG_GENERATION: u32 = 0x0FC;
const REG_CONFIG_BASE: u32 = 0x100;

// ── VirtIO feature bits ───────────────────────────────────────────────────────

pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_NET_S_LINK_UP: u16 = 1;

// ── Constants ─────────────────────────────────────────────────────────────────

const MAGIC: u32 = 0x7472_6976; // "virt" in little-endian
const VERSION: u32 = 2;
const VENDOR_ID: u32 = 0x4856; // "HV"
const QUEUE_NUM_MAX: u32 = 256;
const NUM_QUEUES: usize = 2;
const CONFIG_LEN: usize = 8; // MAC[6] + link_status[2]

// ── Public types ──────────────────────────────────────────────────────────────

/// Responses returned by `VirtioMmio::handle_mmio`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmioResponse {
    ReadValue(u64),
    WriteAck,
    QueueNotify { queue: u16 },
    StatusChanged { status: u32 },
}

/// Per-queue configuration state programmed by the driver.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueConfig {
    pub num: u16,
    pub ready: bool,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
}

impl QueueConfig {
    const fn zeroed() -> Self {
        Self {
            num: 0,
            ready: false,
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
        }
    }
}

/// VirtIO MMIO register state machine.
///
/// Represents a single VirtIO-net MMIO device. Call `handle_mmio` for every
/// trapped MMIO access; the returned `MmioResponse` tells the caller what to
/// inject into the guest register file or what side-effect to trigger.
pub struct VirtioMmio {
    device_id: u32,
    device_features: u64,
    driver_features: u64,
    pub status: u32,
    queue_sel: u32,
    pub queues: [QueueConfig; NUM_QUEUES],
    interrupt_status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    config: [u8; CONFIG_LEN], // MAC[6] + link_status[2]
}

impl VirtioMmio {
    /// Create a new VirtIO MMIO device.
    ///
    /// - `device_id`: VirtIO device ID (1 = net, 2 = block, …).
    /// - `features`: device feature bits (caller should OR in `VIRTIO_F_VERSION_1`).
    /// - `mac`: 6-byte MAC address placed at config[0..6].
    pub fn new(device_id: u32, features: u64, mac: [u8; 6]) -> Self {
        let mut config = [0u8; CONFIG_LEN];
        config[0..6].copy_from_slice(&mac);
        let link_bytes = VIRTIO_NET_S_LINK_UP.to_le_bytes();
        config[6] = link_bytes[0];
        config[7] = link_bytes[1];

        Self {
            device_id,
            device_features: features,
            driver_features: 0,
            status: 0,
            queue_sel: 0,
            queues: [QueueConfig::zeroed(), QueueConfig::zeroed()],
            interrupt_status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            config,
        }
    }

    /// Returns the link status from config space (VIRTIO_NET_S_LINK_UP).
    pub fn link_status(&self) -> u16 {
        u16::from_le_bytes([self.config[6], self.config[7]])
    }

    /// Handle one MMIO access.
    ///
    /// `offset` is the byte offset from the device base address.
    /// `access` is either a `Read` or `Write { value }`.
    pub fn handle_mmio(&mut self, offset: u32, access: AccessType) -> MmioResponse {
        match (offset, access) {
            // ── Read-only identification registers ───────────────────────────
            (REG_MAGIC, AccessType::Read) => MmioResponse::ReadValue(MAGIC as u64),
            (REG_VERSION, AccessType::Read) => MmioResponse::ReadValue(VERSION as u64),
            (REG_DEVICE_ID, AccessType::Read) => MmioResponse::ReadValue(self.device_id as u64),
            (REG_VENDOR_ID, AccessType::Read) => MmioResponse::ReadValue(VENDOR_ID as u64),

            // ── Device features ──────────────────────────────────────────────
            (REG_DEVICE_FEATURES, AccessType::Read) => {
                let word = (self.device_features >> (self.device_features_sel * 32)) as u32;
                MmioResponse::ReadValue(word as u64)
            }
            (REG_DEVICE_FEATURES_SEL, AccessType::Write { value }) => {
                // VirtIO 1.2 §4.2.2: only words 0 and 1 are defined. Clamp to
                // prevent shift-by-64 panic (sel * 32 >= 64 is UB for u64 shift).
                self.device_features_sel = (value as u32).min(1);
                MmioResponse::WriteAck
            }

            // ── Driver features ──────────────────────────────────────────────
            (REG_DRIVER_FEATURES, AccessType::Write { value }) => {
                // Replace the addressed 32-bit word (not OR-accumulate) so the
                // driver can revise features before writing FEATURES_OK (§3.1.1).
                let shift = self.driver_features_sel * 32;
                let mask: u64 = 0xFFFF_FFFF_u64 << shift;
                self.driver_features =
                    (self.driver_features & !mask) | ((value & 0xFFFF_FFFF) << shift);
                MmioResponse::WriteAck
            }
            (REG_DRIVER_FEATURES_SEL, AccessType::Write { value }) => {
                self.driver_features_sel = (value as u32).min(1);
                MmioResponse::WriteAck
            }

            // ── Queue configuration ──────────────────────────────────────────
            (REG_QUEUE_SEL, AccessType::Write { value }) => {
                self.queue_sel = value as u32;
                MmioResponse::WriteAck
            }
            (REG_QUEUE_NUM_MAX, AccessType::Read) => {
                // VirtIO 1.2 §4.2.2.1: return 0 for unavailable queues.
                if self.queue_sel as usize >= NUM_QUEUES {
                    MmioResponse::ReadValue(0)
                } else {
                    MmioResponse::ReadValue(QUEUE_NUM_MAX as u64)
                }
            }
            (REG_QUEUE_NUM, AccessType::Write { value }) => {
                let n = value as u16;
                if let Some(q) = self.selected_queue_checked() {
                    if n > 0 && n.is_power_of_two() && n as u32 <= QUEUE_NUM_MAX {
                        q.num = n;
                    }
                }
                MmioResponse::WriteAck
            }
            (REG_QUEUE_READY, AccessType::Read) => {
                let ready = self.selected_queue_checked().map_or(0, |q| q.ready as u64);
                MmioResponse::ReadValue(ready)
            }
            (REG_QUEUE_READY, AccessType::Write { value }) => {
                if let Some(q) = self.selected_queue_checked() {
                    q.ready = value != 0;
                }
                MmioResponse::WriteAck
            }

            // ── Queue descriptor/available/used ring addresses ────────────────
            // All silently ignored if queue_sel is out of range.
            (REG_QUEUE_DESC_LOW, AccessType::Write { value }) => {
                if let Some(q) = self.selected_queue_checked() {
                    q.desc_addr = (q.desc_addr & 0xFFFF_FFFF_0000_0000) | (value & 0xFFFF_FFFF);
                }
                MmioResponse::WriteAck
            }
            (REG_QUEUE_DESC_HIGH, AccessType::Write { value }) => {
                if let Some(q) = self.selected_queue_checked() {
                    q.desc_addr =
                        (q.desc_addr & 0x0000_0000_FFFF_FFFF) | ((value & 0xFFFF_FFFF) << 32);
                }
                MmioResponse::WriteAck
            }
            (REG_QUEUE_AVAIL_LOW, AccessType::Write { value }) => {
                if let Some(q) = self.selected_queue_checked() {
                    q.avail_addr = (q.avail_addr & 0xFFFF_FFFF_0000_0000) | (value & 0xFFFF_FFFF);
                }
                MmioResponse::WriteAck
            }
            (REG_QUEUE_AVAIL_HIGH, AccessType::Write { value }) => {
                if let Some(q) = self.selected_queue_checked() {
                    q.avail_addr =
                        (q.avail_addr & 0x0000_0000_FFFF_FFFF) | ((value & 0xFFFF_FFFF) << 32);
                }
                MmioResponse::WriteAck
            }
            (REG_QUEUE_USED_LOW, AccessType::Write { value }) => {
                if let Some(q) = self.selected_queue_checked() {
                    q.used_addr = (q.used_addr & 0xFFFF_FFFF_0000_0000) | (value & 0xFFFF_FFFF);
                }
                MmioResponse::WriteAck
            }
            (REG_QUEUE_USED_HIGH, AccessType::Write { value }) => {
                if let Some(q) = self.selected_queue_checked() {
                    q.used_addr =
                        (q.used_addr & 0x0000_0000_FFFF_FFFF) | ((value & 0xFFFF_FFFF) << 32);
                }
                MmioResponse::WriteAck
            }

            // ── Queue notify ─────────────────────────────────────────────────
            (REG_QUEUE_NOTIFY, AccessType::Write { value }) => MmioResponse::QueueNotify {
                queue: value as u16,
            },

            // ── Interrupt status / ack ────────────────────────────────────────
            (REG_INTERRUPT_STATUS, AccessType::Read) => {
                MmioResponse::ReadValue(self.interrupt_status as u64)
            }
            (REG_INTERRUPT_ACK, AccessType::Write { value }) => {
                self.interrupt_status &= !(value as u32);
                MmioResponse::WriteAck
            }

            // ── Device status ────────────────────────────────────────────────
            (REG_STATUS, AccessType::Read) => MmioResponse::ReadValue(self.status as u64),
            (REG_STATUS, AccessType::Write { value }) => {
                self.status = value as u32;
                // VirtIO 1.2 §2.1: writing 0 triggers a device reset.
                if self.status == 0 {
                    self.driver_features = 0;
                    self.queue_sel = 0;
                    self.device_features_sel = 0;
                    self.driver_features_sel = 0;
                    self.interrupt_status = 0;
                    for q in &mut self.queues {
                        *q = QueueConfig::default();
                    }
                }
                MmioResponse::StatusChanged {
                    status: self.status,
                }
            }

            // ── Config generation ────────────────────────────────────────────
            (REG_CONFIG_GENERATION, AccessType::Read) => MmioResponse::ReadValue(0),

            // ── Config space — byte-at-a-time reads (Linux uses readb) ────────
            (offset, AccessType::Read)
                if offset >= REG_CONFIG_BASE && offset < REG_CONFIG_BASE + CONFIG_LEN as u32 =>
            {
                let idx = (offset - REG_CONFIG_BASE) as usize;
                MmioResponse::ReadValue(self.config[idx] as u64)
            }

            // ── Unknown / unimplemented offsets ──────────────────────────────
            (_, AccessType::Read) => MmioResponse::ReadValue(0),
            (_, AccessType::Write { .. }) => MmioResponse::WriteAck,
        }
    }

    /// Return a mutable reference to the currently-selected queue.
    ///
    /// Clamps `queue_sel` to the valid range `[0, NUM_QUEUES - 1]`.
    /// Returns the currently selected queue, or None if queue_sel is out of range.
    fn selected_queue_checked(&mut self) -> Option<&mut QueueConfig> {
        self.queues.get_mut(self.queue_sel as usize)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trap::AccessType;

    const TEST_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
    const TEST_FEATURES: u64 = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_F_VERSION_1;

    fn make_device() -> VirtioMmio {
        VirtioMmio::new(1, TEST_FEATURES, TEST_MAC)
    }

    fn read(dev: &mut VirtioMmio, offset: u32) -> u64 {
        match dev.handle_mmio(offset, AccessType::Read) {
            MmioResponse::ReadValue(v) => v,
            other => panic!("expected ReadValue, got {:?}", other),
        }
    }

    fn write(dev: &mut VirtioMmio, offset: u32, value: u64) {
        dev.handle_mmio(offset, AccessType::Write { value });
    }

    // ── test 1 ───────────────────────────────────────────────────────────────

    #[test]
    fn magic_value_reads_correctly() {
        let mut dev = make_device();
        assert_eq!(read(&mut dev, 0x000), 0x7472_6976);
    }

    // ── test 2 ───────────────────────────────────────────────────────────────

    #[test]
    fn version_reads_2() {
        let mut dev = make_device();
        assert_eq!(read(&mut dev, 0x004), 2);
    }

    // ── test 3 ───────────────────────────────────────────────────────────────

    #[test]
    fn device_id_reads_1() {
        let mut dev = make_device();
        assert_eq!(read(&mut dev, 0x008), 1);
    }

    // ── test 4 ───────────────────────────────────────────────────────────────

    #[test]
    fn vendor_id_reads_hv() {
        let mut dev = make_device();
        assert_eq!(read(&mut dev, 0x00C), 0x4856);
    }

    // ── test 5 ───────────────────────────────────────────────────────────────

    #[test]
    fn device_features_word0() {
        let mut dev = make_device();
        // sel=0 is already the default
        write(&mut dev, REG_DEVICE_FEATURES_SEL, 0);
        let word0 = read(&mut dev, REG_DEVICE_FEATURES);
        // F_MAC = bit 5, F_STATUS = bit 16
        assert_ne!(word0 & (1 << 5), 0, "F_MAC not set in word0");
        assert_ne!(word0 & (1 << 16), 0, "F_STATUS not set in word0");
    }

    // ── test 6 ───────────────────────────────────────────────────────────────

    #[test]
    fn device_features_word1() {
        let mut dev = make_device();
        // sel=1 → bits [63:32]; F_VERSION_1 = 1<<32, so in word1 it is bit 0
        write(&mut dev, REG_DEVICE_FEATURES_SEL, 1);
        let word1 = read(&mut dev, REG_DEVICE_FEATURES);
        assert_ne!(word1 & 1, 0, "F_VERSION_1 (bit 0 of word1) not set");
    }

    // ── test 7 ───────────────────────────────────────────────────────────────

    #[test]
    fn driver_features_accepted() {
        let mut dev = make_device();
        // Write word0 (sel=0)
        write(&mut dev, REG_DRIVER_FEATURES_SEL, 0);
        write(
            &mut dev,
            REG_DRIVER_FEATURES,
            VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS,
        );
        // Write word1 (sel=1)
        write(&mut dev, REG_DRIVER_FEATURES_SEL, 1);
        write(&mut dev, REG_DRIVER_FEATURES, 1); // bit 0 of word1 = F_VERSION_1

        let expected = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_F_VERSION_1;
        assert_eq!(dev.driver_features, expected);
    }

    // ── test 8 ───────────────────────────────────────────────────────────────

    #[test]
    fn queue_select_and_config() {
        let mut dev = make_device();

        // Select queue 0
        write(&mut dev, REG_QUEUE_SEL, 0);

        // Set queue size
        write(&mut dev, REG_QUEUE_NUM, 64);
        assert_eq!(dev.queues[0].num, 64);

        // Set descriptor ring address (0x0000_1000_0000_2000)
        write(&mut dev, REG_QUEUE_DESC_LOW, 0x0000_2000);
        write(&mut dev, REG_QUEUE_DESC_HIGH, 0x0000_1000);
        assert_eq!(dev.queues[0].desc_addr, 0x0000_1000_0000_2000);

        // Set available ring address
        write(&mut dev, REG_QUEUE_AVAIL_LOW, 0x0000_3000);
        write(&mut dev, REG_QUEUE_AVAIL_HIGH, 0x0000_1000);
        assert_eq!(dev.queues[0].avail_addr, 0x0000_1000_0000_3000);

        // Set used ring address
        write(&mut dev, REG_QUEUE_USED_LOW, 0x0000_4000);
        write(&mut dev, REG_QUEUE_USED_HIGH, 0x0000_1000);
        assert_eq!(dev.queues[0].used_addr, 0x0000_1000_0000_4000);

        // Mark ready
        write(&mut dev, REG_QUEUE_READY, 1);
        assert!(dev.queues[0].ready);
        assert_eq!(read(&mut dev, REG_QUEUE_READY), 1);
    }

    // ── test 9 ───────────────────────────────────────────────────────────────

    #[test]
    fn queue_num_max_returns_256() {
        let mut dev = make_device();
        assert_eq!(read(&mut dev, REG_QUEUE_NUM_MAX), 256);
    }

    // ── test 10 ──────────────────────────────────────────────────────────────

    #[test]
    fn queue_notify_returns_written_value() {
        let mut dev = make_device();
        // queue_sel is 0 but we notify queue index 1
        let resp = dev.handle_mmio(REG_QUEUE_NOTIFY, AccessType::Write { value: 1 });
        assert_eq!(resp, MmioResponse::QueueNotify { queue: 1 });
    }

    // ── test 11 ──────────────────────────────────────────────────────────────

    #[test]
    fn status_lifecycle() {
        let mut dev = make_device();

        // ACKNOWLEDGE (bit 0)
        let resp = dev.handle_mmio(REG_STATUS, AccessType::Write { value: 1 });
        assert_eq!(resp, MmioResponse::StatusChanged { status: 1 });
        assert_eq!(read(&mut dev, REG_STATUS), 1);

        // DRIVER (bit 1)
        let resp = dev.handle_mmio(REG_STATUS, AccessType::Write { value: 3 });
        assert_eq!(resp, MmioResponse::StatusChanged { status: 3 });

        // FEATURES_OK (bit 3)
        let resp = dev.handle_mmio(REG_STATUS, AccessType::Write { value: 11 });
        assert_eq!(resp, MmioResponse::StatusChanged { status: 11 });

        // DRIVER_OK (bit 2)
        let resp = dev.handle_mmio(REG_STATUS, AccessType::Write { value: 15 });
        assert_eq!(resp, MmioResponse::StatusChanged { status: 15 });
        assert_eq!(read(&mut dev, REG_STATUS), 15);
    }

    // ── test 12 ──────────────────────────────────────────────────────────────

    #[test]
    fn config_generation_reads_zero() {
        let mut dev = make_device();
        assert_eq!(read(&mut dev, 0x0FC), 0);
    }

    // ── test 13 ──────────────────────────────────────────────────────────────

    #[test]
    fn config_space_mac() {
        let mut dev = make_device();
        for (i, &expected) in TEST_MAC.iter().enumerate() {
            let offset = REG_CONFIG_BASE + i as u32;
            assert_eq!(
                read(&mut dev, offset),
                expected as u64,
                "MAC byte {} mismatch",
                i
            );
        }
    }

    // ── test 14 ──────────────────────────────────────────────────────────────

    #[test]
    fn config_space_status() {
        let mut dev = make_device();
        // config[6] = low byte of VIRTIO_NET_S_LINK_UP (1), config[7] = high byte (0)
        assert_eq!(
            read(&mut dev, REG_CONFIG_BASE + 6),
            1,
            "link_status low byte"
        );
        assert_eq!(
            read(&mut dev, REG_CONFIG_BASE + 7),
            0,
            "link_status high byte"
        );
    }

    // ── test 15 ──────────────────────────────────────────────────────────────

    #[test]
    fn unknown_offset_read_returns_zero() {
        let mut dev = make_device();
        assert_eq!(read(&mut dev, 0xFFF), 0);
    }
}
