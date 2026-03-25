// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC (DesignWare Core) xHCI USB host controller driver.
//!
//! Sans-I/O driver for the xHCI controller on RPi5 (BCM2712).
//! Phase 1: controller init + port detection.
//!
//! All register access goes through the [`RegisterBank`] trait —
//! the driver is a pure state machine with no embedded I/O.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub mod types;
pub use types::*;

pub mod trb;

pub mod context;
pub use context::parse_device_descriptor;

mod ring;

use super::register_bank::RegisterBank;

// ── Capability registers (offset from MMIO base) ─────────────────
const CAPLENGTH_HCIVERSION: usize = 0x00;
const HCSPARAMS1: usize = 0x04;
#[allow(dead_code)] // Phase 2+
const HCSPARAMS2: usize = 0x08;
#[allow(dead_code)]
const HCSPARAMS3: usize = 0x0C;
#[allow(dead_code)]
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;
#[allow(dead_code)]
const HCCPARAMS2: usize = 0x1C;

// ── Operational registers (offset from cap_length) ───────────────
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
#[allow(dead_code)]
const PAGESIZE: usize = 0x08;
#[allow(dead_code)]
const DNCTRL: usize = 0x14;
const CRCR_LO: usize = 0x18;
#[allow(dead_code)]
const CRCR_HI: usize = 0x1C;
const DCBAAP_LO: usize = 0x30;
#[allow(dead_code)]
const DCBAAP_HI: usize = 0x34;
const CONFIG: usize = 0x38;

// ── USBCMD bits ──────────────────────────────────────────────────
const USBCMD_RUN: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
#[allow(dead_code)] // Phase 2a is polling-only; enable when interrupt path is wired
const USBCMD_INTE: u32 = 1 << 2;

// ── USBSTS bits ──────────────────────────────────────────────────
const USBSTS_HCH: u32 = 1 << 0; // HC Halted
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// ── Interrupter 0 registers (offset from rts_offset + 0x20) ─────
const INTERRUPTER_0_BASE: usize = 0x20;
#[allow(dead_code)]
const IMAN: usize = 0x00;
#[allow(dead_code)]
const IMOD: usize = 0x04;
const ERSTSZ: usize = 0x08;
const ERSTBA_LO: usize = 0x10;
#[allow(dead_code)]
const ERSTBA_HI: usize = 0x14;
const ERDP_LO: usize = 0x18;
#[allow(dead_code)]
const ERDP_HI: usize = 0x1C;

// ── PORTSC registers (offset from operational base) ──────────────
/// First PORTSC relative to operational base.
const PORTSC_BASE: usize = 0x400;
/// Byte spacing between successive PORTSC registers.
const PORTSC_STRIDE: usize = 0x10;

// ── PORTSC bits ──────────────────────────────────────────────────
const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
const PORTSC_SPEED_SHIFT: u32 = 10;
const PORTSC_SPEED_MASK: u32 = 0xF << PORTSC_SPEED_SHIFT;

// ── Polling limit ────────────────────────────────────────────────
const MAX_POLL_ITERATIONS: u32 = 1000;

// ── Driver state ─────────────────────────────────────────────────

/// Internal driver state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum XhciState {
    /// Controller halted and reset, ready for port detection.
    Ready,
    /// Rings configured and controller running.
    Running,
    /// Unrecoverable error.
    #[allow(dead_code)] // Phase 2+ transitions; Phase 1 tests construct directly
    Error(XhciError),
}

/// Sans-I/O xHCI USB host controller driver.
///
/// Manages the DesignWare xHCI controller on RPi5. All register access
/// goes through `RegisterBank` methods — no embedded I/O.
///
/// # Lifecycle
///
/// 1. `XhciDriver::init(bank)` — halt, reset, read capabilities → `Ready`
/// 2. `driver.detect_ports(bank)` — scan PORTSC registers → `Vec<PortStatus>`
#[derive(Debug, PartialEq, Eq)]
pub struct XhciDriver {
    /// Number of downstream ports (HCSPARAMS1 bits 31:24).
    max_ports: u8,
    /// Maximum device slots (HCSPARAMS1 bits 7:0).
    max_slots: u8,
    /// Capability register length — offset to operational registers.
    cap_length: usize,
    /// Runtime register offset (RTSOFF) — used for interrupter register base.
    rts_offset: u32,
    /// Doorbell register offset (DBOFF) — used for doorbell writes.
    db_offset: u32,
    /// Current driver state.
    state: XhciState,
    /// Command ring state (set after setup_rings).
    command_ring: Option<ring::CommandRing>,
    /// Event ring state (set after setup_rings).
    event_ring: Option<ring::EventRing>,
    /// Physical address of the DCBAA (set after setup_rings).
    dcbaa_phys: Option<u64>,
    /// Transfer rings keyed by slot ID (populated during device enumeration).
    transfer_rings: BTreeMap<u8, ring::TransferRing>,
}

impl XhciDriver {
    /// Initialize the xHCI controller.
    ///
    /// Reads capability registers, halts the controller, performs a
    /// hardware reset, and waits for the controller to become ready.
    /// Returns the driver in `Ready` state, or an error if any step
    /// times out.
    pub fn init(bank: &mut impl RegisterBank) -> Result<Self, XhciError> {
        // 1. Read capability registers.
        let cap_raw = bank.read(CAPLENGTH_HCIVERSION);
        let cap_length = (cap_raw & 0xFF) as usize;

        let hcsparams1 = bank.read(HCSPARAMS1);
        let max_slots = (hcsparams1 & 0xFF) as u8;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

        let db_offset = bank.read(DBOFF);
        let rts_offset = bank.read(RTSOFF);

        // 2. Halt the controller: clear RUN, wait for HCH.
        let cmd = bank.read(cap_length + USBCMD);
        bank.write(cap_length + USBCMD, cmd & !USBCMD_RUN);

        let mut halted = false;
        for _ in 0..MAX_POLL_ITERATIONS {
            if bank.read(cap_length + USBSTS) & USBSTS_HCH != 0 {
                halted = true;
                break;
            }
        }
        if !halted {
            return Err(XhciError::HaltTimeout);
        }

        // 3. Reset: set HCRST, wait for self-clear + CNR clear.
        let cmd = bank.read(cap_length + USBCMD);
        bank.write(cap_length + USBCMD, cmd | USBCMD_HCRST);

        let mut reset_done = false;
        for _ in 0..MAX_POLL_ITERATIONS {
            if bank.read(cap_length + USBCMD) & USBCMD_HCRST == 0 {
                reset_done = true;
                break;
            }
        }
        if !reset_done {
            return Err(XhciError::ResetTimeout);
        }

        // Wait for CNR to clear (controller ready).
        let mut ready = false;
        for _ in 0..MAX_POLL_ITERATIONS {
            if bank.read(cap_length + USBSTS) & USBSTS_CNR == 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(XhciError::NotReady);
        }

        Ok(Self {
            max_ports,
            max_slots,
            cap_length,
            rts_offset,
            db_offset,
            state: XhciState::Ready,
            command_ring: None,
            event_ring: None,
            dcbaa_phys: None,
            transfer_rings: BTreeMap::new(),
        })
    }

    /// Number of downstream USB ports.
    pub fn max_ports(&self) -> u8 {
        self.max_ports
    }

    /// Maximum device slots supported.
    pub fn max_slots(&self) -> u8 {
        self.max_slots
    }

    /// Scan all ports and return their status.
    ///
    /// Reads the PORTSC register for each port and reports connection
    /// state, enabled state, and negotiated speed.
    ///
    /// Requires `Ready` state (call `init` first).
    pub fn detect_ports(&self, bank: &impl RegisterBank) -> Result<Vec<PortStatus>, XhciError> {
        if self.state != XhciState::Ready {
            return Err(XhciError::InvalidState);
        }

        let mut ports = Vec::with_capacity(self.max_ports as usize);
        for i in 0..self.max_ports {
            let offset = self.cap_length + PORTSC_BASE + PORTSC_STRIDE * (i as usize);
            let portsc = bank.read(offset);

            let speed_id = ((portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT) as u8;

            ports.push(PortStatus {
                port: i,
                connected: portsc & PORTSC_CCS != 0,
                enabled: portsc & PORTSC_PED != 0,
                speed: UsbSpeed::from_id(speed_id),
            });
        }

        Ok(ports)
    }

    /// Enqueue a No-Op command on the command ring.
    ///
    /// Returns WriteTrb actions for the command (and Link TRB if wrapping),
    /// plus a RingDoorbell action to kick the controller.
    ///
    /// Requires `Running` state (call `setup_rings` first).
    pub fn enqueue_noop(&mut self) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }

        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_NOOP_CMD, 0)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        // Ring doorbell 0 (command ring): offset = db_offset + 4 * 0
        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize,
            value: 0,
        });

        Ok(actions)
    }

    /// Enqueue an Enable Slot command.
    ///
    /// After processing the `CommandCompletion` event, the `slot_id`
    /// field contains the assigned slot number (1-based).
    ///
    /// Requires `Running` state (call `setup_rings` first).
    pub fn enable_slot(&mut self) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }

        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_ENABLE_SLOT, 0)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        // Ring doorbell 0 (command ring): offset = db_offset + 4 * 0
        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize,
            value: 0,
        });

        Ok(actions)
    }

    /// Set up a device context and enqueue an Address Device command.
    ///
    /// Returns `(actions, input_context_bytes)`. The caller must:
    /// 1. Write `input_context_bytes` to `input_context_phys` in DMA
    /// 2. Execute all actions in order
    /// 3. Process the `CommandCompletion` event
    ///
    /// Requires `Running` state and a configured DCBAA (call `setup_rings`
    /// with a non-zero `dcbaa_phys` first).
    pub fn address_device(
        &mut self,
        slot_id: u8,
        port: u8,
        speed: UsbSpeed,
        input_context_phys: u64,
        output_context_phys: u64,
        transfer_ring_phys: u64,
    ) -> Result<(Vec<XhciAction>, [u8; 96]), XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }
        let dcbaa_phys = self.dcbaa_phys.ok_or(XhciError::InvalidState)?;

        // Build Input Context
        let input_ctx = context::build_input_context(port, speed, transfer_ring_phys);

        let mut actions = Vec::new();

        // 1. Write Output Context pointer to DCBAA[slot_id]
        let dcbaa_slot_phys = dcbaa_phys + (slot_id as u64) * 8;
        actions.push(XhciAction::WriteDma {
            phys: dcbaa_slot_phys,
            data: output_context_phys.to_le_bytes().to_vec(),
        });

        // 2. Enqueue Address Device command
        // parameter = input_context_phys, slot_id in control bits 31:24
        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_ADDRESS_DEVICE, input_context_phys)?;

        for (phys, mut t) in entries {
            // Set slot_id in control bits 31:24 for the Address Device TRB
            // (not for Link TRBs)
            if t.trb_type() == trb::TRB_ADDRESS_DEVICE {
                t.control |= (slot_id as u32) << 24;
            }
            actions.push(XhciAction::WriteTrb { phys, trb: t });
        }

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize,
            value: 0,
        });

        // Create transfer ring for this slot's EP0
        self.transfer_rings
            .insert(slot_id, ring::TransferRing::new(transfer_ring_phys));

        Ok((actions, input_ctx))
    }

    /// Enqueue a GET_DESCRIPTOR(Device) control transfer on a slot's EP0.
    ///
    /// After execution, poll for `TransferEvent`, then read 18 bytes from
    /// `data_buf_phys` and pass to `parse_device_descriptor`.
    ///
    /// Requires `Running` state and a transfer ring for `slot_id`
    /// (call `address_device` first).
    pub fn get_device_descriptor(
        &mut self,
        slot_id: u8,
        data_buf_phys: u64,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }

        let xfer_ring = self
            .transfer_rings
            .get_mut(&slot_id)
            .ok_or(XhciError::NoTransferRing)?;

        let setup = context::get_descriptor_setup_packet(
            trb::USB_DESC_DEVICE,
            0,
            trb::USB_DEVICE_DESCRIPTOR_SIZE as u16,
        );
        let entries = xfer_ring.enqueue_control_in(
            setup,
            data_buf_phys,
            trb::USB_DEVICE_DESCRIPTOR_SIZE as u16,
        )?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        // Ring doorbell for this slot's EP0: value = 1 (default control endpoint)
        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize + 4 * (slot_id as usize),
            value: 1, // EP0 doorbell target = 1
        });

        Ok(actions)
    }

    /// Check if the next event TRB has a matching cycle bit.
    ///
    /// The caller reads the cycle bit from the TRB at the event ring's
    /// dequeue pointer in DMA memory, then calls this to check if it's
    /// a new event. If `true`, read the full TRB and pass to `process_event`.
    pub fn should_process_event(&self, cycle_bit: bool) -> bool {
        self.event_ring
            .as_ref()
            .map(|r| r.should_process(cycle_bit))
            .unwrap_or(false)
    }

    /// Process one event TRB from the event ring.
    ///
    /// Parses the event type, updates internal state, advances the
    /// event ring dequeue pointer. Returns the parsed event and actions
    /// to execute (`UpdateDequeuePointer`).
    ///
    /// Requires `Running` state (call `setup_rings` first).
    pub fn process_event(
        &mut self,
        trb: trb::Trb,
    ) -> Result<(XhciEvent, Vec<XhciAction>), XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }

        let event = match trb.trb_type() {
            trb::TRB_COMMAND_COMPLETION => {
                let slot_id = (trb.control >> 24) as u8;
                let completion_code = (trb.status >> 24) as u8;
                // Record completion in command ring
                if let Some(cmd_ring) = self.command_ring.as_mut() {
                    cmd_ring.complete_one();
                }
                XhciEvent::CommandCompletion {
                    slot_id,
                    completion_code,
                }
            }
            trb::TRB_PORT_STATUS_CHANGE => {
                let port_id = ((trb.parameter >> 24) & 0xFF) as u8;
                XhciEvent::PortStatusChange { port_id }
            }
            trb::TRB_TRANSFER_EVENT => {
                let slot_id = (trb.control >> 24) as u8;
                let endpoint_id = ((trb.control >> 16) & 0x1F) as u8;
                let completion_code = (trb.status >> 24) as u8;
                let transfer_length = trb.status & 0x00FF_FFFF;
                XhciEvent::TransferEvent {
                    slot_id,
                    endpoint_id,
                    completion_code,
                    transfer_length,
                }
            }
            other => XhciEvent::Unknown { trb_type: other },
        };

        let evt_ring = self.event_ring.as_mut().ok_or(XhciError::InvalidState)?;
        evt_ring.advance();

        let actions = alloc::vec![XhciAction::UpdateDequeuePointer {
            phys: evt_ring.dequeue_pointer(),
        }];

        Ok((event, actions))
    }

    /// Configure command ring, event ring, and start the controller.
    ///
    /// The caller must allocate DMA memory for:
    /// - Command ring: 64 * 16 = 1024 bytes at `cmd_ring_phys`
    /// - Event ring: 256 * 16 = 4096 bytes at `event_ring_phys`
    /// - Event Ring Segment Table: 16 bytes at `erst_phys`
    ///
    /// Returns actions to write register values and the ERST entry.
    /// Execute all actions in order, then the controller is running.
    pub fn setup_rings(
        &mut self,
        cmd_ring_phys: u64,
        event_ring_phys: u64,
        erst_phys: u64,
        dcbaa_phys: u64,
        max_slots_enabled: u8,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Ready {
            return Err(XhciError::InvalidState);
        }

        let cmd_ring = ring::CommandRing::new(cmd_ring_phys);
        let evt_ring = ring::EventRing::new(event_ring_phys);

        let mut actions = Vec::new();
        let op = self.cap_length;
        let intr = self.rts_offset as usize + INTERRUPTER_0_BASE;

        // 1. CONFIG: MaxSlotsEn
        actions.push(XhciAction::WriteRegister {
            offset: op + CONFIG,
            value: max_slots_enabled as u32,
        });

        // 2. DCBAAP
        actions.push(XhciAction::WriteRegister64 {
            offset_lo: op + DCBAAP_LO,
            value: dcbaa_phys,
        });

        // 3. CRCR: command ring base + cycle bit
        actions.push(XhciAction::WriteRegister64 {
            offset_lo: op + CRCR_LO,
            value: cmd_ring.crcr_value(),
        });

        // 4. Write ERST entry (16 bytes): {base_phys, size, reserved}.
        // Reuse WriteTrb as a 16-byte DMA write — ERST entry layout
        // coincides with Trb (u64 + u32 + u32). Not a real TRB.
        actions.push(XhciAction::WriteTrb {
            phys: erst_phys,
            trb: trb::Trb {
                parameter: event_ring_phys,
                status: ring::EVENT_RING_SIZE as u32,
                control: 0,
            },
        });

        // 5. ERSTSZ = 1 (one segment)
        actions.push(XhciAction::WriteRegister {
            offset: intr + ERSTSZ,
            value: 1,
        });

        // 6. ERSTBA = erst_phys
        actions.push(XhciAction::WriteRegister64 {
            offset_lo: intr + ERSTBA_LO,
            value: erst_phys,
        });

        // 7. ERDP = event ring dequeue pointer
        actions.push(XhciAction::WriteRegister64 {
            offset_lo: intr + ERDP_LO,
            value: evt_ring.dequeue_pointer(),
        });

        // 8. USBCMD: RUN + INTE
        actions.push(XhciAction::WriteRegister {
            offset: op + USBCMD,
            // Polling-only: omit INTE until interrupt path is wired.
            // INTE without IMAN.IE would set IMAN.IP but never fire.
            value: USBCMD_RUN,
        });

        self.command_ring = Some(cmd_ring);
        self.event_ring = Some(evt_ring);
        self.dcbaa_phys = if dcbaa_phys != 0 {
            Some(dcbaa_phys)
        } else {
            None
        };
        self.state = XhciState::Running;

        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;
    use alloc::vec;

    #[test]
    fn usb_speed_from_id() {
        assert!(matches!(UsbSpeed::from_id(1), UsbSpeed::FullSpeed));
        assert!(matches!(UsbSpeed::from_id(2), UsbSpeed::LowSpeed));
        assert!(matches!(UsbSpeed::from_id(3), UsbSpeed::HighSpeed));
        assert!(matches!(UsbSpeed::from_id(4), UsbSpeed::SuperSpeed));
        assert!(matches!(UsbSpeed::from_id(5), UsbSpeed::SuperSpeedPlus));
        assert!(matches!(UsbSpeed::from_id(0), UsbSpeed::Unknown(0)));
        assert!(matches!(UsbSpeed::from_id(15), UsbSpeed::Unknown(15)));
    }

    /// Build a mock that passes init: cap_length=0x20, 4 ports, 32 slots,
    /// halts immediately, resets immediately.
    fn mock_init_success() -> MockRegisterBank {
        let mut bank = MockRegisterBank::new();
        // Capability registers
        bank.on_read(CAPLENGTH_HCIVERSION, vec![0x0100_0020]); // hci_ver=1.0, cap_length=0x20
        bank.on_read(HCSPARAMS1, vec![0x0400_0020]); // 4 ports (bits 31:24), 32 slots (bits 7:0)
        bank.on_read(DBOFF, vec![0x1000]);
        bank.on_read(RTSOFF, vec![0x2000]);
        // Operational registers (at cap_length=0x20)
        bank.on_read(0x20 + USBCMD, vec![USBCMD_RUN, 0]); // pre-halt: RUN set; pre-reset + poll: 0 (HCRST self-clears)
        bank.on_read(0x20 + USBSTS, vec![0, USBSTS_HCH, 0]); // halt: 0 then HCH; CNR poll: 0 (ready)
        bank
    }

    #[test]
    fn init_reads_capability_registers() {
        let mut bank = mock_init_success();
        let driver = XhciDriver::init(&mut bank).unwrap();
        assert_eq!(driver.max_ports(), 4);
        assert_eq!(driver.max_slots(), 32);
    }

    #[test]
    fn init_halts_then_resets() {
        let mut bank = mock_init_success();
        let _driver = XhciDriver::init(&mut bank).unwrap();
        // Verify writes: should have cleared RUN, then set HCRST
        let cmd_writes: Vec<_> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == 0x20 + USBCMD)
            .map(|(_, val)| *val)
            .collect();
        // First write: clear RUN (value should not have RUN bit set)
        assert_eq!(cmd_writes[0] & USBCMD_RUN, 0, "should clear RUN bit");
        // Second write: set HCRST
        assert_ne!(cmd_writes[1] & USBCMD_HCRST, 0, "should set HCRST bit");
    }

    #[test]
    fn init_halt_timeout() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(CAPLENGTH_HCIVERSION, vec![0x20]); // cap_length=0x20
        bank.on_read(HCSPARAMS1, vec![0x0100_0001]);
        bank.on_read(DBOFF, vec![0]);
        bank.on_read(RTSOFF, vec![0]);
        bank.on_read(0x20 + USBCMD, vec![USBCMD_RUN]); // RUN always set (sticky)
        bank.on_read(0x20 + USBSTS, vec![0]); // HCH never set (sticky 0)
        assert_eq!(XhciDriver::init(&mut bank), Err(XhciError::HaltTimeout));
    }

    #[test]
    fn init_reset_timeout() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(CAPLENGTH_HCIVERSION, vec![0x20]);
        bank.on_read(HCSPARAMS1, vec![0x0100_0001]);
        bank.on_read(DBOFF, vec![0]);
        bank.on_read(RTSOFF, vec![0]);
        bank.on_read(
            0x20 + USBCMD,
            vec![
                USBCMD_RUN,   // pre-halt read
                USBCMD_HCRST, // post-reset: HCRST never clears (sticky)
            ],
        );
        bank.on_read(
            0x20 + USBSTS,
            vec![
                0, USBSTS_HCH, // halt succeeds (0 then HCH)
            ],
        );
        assert_eq!(XhciDriver::init(&mut bank), Err(XhciError::ResetTimeout));
    }

    /// Build a mock for port detection: 4 ports with specified PORTSC values.
    fn mock_with_ports(cap_length: usize, portsc_values: &[u32]) -> MockRegisterBank {
        let mut bank = mock_init_success();
        for (i, &val) in portsc_values.iter().enumerate() {
            bank.on_read(cap_length + PORTSC_BASE + PORTSC_STRIDE * i, vec![val]);
        }
        bank
    }

    #[test]
    fn detect_ports_empty() {
        let mut bank = mock_with_ports(0x20, &[0, 0, 0, 0]);
        let driver = XhciDriver::init(&mut bank).unwrap();
        let ports = driver.detect_ports(&bank).unwrap();
        assert_eq!(ports.len(), 4);
        assert!(ports.iter().all(|p| !p.connected));
    }

    #[test]
    fn detect_ports_one_usb2_device() {
        // Port 0: CCS=1, PED=1, speed=HighSpeed(3)
        let portsc = PORTSC_CCS | PORTSC_PED | (3 << PORTSC_SPEED_SHIFT);
        let mut bank = mock_with_ports(0x20, &[portsc, 0, 0, 0]);
        let driver = XhciDriver::init(&mut bank).unwrap();
        let ports = driver.detect_ports(&bank).unwrap();
        assert_eq!(ports[0].port, 0);
        assert!(ports[0].connected);
        assert!(ports[0].enabled);
        assert_eq!(ports[0].speed, UsbSpeed::HighSpeed);
        assert!(!ports[1].connected);
    }

    #[test]
    fn detect_ports_mixed_speeds() {
        let fs = PORTSC_CCS | PORTSC_PED | (1 << PORTSC_SPEED_SHIFT); // Full Speed
        let hs = PORTSC_CCS | PORTSC_PED | (3 << PORTSC_SPEED_SHIFT); // High Speed
        let ss = PORTSC_CCS | PORTSC_PED | (4 << PORTSC_SPEED_SHIFT); // SuperSpeed
        let mut bank = mock_with_ports(0x20, &[fs, 0, hs, ss]);
        let driver = XhciDriver::init(&mut bank).unwrap();
        let ports = driver.detect_ports(&bank).unwrap();
        assert_eq!(ports[0].speed, UsbSpeed::FullSpeed);
        assert!(!ports[1].connected);
        assert_eq!(ports[2].speed, UsbSpeed::HighSpeed);
        assert_eq!(ports[3].speed, UsbSpeed::SuperSpeed);
    }

    #[test]
    fn detect_ports_unknown_speed() {
        let portsc = PORTSC_CCS | (15 << PORTSC_SPEED_SHIFT);
        let mut bank = mock_with_ports(0x20, &[portsc, 0, 0, 0]);
        let driver = XhciDriver::init(&mut bank).unwrap();
        let ports = driver.detect_ports(&bank).unwrap();
        assert_eq!(ports[0].speed, UsbSpeed::Unknown(15));
    }

    #[test]
    fn init_not_ready_timeout() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(CAPLENGTH_HCIVERSION, vec![0x20]);
        bank.on_read(HCSPARAMS1, vec![0x0100_0001]);
        bank.on_read(DBOFF, vec![0]);
        bank.on_read(RTSOFF, vec![0]);
        // Halt succeeds, reset completes, but CNR never clears.
        bank.on_read(0x20 + USBCMD, vec![USBCMD_RUN, 0]); // halt ok, HCRST self-clears
        bank.on_read(0x20 + USBSTS, vec![0, USBSTS_HCH, USBSTS_CNR]); // halt ok, then CNR sticky
        assert_eq!(XhciDriver::init(&mut bank), Err(XhciError::NotReady));
    }

    #[test]
    fn detect_ports_in_error_state_fails() {
        // Directly construct a driver in Error state to test the guard.
        let driver = XhciDriver {
            max_ports: 1,
            max_slots: 1,
            cap_length: 0x20,
            rts_offset: 0,
            db_offset: 0,
            state: XhciState::Error(XhciError::HaltTimeout),
            command_ring: None,
            event_ring: None,
            dcbaa_phys: None,
            transfer_rings: BTreeMap::new(),
        };
        let bank = MockRegisterBank::new();
        assert_eq!(driver.detect_ports(&bank), Err(XhciError::InvalidState));
    }

    #[test]
    fn setup_rings_returns_register_actions() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        let actions = driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0)
            .unwrap();

        // Should contain: CONFIG, DCBAAP(64), CRCR(64), ERST entry(WriteTrb),
        // ERSTSZ, ERSTBA(64), ERDP(64), USBCMD(RUN|INTE)
        // That's at least 8 actions
        assert!(
            actions.len() >= 8,
            "expected at least 8 setup actions, got {}",
            actions.len()
        );

        // Verify USBCMD.RUN is the last action (controller starts)
        let last = actions.last().unwrap();
        match last {
            XhciAction::WriteRegister { offset, value } => {
                assert_eq!(*offset, 0x20 + USBCMD); // cap_length + USBCMD
                assert_ne!(*value & USBCMD_RUN, 0, "should set RUN");
                // INTE omitted — Phase 2a is polling-only.
            }
            _ => panic!("last action should be WriteRegister for USBCMD"),
        }
    }

    #[test]
    fn setup_rings_before_ready_fails() {
        let mut driver = XhciDriver {
            max_ports: 1,
            max_slots: 1,
            cap_length: 0x20,
            rts_offset: 0x2000,
            db_offset: 0x1000,
            state: XhciState::Error(XhciError::HaltTimeout),
            command_ring: None,
            event_ring: None,
            dcbaa_phys: None,
            transfer_rings: BTreeMap::new(),
        };
        assert_eq!(
            driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0),
            Err(XhciError::InvalidState)
        );
    }

    #[test]
    fn enqueue_noop_returns_write_and_doorbell() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0)
            .unwrap();

        let actions = driver.enqueue_noop().unwrap();
        // Should have: WriteTrb + RingDoorbell (minimum 2)
        assert!(actions.len() >= 2);

        // First action: WriteTrb for the No-Op command
        match &actions[0] {
            XhciAction::WriteTrb { phys, trb } => {
                assert_eq!(*phys, 0x2000_0000); // base of command ring
                assert_eq!(trb.trb_type(), trb::TRB_NOOP_CMD);
                assert!(trb.cycle_bit());
            }
            other => panic!("expected WriteTrb, got {:?}", other),
        }

        // Last action: RingDoorbell
        let last = actions.last().unwrap();
        match last {
            XhciAction::RingDoorbell { offset, value } => {
                assert_eq!(*offset, 0x1000); // db_offset from mock
                assert_eq!(*value, 0); // slot 0, endpoint 0
            }
            other => panic!("expected RingDoorbell, got {:?}", other),
        }
    }

    #[test]
    fn enqueue_before_running_fails() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        // Still in Ready state, not Running
        assert_eq!(driver.enqueue_noop(), Err(XhciError::InvalidState));
    }

    #[test]
    fn process_command_completion() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0)
            .unwrap();
        driver.enqueue_noop().unwrap();

        // Simulate controller posting a Command Completion event
        // slot_id is in control bits 31:24 (xHCI Table 6-38)
        let slot_id: u8 = 3;
        let evt_trb = trb::Trb {
            parameter: 0x2000_0000, // command TRB pointer
            status: (trb::COMPLETION_SUCCESS as u32) << 24,
            control: (slot_id as u32) << 24 | (trb::TRB_COMMAND_COMPLETION as u32) << 10 | 1, // cycle bit
        };

        let (event, actions) = driver.process_event(evt_trb).unwrap();
        assert_eq!(
            event,
            XhciEvent::CommandCompletion {
                slot_id: 3,
                completion_code: trb::COMPLETION_SUCCESS,
            }
        );

        // Should have UpdateDequeuePointer action
        assert!(actions
            .iter()
            .any(|a| matches!(a, XhciAction::UpdateDequeuePointer { .. })));
    }

    #[test]
    fn process_port_status_change() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0)
            .unwrap();

        let evt_trb = trb::Trb {
            parameter: (3u64) << 24, // port_id = 3 (bits 31:24 of parameter low dword)
            status: 0,
            control: (trb::TRB_PORT_STATUS_CHANGE as u32) << 10 | 1,
        };

        let (event, _) = driver.process_event(evt_trb).unwrap();
        assert_eq!(event, XhciEvent::PortStatusChange { port_id: 3 });
    }

    #[test]
    fn process_unknown_event() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0)
            .unwrap();

        let evt_trb = trb::Trb {
            parameter: 0,
            status: 0,
            control: (63u32) << 10 | 1, // unknown type 63
        };

        let (event, _) = driver.process_event(evt_trb).unwrap();
        assert_eq!(event, XhciEvent::Unknown { trb_type: 63 });
    }

    #[test]
    fn enable_slot_enqueues_command() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();

        let actions = driver.enable_slot().unwrap();
        // Should have WriteTrb (Enable Slot cmd) + RingDoorbell
        assert!(actions.len() >= 2);
        match &actions[0] {
            XhciAction::WriteTrb { trb, .. } => {
                assert_eq!(trb.trb_type(), trb::TRB_ENABLE_SLOT);
            }
            other => panic!("expected WriteTrb, got {:?}", other),
        }
        match actions.last().unwrap() {
            XhciAction::RingDoorbell { offset, value } => {
                assert_eq!(*offset, 0x1000); // db_offset from mock
                assert_eq!(*value, 0);
            }
            other => panic!("expected RingDoorbell, got {:?}", other),
        }
    }

    #[test]
    fn address_device_returns_input_context_and_actions() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();

        let (actions, input_ctx) = driver
            .address_device(
                1, // slot_id
                2, // port
                UsbSpeed::HighSpeed,
                0x6000_0000, // input_context_phys
                0x7000_0000, // output_context_phys
                0x8000_0000, // transfer_ring_phys
            )
            .unwrap();

        // Input context should be 96 bytes
        assert_eq!(input_ctx.len(), 96);

        // Should have: WriteDma (DCBAA slot) + WriteTrb (Address Device cmd) + RingDoorbell
        assert!(actions.len() >= 3);

        // First action: WriteDma for DCBAA slot 1 at dcbaa_phys + 8
        match &actions[0] {
            XhciAction::WriteDma { phys, data } => {
                assert_eq!(*phys, 0x5000_0000 + 8); // slot 1 * 8
                assert_eq!(data.len(), 8);
                let ptr = u64::from_le_bytes(data[..8].try_into().unwrap());
                assert_eq!(ptr, 0x7000_0000); // output_context_phys
            }
            other => panic!("expected WriteDma, got {:?}", other),
        }

        // Address Device command TRB should be present
        let cmd_action = actions.iter().find(|a| {
            matches!(a, XhciAction::WriteTrb { trb, .. } if trb.trb_type() == trb::TRB_ADDRESS_DEVICE)
        });
        assert!(
            cmd_action.is_some(),
            "should have Address Device command TRB"
        );
    }

    #[test]
    fn address_device_without_dcbaa_fails() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        // setup_rings with dcbaa_phys=0 → no DCBAA stored
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0)
            .unwrap();

        let result = driver.address_device(1, 2, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000);
        assert_eq!(result, Err(XhciError::InvalidState));
    }

    #[test]
    fn get_device_descriptor_enqueues_3_trbs_and_doorbell() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();
        driver
            .address_device(1, 2, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000)
            .unwrap();

        let actions = driver.get_device_descriptor(1, 0x9000_0000).unwrap();

        // Count WriteTrb actions (should be 3: Setup, Data, Status)
        let write_trbs: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .collect();
        assert_eq!(write_trbs.len(), 3);

        // Last action should be RingDoorbell for slot 1
        match actions.last().unwrap() {
            XhciAction::RingDoorbell { offset, value } => {
                assert_eq!(*offset, 0x1000 + 4); // db_offset + 4 * slot_id
                assert_eq!(*value, 1); // endpoint 0 doorbell value = 1
            }
            other => panic!("expected RingDoorbell, got {:?}", other),
        }
    }

    #[test]
    fn get_device_descriptor_without_transfer_ring_fails() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();
        // No address_device call → no transfer ring for slot 1
        assert_eq!(
            driver.get_device_descriptor(1, 0x9000),
            Err(XhciError::NoTransferRing)
        );
    }

    #[test]
    fn process_transfer_event() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();

        let slot_id: u8 = 1;
        let endpoint_id: u8 = 1; // EP0 = endpoint ID 1 in xHCI
        let evt_trb = trb::Trb {
            parameter: 0x8000_0010, // TRB pointer (not parsed in Phase 2b)
            status: (trb::COMPLETION_SUCCESS as u32) << 24, // 0 residual
            control: (slot_id as u32) << 24
                | (endpoint_id as u32) << 16
                | (trb::TRB_TRANSFER_EVENT as u32) << 10
                | 1, // cycle bit
        };

        let (event, actions) = driver.process_event(evt_trb).unwrap();
        assert_eq!(
            event,
            XhciEvent::TransferEvent {
                slot_id: 1,
                endpoint_id: 1,
                completion_code: trb::COMPLETION_SUCCESS,
                transfer_length: 0,
            }
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, XhciAction::UpdateDequeuePointer { .. })));
    }

    #[test]
    fn parse_device_descriptor_integration() {
        let data: [u8; 18] = [
            18, 1, 0x10, 0x02, 0x00, 0x00, 0x00, 64, 0x6B,
            0x1D, // vendor = 0x1D6B (Linux Foundation)
            0x02, 0x00, // product = 0x0002
            0x10, 0x05, // version = 5.10
            1, 2, 3, 1, // string indices + num_configurations
        ];
        let desc = context::parse_device_descriptor(&data).unwrap();
        assert_eq!(desc.vendor_id, 0x1D6B);
        assert_eq!(desc.product_id, 0x0002);
        assert_eq!(desc.usb_version, 0x0210);
        assert_eq!(desc.num_configurations, 1);
    }

    #[test]
    fn address_device_creates_transfer_ring() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();

        driver
            .address_device(1, 2, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000)
            .unwrap();

        // get_device_descriptor should now work for slot 1
        assert!(driver.get_device_descriptor(1, 0x9000).is_ok());
    }

    #[test]
    fn should_process_event_delegates_to_event_ring() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0)
            .unwrap();

        assert!(driver.should_process_event(true)); // initial CCS = true
        assert!(!driver.should_process_event(false));
    }

    #[test]
    fn setup_rings_transitions_to_running() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0)
            .unwrap();
        // Enqueue should succeed (Running state)
        assert!(driver.enqueue_noop().is_ok());
    }
}
