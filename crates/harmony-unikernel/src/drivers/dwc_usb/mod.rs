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
    /// Configured max slots (from setup_rings, written to CONFIG register).
    /// Slot IDs must be 1..=max_slots_enabled.
    max_slots_enabled: u8,
    /// Transfer rings keyed by (slot_id << 8 | endpoint_id).
    transfer_rings: BTreeMap<u16, ring::TransferRing>,
}

/// Compute transfer ring map key: (slot_id << 8) | endpoint_id.
fn ring_key(slot_id: u8, endpoint_id: u8) -> u16 {
    (slot_id as u16) << 8 | endpoint_id as u16
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
            max_slots_enabled: 0,
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
        // xHCI ports are 1-based in the Slot Context (§6.2.2), so we
        // report 1-based port numbers. PORTSC registers are 0-indexed
        // (port N at PORTSC_BASE + PORTSC_STRIDE * (N-1)).
        for port_num in 1..=self.max_ports {
            let reg_index = (port_num - 1) as usize;
            let offset = self.cap_length + PORTSC_BASE + PORTSC_STRIDE * reg_index;
            let portsc = bank.read(offset);

            let speed_id = ((portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT) as u8;

            ports.push(PortStatus {
                port: port_num,
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
    /// `slot_type` must match the Supported Protocol Capability for the
    /// port being enumerated (xHCI §6.4.3.2). Use 0 for USB 2.x ports.
    pub fn enable_slot(&mut self, slot_type: u8) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }
        // No point issuing Enable Slot if no slots are configured.
        if self.max_slots_enabled == 0 {
            return Err(XhciError::InvalidState);
        }

        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_ENABLE_SLOT, 0)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, mut t)| {
                // Set Slot Type in control bits 19:16 for Enable Slot TRBs (xHCI §6.4.3.2 Table 6-10).
                if t.trb_type() == trb::TRB_ENABLE_SLOT {
                    t.control |= ((slot_type as u32) & 0xF) << 16;
                }
                XhciAction::WriteTrb { phys, trb: t }
            })
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
    /// All DMA writes (Input Context, DCBAA slot) are included in the
    /// action list. The caller executes all actions in order, then
    /// processes the `CommandCompletion` event.
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
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }
        // Valid slot IDs are 1..=max_slots (xHCI §4.6.3).
        // Slot 0 is reserved for the Scratchpad Buffer Array pointer.
        if slot_id == 0 || slot_id > self.max_slots_enabled {
            return Err(XhciError::InvalidState);
        }
        // Port 0 is reserved — valid ports are 1..=max_ports (xHCI §6.2.2).
        if port == 0 {
            return Err(XhciError::InvalidState);
        }
        let dcbaa_phys = self.dcbaa_phys.ok_or(XhciError::InvalidState)?;

        // Reject if slot already has a ring — must guard before any
        // mutation (cmd_ring.enqueue advances index + pending_count).
        if self.transfer_rings.contains_key(&ring_key(slot_id, 1)) {
            return Err(XhciError::InvalidState);
        }

        // Both context pointers must be 64-byte aligned (xHCI §6.1, §6.4.3.4).
        debug_assert!(
            input_context_phys & 0x3F == 0,
            "Input Context must be 64-byte aligned, got {:#x}",
            input_context_phys
        );
        debug_assert!(
            output_context_phys & 0x3F == 0,
            "Output Device Context must be 64-byte aligned, got {:#x}",
            output_context_phys
        );

        // Build Input Context
        let input_ctx = context::build_input_context(port, speed, transfer_ring_phys);

        let mut actions = Vec::new();

        // 1. Write Input Context to DMA (must happen before doorbell)
        actions.push(XhciAction::WriteDma {
            phys: input_context_phys,
            data: input_ctx.to_vec(),
        });

        // 2. Write Output Context pointer to DCBAA[slot_id]
        let dcbaa_slot_phys = dcbaa_phys + (slot_id as u64) * 8;
        actions.push(XhciAction::WriteDma {
            phys: dcbaa_slot_phys,
            data: output_context_phys.to_le_bytes().to_vec(),
        });

        // 3. Enqueue Address Device command
        // parameter = input_context_phys, slot_id in control bits 31:24
        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_ADDRESS_DEVICE, input_context_phys)?;

        for (phys, mut t) in entries {
            if t.trb_type() == trb::TRB_ADDRESS_DEVICE {
                t.control |= (slot_id as u32) << 24;
            }
            actions.push(XhciAction::WriteTrb { phys, trb: t });
        }

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize,
            value: 0,
        });

        // Create transfer ring for this slot's EP0.
        self.transfer_rings.insert(
            ring_key(slot_id, 1),
            ring::TransferRing::new(transfer_ring_phys),
        );

        Ok(actions)
    }

    /// Remove all transfer rings for a slot (EP0 + any configured endpoints).
    ///
    /// Call this after a failed Address Device or Configure Endpoint
    /// command completion to allow retrying. Removes all rings sharing
    /// the slot ID prefix, not just EP0.
    pub fn remove_transfer_ring(&mut self, slot_id: u8) {
        let prefix = (slot_id as u16) << 8;
        self.transfer_rings.retain(|&k, _| k & 0xFF00 != prefix);
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
        if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
            return Err(XhciError::InvalidState);
        }
        // Data buffer for DMA must be at least DWORD-aligned (xHCI §4.11.1).
        debug_assert!(
            data_buf_phys & 0x3 == 0,
            "data buffer must be DWORD-aligned, got {:#x}",
            data_buf_phys
        );

        let xfer_ring = self
            .transfer_rings
            .get_mut(&ring_key(slot_id, 1))
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
                let residual_length = trb.status & 0x00FF_FFFF;
                XhciEvent::TransferEvent {
                    slot_id,
                    endpoint_id,
                    completion_code,
                    residual_length,
                    trb_pointer: trb.parameter,
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

        // Clamp to hardware max — writing a value > max_slots to CONFIG
        // is undefined, and accepting slot IDs the hardware doesn't
        // support produces confusing hardware errors.
        let max_slots_enabled = max_slots_enabled.min(self.max_slots);

        // If slots are enabled, DCBAA must be provided — the controller
        // dereferences DCBAAP for slot context pointers.
        if max_slots_enabled > 0 && dcbaa_phys == 0 {
            return Err(XhciError::InvalidState);
        }
        // DCBAAP must be 64-byte aligned (xHCI §5.4.6, bits 5:0 are RsvdP).
        if dcbaa_phys != 0 {
            debug_assert!(
                dcbaa_phys & 0x3F == 0,
                "DCBAA must be 64-byte aligned, got {:#x}",
                dcbaa_phys
            );
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

        // 2. DCBAAP — only write when non-zero to avoid pointing the
        // controller at physical address 0 (exception vector table on RPi5).
        if dcbaa_phys != 0 {
            actions.push(XhciAction::WriteRegister64 {
                offset_lo: op + DCBAAP_LO,
                value: dcbaa_phys,
            });
        }

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
        self.max_slots_enabled = max_slots_enabled;
        self.state = XhciState::Running;

        Ok(actions)
    }

    /// Enqueue GET_DESCRIPTOR(Configuration) for the 9-byte header.
    ///
    /// After execution, poll for `TransferEvent`, then read 9 bytes from
    /// `data_buf_phys` and pass to `parse_config_descriptor`.
    ///
    /// Requires `Running` state and a transfer ring for `slot_id`
    /// (call `address_device` first).
    pub fn get_config_descriptor_header(
        &mut self,
        slot_id: u8,
        config_index: u8,
        data_buf_phys: u64,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
            return Err(XhciError::InvalidState);
        }
        debug_assert!(
            data_buf_phys & 0x3 == 0,
            "data buffer must be DWORD-aligned, got {:#x}",
            data_buf_phys
        );
        let xfer_ring = self
            .transfer_rings
            .get_mut(&ring_key(slot_id, 1))
            .ok_or(XhciError::NoTransferRing)?;

        let setup = context::get_descriptor_setup_packet(
            trb::USB_DESC_CONFIGURATION,
            config_index,
            trb::USB_CONFIG_DESCRIPTOR_HEADER_SIZE,
        );
        let entries = xfer_ring.enqueue_control_in(
            setup,
            data_buf_phys,
            trb::USB_CONFIG_DESCRIPTOR_HEADER_SIZE,
        )?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize + 4 * (slot_id as usize),
            value: 1,
        });

        Ok(actions)
    }

    /// Enqueue GET_DESCRIPTOR(Configuration) for the full descriptor tree.
    ///
    /// The caller must first call `get_config_descriptor_header` to read
    /// `total_length`, then call this with that value to fetch the complete
    /// configuration descriptor.
    ///
    /// Requires `Running` state and a transfer ring for `slot_id`
    /// (call `address_device` first).
    pub fn get_config_descriptor_full(
        &mut self,
        slot_id: u8,
        config_index: u8,
        data_buf_phys: u64,
        total_length: u16,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
            return Err(XhciError::InvalidState);
        }
        debug_assert!(
            data_buf_phys & 0x3 == 0,
            "data buffer must be DWORD-aligned, got {:#x}",
            data_buf_phys
        );
        let xfer_ring = self
            .transfer_rings
            .get_mut(&ring_key(slot_id, 1))
            .ok_or(XhciError::NoTransferRing)?;

        let setup = context::get_descriptor_setup_packet(
            trb::USB_DESC_CONFIGURATION,
            config_index,
            total_length,
        );
        let entries = xfer_ring.enqueue_control_in(setup, data_buf_phys, total_length)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize + 4 * (slot_id as usize),
            value: 1,
        });

        Ok(actions)
    }

    /// Enqueue SET_CONFIGURATION control transfer (no data stage).
    ///
    /// Sends a host-to-device SET_CONFIGURATION request for the specified
    /// configuration value. Uses a Setup + Status (no Data) sequence.
    ///
    /// Requires `Running` state and a transfer ring for `slot_id`
    /// (call `address_device` first).
    pub fn set_configuration(
        &mut self,
        slot_id: u8,
        config_value: u8,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
            return Err(XhciError::InvalidState);
        }
        let xfer_ring = self
            .transfer_rings
            .get_mut(&ring_key(slot_id, 1))
            .ok_or(XhciError::NoTransferRing)?;

        let setup = context::set_configuration_setup_packet(config_value);
        let entries = xfer_ring.enqueue_control_no_data(setup)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize + 4 * (slot_id as usize),
            value: 1,
        });

        Ok(actions)
    }

    /// Enqueue Configure Endpoint xHCI command.
    ///
    /// Sets up transfer rings for the specified endpoints after
    /// SET_CONFIGURATION succeeds. Writes the Input Context and enqueues
    /// a Configure Endpoint command on the command ring.
    ///
    /// `slot_context` is the 32-byte Slot Context from the Output Device
    /// Context (read after Address Device succeeds). Per xHCI §4.6.6, the
    /// Input Context Slot Context must be a copy with Context Entries updated.
    ///
    /// `xfer_ring_phys` is a slice of `(endpoint_id, ring_phys)` pairs.
    ///
    /// Requires `Running` state (call `setup_rings` first).
    pub fn configure_endpoint(
        &mut self,
        slot_id: u8,
        slot_context: &[u8],
        endpoints: &[EndpointDescriptor],
        input_ctx_phys: u64,
        xfer_ring_phys: &[(u8, u64)],
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
            return Err(XhciError::InvalidState);
        }
        debug_assert!(
            input_ctx_phys & 0x3F == 0,
            "Input Context must be 64-byte aligned, got {:#x}",
            input_ctx_phys
        );

        let input_ctx = context::build_configure_endpoint_input_context(
            slot_context,
            endpoints,
            xfer_ring_phys,
        );

        let mut actions = Vec::new();

        // 1. Write Input Context to DMA
        actions.push(XhciAction::WriteDma {
            phys: input_ctx_phys,
            data: input_ctx,
        });

        // 2. Enqueue Configure Endpoint command
        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_CONFIGURE_ENDPOINT, input_ctx_phys)?;

        for (phys, mut t) in entries {
            if t.trb_type() == trb::TRB_CONFIGURE_ENDPOINT {
                t.control |= (slot_id as u32) << 24;
            }
            actions.push(XhciAction::WriteTrb { phys, trb: t });
        }

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize,
            value: 0, // command doorbell
        });

        // 3. Create transfer rings for each endpoint
        for &(ep_id, ring_phys) in xfer_ring_phys {
            self.transfer_rings
                .insert(ring_key(slot_id, ep_id), ring::TransferRing::new(ring_phys));
        }

        Ok(actions)
    }

    // ── Bulk data transfers ─────────────────────────────────────────

    /// Enqueue a bulk OUT (host-to-device) transfer.
    ///
    /// `endpoint_id` must be an even DCI (OUT endpoint). `data_buf_phys`
    /// must be DWORD-aligned (xHCI §4.11.1).
    ///
    /// Requires a configured bulk endpoint (call `configure_endpoint` first).
    /// After execution, poll for `TransferEvent` with matching `slot_id` and
    /// `endpoint_id`. Actual bytes sent = `data_len - residual_length`.
    pub fn bulk_transfer_out(
        &mut self,
        slot_id: u8,
        endpoint_id: u8,
        data_buf_phys: u64,
        data_len: u32,
    ) -> Result<Vec<XhciAction>, XhciError> {
        // OUT endpoints have even DCI (2*n), minimum DCI 2. DCI 0 is reserved.
        if endpoint_id % 2 != 0 || endpoint_id < 2 {
            return Err(XhciError::InvalidState);
        }
        self.enqueue_bulk(slot_id, endpoint_id, data_buf_phys, data_len)
    }

    /// Enqueue a bulk IN (device-to-host) transfer.
    ///
    /// `endpoint_id` must be an odd DCI (IN endpoint). `data_buf_phys`
    /// must be DWORD-aligned (xHCI §4.11.1).
    ///
    /// Requires a configured bulk endpoint (call `configure_endpoint` first).
    /// After execution, poll for `TransferEvent` with matching `slot_id` and
    /// `endpoint_id`. Actual bytes received = `data_len - residual_length`.
    pub fn bulk_transfer_in(
        &mut self,
        slot_id: u8,
        endpoint_id: u8,
        data_buf_phys: u64,
        data_len: u32,
    ) -> Result<Vec<XhciAction>, XhciError> {
        // IN endpoints have odd DCI (2*n + 1). DCI 1 is EP0 (control), not bulk.
        if endpoint_id % 2 == 0 || endpoint_id < 2 {
            return Err(XhciError::InvalidState);
        }
        self.enqueue_bulk(slot_id, endpoint_id, data_buf_phys, data_len)
    }

    /// Shared bulk transfer enqueue logic.
    fn enqueue_bulk(
        &mut self,
        slot_id: u8,
        endpoint_id: u8,
        data_buf_phys: u64,
        data_len: u32,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
            return Err(XhciError::InvalidState);
        }
        // DMA buffer must be DWORD-aligned (xHCI §4.11.1).
        if data_buf_phys & 0x3 != 0 {
            return Err(XhciError::InvalidState);
        }

        let xfer_ring = self
            .transfer_rings
            .get_mut(&ring_key(slot_id, endpoint_id))
            .ok_or(XhciError::NoTransferRing)?;

        let entries = xfer_ring.enqueue_bulk(data_buf_phys, data_len)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        // Doorbell target = endpoint DCI for non-EP0 endpoints.
        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize + 4 * (slot_id as usize),
            value: endpoint_id as u32,
        });

        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;
    use alloc::vec;

    /// Helper: create a Running driver with a slot addressed and ready for transfers.
    fn make_running_driver_with_slot(slot_id: u8) -> XhciDriver {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();
        driver
            .address_device(
                slot_id,
                1,
                UsbSpeed::HighSpeed,
                0x6000_0000,
                0x7000_0000,
                0x8000_0000,
            )
            .unwrap();
        driver
    }

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
        assert_eq!(ports[0].port, 1); // 1-based port numbers
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
            max_slots_enabled: 0,
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

        // With dcbaa_phys=0, DCBAAP is skipped. Should contain:
        // CONFIG, CRCR(64), ERST entry(WriteTrb), ERSTSZ, ERSTBA(64), ERDP(64), USBCMD
        // That's at least 7 actions
        assert!(
            actions.len() >= 7,
            "expected at least 7 setup actions, got {}",
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
            max_slots_enabled: 0,
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

        let actions = driver.enable_slot(0).unwrap(); // slot_type=0 for USB 2.x
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

        let actions = driver
            .address_device(
                1, // slot_id
                2, // port
                UsbSpeed::HighSpeed,
                0x6000_0000, // input_context_phys
                0x7000_0000, // output_context_phys
                0x8000_0000, // transfer_ring_phys
            )
            .unwrap();

        // Should have: WriteDma (Input Context) + WriteDma (DCBAA slot)
        //            + WriteTrb (Address Device cmd) + RingDoorbell
        assert!(actions.len() >= 4);

        // First action: WriteDma for Input Context (96 bytes)
        match &actions[0] {
            XhciAction::WriteDma { phys, data } => {
                assert_eq!(*phys, 0x6000_0000); // input_context_phys
                assert_eq!(data.len(), 96);
            }
            other => panic!("expected WriteDma for Input Context, got {:?}", other),
        }

        // Second action: WriteDma for DCBAA slot 1 at dcbaa_phys + 8
        match &actions[1] {
            XhciAction::WriteDma { phys, data } => {
                assert_eq!(*phys, 0x5000_0000 + 8); // slot 1 * 8
                assert_eq!(data.len(), 8);
                let ptr = u64::from_le_bytes(data[..8].try_into().unwrap());
                assert_eq!(ptr, 0x7000_0000); // output_context_phys
            }
            other => panic!("expected WriteDma for DCBAA, got {:?}", other),
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
        // Directly construct a Running driver with max_slots_enabled > 0
        // but dcbaa_phys = None to test the DCBAA-absence guard specifically.
        let mut driver = XhciDriver {
            max_ports: 4,
            max_slots: 32,
            cap_length: 0x20,
            rts_offset: 0x2000,
            db_offset: 0x1000,
            state: XhciState::Running,
            command_ring: Some(ring::CommandRing::new(0x2000_0000)),
            event_ring: Some(ring::EventRing::new(0x3000_0000)),
            dcbaa_phys: None,
            max_slots_enabled: 4,
            transfer_rings: BTreeMap::new(),
        };

        let result = driver.address_device(1, 1, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000);
        assert_eq!(result, Err(XhciError::InvalidState));
    }

    #[test]
    fn address_device_slot_zero_rejected() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();
        // Slot 0 is reserved for scratchpad — must be rejected
        let result = driver.address_device(0, 2, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000);
        assert_eq!(result, Err(XhciError::InvalidState));
    }

    #[test]
    fn address_device_slot_above_max_rejected() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        // max_slots_enabled=4 (configured limit, not hardware max of 32)
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();
        // slot_id=5 exceeds max_slots_enabled=4
        let result = driver.address_device(5, 2, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000);
        assert_eq!(result, Err(XhciError::InvalidState));
    }

    #[test]
    fn remove_transfer_ring_allows_retry() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver
            .setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4)
            .unwrap();

        // First address_device succeeds (creates transfer ring)
        driver
            .address_device(1, 1, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000)
            .unwrap();

        // Second call blocked by duplicate-slot guard
        assert_eq!(
            driver.address_device(1, 1, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000),
            Err(XhciError::InvalidState)
        );

        // After remove_transfer_ring, retry succeeds
        driver.remove_transfer_ring(1);
        assert!(driver
            .address_device(1, 1, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000)
            .is_ok());
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
                residual_length: 0,
                trb_pointer: 0x8000_0010,
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

    // ── Task 4 tests ────────────────────────────────────────────────

    #[test]
    fn get_config_descriptor_header_produces_trbs() {
        let mut driver = make_running_driver_with_slot(1);
        let actions = driver
            .get_config_descriptor_header(1, 0, 0xB000_0000)
            .unwrap();
        // 3 TRBs (Setup/Data/Status) + 1 RingDoorbell = 4 actions
        let trb_count = actions
            .iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .count();
        assert_eq!(trb_count, 3);
        assert!(actions
            .iter()
            .any(|a| matches!(a, XhciAction::RingDoorbell { .. })));
    }

    #[test]
    fn get_config_descriptor_full_uses_total_length() {
        let mut driver = make_running_driver_with_slot(1);
        let total_length: u16 = 0x0042;
        let actions = driver
            .get_config_descriptor_full(1, 0, 0xB000_0000, total_length)
            .unwrap();
        // Verify wLength in the Setup TRB parameter matches total_length
        let setup_action = actions
            .iter()
            .find(|a| {
                matches!(a, XhciAction::WriteTrb { trb, .. }
                    if trb.trb_type() == trb::TRB_SETUP_STAGE)
            })
            .unwrap();
        if let XhciAction::WriteTrb { trb, .. } = setup_action {
            // Setup packet is stored as u64 LE in parameter
            let pkt = trb.parameter.to_le_bytes();
            let wlength = u16::from_le_bytes([pkt[6], pkt[7]]);
            assert_eq!(wlength, total_length, "wLength should match total_length");
        }
        // 3 TRBs + doorbell
        let trb_count = actions
            .iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .count();
        assert_eq!(trb_count, 3);
    }

    #[test]
    fn set_configuration_produces_two_trbs() {
        let mut driver = make_running_driver_with_slot(1);
        let actions = driver.set_configuration(1, 1).unwrap();
        let trb_count = actions
            .iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .count();
        assert_eq!(trb_count, 2, "Setup + Status, no Data stage");
        assert!(actions
            .iter()
            .any(|a| matches!(a, XhciAction::RingDoorbell { .. })));
    }

    #[test]
    fn configure_endpoint_creates_rings_and_command() {
        let mut driver = make_running_driver_with_slot(1);
        let eps = alloc::vec![
            EndpointDescriptor {
                endpoint_address: 0x02,
                attributes: 0x02,
                max_packet_size: 512,
                interval: 0,
            },
            EndpointDescriptor {
                endpoint_address: 0x82,
                attributes: 0x02,
                max_packet_size: 512,
                interval: 0,
            },
        ];
        let rings = alloc::vec![(4u8, 0xA000_0000u64), (5u8, 0xB000_0000u64)];
        // Fake 32-byte Slot Context (simulates existing Device Context)
        let mut slot_ctx = [0u8; 32];
        // DWord 0: speed=3 (HighSpeed) in bits 23:20, Context Entries=1 in bits 31:27
        let slot_dw0: u32 = (1 << 27) | (3 << 20);
        slot_ctx[0..4].copy_from_slice(&slot_dw0.to_le_bytes());
        // DWord 1: Root Hub Port = 1 in bits 23:16
        slot_ctx[4..8].copy_from_slice(&(1u32 << 16).to_le_bytes());

        let actions = driver
            .configure_endpoint(1, &slot_ctx, &eps, 0xC000_0000, &rings)
            .unwrap();

        // Should have: WriteDma (input ctx) + WriteTrb (command) + RingDoorbell
        assert!(actions
            .iter()
            .any(|a| matches!(a, XhciAction::WriteDma { .. })));
        assert!(actions.iter().any(|a| matches!(
            a,
            XhciAction::RingDoorbell {
                offset: _,
                value: 0
            }
        )));

        // Transfer rings should be created for both endpoints
        assert!(
            driver.transfer_rings.contains_key(&ring_key(1, 4)),
            "should have ring for slot 1 EP4 (bulk OUT)"
        );
        assert!(
            driver.transfer_rings.contains_key(&ring_key(1, 5)),
            "should have ring for slot 1 EP5 (bulk IN)"
        );
    }

    // ── Bulk transfer tests ─────────────────────────────────────────

    /// Helper: create a driver with slot 1 addressed + bulk endpoints configured.
    fn make_driver_with_bulk_endpoints() -> XhciDriver {
        let mut driver = make_running_driver_with_slot(1);
        let eps = alloc::vec![
            EndpointDescriptor {
                endpoint_address: 0x02,
                attributes: 0x02,
                max_packet_size: 512,
                interval: 0,
            },
            EndpointDescriptor {
                endpoint_address: 0x82,
                attributes: 0x02,
                max_packet_size: 512,
                interval: 0,
            },
        ];
        let mut slot_ctx = [0u8; 32];
        let slot_dw0: u32 = (1 << 27) | (3 << 20);
        slot_ctx[0..4].copy_from_slice(&slot_dw0.to_le_bytes());
        slot_ctx[4..8].copy_from_slice(&(1u32 << 16).to_le_bytes());
        let rings = alloc::vec![(4u8, 0xA000_0000u64), (5u8, 0xB000_0000u64)];
        driver
            .configure_endpoint(1, &slot_ctx, &eps, 0xC000_0000, &rings)
            .unwrap();
        driver
    }

    #[test]
    fn bulk_transfer_out_produces_trb_and_doorbell() {
        let mut driver = make_driver_with_bulk_endpoints();
        let actions = driver.bulk_transfer_out(1, 4, 0xD000_0000, 512).unwrap();

        let trb_count = actions
            .iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .count();
        assert_eq!(trb_count, 1, "should produce 1 Normal TRB");

        // Doorbell target = endpoint_id (4 for bulk OUT EP2)
        assert!(actions.iter().any(|a| matches!(
            a,
            XhciAction::RingDoorbell {
                offset: _,
                value: 4,
            }
        )));
    }

    #[test]
    fn bulk_transfer_in_produces_trb_and_doorbell() {
        let mut driver = make_driver_with_bulk_endpoints();
        let actions = driver.bulk_transfer_in(1, 5, 0xD000_0000, 512).unwrap();

        let trb_count = actions
            .iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .count();
        assert_eq!(trb_count, 1);

        // Doorbell target = endpoint_id (5 for bulk IN EP2)
        assert!(actions.iter().any(|a| matches!(
            a,
            XhciAction::RingDoorbell {
                offset: _,
                value: 5,
            }
        )));
    }

    #[test]
    fn bulk_transfer_no_ring_returns_error() {
        let mut driver = make_running_driver_with_slot(1);
        // No configure_endpoint called — endpoint 4 has no ring.
        assert_eq!(
            driver.bulk_transfer_out(1, 4, 0xD000_0000, 512),
            Err(XhciError::NoTransferRing)
        );
    }

    #[test]
    fn bulk_transfer_invalid_state() {
        let mut bank = mock_init_success();
        let driver_result = XhciDriver::init(&mut bank);
        let mut driver = driver_result.unwrap();
        // Ready state, not Running — should fail.
        assert_eq!(
            driver.bulk_transfer_out(1, 4, 0xD000_0000, 512),
            Err(XhciError::InvalidState)
        );
    }

    #[test]
    fn bulk_transfer_out_rejects_in_endpoint() {
        let mut driver = make_driver_with_bulk_endpoints();
        // DCI 5 is odd (IN) — bulk_transfer_out requires even (OUT).
        assert_eq!(
            driver.bulk_transfer_out(1, 5, 0xD000_0000, 512),
            Err(XhciError::InvalidState)
        );
    }

    #[test]
    fn bulk_transfer_in_rejects_out_endpoint() {
        let mut driver = make_driver_with_bulk_endpoints();
        // DCI 4 is even (OUT) — bulk_transfer_in requires odd (IN).
        assert_eq!(
            driver.bulk_transfer_in(1, 4, 0xD000_0000, 512),
            Err(XhciError::InvalidState)
        );
    }

    #[test]
    fn bulk_transfer_in_rejects_ep0() {
        let mut driver = make_driver_with_bulk_endpoints();
        // DCI 1 is EP0 (control), not a bulk endpoint.
        assert_eq!(
            driver.bulk_transfer_in(1, 1, 0xD000_0000, 512),
            Err(XhciError::InvalidState)
        );
    }

    #[test]
    fn bulk_transfer_rejects_unaligned_buffer() {
        let mut driver = make_driver_with_bulk_endpoints();
        // Buffer not DWORD-aligned (0xD000_0001).
        assert_eq!(
            driver.bulk_transfer_out(1, 4, 0xD000_0001, 512),
            Err(XhciError::InvalidState)
        );
    }
}
