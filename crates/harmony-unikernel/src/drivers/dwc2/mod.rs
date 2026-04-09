// SPDX-License-Identifier: GPL-2.0-or-later
//! DWC2 OTG USB device controller driver.
pub mod fifo;
pub mod regs;
pub mod types;
pub use types::{
    DeviceSpeed, Dwc2Action, Dwc2Error, Dwc2Event, GadgetEvent, GadgetRequest, UsbDeviceState,
};

extern crate alloc;
use alloc::vec::Vec;

use super::register_bank::RegisterBank;
use fifo::{
    dieptxf_value, gnptxfsiz_value, RX_FIFO_WORDS, TX1_FIFO_WORDS, TX1_START, TX3_FIFO_WORDS,
    TX3_START,
};
use regs::*;

const MAX_ENDPOINTS: u8 = 4;

// ── Controller ──────────────────────────────────────────────────────────────

/// DWC2 USB device controller state machine.
///
/// All register access goes through the [`RegisterBank`] trait, which
/// the caller provides. The controller performs I/O via the bank and
/// also returns [`Dwc2Action`] values describing what was written,
/// for the caller's bookkeeping and logging.
pub struct Dwc2Controller {
    state: UsbDeviceState,
    speed: DeviceSpeed,
    address: u8,
    /// Deferred address — written to DCFG only after status-stage ZLP is ACKed
    /// (USB 2.0 §9.4.6: device must not change address until status stage completes).
    pending_address: Option<u8>,
    setup_data: Option<[u8; 8]>,
    /// Per-endpoint OUT reassembly buffer. Multi-packet transfers (e.g., a
    /// 1514-byte Ethernet frame over 512-byte bulk MPS) arrive as multiple
    /// PKTSTS_OUT_DATA entries; we accumulate here and emit a single
    /// GadgetEvent::BulkOut on PKTSTS_OUT_COMPLETE.
    rx_reassembly: Vec<u8>,
    device_desc: Option<Vec<u8>>,
    config_desc: Option<Vec<u8>>,
    string_descs: Vec<Vec<u8>>,
}

impl Dwc2Controller {
    /// Initialise the DWC2 controller in device mode.
    ///
    /// Forces device mode, configures FIFO sizes, sets HS speed,
    /// enables global interrupts, unmasks device/EP0 interrupts,
    /// prepares EP0 OUT for SETUP reception, and soft-connects.
    pub fn init(bank: &mut impl RegisterBank) -> Result<(Self, Vec<Dwc2Action>), Dwc2Error> {
        let mut actions = Vec::new();

        // Force device mode (bit 30 of GUSBCFG) + set turnaround time
        let gusbcfg = GUSBCFG_FORCE_DEV | GUSBCFG_TURNAROUND_9;
        bank.write(GUSBCFG, gusbcfg);
        actions.push(Dwc2Action::WriteRegister {
            offset: GUSBCFG,
            value: gusbcfg,
        });

        // Configure FIFO sizes
        bank.write(GRXFSIZ, RX_FIFO_WORDS);
        actions.push(Dwc2Action::WriteRegister {
            offset: GRXFSIZ,
            value: RX_FIFO_WORDS,
        });

        let gnptxfsiz = gnptxfsiz_value();
        bank.write(GNPTXFSIZ, gnptxfsiz);
        actions.push(Dwc2Action::WriteRegister {
            offset: GNPTXFSIZ,
            value: gnptxfsiz,
        });

        // EP1 TX FIFO
        let dieptxf1 = dieptxf_value(TX1_START, TX1_FIFO_WORDS);
        bank.write(dieptxf(1), dieptxf1);
        actions.push(Dwc2Action::WriteRegister {
            offset: dieptxf(1),
            value: dieptxf1,
        });

        // EP3 TX FIFO
        let dieptxf3 = dieptxf_value(TX3_START, TX3_FIFO_WORDS);
        bank.write(dieptxf(3), dieptxf3);
        actions.push(Dwc2Action::WriteRegister {
            offset: dieptxf(3),
            value: dieptxf3,
        });

        // Set HS speed in DCFG
        bank.write(DCFG, DCFG_DEVSPD_HS);
        actions.push(Dwc2Action::WriteRegister {
            offset: DCFG,
            value: DCFG_DEVSPD_HS,
        });

        // Enable global interrupts (GAHBCFG)
        bank.write(GAHBCFG, GAHBCFG_GLBL_INTR_EN);
        actions.push(Dwc2Action::WriteRegister {
            offset: GAHBCFG,
            value: GAHBCFG_GLBL_INTR_EN,
        });

        // Unmask device interrupts (GINTMSK): RxFIFO, suspend, reset, enum done,
        // IN EP int, OUT EP int, wakeup
        let gintmsk = GINTSTS_RXFLVL
            | GINTSTS_USBSUSP
            | GINTSTS_USBRST
            | GINTSTS_ENUMDNE
            | GINTSTS_IEPINT
            | GINTSTS_OEPINT
            | GINTSTS_WKUPINT;
        bank.write(GINTMSK, gintmsk);
        actions.push(Dwc2Action::WriteRegister {
            offset: GINTMSK,
            value: gintmsk,
        });

        // Unmask EP0 IN and EP0 OUT in DAINTMSK
        let daintmsk: u32 = (1 << 0) | (1 << 16); // EP0 IN bit 0, EP0 OUT bit 16
        bank.write(DAINTMSK, daintmsk);
        actions.push(Dwc2Action::WriteRegister {
            offset: DAINTMSK,
            value: daintmsk,
        });

        // Enable transfer-complete interrupts for IN EPs (DIEPMSK)
        bank.write(DIEPMSK, DEPINT_XFERCOMPL);
        actions.push(Dwc2Action::WriteRegister {
            offset: DIEPMSK,
            value: DEPINT_XFERCOMPL,
        });

        // Enable transfer-complete and SETUP interrupts for OUT EPs (DOEPMSK)
        let doepmsk = DEPINT_XFERCOMPL | DOEPINT_SETUP;
        bank.write(DOEPMSK, doepmsk);
        actions.push(Dwc2Action::WriteRegister {
            offset: DOEPMSK,
            value: doepmsk,
        });

        // Prepare EP0 OUT to receive SETUP packets
        let doeptsiz0 = DOEPTSIZ0_SUPCNT_1 | DOEPTSIZ0_PKTCNT_1 | 8u32;
        bank.write(doeptsiz(0), doeptsiz0);
        actions.push(Dwc2Action::WriteRegister {
            offset: doeptsiz(0),
            value: doeptsiz0,
        });

        let doepctl0 = EPCTL_EPENA | EPCTL_CNAK;
        bank.write(doepctl(0), doepctl0);
        actions.push(Dwc2Action::WriteRegister {
            offset: doepctl(0),
            value: doepctl0,
        });

        // Soft-connect: clear SFTDISCON bit in DCTL
        let dctl = bank.read(DCTL) & !DCTL_SFTDISCON;
        bank.write(DCTL, dctl);
        actions.push(Dwc2Action::WriteRegister {
            offset: DCTL,
            value: dctl,
        });

        let ctrl = Dwc2Controller {
            state: UsbDeviceState::Default,
            speed: DeviceSpeed::HighSpeed,
            address: 0,
            pending_address: None,
            setup_data: None,
            rx_reassembly: Vec::new(),
            device_desc: None,
            config_desc: None,
            string_descs: Vec::new(),
        };

        Ok((ctrl, actions))
    }

    /// Store pre-built USB descriptors to serve during enumeration.
    pub fn set_descriptors(
        &mut self,
        device_desc: Vec<u8>,
        config_desc: Vec<u8>,
        string_descs: Vec<Vec<u8>>,
    ) {
        self.device_desc = Some(device_desc);
        self.config_desc = Some(config_desc);
        self.string_descs = string_descs;
    }

    /// Current USB device state.
    pub fn state(&self) -> UsbDeviceState {
        self.state
    }

    /// Negotiated device speed.
    pub fn speed(&self) -> DeviceSpeed {
        self.speed
    }

    /// Process a hardware event and return gadget-level events.
    pub fn handle_event(
        &mut self,
        event: Dwc2Event,
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<GadgetEvent>, Dwc2Error> {
        match event {
            Dwc2Event::BusReset => Ok(self.handle_bus_reset(bank)),
            Dwc2Event::EnumerationDone { speed } => {
                self.speed = speed;
                Ok(Vec::new())
            }
            Dwc2Event::SetupReceived { data } => self.handle_setup(data, bank),
            Dwc2Event::RxFifoNonEmpty => self.handle_rx_fifo(bank),
            Dwc2Event::InTransferComplete { ep } => {
                // Commit deferred SET_ADDRESS after EP0 status-stage ZLP is ACKed.
                if ep == 0 {
                    if let Some(addr) = self.pending_address.take() {
                        let dcfg = (bank.read(DCFG) & !DCFG_DAD_MASK) | dcfg_dad(addr);
                        bank.write(DCFG, dcfg);
                        self.address = addr;
                    }
                    return Ok(Vec::new());
                }
                Ok(alloc::vec![GadgetEvent::BulkInComplete { ep }])
            }
            Dwc2Event::OutTransferComplete { ep } => {
                // Re-arm EP0 if needed; for other EPs, no re-arm here (done in rx_fifo handler)
                if ep == 0 {
                    let doeptsiz0 = DOEPTSIZ0_SUPCNT_1 | DOEPTSIZ0_PKTCNT_1 | 8u32;
                    bank.write(doeptsiz(0), doeptsiz0);
                    bank.write(doepctl(0), EPCTL_EPENA | EPCTL_CNAK);
                }
                Ok(Vec::new())
            }
            Dwc2Event::Suspend => Ok(alloc::vec![GadgetEvent::Suspended]),
            Dwc2Event::Resume => Ok(alloc::vec![GadgetEvent::Resumed]),
        }
    }

    fn handle_bus_reset(&mut self, bank: &mut impl RegisterBank) -> Vec<GadgetEvent> {
        // Return to Default state, clear all pending state.
        self.state = UsbDeviceState::Default;
        self.address = 0;
        self.pending_address = None;
        self.setup_data = None;
        self.rx_reassembly.clear();

        // Clear address in DCFG
        let dcfg = bank.read(DCFG) & !DCFG_DAD_MASK;
        bank.write(DCFG, dcfg);

        // Disable non-EP0 endpoints.
        Self::disable_data_endpoints(bank);

        // Re-arm EP0 OUT for SETUP
        let doeptsiz0 = DOEPTSIZ0_SUPCNT_1 | DOEPTSIZ0_PKTCNT_1 | 8u32;
        bank.write(doeptsiz(0), doeptsiz0);
        bank.write(doepctl(0), EPCTL_EPENA | EPCTL_CNAK);

        alloc::vec![GadgetEvent::Reset]
    }

    fn handle_setup(
        &mut self,
        setup: [u8; 8],
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<GadgetEvent>, Dwc2Error> {
        let bm_request_type = setup[0];
        let b_request = setup[1];
        let w_value = u16::from_le_bytes([setup[2], setup[3]]);
        let w_index = u16::from_le_bytes([setup[4], setup[5]]);
        let w_length = u16::from_le_bytes([setup[6], setup[7]]);

        // Type field is bits [6:5] of bmRequestType
        let req_type = (bm_request_type >> 5) & 0x3;

        match req_type {
            0 => {
                // Standard request
                self.handle_standard_setup(b_request, w_value, w_index, w_length, bank)
            }
            1 => {
                // Class request — forward to gadget
                Ok(alloc::vec![GadgetEvent::SetupClassRequest { setup }])
            }
            _ => {
                // Vendor or other — stall EP0
                bank.write(diepctl(0), bank.read(diepctl(0)) | EPCTL_STALL);
                bank.write(doepctl(0), bank.read(doepctl(0)) | EPCTL_STALL);
                Ok(Vec::new())
            }
        }
    }

    fn handle_standard_setup(
        &mut self,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        w_length: u16,
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<GadgetEvent>, Dwc2Error> {
        match b_request {
            // GET_STATUS (0x00) — mandatory per USB 2.0 §9.4.5.
            // Return 2-byte status: bus-powered, no remote wakeup.
            0x00 => {
                Self::write_ep0_in(bank, &[0x00, 0x00]);
                Ok(Vec::new())
            }
            // SET_ADDRESS — defer DCFG write until status-stage ZLP is ACKed
            // (USB 2.0 §9.4.6: device must not change address until status stage completes).
            0x05 => {
                let addr = (w_value & 0x7F) as u8;
                self.pending_address = Some(addr);
                self.state = UsbDeviceState::Address;

                // Send ZLP status on EP0 IN — DCFG written on InTransferComplete{ep:0}
                Self::write_ep0_in(bank, &[]);

                Ok(Vec::new())
            }
            // GET_DESCRIPTOR
            0x06 => {
                let desc_type = (w_value >> 8) as u8;
                let desc_index = (w_value & 0xFF) as u8;
                let max_len = w_length;

                // Serve pre-registered descriptors directly.
                // Only emit GadgetEvent::GetDescriptor for unknown types.
                let found: Option<Vec<u8>> = match desc_type {
                    1 => self.device_desc.clone(),
                    2 => self.config_desc.clone(),
                    3 => self.string_descs.get(desc_index as usize).cloned(),
                    _ => None,
                };

                if let Some(mut d) = found {
                    d.truncate(max_len as usize);
                    Self::write_ep0_in(bank, &d);
                    Ok(Vec::new())
                } else {
                    // Descriptor not found — ask gadget.
                    Ok(alloc::vec![GadgetEvent::GetDescriptor {
                        desc_type,
                        desc_index,
                        max_len,
                    }])
                }
            }
            // SET_CONFIGURATION
            0x09 => {
                let config_value = (w_value & 0xFF) as u8;
                if config_value > 0 {
                    self.state = UsbDeviceState::Configured;
                    Self::enable_data_endpoints(bank);
                    // Send ZLP status
                    Self::write_ep0_in(bank, &[]);
                    Ok(alloc::vec![GadgetEvent::Configured])
                } else {
                    // Deconfigure: disable data endpoints, return to Address.
                    self.state = UsbDeviceState::Address;
                    Self::disable_data_endpoints(bank);
                    Self::write_ep0_in(bank, &[]);
                    Ok(alloc::vec![GadgetEvent::Reset])
                }
            }
            // GET_CONFIGURATION (0x08) — return current bConfigurationValue.
            0x08 => {
                let val = if self.state == UsbDeviceState::Configured {
                    1u8
                } else {
                    0u8
                };
                Self::write_ep0_in(bank, &[val]);
                Ok(Vec::new())
            }
            // GET_INTERFACE (0x0A) — return current alternate setting.
            0x0A => {
                let iface = (w_index & 0xFF) as u8;
                // Interface 0 (control) always has alt 0.
                // Interface 1 (data) reports alt 1 when configured, alt 0 otherwise.
                let alt = if iface == 1 && self.state == UsbDeviceState::Configured {
                    1u8
                } else {
                    0u8
                };
                Self::write_ep0_in(bank, &[alt]);
                Ok(Vec::new())
            }
            // SET_INTERFACE (0x0B) — enable/disable data endpoints per alternate setting.
            // Emit Configured/Reset so the gadget tracks endpoint state.
            0x0B => {
                let iface = (w_index & 0xFF) as u8;
                let alt = (w_value & 0xFF) as u8;
                let events = if iface == 1 {
                    if alt == 1 {
                        Self::enable_data_endpoints(bank);
                        alloc::vec![GadgetEvent::Configured]
                    } else {
                        Self::disable_data_endpoints(bank);
                        alloc::vec![GadgetEvent::Reset]
                    }
                } else {
                    Vec::new()
                };
                Self::write_ep0_in(bank, &[]);
                Ok(events)
            }
            _ => {
                // Unknown standard request — stall EP0
                bank.write(diepctl(0), bank.read(diepctl(0)) | EPCTL_STALL);
                bank.write(doepctl(0), bank.read(doepctl(0)) | EPCTL_STALL);
                Ok(Vec::new())
            }
        }
    }

    fn enable_data_endpoints(bank: &mut impl RegisterBank) {
        // EP1 IN bulk, MPS=512, FIFO=1 — configure only, no EPENA.
        // write_tx_fifo arms the endpoint when real data is ready.
        let ep1_in = 512u32 | EPCTL_USBAEP | epctl_eptype(EPTYPE_BULK) | epctl_txfnum(1);
        bank.write(diepctl(1), ep1_in);

        // EP2 OUT bulk, MPS=512
        // DWC2 requires transfer size programmed BEFORE endpoint enable.
        // Arm for a full Ethernet frame: 1514 bytes = 3 USB packets (512+512+490).
        let doeptsiz2: u32 = (3 << 19) | 1514; // pktcnt=3, xfersize=1514
        bank.write(doeptsiz(2), doeptsiz2);
        let ep2_out = 512u32 | EPCTL_USBAEP | epctl_eptype(EPTYPE_BULK) | EPCTL_EPENA | EPCTL_CNAK;
        bank.write(doepctl(2), ep2_out);

        // EP3 IN interrupt, MPS=16, FIFO=3 — configure only, no EPENA.
        // write_tx_fifo arms the endpoint when a notification is submitted.
        let ep3_in = 16u32 | EPCTL_USBAEP | epctl_eptype(EPTYPE_INTERRUPT) | epctl_txfnum(3);
        bank.write(diepctl(3), ep3_in);

        // Update DAINTMSK to include EP1 IN, EP2 OUT, EP3 IN
        let daintmsk: u32 = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 16) | (1 << 18);
        bank.write(DAINTMSK, daintmsk);
    }

    fn disable_data_endpoints(bank: &mut impl RegisterBank) {
        for ep in 1..MAX_ENDPOINTS {
            let diepctl_val = bank.read(diepctl(ep));
            if diepctl_val & EPCTL_EPENA != 0 {
                bank.write(diepctl(ep), EPCTL_EPDIS | EPCTL_SNAK);
            } else {
                bank.write(diepctl(ep), EPCTL_SNAK);
            }
            let doepctl_val = bank.read(doepctl(ep));
            if doepctl_val & EPCTL_EPENA != 0 {
                bank.write(doepctl(ep), EPCTL_EPDIS | EPCTL_SNAK);
            } else {
                bank.write(doepctl(ep), EPCTL_SNAK);
            }
        }
        // Revert DAINTMSK to EP0 only.
        bank.write(DAINTMSK, (1 << 0) | (1 << 16));
    }

    fn handle_rx_fifo(
        &mut self,
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<GadgetEvent>, Dwc2Error> {
        let grxstsp = bank.read(GRXSTSP);
        let ep = grxstsp_epnum(grxstsp);
        let bcnt = grxstsp_bcnt(grxstsp);
        let pktsts = grxstsp_pktsts(grxstsp);

        match pktsts {
            PKTSTS_SETUP_DATA => {
                // Read 2 words from EP0 FIFO into setup_data buffer
                let w0 = bank.read(ep_fifo(0));
                let w1 = bank.read(ep_fifo(0));
                let mut data = [0u8; 8];
                data[0..4].copy_from_slice(&w0.to_le_bytes());
                data[4..8].copy_from_slice(&w1.to_le_bytes());
                self.setup_data = Some(data);
                Ok(Vec::new())
            }
            PKTSTS_SETUP_COMPLETE => {
                // Dispatch buffered setup
                if let Some(setup) = self.setup_data.take() {
                    self.handle_setup(setup, bank)
                } else {
                    Ok(Vec::new())
                }
            }
            PKTSTS_OUT_DATA if ep > 0 && bcnt > 0 => {
                // Accumulate into reassembly buffer. Multi-packet transfers
                // (e.g., 1514 bytes over 512-byte MPS) arrive as multiple
                // OUT_DATA entries; we emit a single BulkOut on OUT_COMPLETE.
                let words = (bcnt as usize).div_ceil(4);
                for _ in 0..words {
                    let w = bank.read(ep_fifo(ep));
                    self.rx_reassembly.extend_from_slice(&w.to_le_bytes());
                }
                // Trim to exact byte count (last word may have padding).
                let target_len = self.rx_reassembly.len() - (words * 4 - bcnt as usize);
                self.rx_reassembly.truncate(target_len);
                Ok(Vec::new())
            }
            PKTSTS_OUT_COMPLETE if ep > 0 => {
                // All packets received — emit the reassembled frame.
                let data = core::mem::take(&mut self.rx_reassembly);
                // Re-arm the OUT endpoint for the next frame.
                let doeptsiz_val: u32 = (3 << 19) | 1514; // pktcnt=3, xfersize=1514
                bank.write(doeptsiz(ep), doeptsiz_val);
                bank.write(
                    doepctl(ep),
                    bank.read(doepctl(ep)) | EPCTL_EPENA | EPCTL_CNAK,
                );
                if data.is_empty() {
                    Ok(Vec::new())
                } else {
                    Ok(alloc::vec![GadgetEvent::BulkOut { ep, data }])
                }
            }
            _ => {
                // Drain any remaining FIFO words to avoid stall
                if bcnt > 0 {
                    let words = (bcnt as usize).div_ceil(4);
                    for _ in 0..words {
                        let _ = bank.read(ep_fifo(ep));
                    }
                }
                Ok(Vec::new())
            }
        }
    }

    /// Submit a request from the gadget class driver.
    pub fn submit_request(
        &mut self,
        req: GadgetRequest,
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<Dwc2Action>, Dwc2Error> {
        match req {
            GadgetRequest::ControlIn { data } => {
                Self::write_ep0_in(bank, &data);
                Ok(alloc::vec![Dwc2Action::WriteTxFifo { ep: 0, data }])
            }
            GadgetRequest::ControlAck => {
                // Send ZLP on EP0 IN (status stage)
                Self::write_ep0_in(bank, &[]);
                Ok(alloc::vec![Dwc2Action::WriteTxFifo {
                    ep: 0,
                    data: alloc::vec![]
                }])
            }
            GadgetRequest::ControlStall => {
                let diepctl0 = bank.read(diepctl(0)) | EPCTL_STALL;
                bank.write(diepctl(0), diepctl0);
                let doepctl0 = bank.read(doepctl(0)) | EPCTL_STALL;
                bank.write(doepctl(0), doepctl0);
                Ok(alloc::vec![Dwc2Action::Stall { ep: 0 }])
            }
            GadgetRequest::BulkIn { ep, data } => {
                if self.state != UsbDeviceState::Configured {
                    return Err(Dwc2Error::InvalidState {
                        current: self.state,
                        attempted: "BulkIn",
                    });
                }
                if ep >= MAX_ENDPOINTS {
                    return Err(Dwc2Error::InvalidEndpoint { ep });
                }
                Self::write_tx_fifo(ep, &data, bank);
                Ok(alloc::vec![Dwc2Action::WriteTxFifo { ep, data }])
            }
            GadgetRequest::InterruptIn { ep, data } => {
                // InterruptIn does NOT require Configured state
                if ep >= MAX_ENDPOINTS {
                    return Err(Dwc2Error::InvalidEndpoint { ep });
                }
                Self::write_tx_fifo(ep, &data, bank);
                Ok(alloc::vec![Dwc2Action::WriteTxFifo { ep, data }])
            }
        }
    }

    fn write_ep0_in(bank: &mut impl RegisterBank, data: &[u8]) {
        let len = data.len() as u32;
        // EP0 MPS = 64 bytes. pktcnt = ceil(len / 64), minimum 1 (for ZLP).
        let pkt_cnt = if len == 0 { 1 } else { len.div_ceil(64) };
        let dieptsiz0 = (pkt_cnt << 19) | len;
        bank.write(dieptsiz(0), dieptsiz0);
        // Enable EP0 and clear NAK
        bank.write(diepctl(0), bank.read(diepctl(0)) | EPCTL_EPENA | EPCTL_CNAK);
        // Write data to EP0 FIFO
        Self::write_fifo_words(0, data, bank);
    }

    fn write_tx_fifo(ep: u8, data: &[u8], bank: &mut impl RegisterBank) {
        let len = data.len() as u32;
        // MPS: EP0=64, EP3 interrupt=16, bulk EPs=512.
        let mps: u32 = match ep {
            0 => 64,
            3 => 16,
            _ => 512,
        };
        let mut pkt_cnt = if len == 0 { 1 } else { len.div_ceil(mps) };
        // Only bulk endpoints require a ZLP when the payload is an exact multiple
        // of MPS to signal end-of-transfer. Interrupt and control endpoints send
        // a fixed-size response per polling interval — no ZLP needed.
        let is_bulk = ep != 0 && ep != 3;
        if is_bulk && len > 0 && len % mps == 0 {
            pkt_cnt += 1;
        }
        let dieptsiz_val = (pkt_cnt << 19) | len;
        bank.write(dieptsiz(ep), dieptsiz_val);
        // Enable EP and clear NAK
        bank.write(
            diepctl(ep),
            bank.read(diepctl(ep)) | EPCTL_EPENA | EPCTL_CNAK,
        );
        // Write data to FIFO
        Self::write_fifo_words(ep, data, bank);
    }

    fn write_fifo_words(ep: u8, data: &[u8], bank: &mut impl RegisterBank) {
        let fifo_offset = ep_fifo(ep);
        let mut chunks = data.chunks_exact(4);
        for chunk in chunks.by_ref() {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            bank.write(fifo_offset, word);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut buf = [0u8; 4];
            buf[..rem.len()].copy_from_slice(rem);
            bank.write(fifo_offset, u32::from_le_bytes(buf));
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;

    /// Initialise a controller with a fresh mock bank.
    ///
    /// Pre-configures DCTL read so soft-connect works, then clears writes
    /// after init so each test starts with a clean write log.
    fn init_controller() -> (Dwc2Controller, MockRegisterBank) {
        let mut bank = MockRegisterBank::new();
        // Pre-configure DCTL so soft-connect read returns something non-zero
        // (e.g., SFTDISCON set, as the hardware would have it after reset)
        bank.on_read(DCTL, alloc::vec![DCTL_SFTDISCON]);
        let (ctrl, _actions) = Dwc2Controller::init(&mut bank).expect("init failed");
        // Clear the writes from init so tests start clean
        bank.writes.clear();
        (ctrl, bank)
    }

    #[test]
    fn init_forces_device_mode() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(DCTL, alloc::vec![DCTL_SFTDISCON]);
        let (_ctrl, _actions) = Dwc2Controller::init(&mut bank).expect("init failed");

        // Find the GUSBCFG write and verify force-device bit is set
        let gusbcfg_write = bank.writes.iter().find(|(off, _)| *off == GUSBCFG);
        assert!(gusbcfg_write.is_some(), "GUSBCFG should be written");
        let (_, val) = gusbcfg_write.unwrap();
        assert_ne!(
            val & GUSBCFG_FORCE_DEV,
            0,
            "GUSBCFG_FORCE_DEV bit must be set"
        );
    }

    #[test]
    fn init_configures_fifos() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(DCTL, alloc::vec![DCTL_SFTDISCON]);
        let (_ctrl, _actions) = Dwc2Controller::init(&mut bank).expect("init failed");

        // GRXFSIZ should be written
        let grxfsiz_write = bank.writes.iter().find(|(off, _)| *off == GRXFSIZ);
        assert!(grxfsiz_write.is_some(), "GRXFSIZ should be written");
        let (_, val) = grxfsiz_write.unwrap();
        assert_eq!(*val, RX_FIFO_WORDS, "GRXFSIZ should be RX_FIFO_WORDS");

        // GNPTXFSIZ should be written
        let gnptxfsiz_write = bank.writes.iter().find(|(off, _)| *off == GNPTXFSIZ);
        assert!(gnptxfsiz_write.is_some(), "GNPTXFSIZ should be written");
        let (_, val) = gnptxfsiz_write.unwrap();
        assert_eq!(
            *val,
            gnptxfsiz_value(),
            "GNPTXFSIZ should match gnptxfsiz_value()"
        );
    }

    #[test]
    fn init_soft_connects() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(DCTL, alloc::vec![DCTL_SFTDISCON]);
        let (_ctrl, _actions) = Dwc2Controller::init(&mut bank).expect("init failed");

        // Find the DCTL write and verify SFTDISCON is cleared
        let dctl_write = bank.writes.iter().rev().find(|(off, _)| *off == DCTL);
        assert!(
            dctl_write.is_some(),
            "DCTL should be written for soft-connect"
        );
        let (_, val) = dctl_write.unwrap();
        assert_eq!(
            val & DCTL_SFTDISCON,
            0,
            "SFTDISCON bit must be cleared in DCTL"
        );
    }

    #[test]
    fn bus_reset_returns_to_default() {
        let (mut ctrl, mut bank) = init_controller();
        // Advance to Address state first
        ctrl.state = UsbDeviceState::Address;
        ctrl.address = 5;

        // Pre-configure DCFG read for the reset handler
        bank.on_read(DCFG, alloc::vec![dcfg_dad(5)]);

        let events = ctrl
            .handle_event(Dwc2Event::BusReset, &mut bank)
            .expect("handle_event failed");

        assert_eq!(
            ctrl.state(),
            UsbDeviceState::Default,
            "should return to Default after reset"
        );
        assert_eq!(ctrl.address, 0, "address should be cleared after reset");
        assert!(
            events.contains(&GadgetEvent::Reset),
            "should emit GadgetEvent::Reset"
        );
    }

    #[test]
    fn enumeration_done_sets_speed() {
        let (mut ctrl, mut bank) = init_controller();

        ctrl.handle_event(
            Dwc2Event::EnumerationDone {
                speed: DeviceSpeed::FullSpeed,
            },
            &mut bank,
        )
        .expect("handle_event failed");

        assert_eq!(
            ctrl.speed(),
            DeviceSpeed::FullSpeed,
            "speed should be FullSpeed"
        );
    }

    #[test]
    fn set_address_programs_dcfg() {
        let (mut ctrl, mut bank) = init_controller();

        // SET_ADDRESS(5): bmRequestType=0x00, bRequest=0x05, wValue=5
        let setup: [u8; 8] = [0x00, 0x05, 5, 0, 0, 0, 0, 0];
        bank.on_read(diepctl(0), alloc::vec![0u32]);

        ctrl.handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("handle_event failed");

        // State should be Address, but DCFG not yet written (deferred per USB §9.4.6).
        assert_eq!(ctrl.state(), UsbDeviceState::Address);
        assert!(ctrl.pending_address == Some(5));

        // Simulate EP0 IN transfer complete (status-stage ZLP ACKed by host).
        bank.on_read(DCFG, alloc::vec![0u32]);
        ctrl.handle_event(Dwc2Event::InTransferComplete { ep: 0 }, &mut bank)
            .expect("in_transfer_complete failed");

        // Now DCFG should be written with address 5.
        let dcfg_write = bank
            .writes
            .iter()
            .find(|(off, val)| *off == DCFG && (val & DCFG_DAD_MASK) == dcfg_dad(5));
        assert!(
            dcfg_write.is_some(),
            "DCFG should be written with address 5"
        );
        assert_eq!(ctrl.address, 5);
        assert!(ctrl.pending_address.is_none());
    }

    #[test]
    fn set_configuration_enables_endpoints() {
        let (mut ctrl, mut bank) = init_controller();
        ctrl.state = UsbDeviceState::Address;

        // SET_CONFIGURATION: bmRequestType=0x00, bRequest=0x09, wValue=1
        let setup: [u8; 8] = [0x00, 0x09, 1, 0, 0, 0, 0, 0];

        // Pre-configure diepctl(0) read for the EP0 enable step
        bank.on_read(diepctl(0), alloc::vec![0u32]);

        ctrl.handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("handle_event failed");

        assert_eq!(
            ctrl.state(),
            UsbDeviceState::Configured,
            "state should be Configured"
        );

        // Verify EP1 IN was activated
        let ep1_write = bank
            .writes
            .iter()
            .find(|(off, val)| *off == diepctl(1) && (val & EPCTL_USBAEP) != 0);
        assert!(ep1_write.is_some(), "EP1 IN should be activated");

        // Verify EP2 OUT was activated
        let ep2_write = bank
            .writes
            .iter()
            .find(|(off, val)| *off == doepctl(2) && (val & EPCTL_USBAEP) != 0);
        assert!(ep2_write.is_some(), "EP2 OUT should be activated");

        // Verify EP3 IN was activated
        let ep3_write = bank
            .writes
            .iter()
            .find(|(off, val)| *off == diepctl(3) && (val & EPCTL_USBAEP) != 0);
        assert!(ep3_write.is_some(), "EP3 IN should be activated");
    }

    #[test]
    fn class_request_forwarded_to_gadget() {
        let (mut ctrl, mut bank) = init_controller();

        // Class request: bmRequestType=0x21 (class, interface, host-to-device)
        let setup: [u8; 8] = [0x21, 0x0A, 0, 0, 0, 0, 0, 0];

        let events = ctrl
            .handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("handle_event failed");

        assert!(
            events
                .iter()
                .any(|e| matches!(e, GadgetEvent::SetupClassRequest { .. })),
            "class request should produce GadgetEvent::SetupClassRequest"
        );
    }

    #[test]
    fn unsupported_standard_request_stalls() {
        let (mut ctrl, mut bank) = init_controller();

        // Unknown standard request: bRequest=0xFF
        let setup: [u8; 8] = [0x00, 0xFF, 0, 0, 0, 0, 0, 0];

        // Pre-configure reads for diepctl(0) and doepctl(0)
        bank.on_read(diepctl(0), alloc::vec![0u32]);
        bank.on_read(doepctl(0), alloc::vec![0u32]);

        ctrl.handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("handle_event failed");

        // Verify EP0 IN was stalled
        let ep0_in_stall = bank
            .writes
            .iter()
            .any(|(off, val)| *off == diepctl(0) && (val & EPCTL_STALL) != 0);
        assert!(
            ep0_in_stall,
            "EP0 IN should be stalled for unknown standard request"
        );
    }

    #[test]
    fn get_descriptor_serves_device_desc() {
        let (mut ctrl, mut bank) = init_controller();

        // Pre-register a fake device descriptor (18 bytes).
        let fake_desc: Vec<u8> = (0u8..18).collect();
        ctrl.set_descriptors(fake_desc.clone(), alloc::vec![], alloc::vec![]);

        // GET_DESCRIPTOR(Device, index=0, wLength=18)
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 18, 0x00];
        let events = ctrl
            .handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("setup must succeed");

        // Descriptor served internally — no gadget events.
        assert!(events.is_empty());

        // Verify data was written to EP0 IN FIFO.
        let fifo_writes: Vec<_> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == ep_fifo(0))
            .collect();
        assert!(
            !fifo_writes.is_empty(),
            "Device descriptor must be written to EP0 FIFO"
        );
    }

    #[test]
    fn rx_fifo_bulk_out_produces_gadget_event() {
        let (mut ctrl, mut bank) = init_controller();

        // Step 1: OUT_DATA — accumulates into reassembly buffer.
        let grxstsp_data: u32 = 2 | (4 << 4) | ((PKTSTS_OUT_DATA as u32) << 17);
        bank.on_read(GRXSTSP, alloc::vec![grxstsp_data]);
        bank.on_read(ep_fifo(2), alloc::vec![0xDEADBEEFu32]);

        let events = ctrl
            .handle_event(Dwc2Event::RxFifoNonEmpty, &mut bank)
            .expect("OUT_DATA must succeed");
        assert!(events.is_empty(), "OUT_DATA accumulates, no event yet");

        // Step 2: OUT_COMPLETE — emits the reassembled frame.
        let grxstsp_complete: u32 = 2 | ((PKTSTS_OUT_COMPLETE as u32) << 17);
        bank.on_read(GRXSTSP, alloc::vec![grxstsp_complete]);
        bank.on_read(doepctl(2), alloc::vec![0u32]);

        let events = ctrl
            .handle_event(Dwc2Event::RxFifoNonEmpty, &mut bank)
            .expect("OUT_COMPLETE must succeed");

        assert_eq!(events.len(), 1);
        if let GadgetEvent::BulkOut { ep, data } = &events[0] {
            assert_eq!(*ep, 2);
            assert_eq!(data.len(), 4);
            assert_eq!(&data[..], &0xDEADBEEFu32.to_le_bytes());
        } else {
            panic!("expected BulkOut, got {:?}", events[0]);
        }
    }

    #[test]
    fn submit_bulk_in_before_configured_fails() {
        let (mut ctrl, mut bank) = init_controller();
        // State is Default — not Configured

        let result = ctrl.submit_request(
            GadgetRequest::BulkIn {
                ep: 1,
                data: alloc::vec![0u8; 64],
            },
            &mut bank,
        );

        assert!(result.is_err(), "BulkIn before Configured should fail");
        if let Err(Dwc2Error::InvalidState { current, attempted }) = result {
            assert_eq!(current, UsbDeviceState::Default);
            assert_eq!(attempted, "BulkIn");
        } else {
            panic!("expected InvalidState error");
        }
    }

    #[test]
    fn submit_bulk_in_writes_tx_fifo() {
        let (mut ctrl, mut bank) = init_controller();
        ctrl.state = UsbDeviceState::Configured;

        // Pre-configure diepctl(1) read for the enable step
        bank.on_read(diepctl(1), alloc::vec![0u32]);

        let data = alloc::vec![0xAAu8; 8];
        let actions = ctrl
            .submit_request(
                GadgetRequest::BulkIn {
                    ep: 1,
                    data: data.clone(),
                },
                &mut bank,
            )
            .expect("submit_request failed");

        let fifo_action = actions
            .iter()
            .find(|a| matches!(a, Dwc2Action::WriteTxFifo { ep: 1, .. }));
        assert!(
            fifo_action.is_some(),
            "should return WriteTxFifo action for EP1"
        );

        // Verify data was written to EP1 TX FIFO
        let ep1_fifo_writes: Vec<_> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == ep_fifo(1))
            .collect();
        assert!(
            !ep1_fifo_writes.is_empty(),
            "data should be written to EP1 TX FIFO"
        );
    }

    #[test]
    fn submit_control_stall() {
        let (mut ctrl, mut bank) = init_controller();

        // Pre-configure reads for diepctl(0) and doepctl(0)
        bank.on_read(diepctl(0), alloc::vec![0u32]);
        bank.on_read(doepctl(0), alloc::vec![0u32]);

        let actions = ctrl
            .submit_request(GadgetRequest::ControlStall, &mut bank)
            .expect("submit_request failed");

        // Should return Stall action
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Dwc2Action::Stall { ep: 0 })),
            "ControlStall should return Dwc2Action::Stall for EP0"
        );

        // Verify EP0 IN stall bit was set
        let ep0_in_stall = bank
            .writes
            .iter()
            .any(|(off, val)| *off == diepctl(0) && (val & EPCTL_STALL) != 0);
        assert!(ep0_in_stall, "EP0 IN STALL bit should be set");
    }

    #[test]
    fn suspend_and_resume_events() {
        let (mut ctrl, mut bank) = init_controller();

        let suspend_events = ctrl
            .handle_event(Dwc2Event::Suspend, &mut bank)
            .expect("handle_event Suspend failed");
        assert!(
            suspend_events.contains(&GadgetEvent::Suspended),
            "Suspend event should produce GadgetEvent::Suspended"
        );

        let resume_events = ctrl
            .handle_event(Dwc2Event::Resume, &mut bank)
            .expect("handle_event Resume failed");
        assert!(
            resume_events.contains(&GadgetEvent::Resumed),
            "Resume event should produce GadgetEvent::Resumed"
        );
    }

    #[test]
    fn invalid_endpoint_rejected() {
        let (mut ctrl, mut bank) = init_controller();
        ctrl.state = UsbDeviceState::Configured;

        let result = ctrl.submit_request(
            GadgetRequest::BulkIn {
                ep: 5,
                data: alloc::vec![0u8],
            },
            &mut bank,
        );

        assert!(result.is_err(), "ep=5 should be rejected");
        assert!(
            matches!(result, Err(Dwc2Error::InvalidEndpoint { ep: 5 })),
            "should return InvalidEndpoint error for ep=5"
        );
    }

    #[test]
    fn full_enumeration_flow() {
        use crate::drivers::ecm_gadget::EcmGadget;

        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let mut bank = MockRegisterBank::new();
        bank.on_read(DCTL, alloc::vec![DCTL_SFTDISCON, 0]);

        // 1. Init controller.
        let (mut ctrl, _) = Dwc2Controller::init(&mut bank).unwrap();

        // 2. Create gadget and register descriptors.
        let (mut gadget, dev_desc, cfg_desc, str_descs) = EcmGadget::new(mac);
        ctrl.set_descriptors(dev_desc, cfg_desc, str_descs);

        // 3. Bus reset.
        bank.writes.clear();
        bank.on_read(DCFG, alloc::vec![0]);
        let events = ctrl.handle_event(Dwc2Event::BusReset, &mut bank).unwrap();
        assert_eq!(events, alloc::vec![GadgetEvent::Reset]);
        let reqs = gadget.handle_event(GadgetEvent::Reset);
        assert!(reqs.is_empty()); // No notification — EP3 disabled during reset

        // 4. Enumeration done.
        let events = ctrl
            .handle_event(
                Dwc2Event::EnumerationDone {
                    speed: DeviceSpeed::HighSpeed,
                },
                &mut bank,
            )
            .unwrap();
        assert!(events.is_empty());

        // 5. SET_ADDRESS(7) — deferred until status ZLP ACKed.
        bank.on_read(diepctl(0), alloc::vec![0u32]);
        let setup_addr = [0x00, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00];
        let events = ctrl
            .handle_event(Dwc2Event::SetupReceived { data: setup_addr }, &mut bank)
            .unwrap();
        assert!(events.is_empty());
        assert_eq!(ctrl.state(), UsbDeviceState::Address);

        // 5b. EP0 IN transfer complete — commits the address to DCFG.
        bank.on_read(DCFG, alloc::vec![0]);
        ctrl.handle_event(Dwc2Event::InTransferComplete { ep: 0 }, &mut bank)
            .unwrap();
        assert_eq!(ctrl.address, 7);

        // 6. GET_DESCRIPTOR(Device).
        bank.writes.clear();
        let setup_get_dev = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 18, 0x00];
        let events = ctrl
            .handle_event(
                Dwc2Event::SetupReceived {
                    data: setup_get_dev,
                },
                &mut bank,
            )
            .unwrap();
        assert!(events.is_empty()); // Served internally.
        let fifo_writes: alloc::vec::Vec<_> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == ep_fifo(0))
            .collect();
        assert!(!fifo_writes.is_empty());

        // 7. SET_CONFIGURATION(1).
        bank.writes.clear();
        let setup_set_cfg = [0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let events = ctrl
            .handle_event(
                Dwc2Event::SetupReceived {
                    data: setup_set_cfg,
                },
                &mut bank,
            )
            .unwrap();
        assert_eq!(ctrl.state(), UsbDeviceState::Configured);
        assert!(events.contains(&GadgetEvent::Configured));
        let reqs = gadget.handle_event(GadgetEvent::Configured);
        assert_eq!(reqs.len(), 1); // NETWORK_CONNECTION only (SPEED_CHANGE queued)

        // 7b. Simulate EP3 transfer complete to release intr_in_flight,
        //     then drain the queued SPEED_CHANGE notification.
        gadget.handle_event(GadgetEvent::BulkInComplete { ep: 3 });
        let speed_req = gadget.drain_pending_requests();
        assert!(speed_req.is_some());
        gadget.handle_event(GadgetEvent::BulkInComplete { ep: 3 });

        // 8. Bulk OUT: host sends 60-byte frame (two RxFifoNonEmpty events).
        bank.writes.clear();
        let frame_data: alloc::vec::Vec<u8> = (0u8..60).collect();
        let words = frame_data.len().div_ceil(4);

        // 8a. OUT_DATA — accumulates into reassembly buffer.
        let grxstsp_data: u32 =
            2 | ((frame_data.len() as u32) << 4) | ((PKTSTS_OUT_DATA as u32) << 17);
        bank.on_read(GRXSTSP, alloc::vec![grxstsp_data]);
        let mut fifo_words: alloc::vec::Vec<u32> = alloc::vec::Vec::with_capacity(words);
        for i in 0..words {
            let offset = i * 4;
            let mut word_bytes = [0u8; 4];
            let take = (frame_data.len() - offset).min(4);
            word_bytes[..take].copy_from_slice(&frame_data[offset..offset + take]);
            fifo_words.push(u32::from_le_bytes(word_bytes));
        }
        bank.on_read(ep_fifo(2), fifo_words);
        let events = ctrl
            .handle_event(Dwc2Event::RxFifoNonEmpty, &mut bank)
            .unwrap();
        assert!(events.is_empty()); // Accumulating, no event yet.

        // 8b. OUT_COMPLETE — emits the reassembled frame.
        let grxstsp_complete: u32 = 2 | ((PKTSTS_OUT_COMPLETE as u32) << 17);
        bank.on_read(GRXSTSP, alloc::vec![grxstsp_complete]);
        bank.on_read(doepctl(2), alloc::vec![0u32]);
        let events = ctrl
            .handle_event(Dwc2Event::RxFifoNonEmpty, &mut bank)
            .unwrap();
        assert_eq!(events.len(), 1);
        let gadget_reqs = gadget.handle_event(events.into_iter().next().unwrap());
        assert!(gadget_reqs.is_empty()); // Frame queued internally.

        // 9. poll_rx_frame — retrieve the frame.
        let mut buf = [0u8; 2048];
        let len = gadget.poll_rx_frame(&mut buf).unwrap();
        assert_eq!(len, 60);
        assert_eq!(&buf[..len], &frame_data[..]);

        // 10. queue_tx_frame — send a frame back to host.
        let tx_frame = alloc::vec![0xFF; 100];
        assert!(gadget.queue_tx_frame(&tx_frame));
        let pending = gadget
            .drain_pending_requests()
            .expect("should have one pending request");
        bank.on_read(diepctl(1), alloc::vec![0]);
        let actions = ctrl.submit_request(pending, &mut bank).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Dwc2Action::WriteTxFifo { ep, data } => {
                assert_eq!(*ep, 1);
                assert_eq!(data.as_slice(), &tx_frame[..]);
            }
            other => panic!("expected WriteTxFifo, got {:?}", other),
        }
    }
}
