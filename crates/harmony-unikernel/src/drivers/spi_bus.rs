// SPDX-License-Identifier: GPL-2.0-or-later

//! SPI bus abstraction for sans-I/O drivers.

/// Abstraction over an SPI bus.
///
/// Implementations provide full-duplex transfers and chip-select
/// control. The real implementation drives RP1 SPI hardware; the
/// mock records all transactions for testing.
pub trait SpiBus {
    /// Full-duplex SPI transfer: simultaneously send `tx` and
    /// receive into `rx`. Both slices must have the same length.
    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]);
    /// Assert chip select (drive CS# low).
    fn assert_cs(&mut self);
    /// Deassert chip select (drive CS# high).
    fn deassert_cs(&mut self);
}

#[cfg(any(test, feature = "test-utils"))]
pub mod mock {
    use super::SpiBus;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    /// Mock SPI bus that plays back pre-configured responses keyed by
    /// TPM register address (parsed from the 4-byte SPI PTP header).
    ///
    /// Two response modes:
    /// - **Register mode** (`on_register`): Each CS cycle gets the next
    ///   queued response. Used for TPM_ACCESS, TPM_STS, TPM_DID_VID.
    /// - **FIFO mode** (`on_fifo`): A single long response is consumed
    ///   across multiple CS cycles. Used for TPM_DATA_FIFO where the
    ///   command engine reads the header (6 bytes) and payload in
    ///   separate read_register calls.
    pub struct MockSpiBus {
        /// Register responses: each CS cycle pops the next entry.
        responses: BTreeMap<u32, Vec<Vec<u8>>>,
        response_cursors: BTreeMap<u32, usize>,
        /// FIFO responses: consumed across CS cycles, byte offset persists.
        fifo_responses: BTreeMap<u32, Vec<u8>>,
        fifo_offsets: BTreeMap<u32, usize>,
        /// Number of 0x00 wait-state bytes before ACK per register.
        wait_states: BTreeMap<u32, usize>,
        /// Current transaction state (within one CS cycle).
        header_buf: Vec<u8>,
        current_addr: Option<u32>,
        wait_states_remaining: usize,
        ack_sent: bool,
        payload_cursor: usize,
        cs_active: bool,
        /// Recorded transactions: (addr, is_read, payload_bytes).
        pub transactions: Vec<(u32, bool, Vec<u8>)>,
    }

    impl Default for MockSpiBus {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockSpiBus {
        pub fn new() -> Self {
            Self {
                responses: BTreeMap::new(),
                response_cursors: BTreeMap::new(),
                fifo_responses: BTreeMap::new(),
                fifo_offsets: BTreeMap::new(),
                wait_states: BTreeMap::new(),
                header_buf: Vec::new(),
                current_addr: None,
                wait_states_remaining: 0,
                ack_sent: false,
                payload_cursor: 0,
                cs_active: false,
                transactions: Vec::new(),
            }
        }

        /// Queue a response for a normal register (one per CS cycle).
        pub fn on_register(&mut self, addr: u32, response: Vec<u8>) {
            self.responses.entry(addr).or_default().push(response);
            self.response_cursors.entry(addr).or_insert(0);
        }

        /// Append data to a FIFO response consumed across multiple CS
        /// cycles. Byte offset persists between reads. Call multiple
        /// times to queue responses for sequential commands that all
        /// read from the same FIFO address.
        pub fn on_fifo(&mut self, addr: u32, mut response: Vec<u8>) {
            self.fifo_responses
                .entry(addr)
                .or_default()
                .append(&mut response);
            self.fifo_offsets.entry(addr).or_insert(0);
        }

        /// Set wait-state count for `addr` (default 0).
        pub fn set_wait_states(&mut self, addr: u32, count: usize) {
            self.wait_states.insert(addr, count);
        }

        /// Get the next response byte for the current address.
        fn next_response_byte(&mut self) -> u8 {
            let addr = match self.current_addr {
                Some(a) => a,
                None => return 0,
            };

            // Check FIFO mode first
            if let Some(fifo) = self.fifo_responses.get(&addr) {
                let offset = self.fifo_offsets.get(&addr).copied().unwrap_or(0);
                let byte = if offset < fifo.len() { fifo[offset] } else { 0 };
                self.fifo_offsets.insert(addr, offset + 1);
                return byte;
            }

            // Register mode: use payload_cursor within this CS cycle
            let cursor = self.response_cursors.get(&addr).copied().unwrap_or(0);
            if let Some(responses) = self.responses.get(&addr) {
                let idx = cursor.min(responses.len().saturating_sub(1));
                let resp = &responses[idx];
                let byte = if self.payload_cursor < resp.len() {
                    resp[self.payload_cursor]
                } else {
                    0
                };
                self.payload_cursor += 1;
                return byte;
            }
            0
        }
    }

    impl SpiBus for MockSpiBus {
        fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) {
            for i in 0..tx.len().min(rx.len()) {
                if self.current_addr.is_none() {
                    // Collecting 4-byte header
                    self.header_buf.push(tx[i]);
                    rx[i] = 0xFF;
                    if self.header_buf.len() == 4 {
                        let addr = ((self.header_buf[1] as u32) << 16)
                            | ((self.header_buf[2] as u32) << 8)
                            | (self.header_buf[3] as u32);
                        let is_read = (self.header_buf[0] & 0x80) != 0;
                        self.current_addr = Some(addr);
                        self.wait_states_remaining =
                            self.wait_states.get(&addr).copied().unwrap_or(0);
                        self.ack_sent = false;
                        self.payload_cursor = 0;
                        self.transactions.push((addr, is_read, Vec::new()));
                    }
                } else if !self.ack_sent {
                    if self.wait_states_remaining > 0 {
                        rx[i] = 0x00;
                        self.wait_states_remaining -= 1;
                    } else {
                        rx[i] = 0x01;
                        self.ack_sent = true;
                    }
                } else {
                    rx[i] = self.next_response_byte();
                    if let Some(last) = self.transactions.last_mut() {
                        last.2.push(tx[i]);
                    }
                }
            }
        }

        fn assert_cs(&mut self) {
            self.cs_active = true;
            self.header_buf.clear();
            self.current_addr = None;
            self.ack_sent = false;
            self.payload_cursor = 0;
            // Note: fifo_offsets NOT reset — persists across CS cycles
        }

        fn deassert_cs(&mut self) {
            // Advance register response cursor (not FIFO)
            if let Some(addr) = self.current_addr.take() {
                if self.fifo_responses.contains_key(&addr) {
                    // FIFO: offset persists, don't advance cursor
                } else if let Some(cursor) = self.response_cursors.get_mut(&addr) {
                    let max = self.responses.get(&addr).map(|r| r.len()).unwrap_or(0);
                    if *cursor < max.saturating_sub(1) {
                        *cursor += 1;
                    }
                }
            }
            self.cs_active = false;
            self.header_buf.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockSpiBus;
    use super::SpiBus;
    use alloc::vec;

    #[test]
    fn mock_plays_back_register_response() {
        let mut bus = MockSpiBus::new();
        bus.on_register(0xD40F00, vec![0x15, 0xD1, 0x00, 0x1A]); // fake DID_VID

        bus.assert_cs();
        // Send read header: direction=read(0x80)|size=3, addr=0xD40F00
        let tx_header = [0x80 | 3, 0xD4, 0x0F, 0x00];
        let mut rx = [0u8; 4];
        bus.transfer(&tx_header, &mut rx);

        // Wait-state ACK (0 wait states configured = immediate ACK)
        let mut ack = [0u8; 1];
        bus.transfer(&[0x00], &mut ack);
        assert_eq!(ack[0], 0x01, "immediate ACK");

        // Read 4 payload bytes
        let mut payload = [0u8; 4];
        bus.transfer(&[0x00; 4], &mut payload);
        assert_eq!(payload, [0x15, 0xD1, 0x00, 0x1A]);

        bus.deassert_cs();
    }

    #[test]
    fn mock_simulates_wait_states() {
        let mut bus = MockSpiBus::new();
        bus.on_register(0xD40018, vec![0x42]);
        bus.set_wait_states(0xD40018, 3);

        bus.assert_cs();
        let tx_header = [0x80, 0xD4, 0x00, 0x18]; // read 1 byte from STS
        let mut rx = [0u8; 4];
        bus.transfer(&tx_header, &mut rx);

        // 3 wait states then ACK
        for _ in 0..3 {
            let mut ws = [0u8; 1];
            bus.transfer(&[0x00], &mut ws);
            assert_eq!(ws[0], 0x00, "wait state");
        }
        let mut ack = [0u8; 1];
        bus.transfer(&[0x00], &mut ack);
        assert_eq!(ack[0], 0x01, "ACK after wait states");

        let mut payload = [0u8; 1];
        bus.transfer(&[0x00], &mut payload);
        assert_eq!(payload[0], 0x42);

        bus.deassert_cs();
    }

    #[test]
    fn mock_records_write_transactions() {
        let mut bus = MockSpiBus::new();

        bus.assert_cs();
        // Write header: direction=write(0x00)|size=1, addr=0xD40018
        let tx_header = [1u8, 0xD4, 0x00, 0x18];
        let mut rx = [0u8; 4];
        bus.transfer(&tx_header, &mut rx);

        // ACK
        let mut ack = [0u8; 1];
        bus.transfer(&[0x00], &mut ack);

        // Write payload byte
        let mut rx_payload = [0u8; 1];
        bus.transfer(&[0x40], &mut rx_payload); // commandReady = bit 6

        bus.deassert_cs();

        assert_eq!(bus.transactions.len(), 1);
        assert_eq!(bus.transactions[0].0, 0xD40018); // addr
        assert!(!bus.transactions[0].1); // is_read = false
        assert_eq!(bus.transactions[0].2, vec![0x40]); // payload written
    }
}
