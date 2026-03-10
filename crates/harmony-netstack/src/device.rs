//! Frame buffer device implementing smoltcp's `Device` trait.
//!
//! [`FrameBuffer`] decouples smoltcp from hardware drivers. The caller pushes
//! raw Ethernet frames in via [`FrameBuffer::ingest`] and pulls transmitted
//! frames out via [`FrameBuffer::drain_tx`]. smoltcp accesses the buffer
//! through the [`Device`](smoltcp::phy::Device) trait during
//! `Interface::poll()`.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// A frame buffer that bridges raw Ethernet frames between a hardware driver
/// and smoltcp's IP stack.
///
/// Inbound frames are queued via [`ingest`](Self::ingest) and consumed by
/// smoltcp through the [`Device`] trait. Outbound frames produced by smoltcp
/// are collected via [`drain_tx`](Self::drain_tx).
pub struct FrameBuffer {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl FrameBuffer {
    /// Creates a new, empty frame buffer.
    pub fn new() -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        }
    }

    /// Pushes a raw Ethernet frame into the receive queue.
    ///
    /// The frame will be returned to smoltcp on the next call to
    /// [`Device::receive`].
    pub fn ingest(&mut self, frame: Vec<u8>) {
        self.rx_queue.push_back(frame);
    }

    /// Drains all transmitted frames from the transmit queue.
    ///
    /// Returns an iterator over frames that smoltcp has sent (e.g. ARP
    /// replies, UDP datagrams). The caller is responsible for delivering
    /// these to the network hardware.
    pub fn drain_tx(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.tx_queue.drain(..)
    }
}

impl Default for FrameBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Receive token that owns a single inbound frame.
pub struct FrameBufRxToken(Vec<u8>);

impl phy::RxToken for FrameBufRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

/// Transmit token that borrows the transmit queue to enqueue one outbound
/// frame.
pub struct FrameBufTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl<'a> phy::TxToken for FrameBufTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}

impl Device for FrameBuffer {
    type RxToken<'a> = FrameBufRxToken;
    type TxToken<'a> = FrameBufTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Use struct destructuring to split borrows on rx_queue and tx_queue,
        // allowing smoltcp to send inline replies (e.g. ARP) while receiving.
        let FrameBuffer { rx_queue, tx_queue } = self;

        let frame = rx_queue.pop_front()?;
        Some((FrameBufRxToken(frame), FrameBufTxToken(tx_queue)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(FrameBufTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(1);
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::{RxToken, TxToken};

    #[test]
    fn ingest_and_receive() {
        let mut dev = FrameBuffer::new();
        assert!(dev.receive(Instant::ZERO).is_none());
        dev.ingest(vec![1, 2, 3]);
        let (rx, _tx) = dev.receive(Instant::ZERO).unwrap();
        let data = rx.consume(|buf| buf.to_vec());
        assert_eq!(data, vec![1, 2, 3]);
        assert!(dev.receive(Instant::ZERO).is_none());
    }

    #[test]
    fn transmit_and_drain() {
        let mut dev = FrameBuffer::new();
        let tx = dev.transmit(Instant::ZERO).unwrap();
        tx.consume(5, |buf| {
            buf.copy_from_slice(&[10, 20, 30, 40, 50]);
        });
        let frames: Vec<_> = dev.drain_tx().collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], vec![10, 20, 30, 40, 50]);
        assert_eq!(dev.drain_tx().count(), 0);
    }

    #[test]
    fn capabilities_are_ethernet() {
        let dev = FrameBuffer::new();
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ethernet);
        assert_eq!(caps.max_transmission_unit, 1514);
    }
}
