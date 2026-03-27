// SPDX-License-Identifier: GPL-2.0-or-later

//! Network device abstraction for 9P network servers.

/// A network device that produces and consumes raw Ethernet frames.
pub trait NetworkDevice {
    /// Extract the next transmitted frame from the device.
    /// Writes the frame into `out` and returns the byte count,
    /// or None if no packet is pending.
    fn poll_tx(&mut self, out: &mut [u8]) -> Option<usize>;

    /// Inject a received frame into the device.
    /// Returns true if accepted, false if the device's RX buffer is full.
    fn push_rx(&mut self, frame: &[u8]) -> bool;

    /// The device's MAC address.
    fn mac(&self) -> [u8; 6];

    /// Whether the link is currently up.
    fn link_up(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_is_object_safe() {
        fn _accepts_dyn(_dev: &dyn NetworkDevice) {}
    }
}
