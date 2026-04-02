// SPDX-License-Identifier: GPL-2.0-or-later
//! Handle-based UDP API for the Linuxulator.

use smoltcp::wire::Ipv4Address;

use crate::tcp::NetError;

/// Opaque handle to a UDP socket managed by NetStack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpHandle(pub u32);

/// Abstract UDP socket operations.
pub trait UdpProvider {
    fn udp_create(&mut self) -> Result<UdpHandle, NetError>;
    fn udp_bind(&mut self, handle: UdpHandle, port: u16) -> Result<(), NetError>;
    fn udp_close(&mut self, handle: UdpHandle) -> Result<(), NetError>;
    fn udp_can_recv(&self, handle: UdpHandle) -> bool;
    fn udp_can_send(&self, handle: UdpHandle) -> bool;

    /// Send data to a specific remote address (unconnected mode).
    fn udp_sendto(
        &mut self,
        handle: UdpHandle,
        data: &[u8],
        addr: Ipv4Address,
        port: u16,
    ) -> Result<usize, NetError>;

    /// Receive data and source address (unconnected mode).
    fn udp_recvfrom(
        &mut self,
        handle: UdpHandle,
        buf: &mut [u8],
    ) -> Result<(usize, Ipv4Address, u16), NetError>;

    /// Store a remote endpoint for connected-mode send/recv.
    fn udp_connect(
        &mut self,
        handle: UdpHandle,
        addr: Ipv4Address,
        port: u16,
    ) -> Result<(), NetError>;

    /// Send data using the stored connected endpoint.
    /// Returns `NetError::NotConnected` if no prior `udp_connect`.
    fn udp_send(&mut self, handle: UdpHandle, data: &[u8]) -> Result<usize, NetError>;

    /// Receive data, filtering to only the connected peer.
    /// Non-matching packets are silently dropped.
    /// Returns `NetError::NotConnected` if no prior `udp_connect`.
    fn udp_recv(
        &mut self,
        handle: UdpHandle,
        buf: &mut [u8],
    ) -> Result<(usize, Ipv4Address, u16), NetError>;

    /// Drive the underlying network stack. No-op for `NetStack` (shared with TCP poll).
    fn udp_poll(&mut self, now_ms: i64);
}
