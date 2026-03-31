// SPDX-License-Identifier: GPL-2.0-or-later
//! Handle-based TCP API for the Linuxulator.

use smoltcp::wire::Ipv4Address;

/// Opaque handle to a TCP socket managed by NetStack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpHandle(pub u32);

/// Simplified TCP socket state for epoll readiness checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSocketState {
    Closed,
    Listen,
    Connecting,
    Established,
    CloseWait,
    Closing,
}

/// Errors from TCP operations, mapped to Linux errno by the Linuxulator.
#[derive(Debug)]
pub enum NetError {
    WouldBlock,
    ConnectionRefused,
    ConnectionReset,
    NotConnected,
    AddrInUse,
    InvalidHandle,
    SocketLimit,
}

/// Abstract TCP socket operations.
pub trait TcpProvider {
    fn tcp_create(&mut self) -> Result<TcpHandle, NetError>;
    fn tcp_bind(&mut self, handle: TcpHandle, port: u16) -> Result<(), NetError>;
    fn tcp_listen(&mut self, handle: TcpHandle, backlog: usize) -> Result<(), NetError>;
    fn tcp_accept(&mut self, handle: TcpHandle) -> Result<Option<TcpHandle>, NetError>;
    fn tcp_connect(
        &mut self,
        handle: TcpHandle,
        addr: Ipv4Address,
        port: u16,
    ) -> Result<(), NetError>;
    fn tcp_send(&mut self, handle: TcpHandle, data: &[u8]) -> Result<usize, NetError>;
    fn tcp_recv(&mut self, handle: TcpHandle, buf: &mut [u8]) -> Result<usize, NetError>;
    fn tcp_close(&mut self, handle: TcpHandle) -> Result<(), NetError>;
    fn tcp_state(&self, handle: TcpHandle) -> TcpSocketState;
    fn tcp_can_recv(&self, handle: TcpHandle) -> bool;
    fn tcp_can_send(&self, handle: TcpHandle) -> bool;
    /// Drive the underlying network stack. Must be called periodically.
    fn tcp_poll(&mut self, now_ms: i64);
}
