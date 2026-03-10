// SPDX-License-Identifier: GPL-2.0-or-later
use smoltcp::time::Instant;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};

use crate::config::HARMONY_UDP_PORT;
use crate::stack::NetStack;

/// Fluent builder for [`NetStack`] configuration.
///
/// Requires at minimum a static IPv4 address via [`static_ip`](Self::static_ip).
/// All other fields have sensible defaults (locally-administered MAC,
/// port 4242, broadcast disabled, no explicit peers).
pub struct NetStackBuilder {
    mac: [u8; 6],
    ip: Option<Ipv4Cidr>,
    gateway: Option<Ipv4Address>,
    port: u16,
    broadcast: bool,
    peers: alloc::vec::Vec<(Ipv4Address, u16)>,
}

impl NetStackBuilder {
    pub fn new() -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x00],
            ip: None,
            gateway: None,
            port: HARMONY_UDP_PORT,
            broadcast: false,
            peers: alloc::vec::Vec::new(),
        }
    }

    pub fn mac(mut self, mac: [u8; 6]) -> Self {
        self.mac = mac;
        self
    }

    pub fn static_ip(mut self, cidr: Ipv4Cidr) -> Self {
        self.ip = Some(cidr);
        self
    }

    pub fn gateway(mut self, gw: Ipv4Address) -> Self {
        self.gateway = Some(gw);
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn enable_broadcast(mut self, enabled: bool) -> Self {
        self.broadcast = enabled;
        self
    }

    pub fn add_peer(mut self, addr: Ipv4Address, port: u16) -> Self {
        self.peers.push((addr, port));
        self
    }

    pub fn build(self, now: Instant) -> NetStack {
        let ip = self.ip.expect("static_ip is required");
        NetStack::new(
            self.mac,
            ip,
            self.gateway,
            self.port,
            self.broadcast,
            &self.peers,
            now,
        )
    }
}

impl Default for NetStackBuilder {
    fn default() -> Self {
        Self::new()
    }
}
