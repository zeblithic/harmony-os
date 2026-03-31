// SPDX-License-Identifier: GPL-2.0-or-later
use smoltcp::time::Instant;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};

use crate::config::HARMONY_UDP_PORT;
use crate::stack::{DhcpConfig, NetStack};

/// Fluent builder for [`NetStack`] configuration.
///
/// Requires at minimum either a static IPv4 address via
/// [`static_ip`](Self::static_ip) or DHCP via [`dhcp`](Self::dhcp).
/// All other fields have sensible defaults (locally-administered MAC,
/// port 4242, broadcast disabled, no explicit peers).
pub struct NetStackBuilder {
    mac: [u8; 6],
    ip: Option<Ipv4Cidr>,
    gateway: Option<Ipv4Address>,
    port: u16,
    broadcast: bool,
    peers: alloc::vec::Vec<(Ipv4Address, u16)>,
    // DHCP
    dhcp: bool,
    fallback_ip: Option<Ipv4Cidr>,
    fallback_gateway: Option<Ipv4Address>,
    fallback_timeout_ms: i64,
    // TCP
    tcp_max_sockets: usize,
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
            dhcp: false,
            fallback_ip: None,
            fallback_gateway: None,
            fallback_timeout_ms: 5000,
            tcp_max_sockets: 0,
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

    /// Enable or disable DHCP-based address acquisition.
    ///
    /// When enabled, the stack does not apply a static IP at construction time.
    /// If no lease is received within the fallback timeout the stack applies
    /// the `fallback_ip` (if set) instead.
    pub fn dhcp(mut self, enabled: bool) -> Self {
        self.dhcp = enabled;
        self
    }

    /// Static CIDR to apply when DHCP times out.
    ///
    /// Also used as `fallback_ip` in the [`DhcpConfig`] when DHCP is enabled.
    pub fn fallback_ip(mut self, cidr: Ipv4Cidr) -> Self {
        self.fallback_ip = Some(cidr);
        self
    }

    /// Default gateway to configure alongside the DHCP fallback address.
    pub fn fallback_gateway(mut self, gw: Ipv4Address) -> Self {
        self.fallback_gateway = Some(gw);
        self
    }

    /// How long (ms) to wait for a DHCP lease before applying the fallback IP.
    ///
    /// Defaults to 5000 ms.
    pub fn fallback_timeout_ms(mut self, ms: i64) -> Self {
        self.fallback_timeout_ms = ms;
        self
    }

    /// Maximum number of concurrent TCP sockets.
    ///
    /// Defaults to 0 (no TCP support). Set this to enable the [`TcpProvider`]
    /// trait implementation on [`NetStack`].
    ///
    /// [`TcpProvider`]: crate::tcp::TcpProvider
    pub fn tcp_max_sockets(mut self, max: usize) -> Self {
        self.tcp_max_sockets = max;
        self
    }

    pub fn build(self, now: Instant) -> NetStack {
        let dhcp_config = if self.dhcp {
            Some(DhcpConfig {
                // Prefer explicit fallback_ip; fall back to the static IP if provided.
                fallback_ip: self.fallback_ip.or(self.ip),
                fallback_gateway: self.fallback_gateway.or(self.gateway),
                fallback_timeout_ms: self.fallback_timeout_ms,
            })
        } else {
            None
        };

        // When DHCP is active, no static IP is pre-configured on the interface.
        let ip = if self.dhcp {
            None
        } else {
            Some(
                self.ip
                    .expect("static_ip is required when dhcp is disabled"),
            )
        };

        NetStack::new(
            self.mac,
            ip,
            self.gateway,
            self.port,
            self.broadcast,
            &self.peers,
            self.tcp_max_sockets,
            dhcp_config,
            now,
        )
    }
}

impl Default for NetStackBuilder {
    fn default() -> Self {
        Self::new()
    }
}
