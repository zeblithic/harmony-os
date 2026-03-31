// SPDX-License-Identifier: GPL-2.0-or-later
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant;
use smoltcp::wire::{IpCidr, Ipv4Address, Ipv4Cidr};

/// Manages smoltcp's built-in DHCPv4 socket and reacts to lease events.
///
/// After every `Interface::poll()`, call [`DhcpClient::check_lease()`] to
/// process DHCP events and apply any resulting IP configuration changes to
/// the interface.  If no lease is acquired within `fallback_timeout_ms`
/// milliseconds the client applies the provided static fallback address
/// instead, allowing the node to operate even when no DHCP server is
/// reachable.
pub struct DhcpClient {
    /// Handle into the `SocketSet` for the underlying DHCPv4 socket.
    pub handle: SocketHandle,
    /// Static IP to apply when the DHCP timeout elapses without a lease.
    pub fallback_ip: Option<Ipv4Cidr>,
    /// Default gateway to configure alongside the fallback IP.
    pub fallback_gateway: Option<Ipv4Address>,
    /// How long (ms) to wait for a DHCP lease before falling back.
    pub fallback_timeout_ms: i64,
    /// Timestamp (ms) when DHCP acquisition started.
    pub start_time_ms: i64,
    /// Whether a DHCP lease is currently active.
    pub configured: bool,
    /// Whether the static fallback address has been applied.
    pub fallback_applied: bool,
}

impl DhcpClient {
    /// Create a new `DhcpClient`, registering a [`dhcpv4::Socket`] in `sockets`.
    ///
    /// # Parameters
    /// - `sockets` — the shared socket set; the DHCPv4 socket is added here.
    /// - `fallback_ip` — optional static CIDR to use when DHCP times out.
    /// - `fallback_gateway` — optional default gateway for the fallback path.
    /// - `fallback_timeout_ms` — milliseconds to wait before applying fallback.
    /// - `now` — current time used to record the acquisition start timestamp.
    pub fn new(
        sockets: &mut SocketSet<'static>,
        fallback_ip: Option<Ipv4Cidr>,
        fallback_gateway: Option<Ipv4Address>,
        fallback_timeout_ms: i64,
        now: Instant,
    ) -> Self {
        let dhcp_socket = dhcpv4::Socket::new();
        let handle = sockets.add(dhcp_socket);
        Self {
            handle,
            fallback_ip,
            fallback_gateway,
            fallback_timeout_ms,
            start_time_ms: now.total_millis(),
            configured: false,
            fallback_applied: false,
        }
    }

    /// Poll the DHCPv4 socket and react to lease events.
    ///
    /// Must be called after every `Interface::poll()`.  Returns `true` when
    /// the interface IP configuration was changed (lease acquired/lost or
    /// fallback applied), `false` when nothing changed.
    pub fn check_lease(
        &mut self,
        iface: &mut Interface,
        sockets: &mut SocketSet<'static>,
        now: Instant,
    ) -> bool {
        let event = sockets.get_mut::<dhcpv4::Socket>(self.handle).poll();
        match event {
            Some(dhcpv4::Event::Configured(config)) => {
                apply_ip(iface, config.address);
                if let Some(gw) = config.router {
                    iface.routes_mut().add_default_ipv4_route(gw).unwrap();
                } else {
                    iface.routes_mut().remove_default_ipv4_route();
                }
                self.configured = true;
                true
            }
            Some(dhcpv4::Event::Deconfigured) => {
                apply_ip(iface, Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
                iface.routes_mut().remove_default_ipv4_route();
                self.configured = false;
                true
            }
            None => {
                if !self.configured && !self.fallback_applied {
                    let elapsed = now.total_millis() - self.start_time_ms;
                    if elapsed >= self.fallback_timeout_ms {
                        self.apply_fallback(iface);
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Returns `true` when an IP address is active — either via DHCP lease or
    /// the static fallback.
    pub fn is_configured(&self) -> bool {
        self.configured || self.fallback_applied
    }

    /// Apply the static fallback IP and gateway to `iface`.
    fn apply_fallback(&mut self, iface: &mut Interface) {
        if let Some(cidr) = self.fallback_ip {
            apply_ip(iface, cidr);
        }
        match self.fallback_gateway {
            Some(gw) => {
                iface.routes_mut().add_default_ipv4_route(gw).unwrap();
            }
            None => {
                iface.routes_mut().remove_default_ipv4_route();
            }
        }
        self.fallback_applied = true;
    }
}

/// Update the first (or only) IPv4 address on the interface in-place.
///
/// Mirrors the pattern used in smoltcp's own `dhcp_client` example.
fn apply_ip(iface: &mut Interface, cidr: Ipv4Cidr) {
    iface.update_ip_addrs(|addrs| {
        if let Some(addr) = addrs.iter_mut().next() {
            *addr = IpCidr::Ipv4(cidr);
        } else {
            // No existing address slot — push a new one.
            addrs.push(IpCidr::Ipv4(cidr)).ok();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::SocketStorage;

    #[test]
    fn fallback_not_applied_before_timeout() {
        let storage = [
            SocketStorage::EMPTY,
            SocketStorage::EMPTY,
            SocketStorage::EMPTY,
            SocketStorage::EMPTY,
        ];
        let mut sockets = SocketSet::new(storage);
        let now = Instant::from_millis(0);
        let client = DhcpClient::new(
            &mut sockets,
            Some(Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24)),
            Some(Ipv4Address::new(10, 0, 0, 1)),
            5000,
            now,
        );
        assert!(!client.is_configured());
        assert!(!client.fallback_applied);
    }
}
