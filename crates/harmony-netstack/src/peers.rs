// SPDX-License-Identifier: GPL-2.0-or-later
use alloc::vec::Vec;
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};

/// Manages outbound UDP destinations for Harmony mesh traffic.
///
/// When the netstack sends a Harmony packet, it goes to every entry in the
/// peer table (unicast) plus optionally to the broadcast address for LAN
/// discovery.
pub struct PeerTable {
    peers: Vec<PeerEntry>,
    broadcast: bool,
    port: u16,
}

struct PeerEntry {
    endpoint: IpEndpoint,
}

impl PeerTable {
    /// Create a new peer table.
    ///
    /// - `port`: the default Harmony UDP port (used for broadcast destination).
    /// - `broadcast`: whether to include `255.255.255.255` in destinations.
    pub fn new(port: u16, broadcast: bool) -> Self {
        Self {
            peers: Vec::new(),
            broadcast,
            port,
        }
    }

    /// Add an explicit peer (WAN bootstrap or known node).
    pub fn add_peer(&mut self, addr: Ipv4Address, port: u16) {
        self.peers.push(PeerEntry {
            endpoint: IpEndpoint::new(IpAddress::Ipv4(addr), port),
        });
    }

    /// Iterate over all destinations: broadcast (if enabled) then explicit peers.
    pub fn destinations(&self) -> impl Iterator<Item = IpEndpoint> + '_ {
        let broadcast_iter = self
            .broadcast
            .then(|| IpEndpoint::new(IpAddress::v4(255, 255, 255, 255), self.port));
        broadcast_iter
            .into_iter()
            .chain(self.peers.iter().map(|p| p.endpoint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HARMONY_UDP_PORT;

    #[test]
    fn empty_peer_table_no_broadcast() {
        let table = PeerTable::new(HARMONY_UDP_PORT, false);
        let dests: Vec<_> = table.destinations().collect();
        assert!(dests.is_empty());
    }

    #[test]
    fn broadcast_only() {
        let table = PeerTable::new(HARMONY_UDP_PORT, true);
        let dests: Vec<_> = table.destinations().collect();
        assert_eq!(dests.len(), 1);
        assert_eq!(
            dests[0],
            IpEndpoint::new(IpAddress::v4(255, 255, 255, 255), HARMONY_UDP_PORT)
        );
    }

    #[test]
    fn explicit_peers_plus_broadcast() {
        let mut table = PeerTable::new(HARMONY_UDP_PORT, true);
        table.add_peer(Ipv4Address::new(10, 0, 2, 20), 4242);
        table.add_peer(Ipv4Address::new(192, 168, 1, 100), 4242);
        let dests: Vec<_> = table.destinations().collect();
        assert_eq!(dests.len(), 3);
    }

    #[test]
    fn explicit_peers_no_broadcast() {
        let mut table = PeerTable::new(HARMONY_UDP_PORT, false);
        table.add_peer(Ipv4Address::new(10, 0, 2, 20), 4242);
        let dests: Vec<_> = table.destinations().collect();
        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0], IpEndpoint::new(IpAddress::v4(10, 0, 2, 20), 4242));
    }
}
