// SPDX-License-Identifier: GPL-2.0-or-later

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_identity::PrivateIdentity;
use harmony_platform::{EntropySource, PersistentState};
use harmony_reticulum::destination::DestinationName;
use harmony_reticulum::interface::InterfaceMode;
use harmony_reticulum::path_table::DestinationHash;
use harmony_reticulum::{Node, NodeAction, NodeEvent};

/// Runtime-level output actions. The caller dispatches these — no
/// protocol-internal actions like AnnounceNeeded leak through.
#[derive(Debug)]
pub enum RuntimeAction {
    /// Send raw bytes on a named interface.
    SendOnInterface { interface_name: Arc<str>, raw: Vec<u8> },
    /// A new peer was discovered via announce.
    PeerDiscovered { address_hash: [u8; 16], hops: u8 },
    /// A previously known peer has gone silent.
    PeerLost { address_hash: [u8; 16] },
    /// A heartbeat was received from a peer.
    HeartbeatReceived { address_hash: [u8; 16], uptime_ms: u64 },
    /// A non-heartbeat packet was delivered locally.
    DeliverLocally { destination_hash: [u8; 16], payload: Vec<u8> },
}

/// Tracked state for a discovered peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address_hash: [u8; 16],
    pub last_seen_ms: u64,
    pub hops: u8,
    pub discovered_at_ms: u64,
}

pub struct UnikernelRuntime<E: EntropySource, P: PersistentState> {
    node: Node,
    identity: PrivateIdentity,
    entropy: E,
    persistence: P,
    tick_count: u64,
    // Announcing
    dest_name: Option<DestinationName>,
    dest_hash: Option<DestinationHash>,
    // Peer tracking
    peers: BTreeMap<[u8; 16], PeerInfo>,
    heartbeat_interval_ms: u64,
    peer_timeout_ms: u64,
    last_heartbeat_ms: u64,
    boot_time_ms: u64,
}

impl<E: EntropySource, P: PersistentState> UnikernelRuntime<E, P> {
    pub fn new(identity: PrivateIdentity, entropy: E, persistence: P) -> Self {
        let node = Node::new();
        UnikernelRuntime {
            node,
            identity,
            entropy,
            persistence,
            tick_count: 0,
            dest_name: None,
            dest_hash: None,
            peers: BTreeMap::new(),
            heartbeat_interval_ms: 5_000,
            peer_timeout_ms: 15_000,
            last_heartbeat_ms: 0,
            boot_time_ms: 0,
        }
    }

    pub fn tick(&mut self, now: u64) -> Vec<NodeAction> {
        self.tick_count += 1;
        self.node.handle_event(NodeEvent::TimerTick { now })
    }

    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    pub fn identity(&self) -> &PrivateIdentity {
        &self.identity
    }

    pub fn entropy(&mut self) -> &mut E {
        &mut self.entropy
    }

    pub fn persistence(&mut self) -> &mut P {
        &mut self.persistence
    }

    /// Number of currently tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Register a network interface with the node's routing table.
    pub fn register_interface(&mut self, name: &str) {
        self.node
            .register_interface(String::from(name), InterfaceMode::Full, None);
    }

    /// Feed an inbound packet from a network interface into the node.
    pub fn handle_packet(
        &mut self,
        interface_name: &str,
        data: Vec<u8>,
        now: u64,
    ) -> Vec<NodeAction> {
        self.node.handle_event(NodeEvent::InboundPacket {
            interface_name: String::from(interface_name),
            raw: data,
            now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::entropy::KernelEntropy;
    use crate::platform::persistence::MemoryState;

    fn test_entropy() -> KernelEntropy<impl FnMut(&mut [u8])> {
        let mut counter: u8 = 42;
        KernelEntropy::new(move |buf: &mut [u8]| {
            for byte in buf.iter_mut() {
                *byte = counter;
                counter = counter.wrapping_add(7);
            }
        })
    }

    fn make_runtime() -> UnikernelRuntime<KernelEntropy<impl FnMut(&mut [u8])>, MemoryState> {
        let mut entropy = test_entropy();
        let identity = PrivateIdentity::generate(&mut entropy);
        let persistence = MemoryState::new();
        UnikernelRuntime::new(identity, entropy, persistence)
    }

    #[test]
    fn runtime_initializes() {
        let runtime = make_runtime();
        assert_eq!(runtime.tick_count(), 0);
    }

    #[test]
    fn tick_increments_counter() {
        let mut runtime = make_runtime();
        runtime.tick(1000);
        runtime.tick(1001);
        assert_eq!(runtime.tick_count(), 2);
    }

    #[test]
    fn tick_without_interfaces_returns_empty_or_minimal_actions() {
        let mut runtime = make_runtime();
        let actions = runtime.tick(1000);
        for action in &actions {
            match action {
                NodeAction::SendOnInterface { .. } => panic!("no interfaces, should not send"),
                _ => {}
            }
        }
    }

    #[test]
    fn identity_is_accessible() {
        let runtime = make_runtime();
        let addr = runtime.identity().public_identity().address_hash;
        assert_ne!(addr, [0u8; 16]);
    }

    #[test]
    fn runtime_has_no_peers_initially() {
        let runtime = make_runtime();
        assert_eq!(runtime.peer_count(), 0);
    }

    #[test]
    fn persistence_is_usable() {
        let mut runtime = make_runtime();
        runtime.persistence().save("test", b"data").unwrap();
        assert_eq!(runtime.persistence().load("test").unwrap(), b"data");
    }
}
