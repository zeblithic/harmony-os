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
use harmony_reticulum::{
    DestinationType, HeaderType, Node, NodeAction, NodeEvent, Packet, PacketContext, PacketFlags,
    PacketHeader, PacketType, PropagationType,
};
use rand_core::CryptoRngCore;

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
    pub(crate) peers: BTreeMap<[u8; 16], PeerInfo>,
    heartbeat_interval_ms: u64,
    peer_timeout_ms: u64,
    last_heartbeat_ms: u64,
    boot_time_ms: u64,
}

impl<E: EntropySource + CryptoRngCore, P: PersistentState> UnikernelRuntime<E, P> {
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

    /// Process a timer tick. Resolves AnnounceNeeded internally,
    /// checks peer timeouts. Returns RuntimeAction only.
    /// `now` is monotonic milliseconds.
    pub fn tick(&mut self, now: u64) -> Vec<RuntimeAction> {
        self.tick_count += 1;
        let mut out = Vec::new();

        let now_secs = now / 1000;
        let node_actions = self.node.handle_event(NodeEvent::TimerTick { now: now_secs });

        for action in node_actions {
            match action {
                NodeAction::AnnounceNeeded { dest_hash } => {
                    let announce_actions = self.node.announce(
                        &dest_hash,
                        &mut self.entropy,
                        now_secs,
                    );
                    for aa in announce_actions {
                        if let NodeAction::SendOnInterface { interface_name, raw } = aa {
                            out.push(RuntimeAction::SendOnInterface { interface_name, raw });
                        }
                    }
                }
                NodeAction::SendOnInterface { interface_name, raw } => {
                    out.push(RuntimeAction::SendOnInterface { interface_name, raw });
                }
                _ => {} // PathsExpired etc. — diagnostic, skip
            }
        }

        // Emit heartbeats if interval has elapsed and we have a destination.
        if !self.peers.is_empty()
            && now.saturating_sub(self.last_heartbeat_ms) >= self.heartbeat_interval_ms
        {
            if let Some(ref dest_hash) = self.dest_hash {
                let hbt = self.build_heartbeat(now);
                // Send heartbeat to each peer's destination.
                // For now, broadcast — peers learn our dest_hash from announces.
                // We use route_packet which broadcasts if no path is known.
                let peer_addrs: Vec<[u8; 16]> = self.peers.keys().copied().collect();
                for _peer_addr in &peer_addrs {
                    if let Some(raw) = Self::build_data_packet(dest_hash, &hbt) {
                        let send_actions = self.node.route_packet(dest_hash, raw);
                        for sa in send_actions {
                            if let NodeAction::SendOnInterface { interface_name, raw } = sa {
                                out.push(RuntimeAction::SendOnInterface { interface_name, raw });
                            }
                        }
                        // One broadcast covers all peers on the same LAN.
                        break;
                    }
                }
            }
            self.last_heartbeat_ms = now;
        }

        // Check peer timeouts.
        let timeout = self.peer_timeout_ms;
        let timed_out: Vec<[u8; 16]> = self.peers
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.last_seen_ms) > timeout)
            .map(|(k, _)| *k)
            .collect();
        for addr in timed_out {
            self.peers.remove(&addr);
            out.push(RuntimeAction::PeerLost { address_hash: addr });
        }

        out
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

    /// Build a 28-byte heartbeat payload.
    fn build_heartbeat(&self, now: u64) -> [u8; 28] {
        let mut buf = [0u8; 28];
        // Magic: "HBT\x01"
        buf[0..4].copy_from_slice(&[0x48, 0x42, 0x54, 0x01]);
        // Sender address hash
        buf[4..20].copy_from_slice(&self.identity.public_identity().address_hash);
        // Uptime
        let uptime = now.saturating_sub(self.boot_time_ms);
        buf[20..28].copy_from_slice(&uptime.to_be_bytes());
        buf
    }

    /// Build a Type1 broadcast data packet addressed to `dest_hash`
    /// containing the given payload.
    fn build_data_packet(dest_hash: &DestinationHash, payload: &[u8]) -> Option<Vec<u8>> {
        let packet = Packet {
            header: PacketHeader {
                flags: PacketFlags {
                    ifac: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    propagation: PropagationType::Broadcast,
                    destination_type: DestinationType::Single,
                    packet_type: PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: *dest_hash,
                context: PacketContext::None,
            },
            data: Arc::from(payload),
        };
        packet.to_bytes().ok()
    }

    /// Register this node's identity as an announcing destination.
    ///
    /// Creates a `DestinationName`, registers it on the inner `Node`,
    /// and stores the destination hash for heartbeat routing.
    /// `announce_interval_ms` is in milliseconds; converted to seconds for the Node.
    pub fn register_announcing_destination(
        &mut self,
        app_name: &str,
        aspects: &[&str],
        announce_interval_ms: u64,
        now: u64,
    ) -> DestinationHash {
        let dest_name =
            DestinationName::from_name(app_name, aspects).expect("invalid destination name");
        // Node takes ownership of identity, so we round-trip through bytes.
        let identity_bytes = self.identity.to_private_bytes();
        let identity_clone = PrivateIdentity::from_private_bytes(&identity_bytes)
            .expect("identity round-trip failed");
        let announce_interval_secs = announce_interval_ms / 1000;
        let now_secs = now / 1000;
        let dest_hash = self.node.register_announcing_destination(
            identity_clone,
            dest_name.clone(),
            Vec::new(), // no app_data
            Some(announce_interval_secs),
            now_secs,
        );
        self.dest_name = Some(dest_name);
        self.dest_hash = Some(dest_hash);
        self.boot_time_ms = now;
        dest_hash
    }

    /// Register a network interface with the node's routing table.
    pub fn register_interface(&mut self, name: &str) {
        self.node
            .register_interface(String::from(name), InterfaceMode::Full, None);
    }

    /// Feed an inbound packet into the node and translate results.
    ///
    /// Intercepts `AnnounceReceived` to update the peer table and
    /// `DeliverLocally` to parse heartbeat payloads.
    ///
    /// `now` is monotonic milliseconds.
    pub fn handle_packet(
        &mut self,
        interface_name: &str,
        data: Vec<u8>,
        now: u64,
    ) -> Vec<RuntimeAction> {
        let now_secs = now / 1000;
        let node_actions = self.node.handle_event(NodeEvent::InboundPacket {
            interface_name: String::from(interface_name),
            raw: data,
            now: now_secs,
        });

        let mut out = Vec::new();

        for action in node_actions {
            match action {
                NodeAction::AnnounceReceived {
                    validated_announce,
                    hops,
                    ..
                } => {
                    let addr = validated_announce.identity.address_hash;
                    let is_new = !self.peers.contains_key(&addr);
                    let discovered_at = if is_new {
                        now
                    } else {
                        self.peers[&addr].discovered_at_ms
                    };
                    self.peers.insert(
                        addr,
                        PeerInfo {
                            address_hash: addr,
                            last_seen_ms: now,
                            hops,
                            discovered_at_ms: discovered_at,
                        },
                    );
                    if is_new {
                        out.push(RuntimeAction::PeerDiscovered {
                            address_hash: addr,
                            hops,
                        });
                    }
                }
                NodeAction::DeliverLocally {
                    packet,
                    destination_hash,
                    ..
                } => {
                    let payload: &[u8] = &packet.data;
                    // Check for heartbeat magic: "HBT\x01"
                    if payload.len() >= 28
                        && payload[0..4] == [0x48, 0x42, 0x54, 0x01]
                    {
                        let mut sender = [0u8; 16];
                        sender.copy_from_slice(&payload[4..20]);
                        let uptime_ms = u64::from_be_bytes(
                            payload[20..28].try_into().unwrap(),
                        );
                        // Update last_seen for this peer.
                        if let Some(peer) = self.peers.get_mut(&sender) {
                            peer.last_seen_ms = now;
                        }
                        out.push(RuntimeAction::HeartbeatReceived {
                            address_hash: sender,
                            uptime_ms,
                        });
                    } else {
                        out.push(RuntimeAction::DeliverLocally {
                            destination_hash,
                            payload: payload.to_vec(),
                        });
                    }
                }
                NodeAction::AnnounceNeeded { dest_hash } => {
                    // Resolve inline (can happen on inbound too).
                    let announce_actions =
                        self.node.announce(&dest_hash, &mut self.entropy, now_secs);
                    for aa in announce_actions {
                        if let NodeAction::SendOnInterface {
                            interface_name,
                            raw,
                        } = aa
                        {
                            out.push(RuntimeAction::SendOnInterface {
                                interface_name,
                                raw,
                            });
                        }
                    }
                }
                NodeAction::SendOnInterface {
                    interface_name,
                    raw,
                } => {
                    out.push(RuntimeAction::SendOnInterface {
                        interface_name,
                        raw,
                    });
                }
                _ => {}
            }
        }

        out
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
                RuntimeAction::SendOnInterface { .. } => panic!("no interfaces, should not send"),
                _ => {}
            }
        }
    }

    #[test]
    fn tick_resolves_announce_needed_internally() {
        let mut runtime = make_runtime();
        runtime.register_interface("test0");
        runtime.register_announcing_destination("harmony", &["node"], 1_000, 0);

        // Tick at 1000ms = 1 second. Node scheduler uses seconds,
        // announce_interval=1s, next_announce_at=0, so announce fires.
        let actions = runtime.tick(1_000);

        let has_send = actions.iter().any(|a| matches!(a, RuntimeAction::SendOnInterface { .. }));
        assert!(has_send, "tick should resolve announces into SendOnInterface");
    }

    #[test]
    fn tick_emits_peer_lost_after_timeout() {
        let mut runtime = make_runtime();
        runtime.register_interface("test0");

        // Manually insert a peer.
        runtime.peers.insert([0xAA; 16], PeerInfo {
            address_hash: [0xAA; 16],
            last_seen_ms: 0,
            hops: 1,
            discovered_at_ms: 0,
        });
        assert_eq!(runtime.peer_count(), 1);

        // Tick at 16_000ms — peer_timeout_ms is 15_000.
        let actions = runtime.tick(16_000);
        assert_eq!(runtime.peer_count(), 0);
        let has_lost = actions.iter().any(|a| matches!(a, RuntimeAction::PeerLost { .. }));
        assert!(has_lost, "should emit PeerLost");
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
    fn tick_emits_heartbeats_to_peers() {
        let mut runtime = make_runtime();
        runtime.register_interface("test0");
        runtime.register_announcing_destination("harmony", &["node"], 300_000, 0);

        // Consume the initial announce by ticking at 1 second.
        let _ = runtime.tick(1_000);

        // Insert a fake peer.
        runtime.peers.insert([0xBB; 16], PeerInfo {
            address_hash: [0xBB; 16],
            last_seen_ms: 0,
            hops: 1,
            discovered_at_ms: 0,
        });

        // Tick at 6 seconds — past heartbeat_interval_ms (5000).
        // The announce won't fire again (next_announce_at is ~300s out).
        let actions = runtime.tick(6_000);

        // Should have at least one SendOnInterface for the heartbeat.
        let send_count = actions.iter().filter(|a| matches!(a, RuntimeAction::SendOnInterface { .. })).count();
        assert!(send_count > 0, "should emit heartbeat SendOnInterface");
    }

    #[test]
    fn register_announcing_destination_sets_dest_hash() {
        let mut runtime = make_runtime();
        let dest_hash =
            runtime.register_announcing_destination("harmony", &["node"], 300_000, 0);
        assert_ne!(dest_hash, [0u8; 16]);
        assert_eq!(runtime.node.announcing_destination_count(), 1);
    }

    #[test]
    fn persistence_is_usable() {
        let mut runtime = make_runtime();
        runtime.persistence().save("test", b"data").unwrap();
        assert_eq!(runtime.persistence().load("test").unwrap(), b"data");
    }

    #[test]
    fn handle_packet_emits_peer_discovered_on_announce() {
        let mut runtime = make_runtime();
        runtime.register_interface("test0");
        runtime.register_announcing_destination("harmony", &["node"], 300_000, 0);

        // Build a valid announce from a second identity.
        let mut entropy2 = test_entropy();
        let peer_identity = PrivateIdentity::generate(&mut entropy2);
        let peer_addr = peer_identity.public_identity().address_hash;
        let dest_name = harmony_reticulum::destination::DestinationName::from_name(
            "harmony",
            &["node"],
        )
        .unwrap();

        let announce_packet = harmony_reticulum::announce::build_announce(
            &peer_identity,
            &dest_name,
            &mut entropy2,
            0,
            &[],
            None,
        )
        .unwrap();
        let raw = announce_packet.to_bytes().unwrap();

        let actions = runtime.handle_packet("test0", raw, 1_000);
        let has_discovered = actions.iter().any(|a| {
            matches!(
                a,
                RuntimeAction::PeerDiscovered {
                    address_hash, ..
                } if *address_hash == peer_addr
            )
        });
        assert!(has_discovered, "should emit PeerDiscovered on valid announce");
        assert_eq!(runtime.peer_count(), 1);
    }
}
