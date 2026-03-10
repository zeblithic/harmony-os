use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address, Ipv4Cidr};

use harmony_platform::{NetworkInterface as HarmonyNetworkInterface, PlatformError};

use crate::device::FrameBuffer;
use crate::peers::PeerTable;

/// UDP/IP network interface for Harmony mesh traffic.
///
/// Wraps smoltcp to process raw Ethernet frames and expose Harmony
/// packets received via UDP. Implements `NetworkInterface` so the
/// unikernel runtime can register it as `"udp0"`.
pub struct NetStack {
    device: FrameBuffer,
    iface: Interface,
    sockets: SocketSet<'static>,
    udp_handle: SocketHandle,
    peers: PeerTable,
    rx_queue: VecDeque<Vec<u8>>,
}

impl NetStack {
    pub(crate) fn new(
        mac: [u8; 6],
        ip: Ipv4Cidr,
        gateway: Option<Ipv4Address>,
        port: u16,
        broadcast: bool,
        peers: &[(Ipv4Address, u16)],
        now: Instant,
    ) -> Self {
        let mut device = FrameBuffer::new();

        let config = Config::new(EthernetAddress(mac).into());
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::Ipv4(ip)).unwrap();
        });
        if let Some(gw) = gateway {
            iface.routes_mut().add_default_ipv4_route(gw).unwrap();
        }

        let rx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 8192]);
        let tx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 8192]);
        let mut socket = udp::Socket::new(rx_buf, tx_buf);
        socket.bind(port).expect("failed to bind UDP socket");

        let mut sockets = SocketSet::new(vec![]);
        let udp_handle = sockets.add(socket);

        let mut peer_table = PeerTable::new(port, broadcast);
        for &(addr, peer_port) in peers {
            peer_table.add_peer(addr, peer_port);
        }

        Self {
            device,
            iface,
            sockets,
            udp_handle,
            peers: peer_table,
            rx_queue: VecDeque::new(),
        }
    }

    /// Feed a raw Ethernet frame into the network stack for processing.
    pub fn ingest(&mut self, frame: Vec<u8>) {
        self.device.ingest(frame);
    }

    /// Drive the smoltcp interface and drain received UDP payloads into the rx queue.
    pub fn poll(&mut self, now: Instant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);

        let socket = self.sockets.get_mut::<udp::Socket>(self.udp_handle);
        while socket.can_recv() {
            match socket.recv() {
                Ok((data, _meta)) => {
                    self.rx_queue.push_back(data.to_vec());
                }
                Err(_) => break,
            }
        }
    }

    /// Drain outbound Ethernet frames produced by smoltcp (ARP replies, UDP packets, etc.).
    pub fn drain_tx(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.device.drain_tx()
    }
}

impl HarmonyNetworkInterface for NetStack {
    fn name(&self) -> &str {
        "udp0"
    }

    fn mtu(&self) -> usize {
        1472 // 1500 - 20 (IP) - 8 (UDP)
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        self.rx_queue.pop_front()
    }

    fn send(&mut self, data: &[u8]) -> Result<(), PlatformError> {
        // Collect destinations first to avoid borrow conflict:
        // `self.peers.destinations()` borrows `self.peers` immutably while
        // `self.sockets.get_mut()` borrows `self.sockets` mutably.
        let dests: Vec<_> = self.peers.destinations().collect();
        let socket = self.sockets.get_mut::<udp::Socket>(self.udp_handle);
        for dest in dests {
            if socket.can_send() {
                socket
                    .send_slice(data, dest)
                    .map_err(|_| PlatformError::SendFailed)?;
            } else {
                return Err(PlatformError::SendFailed);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::NetStackBuilder;
    use crate::config::HARMONY_UDP_PORT;
    use harmony_platform::NetworkInterface as HarmonyNetworkInterface;
    use smoltcp::wire::Ipv4Cidr;

    fn build_arp_request(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0u8; 42];
        frame[0..6].copy_from_slice(&[0xFF; 6]); // dst: broadcast
        frame[6..12].copy_from_slice(&sender_mac);
        frame[12] = 0x08;
        frame[13] = 0x06; // ARP
        frame[14] = 0x00;
        frame[15] = 0x01; // hw type: Ethernet
        frame[16] = 0x08;
        frame[17] = 0x00; // proto type: IPv4
        frame[18] = 6;
        frame[19] = 4;
        frame[20] = 0x00;
        frame[21] = 0x01; // ARP request
        frame[22..28].copy_from_slice(&sender_mac);
        frame[28..32].copy_from_slice(&sender_ip);
        frame[32..38].copy_from_slice(&[0; 6]);
        frame[38..42].copy_from_slice(&target_ip);
        frame
    }

    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..header.len()).step_by(2) {
            let word = if i + 1 < header.len() {
                ((header[i] as u32) << 8) | (header[i + 1] as u32)
            } else {
                (header[i] as u32) << 8
            };
            sum += word;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    fn build_udp_frame(
        src_mac: [u8; 6],
        src_ip: Ipv4Address,
        dst_mac: [u8; 6],
        dst_ip: Ipv4Address,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let frame_len = 14 + ip_len;
        let mut frame = vec![0u8; frame_len];

        // Ethernet header
        frame[0..6].copy_from_slice(&dst_mac);
        frame[6..12].copy_from_slice(&src_mac);
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4

        // IPv4 header (minimal, 20 bytes)
        frame[14] = 0x45; // version 4, IHL 5
        frame[16] = (ip_len >> 8) as u8;
        frame[17] = ip_len as u8;
        frame[22] = 64; // TTL
        frame[23] = 17; // protocol: UDP
        frame[26..30].copy_from_slice(&src_ip.0);
        frame[30..34].copy_from_slice(&dst_ip.0);

        // IPv4 header checksum
        let checksum = ipv4_checksum(&frame[14..34]);
        frame[24] = (checksum >> 8) as u8;
        frame[25] = checksum as u8;

        // UDP header
        let udp_offset = 34;
        let src_port = HARMONY_UDP_PORT;
        let dst_port = HARMONY_UDP_PORT;
        frame[udp_offset] = (src_port >> 8) as u8;
        frame[udp_offset + 1] = src_port as u8;
        frame[udp_offset + 2] = (dst_port >> 8) as u8;
        frame[udp_offset + 3] = dst_port as u8;
        frame[udp_offset + 4] = (udp_len >> 8) as u8;
        frame[udp_offset + 5] = udp_len as u8;
        // UDP checksum = 0 (optional for IPv4)

        // Payload
        frame[udp_offset + 8..].copy_from_slice(payload);

        frame
    }

    fn build_arp_reply(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 42];
        frame[0..6].copy_from_slice(&target_mac);
        frame[6..12].copy_from_slice(&sender_mac);
        frame[12] = 0x08;
        frame[13] = 0x06;
        frame[14] = 0x00;
        frame[15] = 0x01;
        frame[16] = 0x08;
        frame[17] = 0x00;
        frame[18] = 6;
        frame[19] = 4;
        frame[20] = 0x00;
        frame[21] = 0x02; // ARP reply
        frame[22..28].copy_from_slice(&sender_mac);
        frame[28..32].copy_from_slice(&sender_ip);
        frame[32..38].copy_from_slice(&target_mac);
        frame[38..42].copy_from_slice(&target_ip);
        frame
    }

    #[test]
    fn builder_creates_netstack() {
        let stack = NetStackBuilder::new()
            .static_ip(Ipv4Cidr::new(
                smoltcp::wire::Ipv4Address::new(10, 0, 0, 1),
                24,
            ))
            .build(Instant::ZERO);
        assert_eq!(stack.name(), "udp0");
    }

    #[test]
    fn arp_reply_on_ingest() {
        let our_ip = [10, 0, 0, 1];
        let our_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sender_ip = [10, 0, 0, 2];

        let mut stack = NetStackBuilder::new()
            .mac(our_mac)
            .static_ip(Ipv4Cidr::new(
                smoltcp::wire::Ipv4Address::new(10, 0, 0, 1),
                24,
            ))
            .build(Instant::ZERO);

        let arp_req = build_arp_request(sender_mac, sender_ip, our_ip);
        stack.ingest(arp_req);
        stack.poll(Instant::ZERO);

        let tx_frames: Vec<_> = stack.drain_tx().collect();
        assert!(
            !tx_frames.is_empty(),
            "expected at least one ARP reply frame"
        );

        // Verify the first TX frame is an ARP reply (ethertype 0x0806, opcode 0x0002).
        let reply = &tx_frames[0];
        assert_eq!(reply[12], 0x08);
        assert_eq!(reply[13], 0x06); // ARP ethertype
        assert_eq!(reply[20], 0x00);
        assert_eq!(reply[21], 0x02); // ARP reply opcode
    }

    #[test]
    fn udp_round_trip() {
        let our_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let our_ip = Ipv4Address::new(10, 0, 0, 1);
        let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sender_ip = Ipv4Address::new(10, 0, 0, 2);

        let mut stack = NetStackBuilder::new()
            .mac(our_mac)
            .static_ip(Ipv4Cidr::new(our_ip, 24))
            .build(Instant::ZERO);

        let payload = b"hello harmony mesh";
        let frame = build_udp_frame(sender_mac, sender_ip, our_mac, our_ip, payload);
        stack.ingest(frame);
        stack.poll(Instant::ZERO);

        let received = stack.receive();
        assert!(received.is_some(), "expected to receive UDP payload");
        assert_eq!(received.unwrap(), payload);

        // No more data pending.
        assert!(stack.receive().is_none());
    }

    #[test]
    fn send_produces_frames() {
        let our_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let our_ip = Ipv4Address::new(10, 0, 0, 1);
        let peer_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let peer_ip = Ipv4Address::new(10, 0, 0, 2);

        let mut stack = NetStackBuilder::new()
            .mac(our_mac)
            .static_ip(Ipv4Cidr::new(our_ip, 24))
            .enable_broadcast(true)
            .add_peer(peer_ip, 4242)
            .build(Instant::ZERO);

        // Seed the ARP cache by ingesting an ARP reply from the peer so
        // smoltcp can resolve the peer's MAC address.
        let arp_reply = build_arp_reply(peer_mac, peer_ip.0, our_mac, our_ip.0);
        stack.ingest(arp_reply);
        stack.poll(Instant::ZERO);
        // Drain any ARP-related frames produced during poll.
        let _: Vec<_> = stack.drain_tx().collect();

        // Also seed ARP for broadcast address (255.255.255.255).
        // smoltcp sends broadcast frames to ff:ff:ff:ff:ff:ff automatically
        // when there's no ARP entry, but we need to ensure frames go out.
        let broadcast_arp = build_arp_reply([0xFF; 6], [255, 255, 255, 255], our_mac, our_ip.0);
        stack.ingest(broadcast_arp);
        stack.poll(Instant::ZERO);
        let _: Vec<_> = stack.drain_tx().collect();

        // Now send a Harmony packet via the trait method.
        let payload = b"outbound harmony packet";
        let result = stack.send(payload);
        assert!(result.is_ok(), "send() should succeed: {:?}", result.err());

        // Poll to flush smoltcp's outbound queue into Ethernet frames.
        stack.poll(Instant::ZERO);
        let tx_frames: Vec<_> = stack.drain_tx().collect();

        assert!(
            !tx_frames.is_empty(),
            "expected at least one outbound Ethernet frame after send()"
        );
    }

    #[test]
    fn mtu_returns_udp_payload_max() {
        let stack = NetStackBuilder::new()
            .static_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24))
            .build(Instant::ZERO);
        // 1500 (Ethernet MTU) - 20 (IP header) - 8 (UDP header) = 1472
        assert_eq!(HarmonyNetworkInterface::mtu(&stack), 1472);
    }
}
