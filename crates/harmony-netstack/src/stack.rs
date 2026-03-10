use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address, Ipv4Cidr};

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
    #[allow(dead_code)] // used by NetworkInterface impl (Task 5)
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

    /// Returns the interface name (`"udp0"`).
    pub fn name(&self) -> &str {
        "udp0"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::NetStackBuilder;
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
}
