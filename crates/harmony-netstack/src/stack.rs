// SPDX-License-Identifier: GPL-2.0-or-later
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};

use harmony_platform::{NetworkInterface as HarmonyNetworkInterface, PlatformError};

use crate::device::FrameBuffer;
use crate::dhcp::DhcpClient;
use crate::peers::PeerTable;
use crate::tcp::{NetError, TcpHandle, TcpProvider, TcpSocketState};

/// Configuration for DHCP-based address acquisition with a static fallback.
pub struct DhcpConfig {
    /// Static CIDR to apply when DHCP acquisition times out.
    pub fallback_ip: Option<Ipv4Cidr>,
    /// Default gateway to configure alongside the fallback IP.
    pub fallback_gateway: Option<Ipv4Address>,
    /// How long (ms) to wait for a DHCP lease before applying fallback.
    pub fallback_timeout_ms: i64,
}

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
    // TCP
    tcp_handles: Vec<Option<SocketHandle>>,
    tcp_bound_ports: BTreeMap<TcpHandle, u16>,
    tcp_listen_ports: BTreeMap<u16, TcpHandle>,
    /// Handles that userspace has called tcp_close() on. Only these are
    /// eligible for reaping once smoltcp reaches Closed/TimeWait.
    tcp_user_closed: alloc::collections::BTreeSet<TcpHandle>,
    // DHCP
    dhcp: Option<DhcpClient>,
}

impl NetStack {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mac: [u8; 6],
        ip: Option<Ipv4Cidr>,
        gateway: Option<Ipv4Address>,
        port: u16,
        broadcast: bool,
        peers: &[(Ipv4Address, u16)],
        tcp_max_sockets: usize,
        dhcp_config: Option<DhcpConfig>,
        now: Instant,
    ) -> Self {
        let mut device = FrameBuffer::new();

        let config = Config::new(EthernetAddress(mac).into());
        let mut iface = Interface::new(config, &mut device, now);

        // Only apply static IP immediately when not using DHCP.
        // When DHCP is configured, the DhcpClient will apply the lease address.
        if dhcp_config.is_none() {
            if let Some(cidr) = ip {
                iface.update_ip_addrs(|addrs| {
                    addrs.push(IpCidr::Ipv4(cidr)).unwrap();
                });
            }
            if let Some(gw) = gateway {
                iface.routes_mut().add_default_ipv4_route(gw).unwrap();
            }
        }

        // Build socket storage with room for UDP + TCP slots + DHCP + spare.
        let socket_capacity = tcp_max_sockets + 3;
        let mut storage = Vec::with_capacity(socket_capacity);
        for _ in 0..socket_capacity {
            storage.push(smoltcp::iface::SocketStorage::EMPTY);
        }
        let mut sockets = SocketSet::new(storage);

        let rx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 8192]);
        let tx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 8192]);
        let mut socket = udp::Socket::new(rx_buf, tx_buf);
        socket.bind(port).expect("failed to bind UDP socket");
        let udp_handle = sockets.add(socket);

        let mut peer_table = PeerTable::new(port, broadcast);
        for &(addr, peer_port) in peers {
            peer_table.add_peer(addr, peer_port);
        }

        // Initialize DHCP client if requested. It registers its own socket in
        // `sockets` and will configure the interface address on first lease.
        let dhcp = dhcp_config.map(|cfg| {
            DhcpClient::new(
                &mut sockets,
                cfg.fallback_ip,
                cfg.fallback_gateway,
                cfg.fallback_timeout_ms,
                now,
            )
        });

        let tcp_handles = vec![None; tcp_max_sockets];

        Self {
            device,
            iface,
            sockets,
            udp_handle,
            peers: peer_table,
            rx_queue: VecDeque::new(),
            tcp_handles,
            tcp_bound_ports: BTreeMap::new(),
            tcp_listen_ports: BTreeMap::new(),
            tcp_user_closed: alloc::collections::BTreeSet::new(),
            dhcp,
        }
    }

    /// Feed a raw Ethernet frame into the network stack for processing.
    pub fn ingest(&mut self, frame: Vec<u8>) {
        self.device.ingest(frame);
    }

    /// Drive the smoltcp interface and drain received UDP payloads into the rx queue.
    pub fn poll(&mut self, now: Instant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);

        // Process any DHCP lease events produced during the interface poll.
        if let Some(ref mut dhcp) = self.dhcp {
            dhcp.check_lease(&mut self.iface, &mut self.sockets, now);
        }

        // Reap TCP sockets that have completed their close handshake.
        self.tcp_reap_closed();

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

    /// Remove sockets that userspace has closed AND whose TCP close handshake
    /// has completed in smoltcp. Sockets that the remote closed but userspace
    /// hasn't called tcp_close() on are NOT reaped — userspace can still read
    /// EOF from them.
    fn tcp_reap_closed(&mut self) {
        for (slot, opt_handle) in self.tcp_handles.iter_mut().enumerate() {
            if let Some(smoltcp_handle) = *opt_handle {
                let handle = TcpHandle(slot as u32);
                // Only reap if userspace has called tcp_close() on this handle.
                if !self.tcp_user_closed.contains(&handle) {
                    continue;
                }
                let state = self.sockets.get::<tcp::Socket>(smoltcp_handle).state();
                if state == tcp::State::Closed || state == tcp::State::TimeWait {
                    self.sockets.remove(smoltcp_handle);
                    *opt_handle = None;
                    self.tcp_user_closed.remove(&handle);
                }
            }
        }
    }

    /// Resolve a `TcpHandle` to the underlying smoltcp `SocketHandle`.
    fn resolve_tcp(&self, handle: TcpHandle) -> Result<SocketHandle, NetError> {
        self.tcp_handles
            .get(handle.0 as usize)
            .and_then(|h| *h)
            .ok_or(NetError::InvalidHandle)
    }

    /// Immediately remove a TCP socket (used for cleanup in error paths).
    fn tcp_close_internal(&mut self, handle: TcpHandle) -> Result<(), NetError> {
        let smoltcp_handle = self.resolve_tcp(handle)?;
        self.sockets.get_mut::<tcp::Socket>(smoltcp_handle).abort();
        self.sockets.remove(smoltcp_handle);
        self.tcp_handles[handle.0 as usize] = None;
        self.tcp_listen_ports.retain(|_, h| *h != handle);
        self.tcp_bound_ports.remove(&handle);
        self.tcp_user_closed.remove(&handle);
        Ok(())
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
        if data.len() > self.mtu() {
            return Err(PlatformError::SendFailed);
        }
        // Collect destinations first to avoid borrow conflict:
        // `self.peers.destinations()` borrows `self.peers` immutably while
        // `self.sockets.get_mut()` borrows `self.sockets` mutably.
        let dests: Vec<_> = self.peers.destinations().collect();
        let socket = self.sockets.get_mut::<udp::Socket>(self.udp_handle);
        // Best-effort: attempt all destinations, report failure only after
        // trying them all. Avoids torn delivery where broadcast succeeds
        // but a later unicast failure short-circuits via `?`.
        let mut failed = false;
        for dest in dests {
            if socket.can_send() {
                if socket.send_slice(data, dest).is_err() {
                    failed = true;
                }
            } else {
                failed = true;
            }
        }
        if failed {
            Err(PlatformError::SendFailed)
        } else {
            Ok(())
        }
    }
}

impl TcpProvider for NetStack {
    fn tcp_create(&mut self) -> Result<TcpHandle, NetError> {
        // Find the first free slot.
        let slot = self
            .tcp_handles
            .iter()
            .position(|h| h.is_none())
            .ok_or(NetError::SocketLimit)?;

        let rx_buf = tcp::SocketBuffer::new(vec![0u8; 8192]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; 8192]);
        let socket = tcp::Socket::new(rx_buf, tx_buf);
        let smoltcp_handle = self.sockets.add(socket);
        self.tcp_handles[slot] = Some(smoltcp_handle);
        Ok(TcpHandle(slot as u32))
    }

    fn tcp_bind(&mut self, handle: TcpHandle, port: u16) -> Result<(), NetError> {
        // Validate the handle exists.
        let _ = self.resolve_tcp(handle)?;
        // Check for duplicate port binding.
        if self.tcp_bound_ports.values().any(|&p| p == port) {
            return Err(NetError::AddrInUse);
        }
        self.tcp_bound_ports.insert(handle, port);
        Ok(())
    }

    fn tcp_listen(&mut self, handle: TcpHandle, _backlog: usize) -> Result<(), NetError> {
        let smoltcp_handle = self.resolve_tcp(handle)?;
        let port = self
            .tcp_bound_ports
            .get(&handle)
            .copied()
            .ok_or(NetError::NotConnected)?;
        self.sockets
            .get_mut::<tcp::Socket>(smoltcp_handle)
            .listen(port)
            .map_err(|_| NetError::AddrInUse)?;
        self.tcp_listen_ports.insert(port, handle);
        Ok(())
    }

    fn tcp_accept(&mut self, handle: TcpHandle) -> Result<Option<TcpHandle>, NetError> {
        let smoltcp_handle = self.resolve_tcp(handle)?;
        let state = self.sockets.get::<tcp::Socket>(smoltcp_handle).state();

        if state != tcp::State::Established {
            return Ok(None);
        }

        // Find which port this handle was listening on.
        let port = self
            .tcp_listen_ports
            .iter()
            .find(|(_, h)| **h == handle)
            .map(|(p, _)| *p)
            .ok_or(NetError::InvalidHandle)?;

        // Temporarily remove port bookkeeping so the replacement listener can
        // bind to the same port. If anything fails below, we restore it.
        self.tcp_bound_ports.remove(&handle);
        self.tcp_listen_ports.remove(&port);

        // Create a new socket to replace the listener on the same port.
        let new_listener = match self.tcp_create() {
            Ok(h) => h,
            Err(e) => {
                // Restore bookkeeping — the original listener is still valid.
                self.tcp_bound_ports.insert(handle, port);
                self.tcp_listen_ports.insert(port, handle);
                return Err(e);
            }
        };
        if let Err(e) = self.tcp_bind(new_listener, port) {
            // Clean up the new socket and restore original listener.
            let _ = self.tcp_close_internal(new_listener);
            self.tcp_bound_ports.insert(handle, port);
            self.tcp_listen_ports.insert(port, handle);
            return Err(e);
        }
        let new_smoltcp = self.resolve_tcp(new_listener)?;
        if self
            .sockets
            .get_mut::<tcp::Socket>(new_smoltcp)
            .listen(port)
            .is_err()
        {
            let _ = self.tcp_close_internal(new_listener);
            self.tcp_bound_ports.insert(handle, port);
            self.tcp_listen_ports.insert(port, handle);
            return Err(NetError::AddrInUse);
        }

        // Swap smoltcp handles so that:
        //   - `handle` maps to the NEW listening socket (caller's fd stays a listener)
        //   - `new_listener` maps to the OLD established socket (returned as accepted)
        let old_smoltcp = self.tcp_handles[handle.0 as usize];
        let new_smoltcp_opt = self.tcp_handles[new_listener.0 as usize];
        self.tcp_handles[handle.0 as usize] = new_smoltcp_opt;
        self.tcp_handles[new_listener.0 as usize] = old_smoltcp;

        // Restore port binding for handle (now the new listener).
        self.tcp_bound_ports.insert(handle, port);
        self.tcp_listen_ports.insert(port, handle);
        // Remove the stale port binding for new_listener — it's now the
        // accepted (established) connection, not a listener.
        self.tcp_bound_ports.remove(&new_listener);

        Ok(Some(new_listener))
    }

    fn tcp_connect(
        &mut self,
        handle: TcpHandle,
        addr: Ipv4Address,
        port: u16,
    ) -> Result<(), NetError> {
        let smoltcp_handle = self.resolve_tcp(handle)?;
        // Use explicitly bound port if available, otherwise assign an ephemeral port.
        let local_port = self
            .tcp_bound_ports
            .get(&handle)
            .copied()
            .unwrap_or_else(|| 49152 + (handle.0 as u16 % 16384));
        let remote = (IpAddress::Ipv4(addr), port);
        // Both self.iface and self.sockets are separate fields — the borrow
        // checker allows simultaneous mutable borrows of distinct fields.
        let cx = self.iface.context();
        self.sockets
            .get_mut::<tcp::Socket>(smoltcp_handle)
            .connect(cx, remote, local_port)
            .map_err(|_| NetError::ConnectionRefused)
    }

    fn tcp_send(&mut self, handle: TcpHandle, data: &[u8]) -> Result<usize, NetError> {
        let smoltcp_handle = self.resolve_tcp(handle)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(smoltcp_handle);
        if !socket.may_send() {
            return Err(NetError::NotConnected);
        }
        match socket.send_slice(data) {
            Ok(0) => Err(NetError::WouldBlock),
            Ok(n) => Ok(n),
            Err(_) => Err(NetError::ConnectionReset),
        }
    }

    fn tcp_recv(&mut self, handle: TcpHandle, buf: &mut [u8]) -> Result<usize, NetError> {
        let smoltcp_handle = self.resolve_tcp(handle)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(smoltcp_handle);
        if !socket.may_recv() {
            // CloseWait: remote has sent FIN — we were connected and the
            // connection is half-closed. Signal EOF to the caller.
            if socket.state() == tcp::State::CloseWait {
                return Ok(0);
            }
            // Any other non-receivable state (Closed, Listen, SynSent, …)
            // means no established connection exists.
            return Err(NetError::NotConnected);
        }
        match socket.recv_slice(buf) {
            Ok(0) => Err(NetError::WouldBlock),
            Ok(n) => Ok(n),
            Err(_) => Err(NetError::ConnectionReset),
        }
    }

    fn tcp_close(&mut self, handle: TcpHandle) -> Result<(), NetError> {
        let smoltcp_handle = self.resolve_tcp(handle)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(smoltcp_handle);
        socket.close();
        // Remove from listener/port tracking immediately.
        self.tcp_listen_ports.retain(|_, h| *h != handle);
        self.tcp_bound_ports.remove(&handle);
        // Mark as user-closed so tcp_reap_closed() can remove it once smoltcp
        // finishes the FIN handshake. Until then, the handle stays valid so
        // userspace can still read EOF (0) instead of getting EBADF.
        self.tcp_user_closed.insert(handle);
        Ok(())
    }

    fn tcp_state(&self, handle: TcpHandle) -> TcpSocketState {
        match self.resolve_tcp(handle) {
            Ok(h) => {
                let s = self.sockets.get::<tcp::Socket>(h);
                match s.state() {
                    tcp::State::Closed | tcp::State::TimeWait => TcpSocketState::Closed,
                    tcp::State::Listen => TcpSocketState::Listen,
                    tcp::State::SynSent | tcp::State::SynReceived => TcpSocketState::Connecting,
                    tcp::State::Established => TcpSocketState::Established,
                    tcp::State::CloseWait => TcpSocketState::CloseWait,
                    _ => TcpSocketState::Closing,
                }
            }
            Err(_) => TcpSocketState::Closed,
        }
    }

    fn tcp_can_recv(&self, handle: TcpHandle) -> bool {
        self.resolve_tcp(handle)
            .ok()
            .map(|h| self.sockets.get::<tcp::Socket>(h).can_recv())
            .unwrap_or(false)
    }

    fn tcp_can_send(&self, handle: TcpHandle) -> bool {
        self.resolve_tcp(handle)
            .ok()
            .map(|h| self.sockets.get::<tcp::Socket>(h).can_send())
            .unwrap_or(false)
    }

    fn tcp_poll(&mut self, now_ms: i64) {
        self.poll(Instant::from_millis(now_ms));
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

#[cfg(test)]
mod tcp_tests {
    use super::*;
    use crate::builder::NetStackBuilder;
    use crate::tcp::TcpProvider;

    fn build_tcp_stack() -> NetStack {
        NetStackBuilder::new()
            .static_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24))
            .tcp_max_sockets(4)
            .build(Instant::from_millis(0))
    }

    #[test]
    fn tcp_create_returns_unique_handles() {
        let mut s = build_tcp_stack();
        let h1 = s.tcp_create().unwrap();
        let h2 = s.tcp_create().unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn tcp_create_beyond_limit() {
        let mut s = build_tcp_stack();
        for _ in 0..4 {
            s.tcp_create().unwrap();
        }
        assert!(matches!(s.tcp_create(), Err(NetError::SocketLimit)));
    }

    #[test]
    fn tcp_close_invalidates_handle() {
        let mut s = build_tcp_stack();
        let h = s.tcp_create().unwrap();
        s.tcp_close(h).unwrap();
        assert_eq!(s.tcp_state(h), TcpSocketState::Closed);
    }

    #[test]
    fn tcp_listen_changes_state() {
        let mut s = build_tcp_stack();
        let h = s.tcp_create().unwrap();
        s.tcp_bind(h, 8080).unwrap();
        s.tcp_listen(h, 1).unwrap();
        assert_eq!(s.tcp_state(h), TcpSocketState::Listen);
    }

    #[test]
    fn tcp_recv_unconnected_errors() {
        let mut s = build_tcp_stack();
        let h = s.tcp_create().unwrap();
        let mut buf = [0u8; 64];
        assert!(matches!(
            s.tcp_recv(h, &mut buf),
            Err(NetError::NotConnected)
        ));
    }

    #[test]
    fn dhcp_builder_doesnt_panic() {
        let _s = NetStackBuilder::new()
            .dhcp(true)
            .fallback_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24))
            .fallback_gateway(Ipv4Address::new(10, 0, 0, 1))
            .build(Instant::from_millis(0));
    }

    #[test]
    fn static_ip_builder_still_works() {
        let s = NetStackBuilder::new()
            .static_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24))
            .build(Instant::from_millis(0));
        assert_eq!(s.name(), "udp0");
    }
}
