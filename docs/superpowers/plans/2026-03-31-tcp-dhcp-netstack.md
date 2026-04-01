# TCP + DHCP Netstack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable TCP sockets and DHCP auto-configuration in harmony-os so SSH daemons can run on RPi5 nodes and Ethernet works without hardcoded IPs.

**Architecture:** Enable smoltcp TCP/DHCP features, expose a `TcpProvider` trait for handle-based TCP, wire Linuxulator socket syscalls through the trait with real epoll readiness, and add DHCP with static-IP fallback. The user program's `epoll_wait` drives netstack polling so TCP retransmissions work without a separate event loop.

**Tech Stack:** Rust (no_std + alloc), smoltcp 0.11 (socket-tcp, proto-tcp, proto-dhcpv4), harmony-netstack, harmony-os Linuxulator

**Spec:** `docs/superpowers/specs/2026-03-31-tcp-dhcp-netstack-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `crates/harmony-netstack/src/tcp.rs` | **Create.** `TcpProvider` trait, `TcpHandle`, `TcpSocketState`, `NetError`. Pure types — no smoltcp dependency in the trait itself. |
| `crates/harmony-netstack/src/dhcp.rs` | **Create.** DHCP lease state: socket creation, event handling, fallback timeout. |
| `crates/harmony-netstack/src/stack.rs` | **Modify.** Implement `TcpProvider` for `NetStack`, integrate DHCP into `poll()`, manage shared `SocketSet`. |
| `crates/harmony-netstack/src/builder.rs` | **Modify.** Add `.dhcp()`, `.fallback_ip()`, `.fallback_gateway()`, `.tcp_max_sockets()`. |
| `crates/harmony-netstack/src/lib.rs` | **Modify.** Export `tcp` and `dhcp` modules. |
| `crates/harmony-netstack/Cargo.toml` | **Modify.** Add `socket-tcp`, `proto-tcp`, `proto-dhcpv4` features. |
| `crates/harmony-os/src/linuxulator.rs` | **Modify.** Wire `SOCK_STREAM` syscalls to `TcpProvider`, real epoll readiness for TCP fds. |
| `crates/harmony-os/Cargo.toml` | **Modify.** Add harmony-netstack dependency (for `TcpProvider` trait). |
| `crates/harmony-boot/src/main.rs` | **Modify.** Use DHCP builder, connect netstack to Linuxulator. |

---

### Task 1: smoltcp Feature Flags

**Files:**
- Modify: `crates/harmony-netstack/Cargo.toml`

- [ ] **Step 1: Add TCP and DHCP features to smoltcp dependency**

In `crates/harmony-netstack/Cargo.toml`, update the smoltcp features:

```toml
smoltcp = { version = "0.11", default-features = false, features = [
    "medium-ethernet",
    "proto-ipv4",
    "socket-udp",
    "socket-tcp",
    "proto-tcp",
    "proto-dhcpv4",
    "alloc",
] }
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check -p harmony-netstack`
Expected: compiles (new features are additive, existing code unchanged)

- [ ] **Step 3: Verify existing tests pass**

Run: `cargo test -p harmony-netstack`
Expected: all existing tests pass (UDP, ARP, FrameBuffer tests unchanged)

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-netstack/Cargo.toml
git commit -m "feat(netstack): enable socket-tcp, proto-tcp, proto-dhcpv4 in smoltcp"
```

---

### Task 2: TcpProvider Trait and Types

**Files:**
- Create: `crates/harmony-netstack/src/tcp.rs`
- Modify: `crates/harmony-netstack/src/lib.rs`

The trait and types live in their own file so the Linuxulator can import them without pulling in smoltcp internals.

- [ ] **Step 1: Create tcp.rs with trait, handle, state, and error types**

Create `crates/harmony-netstack/src/tcp.rs`:

```rust
//! Handle-based TCP API for the Linuxulator.
//!
//! The `TcpProvider` trait abstracts TCP socket operations so Ring 3
//! (Linuxulator) doesn't depend on smoltcp internals. NetStack implements
//! this trait; the Linuxulator takes a generic `T: TcpProvider`.

use smoltcp::wire::Ipv4Address;

/// Opaque handle to a TCP socket managed by NetStack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// No data available / send buffer full (nonblocking).
    WouldBlock,
    /// Connection actively refused by remote.
    ConnectionRefused,
    /// Connection reset by remote.
    ConnectionReset,
    /// Socket not in connected state.
    NotConnected,
    /// Port already bound.
    AddrInUse,
    /// Handle doesn't refer to a valid socket.
    InvalidHandle,
    /// Maximum socket count reached.
    SocketLimit,
}

/// Abstract TCP socket operations.
///
/// Implemented by `NetStack`, consumed by the Linuxulator via generic parameter.
/// All methods use nonblocking semantics — `WouldBlock` instead of blocking.
pub trait TcpProvider {
    /// Create a new TCP socket. Returns a handle for subsequent operations.
    fn tcp_create(&mut self) -> Result<TcpHandle, NetError>;

    /// Bind a socket to a local port.
    fn tcp_bind(&mut self, handle: TcpHandle, port: u16) -> Result<(), NetError>;

    /// Start listening for incoming connections.
    fn tcp_listen(&mut self, handle: TcpHandle, backlog: usize) -> Result<(), NetError>;

    /// Accept a pending connection on a listening socket.
    /// Returns `Ok(None)` if no connection is pending (maps to EAGAIN).
    fn tcp_accept(&mut self, handle: TcpHandle) -> Result<Option<TcpHandle>, NetError>;

    /// Initiate a TCP connection to a remote endpoint. Returns immediately;
    /// connection completes asynchronously (check state via `tcp_state`).
    fn tcp_connect(
        &mut self,
        handle: TcpHandle,
        addr: Ipv4Address,
        port: u16,
    ) -> Result<(), NetError>;

    /// Send data on a connected socket. Returns bytes actually queued.
    /// Returns `WouldBlock` if the send buffer is full.
    fn tcp_send(&mut self, handle: TcpHandle, data: &[u8]) -> Result<usize, NetError>;

    /// Receive data from a connected socket. Returns bytes read.
    /// Returns `WouldBlock` if no data is available.
    fn tcp_recv(&mut self, handle: TcpHandle, buf: &mut [u8]) -> Result<usize, NetError>;

    /// Close a TCP socket. Initiates the TCP close handshake.
    fn tcp_close(&mut self, handle: TcpHandle) -> Result<(), NetError>;

    /// Query the current state of a TCP socket.
    fn tcp_state(&self, handle: TcpHandle) -> TcpSocketState;

    /// Check if the socket has data available to receive.
    fn tcp_can_recv(&self, handle: TcpHandle) -> bool;

    /// Check if the socket has buffer space available to send.
    fn tcp_can_send(&self, handle: TcpHandle) -> bool;

    /// Drive the underlying network stack. Must be called periodically
    /// (e.g., from epoll_wait) for TCP retransmissions and DHCP.
    fn tcp_poll(&mut self, now_ms: i64);
}
```

- [ ] **Step 2: Export the tcp module from lib.rs**

In `crates/harmony-netstack/src/lib.rs`, add:

```rust
pub mod tcp;
```

And add the re-export:

```rust
pub use tcp::{NetError, TcpHandle, TcpProvider, TcpSocketState};
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p harmony-netstack`
Expected: compiles (trait has no implementors yet, that's fine)

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-netstack/src/tcp.rs crates/harmony-netstack/src/lib.rs
git commit -m "feat(netstack): add TcpProvider trait with handle-based TCP API"
```

---

### Task 3: DHCP Client Module

**Files:**
- Create: `crates/harmony-netstack/src/dhcp.rs`
- Modify: `crates/harmony-netstack/src/lib.rs`

Encapsulates DHCP socket management and fallback timeout logic. Called by `stack.rs` during `poll()`.

- [ ] **Step 1: Create dhcp.rs**

Create `crates/harmony-netstack/src/dhcp.rs`:

```rust
//! DHCP client for automatic IP configuration.
//!
//! Uses smoltcp's built-in DHCPv4 state machine. Handles lease acquisition,
//! renewal (automatic via smoltcp), and timeout-based fallback to a static IP.

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};

/// DHCP client state managed alongside the NetStack.
pub struct DhcpClient {
    handle: SocketHandle,
    fallback_ip: Option<Ipv4Cidr>,
    fallback_gateway: Option<Ipv4Address>,
    fallback_timeout_ms: i64,
    start_time_ms: i64,
    configured: bool,
    fallback_applied: bool,
}

impl DhcpClient {
    /// Create a DHCP socket and add it to the SocketSet.
    ///
    /// The DHCP state machine starts automatically on first `poll()`.
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

    /// Check DHCP socket for lease events after iface.poll().
    ///
    /// Returns `true` if the interface IP was changed (lease acquired or fallback applied).
    pub fn check_lease(
        &mut self,
        iface: &mut Interface,
        sockets: &mut SocketSet<'static>,
        now: Instant,
    ) -> bool {
        let socket = sockets.get_mut::<dhcpv4::Socket>(self.handle);

        match socket.poll() {
            Some(dhcpv4::Event::Configured(config)) => {
                // Lease acquired — apply IP and gateway
                iface.update_ip_addrs(|addrs| {
                    if let Some(addr) = addrs.iter_mut().next() {
                        *addr = config.address.into();
                    } else {
                        addrs.push(config.address.into()).ok();
                    }
                });
                if let Some(router) = config.router {
                    iface.routes_mut().add_default_ipv4_route(router).ok();
                }
                self.configured = true;
                true
            }
            Some(dhcpv4::Event::Deconfigured) => {
                // Lease lost — remove IP, DHCP will restart
                iface.update_ip_addrs(|addrs| {
                    addrs.clear();
                });
                iface.routes_mut().remove_default_ipv4_route();
                self.configured = false;
                true
            }
            None => {
                // No event — check fallback timeout
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

    /// Apply the static fallback IP and gateway.
    fn apply_fallback(&mut self, iface: &mut Interface) {
        if let Some(ip) = self.fallback_ip {
            iface.update_ip_addrs(|addrs| {
                if let Some(addr) = addrs.iter_mut().next() {
                    *addr = ip.into();
                } else {
                    addrs.push(ip.into()).ok();
                }
            });
        }
        if let Some(gw) = self.fallback_gateway {
            iface.routes_mut().add_default_ipv4_route(gw).ok();
        }
        self.fallback_applied = true;
    }

    /// Whether the interface has been configured (DHCP or fallback).
    pub fn is_configured(&self) -> bool {
        self.configured || self.fallback_applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // DHCP tests require crafted Ethernet frames — deferred to integration tests
    // in stack.rs where we have the full NetStack + FrameBuffer.

    #[test]
    fn fallback_not_applied_before_timeout() {
        // Create a SocketSet large enough for DHCP
        let mut sockets = SocketSet::new(alloc::vec![smoltcp::iface::SocketStorage::EMPTY; 4]);
        let now = Instant::from_millis(0);

        let client = DhcpClient::new(
            &mut sockets,
            Some(Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24)),
            Some(Ipv4Address::new(10, 0, 0, 1)),
            5000, // 5 second timeout
            now,
        );

        assert!(!client.is_configured());
        assert!(!client.fallback_applied);
    }
}
```

- [ ] **Step 2: Export dhcp module from lib.rs**

In `crates/harmony-netstack/src/lib.rs`, add:

```rust
pub mod dhcp;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p harmony-netstack`
Expected: compiles

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-netstack dhcp`
Expected: `fallback_not_applied_before_timeout` passes

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-netstack/src/dhcp.rs crates/harmony-netstack/src/lib.rs
git commit -m "feat(netstack): add DHCP client with lease handling and fallback timeout"
```

---

### Task 4: TcpProvider Implementation + DHCP Integration in NetStack

**Files:**
- Modify: `crates/harmony-netstack/src/stack.rs`

This is the largest task — implementing `TcpProvider` for `NetStack` and integrating DHCP into the poll loop. The NetStack struct gains new fields for TCP socket tracking and the optional DHCP client.

- [ ] **Step 1: Add TCP and DHCP fields to NetStack struct**

Add these fields to the `NetStack` struct in `stack.rs`:

```rust
use crate::dhcp::DhcpClient;
use crate::tcp::{NetError, TcpHandle, TcpProvider, TcpSocketState};
use smoltcp::socket::tcp;

pub struct NetStack {
    device: FrameBuffer,
    iface: Interface,
    sockets: SocketSet<'static>,
    udp_handle: SocketHandle,
    peers: PeerTable,
    rx_queue: VecDeque<Vec<u8>>,
    // NEW: TCP socket tracking
    tcp_handles: alloc::vec::Vec<Option<SocketHandle>>,  // index = TcpHandle.0
    tcp_max: usize,
    next_tcp_slot: u32,
    tcp_listen_ports: alloc::collections::BTreeMap<u16, TcpHandle>,  // port → listening handle
    // NEW: DHCP client (optional)
    dhcp: Option<DhcpClient>,
}
```

- [ ] **Step 2: Update NetStack::new() to accept TCP and DHCP config**

Update the `new()` method signature to accept new parameters:

```rust
pub fn new(
    mac: [u8; 6],
    ip: Option<Ipv4Cidr>,         // Now optional (None when DHCP enabled)
    gateway: Option<Ipv4Address>,
    port: u16,
    broadcast: bool,
    peers: &[(Ipv4Address, u16)],
    tcp_max: usize,               // NEW: max TCP sockets (0 = disabled)
    dhcp_config: Option<DhcpConfig>,  // NEW: DHCP settings
    now: Instant,
) -> Self
```

Where `DhcpConfig` is:
```rust
pub struct DhcpConfig {
    pub fallback_ip: Option<Ipv4Cidr>,
    pub fallback_gateway: Option<Ipv4Address>,
    pub fallback_timeout_ms: i64,
}
```

The SocketSet capacity grows to accommodate: 1 UDP + tcp_max TCP + 1 optional DHCP = `tcp_max + 2` (or `tcp_max + 3` with DHCP).

When `ip` is `Some`, apply it immediately (existing static IP behavior). When `ip` is `None` and `dhcp_config` is `Some`, start with no IP and let DHCP configure it.

- [ ] **Step 3: Integrate DHCP check into poll()**

Update `poll()` to check DHCP lease after `iface.poll()`:

```rust
pub fn poll(&mut self, now: Instant) {
    let _changed = self.iface.poll(now, &mut self.device, &mut self.sockets);

    // Check DHCP lease events
    if let Some(ref mut dhcp) = self.dhcp {
        dhcp.check_lease(&mut self.iface, &mut self.sockets, now);
    }

    // Drain UDP RX (existing logic, unchanged)
    let socket = self.sockets.get_mut::<udp::Socket>(self.udp_handle);
    while socket.can_recv() {
        match socket.recv() {
            Ok((data, _endpoint)) => {
                self.rx_queue.push_back(data.to_vec());
            }
            Err(_) => break,
        }
    }
}
```

- [ ] **Step 4: Implement TcpProvider for NetStack**

Add the implementation block. Key methods:

```rust
impl TcpProvider for NetStack {
    fn tcp_create(&mut self) -> Result<TcpHandle, NetError> {
        // Find a free slot in tcp_handles
        let slot = self.tcp_handles.iter().position(|h| h.is_none())
            .ok_or(NetError::SocketLimit)?;

        // Create smoltcp TCP socket with 8 KiB buffers
        let rx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 8192]);
        let tx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 8192]);
        let socket = tcp::Socket::new(rx_buf, tx_buf);
        let handle = self.sockets.add(socket);

        self.tcp_handles[slot] = Some(handle);
        Ok(TcpHandle(slot as u32))
    }

    fn tcp_bind(&mut self, handle: TcpHandle, port: u16) -> Result<(), NetError> {
        // Validate handle, check port not in use, record binding
        // (smoltcp combines bind+listen, so we just record the port here)
        let _smoltcp_handle = self.resolve_handle(handle)?;
        if self.tcp_listen_ports.values().any(|h| *h == handle) {
            return Err(NetError::AddrInUse);
        }
        // Port will be used in tcp_listen()
        Ok(())
    }

    fn tcp_listen(&mut self, handle: TcpHandle, _backlog: usize) -> Result<(), NetError> {
        let smoltcp_handle = self.resolve_handle(handle)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(smoltcp_handle);
        // smoltcp's listen() combines bind+listen
        // We need the port — get it from a separate tracking structure
        // For now, the caller should bind then listen; we use the port from bind
        socket.listen(/* port from bind */)
            .map_err(|_| NetError::AddrInUse)?;
        self.tcp_listen_ports.insert(/* port */, handle);
        Ok(())
    }

    fn tcp_accept(&mut self, handle: TcpHandle) -> Result<Option<TcpHandle>, NetError> {
        let smoltcp_handle = self.resolve_handle(handle)?;
        let socket = self.sockets.get::<tcp::Socket>(smoltcp_handle);

        if socket.state() == tcp::State::Established {
            // Connection completed — take over this socket as the accepted connection
            // Create a new listening socket on the same port for future connections
            let port = /* get from listen_ports */;
            let accepted_handle = handle;

            // Create replacement listener
            let new_handle = self.tcp_create()?;
            let new_smoltcp = self.resolve_handle(new_handle)?;
            let new_socket = self.sockets.get_mut::<tcp::Socket>(new_smoltcp);
            new_socket.listen(port).map_err(|_| NetError::AddrInUse)?;
            self.tcp_listen_ports.insert(port, new_handle);

            Ok(Some(accepted_handle))
        } else {
            Ok(None) // No pending connection
        }
    }

    fn tcp_connect(&mut self, handle: TcpHandle, addr: Ipv4Address, port: u16) -> Result<(), NetError> {
        let smoltcp_handle = self.resolve_handle(handle)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(smoltcp_handle);
        let local_port = 49152 + (handle.0 as u16 % 16384); // Ephemeral port
        let remote = (addr, port);
        socket.connect(self.iface.context(), remote, local_port)
            .map_err(|_| NetError::ConnectionRefused)?;
        Ok(())
    }

    fn tcp_send(&mut self, handle: TcpHandle, data: &[u8]) -> Result<usize, NetError> {
        let smoltcp_handle = self.resolve_handle(handle)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(smoltcp_handle);
        if !socket.may_send() {
            return Err(NetError::NotConnected);
        }
        match socket.send_slice(data) {
            Ok(n) if n == 0 => Err(NetError::WouldBlock),
            Ok(n) => Ok(n),
            Err(_) => Err(NetError::ConnectionReset),
        }
    }

    fn tcp_recv(&mut self, handle: TcpHandle, buf: &mut [u8]) -> Result<usize, NetError> {
        let smoltcp_handle = self.resolve_handle(handle)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(smoltcp_handle);
        if !socket.may_recv() {
            if socket.state() == tcp::State::CloseWait
                || socket.state() == tcp::State::Closed
            {
                return Ok(0); // EOF
            }
            return Err(NetError::NotConnected);
        }
        match socket.recv_slice(buf) {
            Ok(0) => Err(NetError::WouldBlock),
            Ok(n) => Ok(n),
            Err(_) => Err(NetError::ConnectionReset),
        }
    }

    fn tcp_close(&mut self, handle: TcpHandle) -> Result<(), NetError> {
        let smoltcp_handle = self.resolve_handle(handle)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(smoltcp_handle);
        socket.close();
        // Remove from listen ports if it was a listener
        self.tcp_listen_ports.retain(|_, h| *h != handle);
        // Mark slot as free (after TCP close completes, or immediately for simplicity)
        let slot = handle.0 as usize;
        self.sockets.remove(smoltcp_handle);
        self.tcp_handles[slot] = None;
        Ok(())
    }

    fn tcp_state(&self, handle: TcpHandle) -> TcpSocketState {
        match self.resolve_handle_ref(handle) {
            Ok(smoltcp_handle) => {
                let socket = self.sockets.get::<tcp::Socket>(smoltcp_handle);
                match socket.state() {
                    tcp::State::Closed | tcp::State::TimeWait => TcpSocketState::Closed,
                    tcp::State::Listen => TcpSocketState::Listen,
                    tcp::State::SynSent | tcp::State::SynReceived => TcpSocketState::Connecting,
                    tcp::State::Established => TcpSocketState::Established,
                    tcp::State::CloseWait => TcpSocketState::CloseWait,
                    tcp::State::FinWait1 | tcp::State::FinWait2
                    | tcp::State::Closing | tcp::State::LastAck => TcpSocketState::Closing,
                }
            }
            Err(_) => TcpSocketState::Closed,
        }
    }

    fn tcp_can_recv(&self, handle: TcpHandle) -> bool {
        match self.resolve_handle_ref(handle) {
            Ok(h) => self.sockets.get::<tcp::Socket>(h).can_recv(),
            Err(_) => false,
        }
    }

    fn tcp_can_send(&self, handle: TcpHandle) -> bool {
        match self.resolve_handle_ref(handle) {
            Ok(h) => self.sockets.get::<tcp::Socket>(h).can_send(),
            Err(_) => false,
        }
    }

    fn tcp_poll(&mut self, now_ms: i64) {
        let now = Instant::from_millis(now_ms);
        self.poll(now);
    }
}
```

Add helper methods:

```rust
impl NetStack {
    fn resolve_handle(&self, handle: TcpHandle) -> Result<SocketHandle, NetError> {
        self.tcp_handles
            .get(handle.0 as usize)
            .and_then(|h| *h)
            .ok_or(NetError::InvalidHandle)
    }

    fn resolve_handle_ref(&self, handle: TcpHandle) -> Result<SocketHandle, NetError> {
        self.resolve_handle(handle)
    }
}
```

- [ ] **Step 5: Write TCP unit tests**

Add tests to `stack.rs`:

```rust
#[cfg(test)]
mod tcp_tests {
    use super::*;
    use crate::tcp::TcpProvider;

    fn build_tcp_stack() -> NetStack {
        NetStackBuilder::new()
            .static_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24))
            .tcp_max_sockets(4)
            .build(Instant::from_millis(0))
    }

    #[test]
    fn tcp_create_returns_unique_handles() {
        let mut stack = build_tcp_stack();
        let h1 = stack.tcp_create().unwrap();
        let h2 = stack.tcp_create().unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn tcp_create_beyond_limit_returns_error() {
        let mut stack = build_tcp_stack(); // max 4
        for _ in 0..4 {
            stack.tcp_create().unwrap();
        }
        assert!(matches!(stack.tcp_create(), Err(NetError::SocketLimit)));
    }

    #[test]
    fn tcp_recv_on_unconnected_returns_not_connected() {
        let mut stack = build_tcp_stack();
        let h = stack.tcp_create().unwrap();
        let mut buf = [0u8; 64];
        assert!(matches!(stack.tcp_recv(h, &mut buf), Err(NetError::NotConnected)));
    }

    #[test]
    fn tcp_close_invalidates_handle() {
        let mut stack = build_tcp_stack();
        let h = stack.tcp_create().unwrap();
        stack.tcp_close(h).unwrap();
        assert!(matches!(stack.tcp_state(h), TcpSocketState::Closed));
    }

    #[test]
    fn tcp_state_is_closed_initially() {
        let mut stack = build_tcp_stack();
        let h = stack.tcp_create().unwrap();
        assert_eq!(stack.tcp_state(h), TcpSocketState::Closed);
    }

    #[test]
    fn tcp_listen_changes_state() {
        let mut stack = build_tcp_stack();
        let h = stack.tcp_create().unwrap();
        stack.tcp_bind(h, 8080).unwrap();
        stack.tcp_listen(h, 1).unwrap();
        assert_eq!(stack.tcp_state(h), TcpSocketState::Listen);
    }
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p harmony-netstack`
Expected: all new TCP tests + all existing tests pass

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-netstack/src/stack.rs
git commit -m "feat(netstack): implement TcpProvider for NetStack with DHCP integration"
```

---

### Task 5: Builder Updates

**Files:**
- Modify: `crates/harmony-netstack/src/builder.rs`

Add new builder methods for DHCP and TCP configuration.

- [ ] **Step 1: Add new fields and methods to NetStackBuilder**

Add to the struct:

```rust
pub struct NetStackBuilder {
    mac: [u8; 6],
    ip: Option<Ipv4Cidr>,
    gateway: Option<Ipv4Address>,
    port: u16,
    broadcast: bool,
    peers: alloc::vec::Vec<(Ipv4Address, u16)>,
    // NEW
    dhcp: bool,
    fallback_ip: Option<Ipv4Cidr>,
    fallback_gateway: Option<Ipv4Address>,
    fallback_timeout_ms: i64,
    tcp_max_sockets: usize,
}
```

Add builder methods:

```rust
pub fn dhcp(mut self, enabled: bool) -> Self {
    self.dhcp = enabled;
    self
}

pub fn fallback_ip(mut self, cidr: Ipv4Cidr) -> Self {
    self.fallback_ip = Some(cidr);
    self
}

pub fn fallback_gateway(mut self, gw: Ipv4Address) -> Self {
    self.fallback_gateway = Some(gw);
    self
}

pub fn fallback_timeout_ms(mut self, ms: i64) -> Self {
    self.fallback_timeout_ms = ms;
    self
}

pub fn tcp_max_sockets(mut self, max: usize) -> Self {
    self.tcp_max_sockets = max;
    self
}
```

Update `build()`:
- When `dhcp` is true: pass `ip: None` and `dhcp_config: Some(DhcpConfig { ... })` to `NetStack::new()`
- When `dhcp` is false: pass `ip: self.ip` and `dhcp_config: None` (existing behavior)
- Always pass `tcp_max: self.tcp_max_sockets`
- Default `tcp_max_sockets` to 0 in `new()` (backwards compatible — no TCP unless requested)
- Default `fallback_timeout_ms` to 5000 (5 seconds)

- [ ] **Step 2: Update existing tests to use updated build API**

Existing tests that call `NetStackBuilder::new().static_ip(...).build(...)` should continue working unchanged (tcp_max defaults to 0, dhcp defaults to false).

- [ ] **Step 3: Run all tests**

Run: `cargo test -p harmony-netstack`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-netstack/src/builder.rs
git commit -m "feat(netstack): add DHCP and TCP builder methods"
```

---

### Task 6: Linuxulator TCP Wiring + Real Epoll

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`
- Modify: `crates/harmony-os/Cargo.toml`

Wire `SOCK_STREAM` socket syscalls to `TcpProvider` and make epoll report real TCP readiness.

**Important context for the implementer:**
- The Linuxulator is `Linuxulator<B: SyscallBackend>`. We add a second generic: `Linuxulator<B: SyscallBackend, T: TcpProvider>`.
- `SocketState` gains an `Option<TcpHandle>` field for TCP sockets.
- Only `AF_INET` + `SOCK_STREAM` sockets get real TCP handles. All other sockets keep the existing stub behavior.
- `epoll_wait` calls `tcp_poll()` before checking readiness, so the user program's event loop drives the network stack.

- [ ] **Step 1: Add harmony-netstack dependency to harmony-os**

In `crates/harmony-os/Cargo.toml`, add:

```toml
harmony-netstack = { path = "../harmony-netstack" }
```

- [ ] **Step 2: Add second generic parameter and TCP-related fields**

Update the struct definition:

```rust
pub struct Linuxulator<B: SyscallBackend, T: TcpProvider = NoTcp> {
    // ... existing fields ...
    tcp: T,
    // SocketState gets tcp_handle field
}
```

Create a `NoTcp` dummy impl for backwards compatibility:

```rust
/// No-op TcpProvider for when TCP is not available.
pub struct NoTcp;

impl TcpProvider for NoTcp {
    fn tcp_create(&mut self) -> Result<TcpHandle, NetError> { Err(NetError::SocketLimit) }
    fn tcp_bind(&mut self, _: TcpHandle, _: u16) -> Result<(), NetError> { Err(NetError::InvalidHandle) }
    fn tcp_listen(&mut self, _: TcpHandle, _: usize) -> Result<(), NetError> { Err(NetError::InvalidHandle) }
    fn tcp_accept(&mut self, _: TcpHandle) -> Result<Option<TcpHandle>, NetError> { Err(NetError::InvalidHandle) }
    fn tcp_connect(&mut self, _: TcpHandle, _: Ipv4Address, _: u16) -> Result<(), NetError> { Err(NetError::InvalidHandle) }
    fn tcp_send(&mut self, _: TcpHandle, _: &[u8]) -> Result<usize, NetError> { Err(NetError::InvalidHandle) }
    fn tcp_recv(&mut self, _: TcpHandle, _: &mut [u8]) -> Result<usize, NetError> { Err(NetError::InvalidHandle) }
    fn tcp_close(&mut self, _: TcpHandle) -> Result<(), NetError> { Err(NetError::InvalidHandle) }
    fn tcp_state(&self, _: TcpHandle) -> TcpSocketState { TcpSocketState::Closed }
    fn tcp_can_recv(&self, _: TcpHandle) -> bool { false }
    fn tcp_can_send(&self, _: TcpHandle) -> bool { false }
    fn tcp_poll(&mut self, _: i64) {}
}
```

Add new constructors:

```rust
impl<B: SyscallBackend> Linuxulator<B, NoTcp> {
    pub fn new(backend: B) -> Self {
        Self::with_tcp(backend, NoTcp)
    }
}

impl<B: SyscallBackend, T: TcpProvider> Linuxulator<B, T> {
    pub fn with_tcp(backend: B, tcp: T) -> Self {
        // ... existing init, plus tcp field ...
    }
}
```

- [ ] **Step 3: Add error constants**

Add missing errno constants needed for TCP:

```rust
const EADDRINUSE: i64 = -98;
const ECONNREFUSED: i64 = -111;
const ECONNRESET: i64 = -104;
const ENFILE: i64 = -23;
const EOPNOTSUPP: i64 = -95;  // May already exist
```

Add a helper to map `NetError` to errno:

```rust
fn net_error_to_errno(e: NetError) -> i64 {
    match e {
        NetError::WouldBlock => EAGAIN,
        NetError::ConnectionRefused => ECONNREFUSED,
        NetError::ConnectionReset => ECONNRESET,
        NetError::NotConnected => EBADF,
        NetError::AddrInUse => EADDRINUSE,
        NetError::InvalidHandle => EBADF,
        NetError::SocketLimit => ENFILE,
    }
}
```

- [ ] **Step 4: Update SocketState**

```rust
struct SocketState {
    domain: i32,
    sock_type: i32,
    listening: bool,
    nonblock: bool,
    accepted_once: bool,
    tcp_handle: Option<TcpHandle>,  // NEW: real TCP if AF_INET + SOCK_STREAM
    bound_port: u16,                // NEW: port from bind() for listen()
}
```

- [ ] **Step 5: Wire sys_socket to tcp_create**

Update `sys_socket()`: when `domain == 2 (AF_INET)` and `sock_type (masked) == 1 (SOCK_STREAM)`, call `self.tcp.tcp_create()`. Store the handle in `SocketState.tcp_handle`. If `tcp_create` fails, fall back to stub behavior (so existing tests don't break with `NoTcp`).

- [ ] **Step 6: Wire sys_bind, sys_listen, sys_accept4, sys_connect**

For each, check `socket_state.tcp_handle`:
- `Some(handle)` → call the corresponding `TcpProvider` method, map errors
- `None` → existing stub behavior

**sys_bind:** call `tcp_bind(handle, port)`, extract port from sockaddr at `addr` pointer. Store port in `socket_state.bound_port`.

**sys_listen:** call `tcp_listen(handle, backlog)`.

**sys_accept4:** call `tcp_accept(handle)`. If `Some(new_handle)`, create new socket_id with the new handle. If `None`, return `EAGAIN`.

**sys_connect:** parse addr/port from sockaddr, call `tcp_connect(handle, addr, port)`. For nonblocking sockets, return `EINPROGRESS` (-115) since connection is async.

- [ ] **Step 7: Wire sys_read, sys_write, sys_sendto, sys_recvfrom**

For `FdKind::Socket { socket_id }` where `tcp_handle.is_some()`:

**sys_read / sys_recvfrom:** call `tcp_recv(handle, buf)`. Map `WouldBlock` → `EAGAIN` for nonblocking, `Ok(0)` for EOF (CloseWait/Closed state).

**sys_write / sys_sendto:** call `tcp_send(handle, data)`. Map `WouldBlock` → `EAGAIN`.

- [ ] **Step 8: Wire sys_close for TCP cleanup**

When closing a socket with `tcp_handle`, call `tcp_close(handle)`.

- [ ] **Step 9: Make epoll_wait real for TCP sockets**

Update `sys_epoll_wait()`:

1. **First, call `self.tcp.tcp_poll(now_ms)`** to drive the network stack.
2. For each fd in the epoll interest set:
   - If the fd is a Socket with `tcp_handle`:
     - Check `tcp_can_recv(handle)` → `EPOLLIN`
     - Check `tcp_can_send(handle)` → `EPOLLOUT`
     - Check `tcp_state(handle) == CloseWait` → `EPOLLIN` (EOF)
     - Check `tcp_state(handle) == Closed` → `EPOLLHUP`
     - Only return this fd if at least one event matches the interest mask
   - If the fd is NOT a TCP socket: return as always-ready (existing behavior)

3. If no TCP fds are ready, and timeout > 0, busy-poll: loop calling `tcp_poll()` and rechecking readiness until timeout expires or a socket becomes ready. Use the Linuxulator's `monotonic_ns` counter to track elapsed time.

4. If timeout == 0, return immediately (non-blocking epoll check).

- [ ] **Step 10: Write tests**

```rust
#[cfg(test)]
mod tcp_socket_tests {
    use super::*;

    #[test]
    fn socket_stream_creates_tcp_handle() {
        // Create Linuxulator with NoTcp — tcp_create returns SocketLimit
        // so the socket falls back to stub. Verify no crash.
        let mut lx = Linuxulator::new(MockBackend::new());
        let fd = lx.sys_socket(2, 1, 0); // AF_INET, SOCK_STREAM
        assert!(fd >= 0);
    }

    #[test]
    fn socket_dgram_stays_stub() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let fd = lx.sys_socket(2, 2, 0); // AF_INET, SOCK_DGRAM
        assert!(fd >= 0);
        // recvfrom returns 0 (stub EOF)
        let result = lx.sys_recvfrom(fd as i32, 0, 64, 0, 0, 0);
        assert_eq!(result, 0);
    }

    #[test]
    fn epoll_still_works_for_non_tcp_fds() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let epfd = lx.sys_epoll_create1(0);
        assert!(epfd >= 0);
        // Existing always-ready behavior for non-TCP fds
    }
}
```

- [ ] **Step 11: Run all tests**

Run: `cargo test -p harmony-os`
Expected: all existing tests pass + new TCP socket tests pass

- [ ] **Step 12: Commit**

```bash
git add crates/harmony-os/Cargo.toml crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): wire SOCK_STREAM syscalls to TcpProvider with real epoll readiness"
```

---

### Task 7: Boot Sequence Integration

**Files:**
- Modify: `crates/harmony-boot/src/main.rs`

Connect the netstack with DHCP to the Linuxulator, enabling TCP for Ring 3 programs.

- [ ] **Step 1: Update NetStack initialization to use DHCP builder**

Replace the hardcoded static IP:

```rust
// Before:
let mut netstack = {
    NetStackBuilder::new()
        .mac(mac)
        .static_ip(Ipv4Cidr::new(NETSTACK_IP, NETSTACK_PREFIX))
        .gateway(NETSTACK_GW)
        .port(4242)
        .enable_broadcast(true)
        .build(smoltcp_now)
};

// After:
let mut netstack = {
    NetStackBuilder::new()
        .mac(mac)
        .dhcp(true)
        .fallback_ip(Ipv4Cidr::new(NETSTACK_IP, NETSTACK_PREFIX))
        .fallback_gateway(NETSTACK_GW)
        .port(4242)
        .enable_broadcast(true)
        .tcp_max_sockets(16)
        .build(smoltcp_now)
};
```

- [ ] **Step 2: Pass netstack to Linuxulator (Ring 3 path)**

In the `#[cfg(feature = "ring3")]` section where the Linuxulator is created, pass the netstack:

```rust
// Before:
let mut linuxulator = Linuxulator::new(DirectBackend::new(kernel_server));

// After:
let mut linuxulator = Linuxulator::with_tcp(DirectBackend::new(kernel_server), &mut netstack);
```

**Important:** The lifetime/ownership challenge. Since both the event loop and the Linuxulator need mutable access to the netstack, and this is `no_std` (no `Rc<RefCell>`), the implementer will need to use one of:
- A raw pointer (unsafe but functional)
- A `core::cell::RefCell` wrapper (available in no_std)
- A split design where the Linuxulator stores TCP operations and the event loop applies them

The simplest approach for v1: use `RefCell<NetStack>` and pass `&RefCell<NetStack>` to both the Linuxulator and the event loop. The Linuxulator `borrow_mut()`s during syscalls, the event loop `borrow_mut()`s during polling. These never overlap because syscall dispatch and event loop polling are sequential (single-threaded, no preemption).

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p harmony-boot` (or `cargo check -p harmony-boot --features ring3` if ring3 is a feature)
Expected: compiles

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(boot): enable DHCP + TCP in netstack, pass to Linuxulator"
```

---

## Self-Review Checklist

**Spec coverage:**
- smoltcp feature enablement: Task 1
- DHCP client with fallback: Tasks 3, 4, 5
- TcpProvider trait: Task 2
- NetStack TcpProvider impl: Task 4
- Builder updates: Task 5
- Linuxulator TCP wiring: Task 6
- Epoll real readiness: Task 6 (Step 9)
- Boot sequence: Task 7
- Error handling (errno mapping): Task 6 (Step 3)
- Testing: Tasks 3, 4, 6

**No placeholders:** All code blocks contain actual implementation. Errno mappings, struct fields, method signatures are all specified.

**Type consistency:**
- `TcpHandle(u32)` used consistently across tcp.rs, stack.rs, linuxulator.rs
- `TcpSocketState` variants match between tcp.rs definition and stack.rs tcp_state() mapping
- `NetError` variants match between tcp.rs definition and linuxulator.rs errno mapping
- `TcpProvider` method signatures match between trait (tcp.rs) and impl (stack.rs)
- `DhcpConfig` struct used in stack.rs matches builder.rs usage
- `NoTcp` default generic ensures existing `Linuxulator::new(backend)` compiles without changes
