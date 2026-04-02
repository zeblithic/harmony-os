# UDP Socket Bridging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bridge Linux SOCK_DGRAM syscalls through smoltcp's UDP support so userspace programs (notably DNS resolvers) can send and receive UDP packets.

**Architecture:** New `UdpProvider` trait in `harmony-netstack` (parallel to `TcpProvider`), implemented by `NetStack` using smoltcp `udp::Socket`. The Linuxulator gets `T: TcpProvider + UdpProvider` bound; `SocketState` gains a `udp_handle` field. Connected-mode UDP stores peer endpoint in the netstack for musl DNS compatibility.

**Tech Stack:** Rust (no_std), smoltcp UDP sockets, harmony-netstack, harmony-os Linuxulator

**Spec:** `docs/superpowers/specs/2026-04-02-udp-socket-bridging-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `crates/harmony-netstack/src/udp.rs` | **New** — `UdpHandle` type, `UdpProvider` trait definition |
| `crates/harmony-netstack/src/lib.rs` | Export `udp` module and public types |
| `crates/harmony-netstack/src/builder.rs` | `udp_max_sockets` builder field + setter |
| `crates/harmony-netstack/src/stack.rs` | `UdpProvider` impl for `NetStack` — socket management, sendto/recvfrom, connected mode |
| `crates/harmony-os/src/linuxulator.rs` | Generic bound change, SocketState `udp_handle`, syscall routing, readiness, sockaddr helpers |
| `crates/harmony-boot/src/main.rs` | `UdpProvider` impl for `RawPtrTcpProvider` (delegation) |

---

### Task 1: UdpProvider Trait and UdpHandle

**Files:**
- Create: `crates/harmony-netstack/src/udp.rs`
- Modify: `crates/harmony-netstack/src/lib.rs:1-17`

- [ ] **Step 1: Create `udp.rs` with `UdpHandle` and `UdpProvider` trait**

```rust
// crates/harmony-netstack/src/udp.rs
// SPDX-License-Identifier: GPL-2.0-or-later
//! Handle-based UDP API for the Linuxulator.

use smoltcp::wire::Ipv4Address;

use crate::tcp::NetError;

/// Opaque handle to a UDP socket managed by NetStack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpHandle(pub u32);

/// Abstract UDP socket operations.
pub trait UdpProvider {
    fn udp_create(&mut self) -> Result<UdpHandle, NetError>;
    fn udp_bind(&mut self, handle: UdpHandle, port: u16) -> Result<(), NetError>;
    fn udp_close(&mut self, handle: UdpHandle) -> Result<(), NetError>;
    fn udp_can_recv(&self, handle: UdpHandle) -> bool;
    fn udp_can_send(&self, handle: UdpHandle) -> bool;

    /// Send data to a specific remote address (unconnected mode).
    fn udp_sendto(
        &mut self,
        handle: UdpHandle,
        data: &[u8],
        addr: Ipv4Address,
        port: u16,
    ) -> Result<usize, NetError>;

    /// Receive data and source address (unconnected mode).
    fn udp_recvfrom(
        &mut self,
        handle: UdpHandle,
        buf: &mut [u8],
    ) -> Result<(usize, Ipv4Address, u16), NetError>;

    /// Store a remote endpoint for connected-mode send/recv.
    fn udp_connect(
        &mut self,
        handle: UdpHandle,
        addr: Ipv4Address,
        port: u16,
    ) -> Result<(), NetError>;

    /// Send data using the stored connected endpoint.
    /// Returns `NetError::NotConnected` if no prior `udp_connect`.
    fn udp_send(&mut self, handle: UdpHandle, data: &[u8]) -> Result<usize, NetError>;

    /// Receive data, filtering to only the connected peer.
    /// Non-matching packets are silently dropped.
    /// Returns `NetError::NotConnected` if no prior `udp_connect`.
    fn udp_recv(
        &mut self,
        handle: UdpHandle,
        buf: &mut [u8],
    ) -> Result<(usize, Ipv4Address, u16), NetError>;

    /// Drive the underlying network stack. No-op for `NetStack` (shared with TCP poll).
    fn udp_poll(&mut self, now_ms: i64);
}
```

- [ ] **Step 2: Add `udp` module to `lib.rs` and export types**

In `crates/harmony-netstack/src/lib.rs`, add the module and re-exports. The file should become:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
#![no_std]
extern crate alloc;

pub mod builder;
pub mod config;
pub mod device;
pub mod dhcp;
pub mod peers;
pub mod stack;
pub mod tcp;
pub mod udp;

pub use builder::NetStackBuilder;
pub use smoltcp;
pub use stack::NetStack;
pub use tcp::{NetError, TcpHandle, TcpProvider, TcpSocketState};
pub use udp::{UdpHandle, UdpProvider};
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p harmony-netstack`
Expected: Compiles with no errors. The trait is defined but not yet implemented.

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-netstack/src/udp.rs crates/harmony-netstack/src/lib.rs
git commit -m "feat(netstack): add UdpHandle type and UdpProvider trait"
```

---

### Task 2: Builder — `udp_max_sockets`

**Files:**
- Modify: `crates/harmony-netstack/src/builder.rs:14-28` (struct fields)
- Modify: `crates/harmony-netstack/src/builder.rs:31-44` (defaults)
- Modify: `crates/harmony-netstack/src/builder.rs:120-153` (build method)
- Modify: `crates/harmony-netstack/src/stack.rs:55-65` (new() signature)

- [ ] **Step 1: Add `udp_max_sockets` field to `NetStackBuilder`**

In `crates/harmony-netstack/src/builder.rs`, add the field to the struct (after `tcp_max_sockets`):

```rust
    // TCP
    tcp_max_sockets: usize,
    // UDP
    udp_max_sockets: usize,
```

In `new()`, initialize it (after `tcp_max_sockets: 0`):

```rust
            tcp_max_sockets: 0,
            udp_max_sockets: 4,
```

- [ ] **Step 2: Add setter method**

Add after the `tcp_max_sockets` setter (after line 118):

```rust
    /// Maximum number of concurrent userspace UDP sockets.
    ///
    /// Defaults to 4. Set to 0 to disable userspace UDP support.
    pub fn udp_max_sockets(mut self, max: usize) -> Self {
        self.udp_max_sockets = max;
        self
    }
```

- [ ] **Step 3: Pass `udp_max_sockets` through `build()`**

In the `build` method, change the `NetStack::new` call to pass `self.udp_max_sockets`:

```rust
        NetStack::new(
            self.mac,
            ip,
            self.gateway,
            self.port,
            self.broadcast,
            &self.peers,
            self.tcp_max_sockets,
            self.udp_max_sockets,
            dhcp_config,
            now,
        )
```

- [ ] **Step 4: Update `NetStack::new` signature**

In `crates/harmony-netstack/src/stack.rs`, add `udp_max_sockets: usize` parameter to `new()` after `tcp_max_sockets`:

```rust
    pub(crate) fn new(
        mac: [u8; 6],
        ip: Option<Ipv4Cidr>,
        gateway: Option<Ipv4Address>,
        port: u16,
        broadcast: bool,
        peers: &[(Ipv4Address, u16)],
        tcp_max_sockets: usize,
        udp_max_sockets: usize,
        dhcp_config: Option<DhcpConfig>,
        now: Instant,
    ) -> Self {
```

Update the socket capacity calculation (line 85):

```rust
        // Build socket storage with room for mesh UDP + userspace UDP + TCP + DHCP + spare.
        let socket_capacity = tcp_max_sockets + udp_max_sockets + 3;
```

Add `udp_handles` field initialization alongside `tcp_handles` (after line 115):

```rust
        let tcp_handles = vec![None; tcp_max_sockets];
        let udp_handles = vec![None; udp_max_sockets];
```

Add the new fields to the `Self` initializer:

```rust
            tcp_handles,
            // UDP userspace sockets
            udp_handles,
            udp_bound_ports: BTreeMap::new(),
            udp_connected: BTreeMap::new(),
            udp_next_ephemeral: 49152,
```

- [ ] **Step 5: Add the new fields to `NetStack` struct**

In the `NetStack` struct definition (after `tcp_user_closed`), add:

```rust
    // UDP userspace sockets
    udp_handles: Vec<Option<SocketHandle>>,
    udp_bound_ports: BTreeMap<UdpHandle, u16>,
    udp_connected: BTreeMap<UdpHandle, (Ipv4Address, u16)>,
    /// Next ephemeral port for outbound UDP.
    udp_next_ephemeral: u16,
```

Add the `UdpHandle` import to the top of `stack.rs`:

```rust
use crate::udp::UdpHandle;
```

- [ ] **Step 6: Verify it compiles**

Run: `cargo build -p harmony-netstack`
Expected: Compiles. The fields exist but `UdpProvider` is not yet implemented.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-netstack/src/builder.rs crates/harmony-netstack/src/stack.rs
git commit -m "feat(netstack): add udp_max_sockets to builder and NetStack fields"
```

---

### Task 3: NetStack UdpProvider Implementation

**Files:**
- Modify: `crates/harmony-netstack/src/stack.rs` — add `resolve_udp` helper and `impl UdpProvider for NetStack`

**Reference:** The `TcpProvider` impl is at `crates/harmony-netstack/src/stack.rs:252-491`. Follow the same patterns for handle resolution, slot management, and error mapping.

- [ ] **Step 1: Write failing test — `udp_create_returns_unique_handles`**

Add a new test module in `crates/harmony-netstack/src/stack.rs`, after the existing `tcp_tests` module (after line 812). Add this inside a new `mod udp_tests`:

```rust
#[cfg(test)]
mod udp_tests {
    use super::*;
    use crate::builder::NetStackBuilder;
    use crate::udp::UdpProvider;
    use smoltcp::time::Instant;
    use smoltcp::wire::{Ipv4Address, Ipv4Cidr};

    fn build_udp_stack() -> NetStack {
        NetStackBuilder::new()
            .static_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24))
            .udp_max_sockets(4)
            .build(Instant::from_millis(0))
    }

    #[test]
    fn udp_create_returns_unique_handles() {
        let mut s = build_udp_stack();
        let h1 = s.udp_create().unwrap();
        let h2 = s.udp_create().unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn udp_create_beyond_limit() {
        let mut s = build_udp_stack();
        for _ in 0..4 {
            s.udp_create().unwrap();
        }
        assert!(matches!(s.udp_create(), Err(NetError::SocketLimit)));
    }

    #[test]
    fn udp_close_frees_slot() {
        let mut s = build_udp_stack();
        let h = s.udp_create().unwrap();
        s.udp_close(h).unwrap();
        // Slot should be reusable.
        let h2 = s.udp_create().unwrap();
        assert_eq!(h, h2); // Same slot index reused.
    }

    #[test]
    fn udp_bind_and_port_conflict() {
        let mut s = build_udp_stack();
        let h1 = s.udp_create().unwrap();
        let h2 = s.udp_create().unwrap();
        s.udp_bind(h1, 5353).unwrap();
        assert!(matches!(s.udp_bind(h2, 5353), Err(NetError::AddrInUse)));
    }

    #[test]
    fn udp_can_send_after_bind() {
        let mut s = build_udp_stack();
        let h = s.udp_create().unwrap();
        s.udp_bind(h, 5353).unwrap();
        assert!(s.udp_can_send(h));
    }

    #[test]
    fn udp_recvfrom_empty_returns_wouldblock() {
        let mut s = build_udp_stack();
        let h = s.udp_create().unwrap();
        s.udp_bind(h, 5353).unwrap();
        let mut buf = [0u8; 512];
        assert!(matches!(s.udp_recvfrom(h, &mut buf), Err(NetError::WouldBlock)));
    }

    #[test]
    fn udp_send_without_connect_returns_not_connected() {
        let mut s = build_udp_stack();
        let h = s.udp_create().unwrap();
        s.udp_bind(h, 5353).unwrap();
        assert!(matches!(
            s.udp_send(h, b"hello"),
            Err(NetError::NotConnected)
        ));
    }

    #[test]
    fn udp_recv_without_connect_returns_not_connected() {
        let mut s = build_udp_stack();
        let h = s.udp_create().unwrap();
        s.udp_bind(h, 5353).unwrap();
        let mut buf = [0u8; 512];
        assert!(matches!(
            s.udp_recv(h, &mut buf),
            Err(NetError::NotConnected)
        ));
    }

    #[test]
    fn udp_connect_stores_peer() {
        let mut s = build_udp_stack();
        let h = s.udp_create().unwrap();
        s.udp_connect(h, Ipv4Address::new(8, 8, 8, 8), 53).unwrap();
        // After connect, udp_send should not return NotConnected
        // (it may return WouldBlock due to no route, but NOT NotConnected).
        let result = s.udp_send(h, b"hello");
        assert!(!matches!(result, Err(NetError::NotConnected)));
    }

    #[test]
    fn udp_sendto_auto_binds() {
        let mut s = build_udp_stack();
        let h = s.udp_create().unwrap();
        // sendto without explicit bind should auto-bind to an ephemeral port.
        // It may fail with WouldBlock (no ARP entry), but NOT InvalidHandle.
        let result = s.udp_sendto(h, b"hello", Ipv4Address::new(10, 0, 0, 2), 5353);
        assert!(!matches!(result, Err(NetError::InvalidHandle)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-netstack udp_tests`
Expected: Compilation error — `UdpProvider` not implemented for `NetStack`.

- [ ] **Step 3: Add `resolve_udp` helper to NetStack**

Add after the existing `tcp_close_internal` method (around line 206):

```rust
    /// Resolve a `UdpHandle` to the underlying smoltcp `SocketHandle`.
    fn resolve_udp(&self, handle: UdpHandle) -> Result<SocketHandle, NetError> {
        self.udp_handles
            .get(handle.0 as usize)
            .and_then(|h| *h)
            .ok_or(NetError::InvalidHandle)
    }
```

- [ ] **Step 4: Implement `UdpProvider` for `NetStack`**

Add after the `TcpProvider` impl block (after line 491):

```rust
impl UdpProvider for NetStack {
    fn udp_create(&mut self) -> Result<UdpHandle, NetError> {
        let slot = self
            .udp_handles
            .iter()
            .position(|h| h.is_none())
            .ok_or(NetError::SocketLimit)?;

        let rx_buf = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 8],
            vec![0; 4096],
        );
        let tx_buf = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 8],
            vec![0; 4096],
        );
        let socket = udp::Socket::new(rx_buf, tx_buf);
        let smoltcp_handle = self.sockets.add(socket);
        self.udp_handles[slot] = Some(smoltcp_handle);
        Ok(UdpHandle(slot as u32))
    }

    fn udp_bind(&mut self, handle: UdpHandle, port: u16) -> Result<(), NetError> {
        let smoltcp_handle = self.resolve_udp(handle)?;
        if self.udp_bound_ports.values().any(|&p| p == port) {
            return Err(NetError::AddrInUse);
        }
        self.sockets
            .get_mut::<udp::Socket>(smoltcp_handle)
            .bind(port)
            .map_err(|_| NetError::AddrInUse)?;
        self.udp_bound_ports.insert(handle, port);
        Ok(())
    }

    fn udp_close(&mut self, handle: UdpHandle) -> Result<(), NetError> {
        let smoltcp_handle = self.resolve_udp(handle)?;
        self.sockets.get_mut::<udp::Socket>(smoltcp_handle).close();
        self.sockets.remove(smoltcp_handle);
        self.udp_handles[handle.0 as usize] = None;
        self.udp_bound_ports.remove(&handle);
        self.udp_connected.remove(&handle);
        Ok(())
    }

    fn udp_can_recv(&self, handle: UdpHandle) -> bool {
        self.resolve_udp(handle)
            .ok()
            .map(|h| self.sockets.get::<udp::Socket>(h).can_recv())
            .unwrap_or(false)
    }

    fn udp_can_send(&self, handle: UdpHandle) -> bool {
        self.resolve_udp(handle)
            .ok()
            .map(|h| self.sockets.get::<udp::Socket>(h).can_send())
            .unwrap_or(false)
    }

    fn udp_sendto(
        &mut self,
        handle: UdpHandle,
        data: &[u8],
        addr: Ipv4Address,
        port: u16,
    ) -> Result<usize, NetError> {
        // Auto-bind to ephemeral port if not yet bound.
        if !self.udp_bound_ports.contains_key(&handle) {
            let ep_port = self.udp_next_ephemeral;
            self.udp_next_ephemeral = if ep_port == 65535 { 49152 } else { ep_port + 1 };
            self.udp_bind(handle, ep_port)?;
        }
        let smoltcp_handle = self.resolve_udp(handle)?;
        let dest = (IpAddress::Ipv4(addr), port);
        let socket = self.sockets.get_mut::<udp::Socket>(smoltcp_handle);
        if !socket.can_send() {
            return Err(NetError::WouldBlock);
        }
        socket
            .send_slice(data, dest)
            .map_err(|_| NetError::WouldBlock)?;
        Ok(data.len())
    }

    fn udp_recvfrom(
        &mut self,
        handle: UdpHandle,
        buf: &mut [u8],
    ) -> Result<(usize, Ipv4Address, u16), NetError> {
        let smoltcp_handle = self.resolve_udp(handle)?;
        let socket = self.sockets.get_mut::<udp::Socket>(smoltcp_handle);
        if !socket.can_recv() {
            return Err(NetError::WouldBlock);
        }
        match socket.recv_slice(buf) {
            Ok((len, endpoint)) => {
                let src_addr = match endpoint.endpoint.addr {
                    IpAddress::Ipv4(a) => a,
                    _ => Ipv4Address::UNSPECIFIED,
                };
                Ok((len, src_addr, endpoint.endpoint.port))
            }
            Err(_) => Err(NetError::WouldBlock),
        }
    }

    fn udp_connect(
        &mut self,
        handle: UdpHandle,
        addr: Ipv4Address,
        port: u16,
    ) -> Result<(), NetError> {
        let _ = self.resolve_udp(handle)?;
        // Auto-bind to ephemeral port if not yet bound.
        if !self.udp_bound_ports.contains_key(&handle) {
            let ep_port = self.udp_next_ephemeral;
            self.udp_next_ephemeral = if ep_port == 65535 { 49152 } else { ep_port + 1 };
            self.udp_bind(handle, ep_port)?;
        }
        self.udp_connected.insert(handle, (addr, port));
        Ok(())
    }

    fn udp_send(&mut self, handle: UdpHandle, data: &[u8]) -> Result<usize, NetError> {
        let (addr, port) = self
            .udp_connected
            .get(&handle)
            .copied()
            .ok_or(NetError::NotConnected)?;
        self.udp_sendto(handle, data, addr, port)
    }

    fn udp_recv(
        &mut self,
        handle: UdpHandle,
        buf: &mut [u8],
    ) -> Result<(usize, Ipv4Address, u16), NetError> {
        let (peer_addr, peer_port) = self
            .udp_connected
            .get(&handle)
            .copied()
            .ok_or(NetError::NotConnected)?;
        // Loop, dropping packets from non-connected sources.
        loop {
            let (len, src_addr, src_port) = self.udp_recvfrom(handle, buf)?;
            if src_addr == peer_addr && src_port == peer_port {
                return Ok((len, src_addr, src_port));
            }
            // Non-matching packet — drop and try again.
            // udp_recvfrom returns WouldBlock when buffer is empty, breaking the loop.
        }
    }

    fn udp_poll(&mut self, now_ms: i64) {
        // No-op: the shared iface.poll() in poll_network() drives all sockets.
        let _ = now_ms;
    }
}
```

- [ ] **Step 5: Add `UdpProvider` import to `stack.rs`**

At the top of `stack.rs`, add to the existing `crate::` imports:

```rust
use crate::udp::{UdpHandle, UdpProvider};
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p harmony-netstack udp_tests`
Expected: All 10 tests pass.

- [ ] **Step 7: Run full netstack tests to check for regressions**

Run: `cargo test -p harmony-netstack`
Expected: All existing tests still pass (TCP tests, UDP mesh tests, builder tests).

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-netstack/src/stack.rs
git commit -m "feat(netstack): implement UdpProvider for NetStack"
```

---

### Task 4: NoUdp Stub on `NoTcp`

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:132-174` (add `impl UdpProvider for NoTcp` after the `TcpProvider` impl)

**Context:** `NoTcp` is at `crates/harmony-os/src/linuxulator.rs:132`. It's the zero-cost stub used when the Linuxulator has no network stack. It needs to implement `UdpProvider` too, so that `NoTcp` satisfies the `T: TcpProvider + UdpProvider` bound.

- [ ] **Step 1: Write failing test**

Add a test in the existing test module (around line 12555 area) to verify `NoTcp` can be used where `UdpProvider` is required:

```rust
    #[test]
    fn no_tcp_implements_udp_provider() {
        use harmony_netstack::udp::UdpProvider;
        let mut no_tcp = NoTcp;
        assert!(no_tcp.udp_create().is_err());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-os no_tcp_implements_udp_provider`
Expected: Compilation error — `UdpProvider` not implemented for `NoTcp`.

- [ ] **Step 3: Implement `UdpProvider` for `NoTcp`**

In `crates/harmony-os/src/linuxulator.rs`, after the `impl TcpProvider for NoTcp` block (after line 174), add:

```rust
impl harmony_netstack::udp::UdpProvider for NoTcp {
    fn udp_create(&mut self) -> Result<harmony_netstack::UdpHandle, harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::SocketLimit)
    }
    fn udp_bind(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: u16,
    ) -> Result<(), harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_close(
        &mut self,
        _: harmony_netstack::UdpHandle,
    ) -> Result<(), harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_can_recv(&self, _: harmony_netstack::UdpHandle) -> bool {
        false
    }
    fn udp_can_send(&self, _: harmony_netstack::UdpHandle) -> bool {
        false
    }
    fn udp_sendto(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: &[u8],
        _: harmony_netstack::smoltcp::wire::Ipv4Address,
        _: u16,
    ) -> Result<usize, harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_recvfrom(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: &mut [u8],
    ) -> Result<(usize, harmony_netstack::smoltcp::wire::Ipv4Address, u16), harmony_netstack::NetError>
    {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_connect(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: harmony_netstack::smoltcp::wire::Ipv4Address,
        _: u16,
    ) -> Result<(), harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_send(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: &[u8],
    ) -> Result<usize, harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_recv(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: &mut [u8],
    ) -> Result<(usize, harmony_netstack::smoltcp::wire::Ipv4Address, u16), harmony_netstack::NetError>
    {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_poll(&mut self, _: i64) {}
}
```

- [ ] **Step 4: Run test**

Run: `cargo test -p harmony-os no_tcp_implements_udp_provider`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): implement UdpProvider for NoTcp stub"
```

---

### Task 5: Linuxulator Generic Bound and SocketState Changes

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`
  - Line 2309: struct generic bound
  - Lines 2157-2171: SocketState struct
  - Lines 2409-2419: `impl` blocks
  - Line 4300-4304: `sys_socket` UDP handle creation

**Context:** This task changes the Linuxulator's generic bound from `T: TcpProvider` to `T: TcpProvider + UdpProvider`, adds `udp_handle` to `SocketState`, and wires `sys_socket` to create UDP handles for `SOCK_DGRAM`. This is a mechanical change but touches many `impl` blocks due to the bound change.

- [ ] **Step 1: Write failing test — SOCK_DGRAM creates socket with udp_handle**

```rust
    #[test]
    fn test_socket_dgram_creates_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // AF_INET (2), SOCK_DGRAM (2), protocol 0
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,
            sock_type: 2,
            protocol: 0,
        });
        assert!(fd >= 0, "socket(AF_INET, SOCK_DGRAM) should return valid fd, got {fd}");
        assert!(lx.has_fd(fd as i32));
    }
```

- [ ] **Step 2: Run test to verify current behavior**

Run: `cargo test -p harmony-os test_socket_dgram_creates_fd`
Expected: PASS (SOCK_DGRAM already creates a stub socket fd). This is a baseline — the next steps make it create a real UDP handle.

- [ ] **Step 3: Change the generic bound**

In `crates/harmony-os/src/linuxulator.rs`:

Change line 2309:
```rust
pub struct Linuxulator<B: SyscallBackend, T: TcpProvider = NoTcp> {
```
to:
```rust
pub struct Linuxulator<B: SyscallBackend, T: TcpProvider + harmony_netstack::udp::UdpProvider = NoTcp> {
```

Change the impl block at line 2421:
```rust
impl<B: SyscallBackend, T: TcpProvider> Linuxulator<B, T> {
```
to:
```rust
impl<B: SyscallBackend, T: TcpProvider + harmony_netstack::udp::UdpProvider> Linuxulator<B, T> {
```

Search for all other `impl` blocks that reference `T: TcpProvider` and update them. Key locations:
- `impl<B: SyscallBackend, T: TcpProvider> Clone for Linuxulator<B, T>` (if present)
- `ChildProcess<B, T>` struct and its usages

The `impl<B: SyscallBackend> Linuxulator<B, NoTcp>` block (line 2409) stays unchanged since `NoTcp` already implements both traits after Task 4.

- [ ] **Step 4: Add `udp_handle` to `SocketState`**

In the `SocketState` struct (line 2157), add after `tcp_handle`:

```rust
    /// Handle into the UdpProvider, if socket was created as SOCK_DGRAM
    /// via udp_create. None for SOCK_STREAM/AF_UNIX/stub sockets.
    udp_handle: Option<harmony_netstack::UdpHandle>,
```

Update every place that constructs a `SocketState` to include `udp_handle: None`. Search for `SocketState {` in the file — there will be several (in `sys_socket`, `sys_accept4`, `sys_socketpair`, and `fork`/`clone` code). Add `udp_handle: None,` to each.

- [ ] **Step 5: Wire `sys_socket` for SOCK_DGRAM**

In `sys_socket` (around line 4297), after the TCP handle creation:

Change from:
```rust
        const SOCK_STREAM: i32 = 1;

        // Attempt to create a real TCP handle for AF_INET SOCK_STREAM sockets.
        let tcp_handle = if domain == AF_INET && base_type == SOCK_STREAM {
            self.tcp.tcp_create().ok()
        } else {
            None
        };
```

To:
```rust
        const SOCK_STREAM: i32 = 1;
        const SOCK_DGRAM: i32 = 2;

        // Attempt to create a real TCP handle for AF_INET SOCK_STREAM sockets.
        let tcp_handle = if domain == AF_INET && base_type == SOCK_STREAM {
            self.tcp.tcp_create().ok()
        } else {
            None
        };

        // Attempt to create a real UDP handle for AF_INET SOCK_DGRAM sockets.
        let udp_handle = if domain == AF_INET && base_type == SOCK_DGRAM {
            self.tcp.udp_create().ok()
        } else {
            None
        };
```

And in the `SocketState` construction inside `sys_socket`, add the `udp_handle` field:

```rust
            SocketState {
                domain,
                sock_type: base_type,
                listening: false,
                nonblock: flags & SOCK_NONBLOCK != 0,
                accepted_once: false,
                tcp_handle,
                udp_handle,
                bound_port: 0,
            },
```

- [ ] **Step 6: Verify it compiles and tests pass**

Run: `cargo test -p harmony-os test_socket_dgram_creates_fd`
Expected: PASS

Run: `cargo clippy --workspace`
Expected: No new warnings (existing ones OK).

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add UdpProvider bound and udp_handle to SocketState"
```

---

### Task 6: Linuxulator Syscall Wiring — bind, connect, sendto, recvfrom, close

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`
  - `sys_bind` (~line 4350)
  - `sys_connect` (~line 4530)
  - `sys_sendto` (~line 4580)
  - `sys_recvfrom` (~line 4622)
  - `close_fd_entry` (~line 3799)

**Context:** Each of these syscalls currently branches on `tcp_handle`. We add a second branch for `udp_handle`. The pattern is: check `tcp_handle` first, then check `udp_handle`, then fall through to existing stub behavior.

- [ ] **Step 1: Write failing tests for UDP syscalls**

Add these tests in `linuxulator.rs`:

```rust
    #[test]
    fn test_udp_sendto_recvfrom_stub() {
        // Without real netstack, UDP sendto goes to stub (pretend success).
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,    // AF_INET
            sock_type: 2, // SOCK_DGRAM
            protocol: 0,
        });
        assert!(fd >= 0);

        // sendto with a destination address
        let data = b"hello";
        // Build a sockaddr_in: AF_INET=2, port=53, addr=8.8.8.8
        let mut sockaddr = [0u8; 16];
        sockaddr[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        sockaddr[2..4].copy_from_slice(&53u16.to_be_bytes()); // port 53
        sockaddr[4..8].copy_from_slice(&[8, 8, 8, 8]); // 8.8.8.8

        let r = lx.dispatch_syscall(LinuxSyscall::Sendto {
            fd: fd as i32,
            buf: data.as_ptr() as u64,
            len: data.len() as u64,
            flags: 0,
            addr: sockaddr.as_ptr() as u64,
            addrlen: 16,
        });
        // NoTcp udp_create returns SocketLimit, so no udp_handle →
        // falls to stub path. Stub pretends success.
        assert_eq!(r, 5);
    }

    #[test]
    fn test_udp_sendto_null_dest_unconnected() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,
            sock_type: 2,
            protocol: 0,
        });
        assert!(fd >= 0);

        let data = b"hello";
        let r = lx.dispatch_syscall(LinuxSyscall::Sendto {
            fd: fd as i32,
            buf: data.as_ptr() as u64,
            len: data.len() as u64,
            flags: 0,
            addr: 0, // NULL dest
            addrlen: 0,
        });
        // No udp_handle (NoTcp) AND no dest addr → stub pretends success.
        // With a real udp_handle but no connect: EDESTADDRREQ.
        // This test uses NoTcp, so it goes to stub. That's expected.
        assert_eq!(r, 5);
    }
```

- [ ] **Step 2: Run tests to verify baseline**

Run: `cargo test -p harmony-os test_udp_sendto`
Expected: PASS (stub behavior).

- [ ] **Step 3: Wire `sys_bind` for UDP**

In `sys_bind` (around line 4350), after the TCP `if let Some(h) = tcp_handle` block and before the stub `0` return, add:

```rust
        // UDP path.
        let udp_handle = self.sockets.get(&socket_id).and_then(|s| s.udp_handle);
        if let Some(h) = udp_handle {
            if addr == 0 || addrlen < 4 {
                return EINVAL;
            }
            let ptr = addr as *const u8;
            let port = u16::from_be_bytes(unsafe { [*ptr.add(2), *ptr.add(3)] });
            if let Some(state) = self.sockets.get_mut(&socket_id) {
                state.bound_port = port;
            }
            match self.tcp.udp_bind(h, port) {
                Ok(()) => return 0,
                Err(e) => return net_error_to_errno(e),
            }
        }
```

- [ ] **Step 4: Wire `sys_connect` for UDP**

In `sys_connect` (around line 4530), in the `else` branch (no `tcp_handle`), before the AF_UNIX check, add the UDP path:

Replace the existing else block:
```rust
        } else {
            // AF_UNIX connect: no daemon is running → ECONNREFUSED.
            ...
        }
```

With:
```rust
        } else if let Some(h) = self.sockets.get(&socket_id).and_then(|s| s.udp_handle) {
            // UDP connect — stores the remote endpoint, returns immediately.
            if addr == 0 || addrlen < 8 {
                return EINVAL;
            }
            let ptr = addr as *const u8;
            let port = u16::from_be_bytes(unsafe { [*ptr.add(2), *ptr.add(3)] });
            let ip = harmony_netstack::smoltcp::wire::Ipv4Address::new(
                unsafe { *ptr.add(4) },
                unsafe { *ptr.add(5) },
                unsafe { *ptr.add(6) },
                unsafe { *ptr.add(7) },
            );
            match self.tcp.udp_connect(h, ip, port) {
                Ok(()) => 0,
                Err(e) => net_error_to_errno(e),
            }
        } else {
            // AF_UNIX connect: no daemon is running → ECONNREFUSED.
            let domain = self.sockets.get(&socket_id).map(|s| s.domain).unwrap_or(0);
            if domain == 1 {
                -111 // ECONNREFUSED
            } else {
                0
            }
        }
```

- [ ] **Step 5: Wire `sys_sendto` for UDP**

In `sys_sendto` (around line 4580), after the `if let Some(h) = tcp_handle` block, before the stub path, add the UDP branch:

```rust
        // UDP path.
        if let Some(h) = self.sockets.get(&socket_id).and_then(|s| s.udp_handle) {
            let count = len as usize;
            if count == 0 {
                return 0;
            }
            if buf == 0 {
                return EFAULT;
            }
            let data = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };

            if dest_addr != 0 && addrlen >= 8 {
                // Explicit destination — use sendto.
                let ptr = dest_addr as *const u8;
                let port = u16::from_be_bytes(unsafe { [*ptr.add(2), *ptr.add(3)] });
                let ip = harmony_netstack::smoltcp::wire::Ipv4Address::new(
                    unsafe { *ptr.add(4) },
                    unsafe { *ptr.add(5) },
                    unsafe { *ptr.add(6) },
                    unsafe { *ptr.add(7) },
                );
                return match self.tcp.udp_sendto(h, data, ip, port) {
                    Ok(n) => n as i64,
                    Err(NetError::WouldBlock) => EAGAIN,
                    Err(e) => net_error_to_errno(e),
                };
            }

            // No destination — must be connected.
            return match self.tcp.udp_send(h, data) {
                Ok(n) => n as i64,
                Err(NetError::NotConnected) => {
                    const EDESTADDRREQ: i64 = -89;
                    EDESTADDRREQ
                }
                Err(NetError::WouldBlock) => EAGAIN,
                Err(e) => net_error_to_errno(e),
            };
        }
```

Note: The existing `_addr` and `_addrlen` parameters in `sys_sendto` need to be renamed to `dest_addr` and `addrlen` (remove the underscore prefixes) since we now use them.

- [ ] **Step 6: Wire `sys_recvfrom` for UDP**

In `sys_recvfrom` (around line 4622), after the `if let Some(h) = tcp_handle` block, before the stub path, add:

```rust
        // UDP path.
        if let Some(h) = self.sockets.get(&socket_id).and_then(|s| s.udp_handle) {
            let count = len as usize;
            if count == 0 {
                return 0;
            }
            if buf == 0 {
                return EFAULT;
            }
            let data = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };

            // Try connected recv first; on NotConnected, fall back to recvfrom.
            let result = match self.tcp.udp_recv(h, data) {
                Ok(r) => Ok(r),
                Err(NetError::NotConnected) => self.tcp.udp_recvfrom(h, data),
                Err(e) => Err(e),
            };

            return match result {
                Ok((n, src_addr, src_port)) => {
                    // Write source address if caller provided a buffer.
                    if src != 0 && addrlen != 0 {
                        let addrlen_bytes = unsafe {
                            core::slice::from_raw_parts(addrlen as *const u8, 4)
                        };
                        let buf_len =
                            u32::from_ne_bytes(addrlen_bytes.try_into().unwrap()) as usize;
                        if buf_len >= 8 {
                            let sa = unsafe {
                                core::slice::from_raw_parts_mut(src as *mut u8, buf_len.min(16))
                            };
                            sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
                            sa[2..4].copy_from_slice(&src_port.to_be_bytes());
                            sa[4..8].copy_from_slice(&src_addr.0);
                            if buf_len >= 16 {
                                sa[8..16].fill(0); // sin_zero
                            }
                            // Update addrlen to actual size written.
                            let actual_len = 16u32.min(buf_len as u32);
                            let out =
                                unsafe { core::slice::from_raw_parts_mut(addrlen as *mut u8, 4) };
                            out.copy_from_slice(&actual_len.to_ne_bytes());
                        }
                    }
                    n as i64
                }
                Err(NetError::WouldBlock) => EAGAIN,
                Err(e) => net_error_to_errno(e),
            };
        }
```

- [ ] **Step 7: Wire `close_fd_entry` for UDP**

In `close_fd_entry` (around line 3799), in the `FdKind::Socket` arm, after `tcp_close`:

```rust
            FdKind::Socket { socket_id } => {
                let still_referenced = self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::Socket { socket_id: id } if *id == socket_id),
                );
                if !still_referenced {
                    if let Some(state) = self.sockets.remove(&socket_id) {
                        if let Some(h) = state.tcp_handle {
                            let _ = self.tcp.tcp_close(h);
                        }
                        if let Some(h) = state.udp_handle {
                            let _ = self.tcp.udp_close(h);
                        }
                    }
                }
            }
```

- [ ] **Step 8: Run tests**

Run: `cargo test -p harmony-os test_udp`
Expected: All UDP tests pass.

Run: `cargo test -p harmony-os`
Expected: No regressions in existing tests.

- [ ] **Step 9: Run clippy**

Run: `cargo clippy --workspace`
Expected: No new warnings.

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): wire UDP bind, connect, sendto, recvfrom, close"
```

---

### Task 7: Linuxulator Readiness — is_fd_readable / is_fd_writable for UDP

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`
  - `is_fd_readable` (~line 8118)
  - `is_fd_writable` (~line 8165)

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn test_udp_readiness_stub() {
        // With NoTcp, UDP sockets have no udp_handle → fall through to
        // "Non-TCP sockets: always ready" which returns true.
        // This tests the code path without a real netstack.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,    // AF_INET
            sock_type: 2, // SOCK_DGRAM
            protocol: 0,
        }) as i32;
        assert!(fd >= 0);

        // With NoTcp, udp_create fails → no udp_handle → stub path.
        assert!(lx.is_fd_readable(fd));
        assert!(lx.is_fd_writable(fd));
    }
```

- [ ] **Step 2: Run test to verify baseline passes**

Run: `cargo test -p harmony-os test_udp_readiness_stub`
Expected: PASS (falls through to "always ready" stub).

- [ ] **Step 3: Add UDP branches to `is_fd_readable`**

In `is_fd_readable`, in the `FdKind::Socket` arm (around line 8138), after the TCP block but before the "Non-TCP sockets" comment:

```rust
            FdKind::Socket { socket_id } => {
                if let Some(state) = self.sockets.get(socket_id) {
                    if let Some(h) = state.tcp_handle {
                        let tcp_state = self.tcp.tcp_state(h);
                        if state.listening {
                            return tcp_state == TcpSocketState::Established;
                        }
                        return self.tcp.tcp_can_recv(h)
                            || tcp_state == TcpSocketState::CloseWait
                            || tcp_state == TcpSocketState::Closing
                            || tcp_state == TcpSocketState::Closed;
                    }
                    if let Some(h) = state.udp_handle {
                        return self.tcp.udp_can_recv(h);
                    }
                }
                // Non-TCP/UDP sockets (AF_UNIX stubs, socketpair): always ready.
                true
            }
```

- [ ] **Step 4: Add UDP branches to `is_fd_writable`**

In `is_fd_writable`, in the `FdKind::Socket` arm (around line 8174), after the TCP block:

```rust
            FdKind::Socket { socket_id } => {
                if let Some(state) = self.sockets.get(socket_id) {
                    if let Some(h) = state.tcp_handle {
                        let tcp_state = self.tcp.tcp_state(h);
                        return !state.listening
                            && self.tcp.tcp_can_send(h)
                            && (tcp_state == TcpSocketState::Established
                                || tcp_state == TcpSocketState::CloseWait);
                    }
                    if let Some(h) = state.udp_handle {
                        return self.tcp.udp_can_send(h);
                    }
                }
                // Non-TCP/UDP sockets (AF_UNIX stubs, socketpair): always ready.
                true
            }
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-os test_udp_readiness`
Expected: PASS

Run: `cargo test -p harmony-os`
Expected: No regressions.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add UDP readiness to is_fd_readable/is_fd_writable"
```

---

### Task 8: RawPtrTcpProvider UdpProvider Delegation

**Files:**
- Modify: `crates/harmony-boot/src/main.rs:596-677` (add `impl UdpProvider for RawPtrTcpProvider`)

**Context:** `RawPtrTcpProvider` wraps a raw pointer to `NetStack` and delegates all `TcpProvider` calls through it. We need the same delegation for `UdpProvider`. This is at `crates/harmony-boot/src/main.rs:596`.

- [ ] **Step 1: Add `UdpProvider` impl for `RawPtrTcpProvider`**

After the existing `TcpProvider` impl block (after line 677), add:

```rust
#[cfg(feature = "ring3")]
impl harmony_netstack::udp::UdpProvider for RawPtrTcpProvider {
    fn udp_create(&mut self) -> Result<harmony_netstack::UdpHandle, harmony_netstack::NetError> {
        unsafe { (*self.0).udp_create() }
    }
    fn udp_bind(
        &mut self,
        h: harmony_netstack::UdpHandle,
        port: u16,
    ) -> Result<(), harmony_netstack::NetError> {
        unsafe { (*self.0).udp_bind(h, port) }
    }
    fn udp_close(
        &mut self,
        h: harmony_netstack::UdpHandle,
    ) -> Result<(), harmony_netstack::NetError> {
        unsafe { (*self.0).udp_close(h) }
    }
    fn udp_can_recv(&self, h: harmony_netstack::UdpHandle) -> bool {
        unsafe { (*self.0).udp_can_recv(h) }
    }
    fn udp_can_send(&self, h: harmony_netstack::UdpHandle) -> bool {
        unsafe { (*self.0).udp_can_send(h) }
    }
    fn udp_sendto(
        &mut self,
        h: harmony_netstack::UdpHandle,
        data: &[u8],
        addr: smoltcp::wire::Ipv4Address,
        port: u16,
    ) -> Result<usize, harmony_netstack::NetError> {
        unsafe { (*self.0).udp_sendto(h, data, addr, port) }
    }
    fn udp_recvfrom(
        &mut self,
        h: harmony_netstack::UdpHandle,
        buf: &mut [u8],
    ) -> Result<(usize, smoltcp::wire::Ipv4Address, u16), harmony_netstack::NetError> {
        unsafe { (*self.0).udp_recvfrom(h, buf) }
    }
    fn udp_connect(
        &mut self,
        h: harmony_netstack::UdpHandle,
        addr: smoltcp::wire::Ipv4Address,
        port: u16,
    ) -> Result<(), harmony_netstack::NetError> {
        unsafe { (*self.0).udp_connect(h, addr, port) }
    }
    fn udp_send(
        &mut self,
        h: harmony_netstack::UdpHandle,
        data: &[u8],
    ) -> Result<usize, harmony_netstack::NetError> {
        unsafe { (*self.0).udp_send(h, data) }
    }
    fn udp_recv(
        &mut self,
        h: harmony_netstack::UdpHandle,
        buf: &mut [u8],
    ) -> Result<(usize, smoltcp::wire::Ipv4Address, u16), harmony_netstack::NetError> {
        unsafe { (*self.0).udp_recv(h, buf) }
    }
    fn udp_poll(&mut self, now_ms: i64) {
        unsafe { (*self.0).udp_poll(now_ms) }
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p harmony-boot --features ring3`

If the `ring3` feature isn't available in isolation, try:
Run: `cargo clippy --workspace`
Expected: No errors related to `UdpProvider` bound on the `LINUXULATOR` static.

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(boot): delegate UdpProvider through RawPtrTcpProvider"
```

---

### Task 9: Sockaddr Helpers and Cleanup

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs` — extract `parse_sockaddr_in` and `write_sockaddr_in` helpers

**Context:** The sockaddr parsing code (read port from bytes 2-3, read IP from bytes 4-7) is duplicated in `sys_bind`, `sys_connect`, and `sys_sendto`. The sockaddr writing code appears in `sys_recvfrom` and `write_stub_sockaddr`. Extract shared helpers to reduce duplication and prevent parse inconsistencies.

- [ ] **Step 1: Write test for parse helper**

```rust
    #[test]
    fn test_parse_sockaddr_in() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);

        // Build a valid sockaddr_in: AF_INET=2, port=8080, addr=10.0.0.1
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        sa[2..4].copy_from_slice(&8080u16.to_be_bytes());
        sa[4..8].copy_from_slice(&[10, 0, 0, 1]);

        let result = lx.parse_sockaddr_in(sa.as_ptr() as u64, 16);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(port, 8080);
        assert_eq!(ip, harmony_netstack::smoltcp::wire::Ipv4Address::new(10, 0, 0, 1));
    }

    #[test]
    fn test_parse_sockaddr_in_null() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);
        assert!(lx.parse_sockaddr_in(0, 16).is_none());
    }

    #[test]
    fn test_parse_sockaddr_in_too_short() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);
        let sa = [0u8; 4];
        assert!(lx.parse_sockaddr_in(sa.as_ptr() as u64, 4).is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os test_parse_sockaddr`
Expected: Compilation error — `parse_sockaddr_in` not defined.

- [ ] **Step 3: Implement `parse_sockaddr_in`**

Add as a method on `Linuxulator`:

```rust
    /// Parse a `sockaddr_in` from userspace memory.
    /// Returns `None` if the pointer is null or the buffer is too short
    /// (needs at least 8 bytes: family + port + addr).
    fn parse_sockaddr_in(
        &self,
        addr: u64,
        addrlen: u32,
    ) -> Option<(harmony_netstack::smoltcp::wire::Ipv4Address, u16)> {
        if addr == 0 || addrlen < 8 {
            return None;
        }
        let ptr = addr as *const u8;
        let port = u16::from_be_bytes(unsafe { [*ptr.add(2), *ptr.add(3)] });
        let ip = harmony_netstack::smoltcp::wire::Ipv4Address::new(
            unsafe { *ptr.add(4) },
            unsafe { *ptr.add(5) },
            unsafe { *ptr.add(6) },
            unsafe { *ptr.add(7) },
        );
        Some((ip, port))
    }
```

- [ ] **Step 4: Implement `write_sockaddr_in`**

```rust
    /// Write a `sockaddr_in` to userspace memory.
    /// No-op if `addr` or `addrlen_ptr` is null.
    fn write_sockaddr_in(
        &self,
        addr: u64,
        addrlen_ptr: u64,
        ip: harmony_netstack::smoltcp::wire::Ipv4Address,
        port: u16,
    ) {
        if addr == 0 || addrlen_ptr == 0 {
            return;
        }
        let addrlen_bytes =
            unsafe { core::slice::from_raw_parts(addrlen_ptr as *const u8, 4) };
        let buf_len = u32::from_ne_bytes(addrlen_bytes.try_into().unwrap()) as usize;
        if buf_len < 8 {
            return;
        }
        let n = buf_len.min(16);
        let sa = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, n) };
        sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        sa[2..4].copy_from_slice(&port.to_be_bytes());
        sa[4..8].copy_from_slice(&ip.0);
        if n >= 16 {
            sa[8..16].fill(0); // sin_zero
        }
        let actual = 16u32.min(buf_len as u32);
        let out = unsafe { core::slice::from_raw_parts_mut(addrlen_ptr as *mut u8, 4) };
        out.copy_from_slice(&actual.to_ne_bytes());
    }
```

- [ ] **Step 5: Refactor existing code to use helpers**

Replace the inline sockaddr parsing in:
- `sys_bind`: replace `let ptr = addr as *const u8; let port = ...` with `parse_sockaddr_in(addr, addrlen)`
- `sys_connect`: same replacement for both TCP and UDP paths
- `sys_sendto`: same for the UDP dest_addr parsing
- `sys_recvfrom`: replace the inline sockaddr_in writing in the UDP path with `write_sockaddr_in`

This is optional cleanup — the code works without it. Do it only if the duplication is causing maintenance issues. If skipped, the helpers still serve the UDP path.

- [ ] **Step 6: Run tests**

Run: `cargo test -p harmony-os test_parse_sockaddr`
Expected: All 3 tests pass.

Run: `cargo test -p harmony-os`
Expected: No regressions.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "refactor(linuxulator): extract parse_sockaddr_in and write_sockaddr_in helpers"
```

---

### Task 10: Final Clippy and Full Test Suite

**Files:** All modified files.

- [ ] **Step 1: Run nightly rustfmt**

Run: `cargo +nightly fmt --all`
Expected: Formats all files. (CI uses nightly rustfmt.)

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: No new warnings. Fix any that appear (likely: unused variables from renamed params, redundant closures, etc.)

- [ ] **Step 3: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass — both new UDP tests and existing TCP/networking/linuxulator tests.

- [ ] **Step 4: Commit any formatting/clippy fixes**

```bash
git add -A
git commit -m "chore: fix clippy warnings and nightly fmt"
```

(Skip this step if no changes.)
