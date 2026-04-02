# UDP Socket Bridging

**Bead:** harmony-os-c0x (P3, feature)
**Date:** 2026-04-02
**Status:** Design approved

## Problem

The TCP socket path is fully wired (PR #97), but `SOCK_DGRAM` sockets still use stubs: `sendto` pretends all bytes were sent, `recvfrom` returns EOF. This means UDP-based protocols don't work, most notably DNS resolution. smoltcp already has UDP socket support, and the TCP wiring pattern is well-established. This feature bridges the gap.

## Design

### UdpProvider Trait

New file `crates/harmony-netstack/src/udp.rs`, parallel to `tcp.rs`.

**Types:**
- `UdpHandle(u32)` — opaque slot index, same pattern as `TcpHandle`
- Reuses existing `NetError` from `tcp.rs`

**Trait:**

```rust
pub trait UdpProvider {
    fn udp_create(&mut self) -> Result<UdpHandle, NetError>;
    fn udp_bind(&mut self, handle: UdpHandle, port: u16) -> Result<(), NetError>;
    fn udp_close(&mut self, handle: UdpHandle) -> Result<(), NetError>;
    fn udp_can_recv(&self, handle: UdpHandle) -> bool;
    fn udp_can_send(&self, handle: UdpHandle) -> bool;

    // Unconnected mode
    fn udp_sendto(
        &mut self, handle: UdpHandle, data: &[u8],
        addr: Ipv4Address, port: u16,
    ) -> Result<usize, NetError>;
    fn udp_recvfrom(
        &mut self, handle: UdpHandle, buf: &mut [u8],
    ) -> Result<(usize, Ipv4Address, u16), NetError>;

    // Connected mode
    fn udp_connect(
        &mut self, handle: UdpHandle, addr: Ipv4Address, port: u16,
    ) -> Result<(), NetError>;
    fn udp_send(&mut self, handle: UdpHandle, data: &[u8]) -> Result<usize, NetError>;
    fn udp_recv(
        &mut self, handle: UdpHandle, buf: &mut [u8],
    ) -> Result<(usize, Ipv4Address, u16), NetError>;

    fn udp_poll(&mut self, now_ms: i64);
}
```

Design choices:
- `udp_connect` stores the remote endpoint in the netstack, not the Linuxulator. Keeps connection state co-located with the socket.
- `udp_send` is `udp_sendto` using the stored endpoint. Returns `NetError::NotConnected` if no prior `connect`.
- `udp_recv` calls `udp_recvfrom` internally but filters to only the connected peer, dropping non-matching packets. Matches Linux semantics.
- `udp_poll` is a no-op in `NetStack` (the shared `iface.poll()` in `poll_network()` already drives all sockets). Exists for trait completeness so `NoUdp` has a consistent interface.

**`NoUdp` stub:** `impl UdpProvider for NoTcp` — returns `NetError::ConnectionRefused` for all methods. Used when the Linuxulator runs without a network stack.

### NetStack Implementation

`NetStack` in `stack.rs` implements `UdpProvider` using smoltcp's `udp::Socket`.

**New fields:**
- `udp_handles: Vec<Option<SocketHandle>>` — slot array, sized by `udp_max_sockets`
- `udp_bound_ports: BTreeMap<UdpHandle, u16>` — tracks bound ports to prevent duplicates
- `udp_connected: BTreeMap<UdpHandle, (Ipv4Address, u16)>` — stores connected peer endpoint

**Socket creation** (`udp_create`):
- Find first `None` slot in `udp_handles`
- Create smoltcp `udp::Socket` with per-socket buffers (8 packet metadata slots, 4KB rx/tx)
- Add to `SocketSet`, store the `SocketHandle`
- Return `UdpHandle(slot)`

**Bind** (`udp_bind`):
- Check port not already in `udp_bound_ports`
- Call smoltcp `socket.bind(port)`
- Track in `udp_bound_ports`

**Sendto** (`udp_sendto`):
- Auto-bind to ephemeral port if unbound (mirrors TCP connect behavior)
- Call smoltcp `socket.send_slice(data, (addr, port))`
- Returns bytes sent or `WouldBlock` if tx buffer full

**Recvfrom** (`udp_recvfrom`):
- Call smoltcp `socket.recv_slice(buf)` — returns `(len, endpoint)`
- Returns `(len, addr, port)` or `WouldBlock`

**Connected mode:**
- `udp_connect` stores `(addr, port)` in `udp_connected`, auto-binds if unbound
- `udp_send` looks up stored endpoint, calls internal sendto logic
- `udp_recv` calls internal recvfrom, drops packets not from connected peer (loops until match or WouldBlock)

**Readiness:**
- `udp_can_recv`: smoltcp `socket.can_recv()`
- `udp_can_send`: smoltcp `socket.can_send()`

**Builder:** `NetStackBuilder` gets `udp_max_sockets(n: usize)` (default 4). Socket capacity calculation: `tcp_max_sockets + udp_max_sockets + 3`.

### Linuxulator Wiring

**Generic bound change:**
- Current: `Linuxulator<B, T>` where `T: TcpProvider`
- New: `T: TcpProvider + UdpProvider`
- Field stays named `tcp` (renaming to `net` would touch every TCP call site for no functional benefit)

**SocketState:**
```rust
udp_handle: Option<UdpHandle>,
```
Alongside existing `tcp_handle`. For AF_INET sockets, exactly one is `Some`. Both are `None` for AF_UNIX stubs.

**Syscall routing:**

| Syscall | SOCK_DGRAM behavior |
|---------|-------------------|
| `socket(AF_INET, SOCK_DGRAM)` | `udp_create()`, store handle in SocketState |
| `bind` | `udp_bind(h, port)` |
| `connect` | `udp_connect(h, addr, port)`, returns 0 immediately (no handshake) |
| `sendto` (dest non-null) | Parse sockaddr_in, `udp_sendto(h, data, addr, port)` |
| `sendto` (dest null, connected) | `udp_send(h, data)` |
| `sendto` (dest null, unconnected) | Return `EDESTADDRREQ` |
| `recvfrom` (connected) | `udp_recv(h, buf)`, write source to src_addr if non-null |
| `recvfrom` (unconnected) | `udp_recvfrom(h, buf)`, write source to src_addr if non-null |
| `close` | `udp_close(h)` |

**Sockaddr helpers** — extract from existing duplicated code:
- `parse_sockaddr_in(addr: u64, addrlen: u32) -> Option<(Ipv4Address, u16)>` — reusable by bind, connect, sendto
- `write_sockaddr_in(addr: u64, addrlen_ptr: u64, ip: Ipv4Address, port: u16)` — reusable by recvfrom, accept4, getsockname

**Readiness** (`is_fd_readable` / `is_fd_writable`):
- UDP socket readable: `udp_can_recv(h)`
- UDP socket writable: `udp_can_send(h)`
- Integrates with existing select/poll/epoll spin-wait

**main.rs:** `RawPtrTcpProvider` also impls `UdpProvider`, delegating through the same unsafe global pointer pattern.

### Edge Cases

- `sendto` on connected socket with non-null dest_addr: use the provided addr (Linux behavior — connected addr is default, explicit overrides)
- `recvfrom` with null `src_addr`: skip writing source address, just return data
- Auto-bind: `sendto`/`connect` on unbound socket auto-binds to ephemeral port
- Watchdog: UDP I/O does NOT reset the dispatch idle watchdog timer. The watchdog exists to detect dead SSH sessions; DNS queries during a stuck session shouldn't keep it alive.

## Files Changed

| File | Changes |
|------|---------|
| `crates/harmony-netstack/src/udp.rs` | New — `UdpHandle`, `UdpProvider` trait, `NoUdp` impl on `NoTcp` |
| `crates/harmony-netstack/src/stack.rs` | Impl `UdpProvider` for `NetStack`, new fields, socket capacity |
| `crates/harmony-netstack/src/lib.rs` | Export `udp` module and types |
| `crates/harmony-netstack/src/builder.rs` | `udp_max_sockets` field + setter, default 4 |
| `crates/harmony-os/src/linuxulator.rs` | Generic bound change, SocketState `udp_handle`, wire socket/bind/connect/sendto/recvfrom/close, readiness, sockaddr helpers |
| `crates/harmony-boot/src/main.rs` | `RawPtrTcpProvider` impls `UdpProvider` (delegates through unsafe global) |

## Testing

**Unit tests (harmony-netstack):**
- `UdpHandle` creation and slot exhaustion
- bind, port conflict detection
- sendto/recvfrom round-trip via smoltcp loopback
- Connected mode: connect + send/recv, filtering of non-peer packets
- Auto-bind on sendto/connect
- can_recv/can_send readiness

**Unit tests (harmony-os):**
- `socket(AF_INET, SOCK_DGRAM)` creates SocketState with udp_handle
- sendto/recvfrom through full syscall dispatch
- Connected-mode send/recv
- Readiness: is_fd_readable/is_fd_writable for UDP sockets
- close cleans up udp_handle
- Sockaddr helper parse/write round-trip

**QEMU integration:**
- DNS resolution via busybox `nslookup` (if available in rootfs)
- Manual UDP echo test if nslookup not available

## Out of Scope

- IPv6 UDP — AF_INET6 sockets remain stubs (no smoltcp IPv6 configured)
- UDP multicast — not needed for DNS or Iroh's initial use case
- `MSG_PEEK`, `MSG_TRUNC`, `MSG_DONTWAIT` flags — can be added incrementally
- `getsockname`/`getpeername` for UDP — existing stubs sufficient for now
- Per-socket buffer size configuration via `setsockopt(SO_RCVBUF/SO_SNDBUF)` — fixed 4KB is sufficient
