# TCP + DHCP Support for harmony-os

**Beads:** harmony-os-v6i (TCP), harmony-os-fxo (DHCP)
**Date:** 2026-03-31
**Status:** Draft

## Problem

harmony-os nodes (RPi5 fleet) have UDP/IP networking via smoltcp but no TCP
or DHCP support. Without TCP, SSH daemons can't run — every node requires
physical HDMI+keyboard access for management. Without DHCP, every node needs
a hardcoded static IP, making plug-and-play Ethernet impossible.

## Solution

Enable TCP and DHCP in smoltcp, expose a handle-based TCP API via a
`TcpProvider` trait, wire the Linuxulator's socket syscalls to real TCP
through that trait, and add DHCP client logic with static-IP fallback.

**Primary use case:** SSH into RPi5 nodes for remote management. SSH daemons
(dropbear/openssh) use `epoll` + nonblocking `SOCK_STREAM` sockets, so we
implement nonblocking TCP semantics with real epoll readiness reporting.

## Architecture

### smoltcp Feature Enablement

Add three features to `harmony-netstack/Cargo.toml`:

```toml
smoltcp = { version = "0.11", default-features = false, features = [
    "medium-ethernet",
    "proto-ipv4",
    "socket-udp",
    "socket-tcp",      # NEW — TCP socket support
    "proto-tcp",       # NEW — TCP protocol processing
    "proto-dhcpv4",    # NEW — DHCP client protocol
    "alloc",
] }
```

All three protocols share a single `SocketSet` and a single `iface.poll()`
call. smoltcp processes TCP segments, DHCP packets, and UDP datagrams in the
same poll cycle. Existing UDP functionality is unaffected — features are
additive.

### DHCP Client

smoltcp provides a built-in DHCP state machine (`dhcpv4::Socket`). We add it
to the shared `SocketSet` and check for lease events after each `poll()`.

**Builder API changes:**

```rust
// Before (hardcoded static IP):
NetStackBuilder::new()
    .static_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 2, 15), 24))
    .gateway(Ipv4Address::new(10, 0, 2, 2))

// After (DHCP with fallback):
NetStackBuilder::new()
    .dhcp(true)
    .fallback_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 2, 15), 24))
    .fallback_gateway(Ipv4Address::new(10, 0, 2, 2))
```

**Behavior:**
- When `.dhcp(true)`, a `dhcpv4::Socket` is created in the `SocketSet`
- The interface starts with no IP address
- `NetStack::poll()` checks for `dhcpv4::Event::Configured` after `iface.poll()`
- On lease acquisition: apply IP, gateway, DNS to the interface
- If no lease within 5 seconds: apply the fallback static IP and log a warning
- smoltcp handles lease renewal automatically (no application logic needed)
- When `.dhcp(false)` (default): existing static IP behavior unchanged

### TCP Handle-Based API

**TcpProvider trait** (defined in `harmony-netstack/src/tcp.rs`):

```rust
pub trait TcpProvider {
    type Handle: Copy;

    fn tcp_create(&mut self) -> Result<Self::Handle, NetError>;
    fn tcp_bind(&mut self, handle: Self::Handle, port: u16) -> Result<(), NetError>;
    fn tcp_listen(&mut self, handle: Self::Handle, backlog: usize) -> Result<(), NetError>;
    fn tcp_accept(&mut self, handle: Self::Handle) -> Result<Option<Self::Handle>, NetError>;
    fn tcp_connect(&mut self, handle: Self::Handle, addr: Ipv4Address, port: u16) -> Result<(), NetError>;
    fn tcp_send(&mut self, handle: Self::Handle, data: &[u8]) -> Result<usize, NetError>;
    fn tcp_recv(&mut self, handle: Self::Handle, buf: &mut [u8]) -> Result<usize, NetError>;
    fn tcp_close(&mut self, handle: Self::Handle) -> Result<(), NetError>;
    fn tcp_state(&self, handle: Self::Handle) -> TcpSocketState;
}
```

**Types:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHandle(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSocketState {
    Closed,
    Listen,
    Connecting,
    Established,
    CloseWait,
    Closing,
}

#[derive(Debug)]
pub enum NetError {
    WouldBlock,
    ConnectionRefused,
    ConnectionReset,
    NotConnected,
    AddrInUse,
    InvalidHandle,
    SocketLimit,
}
```

**NetStack implementation:**

- `tcp_create()` — creates a `tcp::Socket` with configurable buffer sizes
  (default 8 KiB RX, 8 KiB TX), adds to the shared `SocketSet`, returns
  `TcpHandle` wrapping smoltcp's `SocketHandle`
- `tcp_bind()` + `tcp_listen()` — smoltcp combines these into `socket.listen(port)`.
  `tcp_bind()` records the port, `tcp_listen()` calls `socket.listen()`
- `tcp_accept()` — checks if a listening socket has a completed connection.
  If the socket is in `Established` state, moves it to an "accepted" slot,
  creates a new listening socket on the same port, and returns the accepted
  socket's handle. Returns `Ok(None)` when no pending connection
- `tcp_connect()` — calls `socket.connect(remote_endpoint, local_port)`.
  Returns immediately; connection completes asynchronously via `poll()`
- `tcp_send()` / `tcp_recv()` — delegates to smoltcp's `send_slice()` /
  `recv_slice()`. Returns `NetError::WouldBlock` when buffers are full/empty
- `tcp_close()` — calls `socket.close()`, marks handle for cleanup after
  TCP close handshake completes
- `tcp_state()` — maps smoltcp's `tcp::State` enum to `TcpSocketState`

**Socket capacity:** The `SocketSet` is initialized with room for a configurable
max number of TCP sockets (default 16) plus the UDP socket and optional DHCP
socket. This is plenty for an SSH daemon with a few concurrent sessions.

### Linuxulator Wiring

The Linuxulator gains a generic `TcpProvider` parameter so Ring 3 doesn't
depend on Ring 1 internals:

```rust
struct LinuxulatorState<T: TcpProvider> {
    tcp: T,
    sockets: BTreeMap<usize, SocketState>,
    // ... existing fields
}
```

**SocketState changes:**

```rust
struct SocketState {
    domain: i32,
    sock_type: i32,
    listening: bool,
    nonblock: bool,
    tcp_handle: Option<TcpHandle>,  // None for stub/UDP sockets
}
```

**Syscall routing — what becomes real:**

| Syscall | Before (stub) | After (TCP) |
|---------|--------------|-------------|
| `socket(AF_INET, SOCK_STREAM)` | Stub fd only | `tcp_create()` → real handle |
| `bind` | No-op | `tcp_bind(handle, port)` |
| `listen` | Sets flag | `tcp_listen(handle, backlog)` |
| `accept4` | Synthetic fd | `tcp_accept(handle)` → new fd with handle, or `EAGAIN` |
| `connect` | No-op | `tcp_connect(handle, addr, port)` |
| `read`/`recvfrom` | Returns EOF (0) | `tcp_recv(handle, buf)` → data or `EAGAIN` |
| `write`/`sendto` | Pretends all sent | `tcp_send(handle, data)` → bytes actually queued |
| `close` | Removes fd | `tcp_close(handle)` + removes fd |

**What stays stubbed for v1:**
- `SOCK_DGRAM` (UDP) sockets — still stub behavior
- `setsockopt` / `getsockopt` — no-op (smoltcp defaults are fine for SSH)
- `getsockname` / `getpeername` — return zeros

**Epoll becomes real for TCP fds:**

The current epoll always returns "all fds ready." For TCP sockets with handles,
we check actual readiness via `tcp_state()`:

| Event | Condition |
|-------|-----------|
| `EPOLLIN` | State is `Established` AND `tcp_recv` would not return `WouldBlock`, OR state is `Listen` AND `tcp_accept` would return `Some`, OR state is `CloseWait` (EOF readable) |
| `EPOLLOUT` | State is `Established` AND `tcp_send` would not return `WouldBlock` |
| `EPOLLHUP` | State is `Closed` or `Closing` |
| `EPOLLERR` | Connection refused or reset |

For non-TCP fds (pipes, stub UDP sockets), epoll continues returning "always
ready" as before. This eliminates the busy-spin problem for TCP connections
while leaving existing stub behavior unaffected.

### Polling Integration

No structural changes to the boot event loop. `iface.poll()` already runs on
every iteration — TCP segments, DHCP packets, and UDP datagrams are all
processed in the same call. The existing polling frequency (250ms Reticulum
tick + interrupt-driven) is sufficient for TCP retransmission timers (smoltcp
default RTO starts at 1 second).

After `iface.poll()`, `iface.poll_delay()` is checked to expose when smoltcp
next needs attention (informational for v1 since the loop is already busy-poll).

### Boot Sequence Changes

The boot crate creates `NetStack` with the new DHCP builder, then passes a
reference to the Linuxulator:

```rust
let netstack = NetStackBuilder::new()
    .mac(mac_addr)
    .dhcp(true)
    .fallback_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 2, 15), 24))
    .fallback_gateway(Ipv4Address::new(10, 0, 2, 2))
    .port(4242)
    .enable_broadcast(true)
    .tcp_max_sockets(16)
    .build(now);

// Linuxulator gets TcpProvider access
let linuxulator = LinuxulatorState::new(netstack);
```

The concrete type threading is: boot crate owns `NetStack`, passes it (or an
`Rc<RefCell<NetStack>>`) to the Linuxulator which stores it as `T: TcpProvider`.

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `crates/harmony-netstack/src/tcp.rs` | `TcpProvider` trait, `TcpHandle`, `TcpSocketState`, `NetError` types |
| `crates/harmony-netstack/src/dhcp.rs` | DHCP client: socket creation, lease event handling, fallback timeout |

### Modified Files

| File | Change |
|------|--------|
| `crates/harmony-netstack/Cargo.toml` | Add `socket-tcp`, `proto-tcp`, `proto-dhcpv4` features |
| `crates/harmony-netstack/src/lib.rs` | Export `tcp` and `dhcp` modules |
| `crates/harmony-netstack/src/stack.rs` | Implement `TcpProvider` for `NetStack`, integrate DHCP into `poll()` |
| `crates/harmony-netstack/src/builder.rs` | Add `.dhcp()`, `.fallback_ip()`, `.fallback_gateway()`, `.tcp_max_sockets()` |
| `crates/harmony-os/src/linuxulator.rs` | Wire `SOCK_STREAM` syscalls to `TcpProvider`, real epoll readiness for TCP fds |
| `crates/harmony-boot/src/main.rs` | Use DHCP builder, pass netstack to Linuxulator |

### File Responsibilities

- **`tcp.rs`** — Pure types and trait definition. No smoltcp dependency in the
  trait itself (only in the NetStack impl). The Linuxulator imports the trait
  and types without pulling in smoltcp.

- **`dhcp.rs`** — DHCP lease state machine. Handles socket creation, lease event
  processing, fallback timeout logic. Called by `stack.rs` during `poll()`.

- **`stack.rs`** — Integrates everything. Implements `TcpProvider`, delegates
  DHCP to `dhcp.rs`, manages the shared `SocketSet`.

## Testing

### Unit Tests (tcp.rs)

- `tcp_create` returns valid handle, second returns different handle
- `tcp_create` beyond limit returns `SocketLimit`
- `tcp_bind` + `tcp_listen` on valid port succeeds
- `tcp_bind` on in-use port returns `AddrInUse`
- `tcp_recv` on unconnected socket returns `NotConnected`
- `tcp_close` invalidates handle, subsequent ops return `InvalidHandle`
- `tcp_state` reflects correct lifecycle

### Integration Tests (TCP loopback)

- Two NetStack instances sharing a simulated wire (FrameBuffer crossover)
- Server: create → bind(8080) → listen → poll → accept
- Client: create → connect(server_ip, 8080) → poll
- Exchange data bidirectionally, verify bytes match
- Full TCP handshake + data transfer through smoltcp

### Unit Tests (dhcp.rs)

- DHCP-enabled NetStack starts with no IP
- Feed crafted DHCP OFFER+ACK frames → verify IP applied after poll
- No DHCP response within timeout → verify fallback IP applied
- DHCP-disabled mode → static IP applied immediately (regression test)

### Linuxulator Tests

- Existing socket stub tests continue passing (UDP unchanged)
- `socket(AF_INET, SOCK_STREAM)` with mock `TcpProvider` → `tcp_create` called
- `accept4` on listening TCP socket → `EAGAIN` when no connection pending
- `epoll_wait` returns TCP fd as readable when data available
- `epoll_wait` does NOT return TCP fd when no data available

## What is NOT in Scope

- **Blocking I/O** — follow-up bead `harmony-os-cqy`. v1 is nonblocking only.
- **Real UDP through smoltcp** — Linuxulator UDP sockets stay stubbed.
- **IPv6** — proto-ipv6 not enabled.
- **ICMP/ping** — proto-icmp not enabled.
- **DNS resolution** — No resolver, hardcoded IPs only.
- **Raw sockets** — No SOCK_RAW support.
- **Multiple interfaces** — Single eth0 only.
- **`getsockname`/`getpeername` with real addresses** — Return zeros for v1.
- **`setsockopt` TCP options** — No-op, smoltcp defaults are fine.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| TCP socket limit reached | `tcp_create()` returns `SocketLimit` → Linuxulator returns `ENFILE` |
| Port already in use | `tcp_bind()` returns `AddrInUse` → Linuxulator returns `EADDRINUSE` |
| Connection refused | `tcp_connect()` state → `Closed` → epoll reports `EPOLLERR` |
| Connection reset | `tcp_recv()` returns `ConnectionReset` → Linuxulator returns `ECONNRESET` |
| No data available | `tcp_recv()` returns `WouldBlock` → Linuxulator returns `EAGAIN` |
| Send buffer full | `tcp_send()` returns `WouldBlock` → Linuxulator returns `EAGAIN` |
| DHCP timeout | Fallback static IP applied, warning logged |
| DHCP lease lost | smoltcp emits `Deconfigured` event, IP removed, DHCP restarts |
| Invalid socket handle | `InvalidHandle` → Linuxulator returns `EBADF` |
