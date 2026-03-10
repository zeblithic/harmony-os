# Ring 1 Network Stack Design

**Bead:** harmony-haq
**Scope:** Ring 1 — smoltcp IP + UDP transport for Harmony mesh routing

## Goal

Add an IP networking layer to the Ring 1 unikernel so Harmony mesh nodes can
communicate over conventional IP networks (LAN and WAN) in addition to the
existing raw Ethernet path. This unblocks mesh-over-internet deployment and
is a prerequisite for the RPi5 bootable image (harmony-4g8).

## Background

Today, the unikernel communicates using raw Ethernet frames with a custom
EtherType (`0x88B5`). The VirtIO-net driver wraps Reticulum packets directly
in Ethernet headers — no IP stack involved. This works for LAN mesh
deployments (broadcast on a shared segment) but cannot traverse routers or
the public internet.

The `NetworkInterface` trait (`harmony-platform`) is already
transport-agnostic: `send(&[u8])` / `receive() -> Option<Vec<u8>>`. The
sans-I/O `Node` state machine consumes raw byte slices and doesn't care what
physical medium delivered them. Adding UDP/IP is a matter of creating a new
`NetworkInterface` implementation that wraps smoltcp.

## Architecture

### Dual-Interface Model

The boot loop registers two interfaces with the `UnikernelRuntime`:

- **`"eth0"`** — raw Ethernet (existing, unchanged). Harmony packets ride
  directly on Ethernet with EtherType `0x88B5`. For LAN mesh.
- **`"udp0"`** — UDP/IP via the new netstack. Harmony packets are
  encapsulated in UDP datagrams. For LAN discovery (broadcast) and WAN
  links (explicit peers).

Both coexist. The Reticulum protocol layer handles deduplication — a packet
arriving on both interfaces is processed once.

### Frame Routing

The boot loop routes raw Ethernet frames by EtherType:

| EtherType | Destination |
|-----------|-------------|
| `0x88B5` (Harmony) | Strip header, deliver to runtime as `"eth0"` |
| `0x0800` (IPv4) | Feed to netstack for smoltcp processing |
| `0x0806` (ARP) | Feed to netstack for smoltcp processing |
| Other | Drop silently |

```
                        ┌─────────────┐
    VirtIO-net ────────►│ Boot Loop   │
    (raw Ethernet)      │ EtherType   │
                        │ router      │
                        └──┬──────┬───┘
                   0x88B5  │      │  0x0800/0x0806
                           ▼      ▼
                      ┌────────┐ ┌──────────────┐
                      │ eth0   │ │ NetStack     │
                      │(direct)│ │ (smoltcp)    │
                      └───┬────┘ │  ┌─────────┐ │
                          │      │  │UDP sock │ │
                          │      │  └────┬────┘ │
                          │      └───────┼──────┘
                          │              │ udp0
                          ▼              ▼
                      ┌──────────────────────┐
                      │  UnikernelRuntime     │
                      │  (Node state machine) │
                      └──────────────────────┘
```

## New Crate: `harmony-netstack`

A `no_std`-compatible crate (with `alloc`) that bridges raw Ethernet devices
and the Harmony protocol layer via smoltcp's IP stack.

### Crate Structure

```
crates/harmony-netstack/
├── Cargo.toml
├── src/
│   ├── lib.rs          // NetStack struct, NetworkInterface impl
│   ├── builder.rs      // NetStackBuilder
│   ├── device.rs       // FrameBuffer implementing smoltcp::phy::Device
│   ├── peers.rs        // PeerTable, PeerEntry
│   └── config.rs       // HARMONY_UDP_PORT, constants
```

### Dependencies

```toml
[dependencies]
smoltcp = { version = "0.12", default-features = false, features = [
    "medium-ethernet",
    "proto-ipv4",
    "socket-udp",
    "alloc",
] }
harmony-platform = { path = "../../harmony/crates/harmony-platform" }
```

Added to the harmony-os workspace members list. Not excluded (unlike boot
crates) since it doesn't require a bare-metal target.

### API

**Builder pattern for configuration:**

```rust
let netstack = NetStack::builder()
    .mac(virtio_net.mac())
    .static_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 2, 15), 24))
    .gateway(Ipv4Address::new(10, 0, 2, 2))
    .port(4242)
    .enable_broadcast(true)
    .add_peer("10.0.2.20", 4242)   // explicit peer
    .build(now);
```

**Core methods:**

```rust
impl NetStack {
    /// Feed a raw Ethernet frame into smoltcp for IP/ARP processing.
    fn ingest(&mut self, frame: &[u8]);

    /// Drive smoltcp's internal processing. Call after ingest(),
    /// before receive().
    fn poll(&mut self, now: Instant);

    /// Drain outbound Ethernet frames produced by smoltcp
    /// (ARP replies, UDP datagrams). Caller sends via hardware driver.
    fn drain_tx(&mut self) -> impl Iterator<Item = &[u8]>;
}
```

**`NetworkInterface` implementation:**

```rust
impl NetworkInterface for NetStack {
    fn name(&self) -> &str { "udp0" }
    fn mtu(&self) -> usize { 1472 } // 1500 - 20 (IP) - 8 (UDP)

    /// Returns next Harmony packet received via UDP, or None.
    fn receive(&mut self) -> Option<Vec<u8>>;

    /// Sends a Harmony packet as UDP to all peers
    /// (broadcast + explicit peer list).
    fn send(&mut self, data: &[u8]) -> Result<(), PlatformError>;
}
```

### smoltcp Device Integration

The netstack uses an internal `FrameBuffer` that implements smoltcp's
`Device` trait. Frames flow through queues rather than giving smoltcp
direct hardware access:

- `ingest()` pushes frames into the RX queue
- smoltcp's `poll()` consumes from RX, produces to TX
- `drain_tx()` reads from the TX queue

This keeps the netstack fully decoupled from any specific hardware driver —
it works with VirtIO, GENET, or any future Ethernet device.

## Peer Management

### Peer Table

```rust
struct PeerTable {
    peers: Vec<PeerEntry>,   // explicit WAN peers (IP:port)
    broadcast: bool,         // send to 255.255.255.255 on LAN
    port: u16,               // Harmony UDP port (default 4242)
}
```

### Send Behavior

When `NetworkInterface::send()` is called:

1. If broadcast enabled: send as UDP to `255.255.255.255:4242`
2. For each explicit peer: send a unicast UDP copy

A single `send()` may produce multiple UDP datagrams. This is correct for
mesh semantics — announces and heartbeats should reach all known peers.

### Receive Behavior

Any UDP packet arriving on the Harmony port is accepted regardless of
source IP. The Reticulum protocol layer handles authentication via
cryptographic announces. Unknown senders are expected — that's how new
peers are discovered.

### Configuration

Peers are configured via the builder pattern in the boot crate's `main.rs`.
This allows different peer lists per platform (QEMU vs RPi5) without
recompiling the netstack. DNS resolution for hostnames is out of scope for
now (accepts IP strings only).

## VirtIO Driver Changes

The current driver strips Ethernet headers on receive and adds them on send.
Two new methods expose raw frames:

```rust
impl VirtioNet {
    // Existing (unchanged)
    fn receive(&mut self) -> Option<Vec<u8>>;  // strips headers, Harmony only
    fn send(&mut self, data: &[u8]) -> Result<(), PlatformError>;

    // New — full Ethernet frames, no filtering
    fn receive_raw(&mut self) -> Option<Vec<u8>>;  // includes Ethernet header
    fn send_raw(&mut self, frame: &[u8]) -> Result<(), PlatformError>;
}
```

The boot loop switches to `receive_raw()` and routes by EtherType. The
existing `NetworkInterface` impl stays unchanged.

## IP Configuration

Static IP assignment only. Configured via the builder:

```rust
.static_ip(Ipv4Cidr::new(Ipv4Address::new(10, 0, 2, 15), 24))
.gateway(Ipv4Address::new(10, 0, 2, 2))
```

DHCP support is deferred — smoltcp has a DHCP client that can be added
later without architectural changes.

## Boot Loop Integration

```rust
loop {
    let now = pit.now_ms();

    // RX: poll hardware, route by EtherType
    while let Some(frame) = virtio_net.receive_raw() {
        match ethertype(&frame) {
            0x88B5 => {
                let payload = &frame[14..]; // strip Ethernet header
                let actions = runtime.handle_packet("eth0", payload.to_vec(), now);
                dispatch_actions(&actions, ...);
            }
            0x0800 | 0x0806 => netstack.ingest(&frame),
            _ => {}
        }
    }

    // Process IP stack
    netstack.poll(smoltcp::time::Instant::from_millis(now as i64));

    // TX: send frames smoltcp produced
    for frame in netstack.drain_tx() {
        virtio_net.send_raw(frame);
    }

    // UDP-received Harmony packets
    while let Some(pkt) = netstack.receive() {
        let actions = runtime.handle_packet("udp0", pkt, now);
        dispatch_actions(&actions, ...);
    }

    // Existing: runtime tick, dispatch actions
    let actions = runtime.tick(now);
    dispatch_actions(&actions, ...);

    core::hint::spin_loop();
}
```

## Testing

### Unit Tests (harmony-netstack, host)

Run with `cargo test -p harmony-netstack`.

1. **Frame buffer device** — ingest queues frames, drain_tx produces frames
2. **UDP round-trip** — feed raw Ethernet/IP/UDP frame, verify receive()
   returns the UDP payload
3. **Send to peers** — call send(), verify drain_tx() produces broadcast +
   unicast frames
4. **ARP handling** — feed ARP request, verify ARP reply in drain_tx()
5. **Peer table** — builder adds peers, broadcast toggle, correct datagram count
6. **EtherType routing** — verify routing logic (helper function)

### QEMU Integration Smoke Test

Extend the x86_64 boot crate behind `#[cfg(feature = "qemu-test")]`:

1. NetStack initializes without panic
2. ARP responds (QEMU virtual network)
3. UDP send/receive via QEMU user-mode networking with port forwarding

Built on existing `cargo xtask build-image-test` infrastructure.

## Out of Scope

- **DHCP** — static IP only for now
- **IPv6** — IPv4 only; smoltcp feature flag makes this easy to add later
- **DNS resolution** — peers configured by IP string, not hostname
- **GENET driver** — RPi5 Ethernet is bead harmony-b9e's territory
- **9P `/dev/net/*` namespace** — Ring 2 concern, separate bead
- **QUIC / hole-punching** — future layer on top of this foundation
- **IPv6 key-derived addresses** — future (Yggdrasil-style)
- **Two-node QEMU mesh test over UDP** — composition with existing mesh
  test; sound if unit tests pass

## Future Direction

The `NetworkInterface` trait is already transport-agnostic. Each new link
layer (WiFi, BLE, LoRa, cellular) registers as another named interface with
the runtime. The netstack wraps any raw Ethernet source; non-Ethernet
transports (serial, LoRa) bypass smoltcp entirely and implement
`NetworkInterface` directly. The Node state machine handles multi-interface
routing, deduplication, and peer discovery at the protocol layer.

A bootstrap server (e.g., `h.q8.fyi`) can be added as an explicit peer.
Future work includes QUIC-based hole-punching (inspired by Iroh) and
IPv6 addresses derived from public keys (inspired by Yggdrasil) for
direct peer-to-peer connectivity.
