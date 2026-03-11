# RPi5 USB (DWC) + Ethernet (GENET) Drivers

**Bead:** harmony-2ey
**Scope:** Ring 1 GENET driver + Ring 2 9P FileServer + DWC USB stub

## Goal

Add a BCM54213PE GENET Ethernet driver to harmony-os following the established
sans-I/O pattern (RegisterBank trait, MockRegisterBank for tests). Wrap it in a
9P FileServer for Ring 2. Stub out the DWC USB register map for future work.

## Scope Decisions

- **GENET: full implementation.** Primary Ethernet on RPi5, critical path for
  mesh networking. Sans-I/O driver + 9P FileServer with rich namespace.
- **DWC USB: stub only.** USB xHCI is a massive spec. Register map constants
  and empty struct only — no logic, no tests. Future bead.
- **Boot loop integration: out of scope.** The RPi5 bootable image bead wires
  GENET into the boot loop. This bead delivers tested, ready-to-wire components.
- **NetworkInterface impl: deferred.** That trait is for Ring 1 boot-loop direct
  usage. The Ring 2 deliverable here is the 9P FileServer.

## Module Layout

```
harmony-unikernel/src/drivers/
├── mod.rs              # add genet, dwc_usb modules
├── register_bank.rs    # existing (shared)
├── pl011.rs            # existing (reference)
├── genet.rs            # NEW — BCM54213PE sans-I/O driver
└── dwc_usb.rs          # NEW — register constants, empty struct

harmony-microkernel/src/
├── genet_server.rs     # NEW — 9P FileServer
└── lib.rs              # register GenetServer
```

## GENET Driver (Ring 1)

### Register Map

Derived from the Linux `bcmgenet` driver (`drivers/net/ethernet/broadcom/genet/`).
~30-40 register offset constants covering:

- System control (SYS_REV_CTRL, SYS_PORT_CTRL)
- UniMAC (UMAC_CMD, UMAC_MAC0, UMAC_MAC1)
- TX/RX DMA control and status
- PHY/MDIO interface
- Hardware counters (MIB)

### Driver Struct

```rust
pub struct GenetDriver<const RX_RING: usize, const TX_RING: usize> {
    rx_head: usize,           // next descriptor to check
    tx_tail: usize,           // next descriptor to use
    tx_pending: usize,        // frames queued, not yet completed
    mac: [u8; 6],             // cached MAC address
    link_up: bool,            // PHY link status
}
```

### API

All methods take `&mut impl RegisterBank` — no embedded I/O.

```rust
// Initialization
pub fn init(bank: &mut impl RegisterBank, mac: [u8; 6]) -> Result<Self, GenetError>

// TX path
pub fn tx_ready(&self, bank: &impl RegisterBank) -> bool
pub fn send(&mut self, bank: &mut impl RegisterBank, frame: &[u8]) -> Result<(), GenetError>
pub fn tx_complete(&mut self, bank: &impl RegisterBank) -> usize

// RX path
pub fn poll_rx(&mut self, bank: &impl RegisterBank) -> Option<RxFrame>

// Status
pub fn link_status(&mut self, bank: &impl RegisterBank) -> bool
pub fn mac(&self) -> [u8; 6]
pub fn stats(&self, bank: &impl RegisterBank) -> GenetStats
```

### DMA Handling

The driver manages descriptor ring state internally (indices, pending counts).
Frame bytes flow in/out as `&[u8]` slices — the caller owns buffer memory.
No DMA trait abstraction needed. RegisterBank handles the MMIO control
registers; the driver encapsulates the ring management complexity.

This matches how PL011 handles its ring buffer internally while exposing
`write_bytes(&[u8])` / `read_buffered(&mut [u8])` to the caller.

## 9P FileServer (Ring 2)

### Namespace

```
/dev/net/genet0/
├── data       # read = next RX frame, write = send TX frame
├── mac        # read-only, "aa:bb:cc:dd:ee:ff\n"
├── mtu        # read-only, "1500\n"
├── stats      # read-only, "rx_packets: N\ntx_packets: N\n..."
└── link       # read-only, "up\n" or "down\n"
```

### Semantics

| File | read() | write() | Mode |
|------|--------|---------|------|
| data | One Ethernet frame (empty if none) | Send one frame | ReadWrite |
| mac | MAC address as hex string | error | ReadOnly |
| mtu | "1500\n" | error | ReadOnly |
| stats | Key-value counters | error | ReadOnly |
| link | "up\n" / "down\n" | error | ReadOnly |

### Struct

```rust
pub struct GenetServer<B: RegisterBank, const RX: usize, const TX: usize> {
    driver: GenetDriver<RX, TX>,
    bank: B,
    fids: BTreeMap<Fid, FidState>,
}
```

FidState tracks QPath (Root, Data, Mac, Mtu, Stats, Link) and open state.
Walk to "genet0" enters the directory, then walk to child files. Standard 9P
directory traversal following UartServer patterns.

## DWC USB Stub

Register offset constants from the xHCI spec. Empty `DwcUsbDriver` struct.
No methods, no tests. Placeholder for a future bead.

## Testing

### GENET Driver (~15-20 tests)

- init_writes_correct_registers
- send_frame_writes_dma_control_registers
- send_when_ring_full_returns_error
- tx_complete_frees_descriptors
- poll_rx_returns_frame_when_available
- poll_rx_returns_none_when_empty
- poll_rx_reports_error_frames
- link_status_reads_phy_register
- stats_returns_counters
- mac_address_set_during_init

### GenetServer (~10-12 tests)

- Walk/open/clunk lifecycle for each file
- Read mac/mtu/link returns correct values
- Write to data sends frame through driver
- Read from data returns next RX frame
- Write to read-only files returns IpcError
- Walk to nonexistent file returns error

### No QEMU integration tests — sans-I/O correctness against the Linux driver
register sequences is sufficient. Hardware validation comes with the RPi5
bootable image bead.

## Integration Points

GENET slots into the existing architecture where VirtIO-net sits:

```
GenetDriver (this bead)
    ↓ raw frames via poll_rx() / send()
GenetServer (this bead, Ring 2)
    ↓ 9P read/write on /dev/net/genet0/data
FrameBuffer (existing, harmony-netstack)
    ↓ smoltcp Device trait
NetStack → UnikernelRuntime
```

No changes to existing crates. GENET is additive.

## Deviations from Plan

The following API signatures changed during implementation and review:

| Design doc | Final implementation | Reason |
|---|---|---|
| `GenetDriver { rx_head, tx_tail, tx_pending }` | `{ rx_cons_index, tx_prod_index, tx_cons_index }` | Names match GENET hardware register semantics |
| `init(bank, mac) -> Result<Self, GenetError>` | `init(bank, mac, poll_count) -> Result<Self, GenetError>` | Sans-I/O: caller controls DMA timeout |
| `link_status(bank) -> bool` | `link_status(bank, poll_count) -> Result<bool, GenetError>` | MDIO timeout/NACK are reportable errors |
| `stats(bank) -> GenetStats` | `stats() -> GenetStats` | Stats tracked internally, no register reads needed |

Additional features added during review:
- `GenetError::MdioReadFail` — distinct from `MdioTimeout` (PHY NACK vs bus hang)
- SOP/EOP validation on RX descriptors
- Zero-length RX descriptor rejection
- 9P offset handling for text pseudo-files
- Accurate `stat.size` for fixed-content files (mac=18, mtu=5)
