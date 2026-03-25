# xHCI Bulk IN/OUT Data Transfers — Design Spec

## Goal

Add bulk data transfer support to `XhciDriver` so configured bulk
endpoints can send and receive data. Foundation for USB mass storage
and network class drivers.

## Background

Phase 3 configures bulk endpoints with transfer rings. This bead adds
the ability to enqueue Normal TRBs on those rings and process their
completion events. Bulk transfers are the simplest transfer type — no
Setup/Status stages, just data.

## New Constant

```rust
pub const TRB_NORMAL: u8 = 1;
```

## New TransferRing Method

```rust
pub fn enqueue_bulk(
    &mut self,
    data_buf_phys: u64,
    data_len: u32,
) -> Result<Vec<(u64, Trb)>, XhciError>
```

Enqueues a single Normal TRB with `IOC | ISP` flags. ISP ensures a
Transfer Event on short packets (device returns less data than the
buffer size). Returns TRB entries to write to DMA.

## New Driver Methods

### bulk_transfer_out

```rust
pub fn bulk_transfer_out(
    &mut self,
    slot_id: u8,
    endpoint_id: u8,
    data_buf_phys: u64,
    data_len: u32,
) -> Result<Vec<XhciAction>, XhciError>
```

Enqueues a bulk OUT (host-to-device) transfer on the specified
endpoint. Caller must have called `configure_endpoint` first to set up
the transfer ring for this endpoint.

### bulk_transfer_in

```rust
pub fn bulk_transfer_in(
    &mut self,
    slot_id: u8,
    endpoint_id: u8,
    data_buf_phys: u64,
    data_len: u32,
) -> Result<Vec<XhciAction>, XhciError>
```

Enqueues a bulk IN (device-to-host) transfer. Same pattern as OUT.

### Shared Logic

Both methods:
1. Validate Running state, slot_id range
2. Look up `ring_key(slot_id, endpoint_id)` in `transfer_rings`
3. `debug_assert!` DWORD-alignment on `data_buf_phys`
4. Call `xfer_ring.enqueue_bulk(data_buf_phys, data_len)`
5. Convert entries to `Vec<XhciAction::WriteTrb>`
6. Append `XhciAction::RingDoorbell` with target = endpoint_id

Since bulk IN and OUT use the same Normal TRB (direction is determined
by the endpoint's configuration, not the TRB), a single internal
method can serve both. The two public methods exist for API clarity.

## Doorbell Target

For EP0, the doorbell target is always 1. For non-EP0 endpoints, the
target equals the endpoint DCI (which is the `endpoint_id`). The
doorbell offset is `db_offset + 4 * slot_id`.

## Transfer Event Matching

Already implemented in `process_event` — returns `TransferEvent` with
`slot_id`, `endpoint_id`, `completion_code`, `residual_length`, and
`trb_pointer`. The caller matches on `(slot_id, endpoint_id)` to
determine which bulk transfer completed.

Actual bytes transferred = `data_len - residual_length`.

## Testing

- `enqueue_bulk` produces 1 Normal TRB with IOC + ISP flags
- `bulk_transfer_out` produces 1 WriteTrb + RingDoorbell(target=ep_id)
- `bulk_transfer_in` same pattern
- State guard: InvalidState when not Running
- Ring guard: NoTransferRing when endpoint not configured
- Doorbell target uses endpoint_id, not hardcoded 1

## Out of Scope

- Scatter-gather (multiple Normal TRBs per transfer)
- Stream transfers (SuperSpeed bulk streams)
- Error recovery (endpoint halt/stall handling)
