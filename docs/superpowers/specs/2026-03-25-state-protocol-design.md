# /state File Convention + State Transfer Protocol

## Goal

Define the `/state` pseudo-file convention for `FileServer` implementations, wire state transfer into the kernel's `hot_swap` method, and implement a reference `/state` on `EchoServer`. After this, hot-swapping a stateful server preserves its data across the swap.

## Scope

**In scope (this bead — harmony-os-lbz):**
- `/state` file convention: read = serialize state, write = restore state
- Walk-based discovery: walk to `state` → `NotFound` means stateless
- State transfer step in `Kernel::hot_swap`: read old `/state` → write new `/state`
- `EchoServer` reference implementation of `/state`
- `MAX_STATE_SIZE` constant (4MB) bounding transfer memory
- Tests: EchoServer state round-trip, kernel hot_swap with state transfer, stateless server skip

**Out of scope (harmony-os-su6):**
- ContentServer `/state` (books + pages serialization)
- NixStoreServer `/state` (store paths serialization)
- ConfigServer `/state` (config pointer serialization)

**Out of scope (harmony-os-1um):**
- Hardware/ephemeral servers (GenetServer, SDServer, SerialServer, GPIOServer)

## Architecture

### The /state Convention

Any `FileServer` that supports state transfer exposes a virtual file named `state` in its root directory. The kernel discovers this via a normal walk — no trait changes, no flags, no new plumbing.

**Read:** Returns the server's transferable state as opaque bytes. Format is server-defined. The kernel never interprets these bytes.

**Write:** Restores the server from the provided bytes. Only valid before the server has handled client requests (immediately after construction, before mount rebind).

**Discovery:** `walk(root_fid, "state")` → `NotFound` means the server is stateless. The kernel skips state transfer and proceeds with a stateless swap.

### State Transfer Sequence

The kernel's `hot_swap` method gains steps 3-4:

```
1. Validate mount (Active, exact path, not self-mount)
2. Spawn new process with fresh server
3. Read /state from old server:
   a. clone_fid(root) → walk_fid
   b. walk(walk_fid, "state") — if NotFound, skip to step 5
   c. open(state_fid, Read)
   d. read(state_fid, 0, MAX_STATE_SIZE)
   e. clunk(state_fid)
4. Write /state to new server:
   a. clone_fid(root) → walk_fid
   b. walk(walk_fid, "state") — if NotFound, skip to step 5
   c. open(state_fid, Write)
   d. write(state_fid, 0, &state_bytes)
   e. clunk(state_fid)
5. Mark Swapping
6. Rebind
7. Destroy old
```

The kernel calls `FileServer` methods directly on the `Box<dyn FileServer>` — no wire encoding. Server-side fids are allocated internally (not exposed to clients).

### Error Handling

- Walk to `state` returns `NotFound` on either server → skip state transfer (stateless swap). Not an error.
- Read or write of `/state` fails → rollback. Destroy new process, old server stays active.
- State too large (> `MAX_STATE_SIZE`) → the read returns a truncated buffer. Server's write handler can reject it or accept what fits.

### Size Limit

`MAX_STATE_SIZE = 4 * 1024 * 1024` (4MB). A single `read(fid, 0, MAX_STATE_SIZE)` call. Servers with state larger than 4MB should use shared backing stores (e.g., `Arc<ContentServer>` as ConfigServer already does). For EchoServer this is far more than enough.

## EchoServer /state Implementation

### Current State

```rust
pub struct EchoServer {
    tracker: FidTracker<()>,   // session — NOT transferred
    echo_data: Vec<u8>,        // transferable — the echo buffer
}
```

### Changes

Add `state` to the virtual filesystem:

```
/
├── hello   — read-only greeting
├── echo    — read/write echo buffer
└── state   — read: echo_data bytes; write: replace echo_data
```

**QPath:** Add `STATE` constant (e.g., `3`) and `NodeKind::State` variant to the existing fid tracking.

**Walk:** `"state"` → `NodeKind::State`

**Open:** `State` accepts `Read`, `Write`, and `ReadWrite` modes.

**Read:** Return `self.echo_data.clone()`.

**Write:** Replace `self.echo_data` with the written bytes. Return bytes written.

**Stat:** Regular file, size = `echo_data.len()`.

The echo buffer IS the serialization format — no encoding/decoding needed. This is the simplest possible `/state` implementation, serving as the reference for more complex servers.

## hot_swap State Transfer

### Implementation in kernel.rs

The state transfer step goes between `spawn_process` (step 2) and `set_mount_state(Swapping)` (step 5 in the new numbering).

The kernel needs to:
1. Get a fid on the old server's root (the mount's `root_fid`)
2. Walk to `state`, open, read, clunk
3. Get a fid on the new server's root
4. Walk to `state`, open, write, clunk

**Fid management:** The kernel allocates temporary server-side fids via `allocate_server_fid()` (existing method). These fids are used only for the state transfer call and clunked immediately after.

**Direct server access:** The kernel accesses `processes[pid].server` directly (it owns the `Box<dyn FileServer>`). No capability checks needed — the kernel is trusted.

### Helper: `try_transfer_state`

Extract the state transfer logic into a helper to keep `hot_swap` readable:

```rust
fn try_transfer_state(
    &mut self,
    old_pid: u32,
    new_pid: u32,
) -> Result<bool, IpcError>
```

Returns `Ok(true)` if state was transferred, `Ok(false)` if either server doesn't support `/state`, `Err` if transfer failed.

The helper:
1. Allocates temp fids for old server
2. Tries `clone_fid(root) + walk("state")` on old server — if `NotFound`, return `Ok(false)`
3. Opens and reads state bytes
4. Clunks old fids
5. Allocates temp fids for new server
6. Tries `clone_fid(root) + walk("state")` on new server — if `NotFound`, return `Ok(false)`
7. Opens and writes state bytes
8. Clunks new fids
9. Returns `Ok(true)`

## File Map

| File | Change |
|------|--------|
| `harmony-microkernel/src/echo.rs` | Add `state` to walk/open/read/write/stat handlers, ~30 lines |
| `harmony-microkernel/src/kernel.rs` | Add `MAX_STATE_SIZE`, `try_transfer_state` helper, wire into `hot_swap` |

## Testing Strategy

### echo.rs tests (~4 tests)
- `state_walk_exists` — walk to "state" from root succeeds
- `state_read_returns_echo_data` — write "hello" to echo, read state, bytes match
- `state_write_restores_data` — write state bytes to fresh EchoServer, echo file returns restored data
- `state_round_trip` — write → read state → new server → write state → verify

### kernel.rs tests (~2 tests)
- `hot_swap_transfers_state` — write to old echo → hot_swap → read from new echo → data preserved
- `hot_swap_stateless_server_succeeds` — swap with server that doesn't expose `/state` → succeeds, no crash

## Future Work (Explicitly Deferred)

- **harmony-os-su6:** ContentServer, NixStoreServer, ConfigServer `/state` with CBOR serialization
- **harmony-os-1um:** Hardware/ephemeral servers (optional)
- **State versioning:** Server-side concern — the server's write handler can check a version prefix and reject incompatible state. No kernel involvement needed.
- **Incremental state transfer:** For servers with >4MB state, use shared backing stores (`Arc`) instead of `/state` byte transfer.
- **ConfigApplicator integration:** Trigger hot-swap from NodeConfig diffs (services_updated in ConfigDiff) — separate from the state protocol itself.
