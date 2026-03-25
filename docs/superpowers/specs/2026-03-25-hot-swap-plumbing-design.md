# 9P Service Hot-Swap — Kernel Plumbing

## Goal

Add the kernel-level infrastructure to atomically replace a running 9P service with a new one, without rebooting. This enables `nixos-rebuild switch` semantics: services hot-swap while the microkernel stays running.

## Scope

**In scope (this bead — harmony-os-fn1):**
- `MountState` enum (`Active`, `Swapping`) on mount points
- `Namespace::set_mount_state()` — transition a mount's state
- `Namespace::rebind()` — atomically replace a mount's target server
- `Kernel::hot_swap()` — orchestrate the full swap sequence
- Reject-and-retry: requests to `Swapping` mounts return `IpcError::NotReady`
- Tests with mock `EchoServer` instances

**Out of scope (harmony-os-lbz — Phase 2):**
- `/state` pseudo-file convention for `FileServer` implementations
- State serialization/transfer between old and new servers
- State format versioning and compatibility
- Per-server `/state` implementations (ContentServer, NixStoreServer, etc.)
- ConfigApplicator integration (triggering swaps from NodeConfig diffs)
- SwapServer 9P control interface (if needed later)

## Architecture

### Why This Is Simple

Three design decisions eliminate most complexity:

1. **Reject-and-retry** (not queuing) — During the swap window, new requests to the affected mount return `IpcError::NotReady`. Callers retry. No kernel-level request buffering, no replay logic, no fid translation headaches.

2. **Synchronous quiescence** — The kernel is single-threaded and cooperative. When `hot_swap()` runs, no other request is in-flight. The `Swapping` state is a safety net, not a synchronization primitive.

3. **Kernel method** (not 9P server) — `hot_swap()` is an internal kernel method. No SwapServer, no control files. Ring 3 integration (ConfigApplicator calling hot_swap) is Phase 2 work.

### The Sequence

```
1. Validate mount_path exists, not already Swapping
2. Spawn new process with new FileServer
3. Set mount state to Swapping (new requests → NotReady)
4. Quiescence is immediate (single-threaded, no in-flight requests)
5. Rebind mount point to new process (atomic)
6. Destroy old process (clunk fids, remove from table)
7. Mount is Active again — next request goes to new server
```

### Error Handling

- If spawn fails: mount stays `Active` on old server (no state change).
- If rebind fails (shouldn't — mount was validated): destroy new process, reset mount to `Active`.
- The old server is only destroyed after successful rebind — no service gap.

## Mount Point State

### MountState enum

```rust
/// Lifecycle state of a mount point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountState {
    /// Normal operation — requests dispatched to target server.
    Active,
    /// Hot-swap in progress — new requests rejected with NotReady.
    Swapping,
}
```

### Updated MountPoint

```rust
pub struct MountPoint {
    pub target_pid: u32,
    pub root_fid: Fid,
    pub state: MountState,
}
```

All existing `mount()` calls create mounts in `Active` state. No API change for callers that don't use hot-swap.

## Namespace Methods

### set_mount_state

```rust
pub fn set_mount_state(&mut self, path: &str, state: MountState) -> Result<(), IpcError>
```

- Requires `path` to be an existing mount point (exact match, not prefix).
- Returns `NotFound` if no mount at `path`.
- Transitions the mount's state.

### rebind

```rust
pub fn rebind(
    &mut self,
    path: &str,
    new_pid: u32,
    new_root_fid: Fid,
) -> Result<MountPoint, IpcError>
```

- Requires `path` to be an existing mount point.
- Atomically replaces `target_pid` and `root_fid` with new values.
- Resets `state` to `Active`.
- Returns the **old** `MountPoint` (caller uses `old.target_pid` for cleanup).
- Returns `NotFound` if no mount at `path`.

### Request rejection

The kernel's IPC dispatch path checks `mount.state` after resolving the path. If `Swapping`, the dispatch returns `IpcError::NotReady` without calling any `FileServer` method. This is checked in the kernel's dispatch logic, not in `Namespace` itself.

## Kernel::hot_swap

```rust
pub fn hot_swap(
    &mut self,
    client_pid: u32,
    mount_path: &str,
    new_server: Box<dyn FileServer>,
    new_server_name: &str,
) -> Result<(), IpcError>
```

- `client_pid` — the process whose namespace contains the mount (typically the init process or the process requesting the swap).
- `mount_path` — the mount point to swap (e.g., `/srv/content`).
- `new_server` — the replacement `FileServer` implementation.
- `new_server_name` — human-readable name for the new process.

**Steps:**

1. Look up `mount_path` in `client_pid`'s namespace. Verify it exists and is `Active`. Return `InvalidArgument` if not found. Return `InvalidState` if already `Swapping`.

2. Spawn new process: `spawn_process(new_server_name, new_server, ...)` → `new_pid`. If spawn fails, return error (mount unchanged).

3. Mark swapping: `namespace.set_mount_state(mount_path, Swapping)`.

4. Rebind: `namespace.rebind(mount_path, new_pid, new_root_fid)` → `old_mount`.

5. Destroy old process: `destroy_process(old_mount.target_pid)`.

6. Return `Ok(())`.

**Rollback on rebind failure:**
If step 4 fails (defensive — shouldn't happen since we validated in step 1):
- `destroy_process(new_pid)` — clean up the new process.
- `set_mount_state(mount_path, Active)` — restore the mount.
- Return the error.

## Integration with Existing Code

### kernel.rs changes

- Add `hot_swap()` method to the kernel impl.
- In the IPC dispatch path (where the kernel resolves a path and dispatches to the target server), add a check: if the resolved mount has `state == Swapping`, return `IpcError::NotReady`.

### namespace.rs changes

- Add `MountState` enum.
- Add `state: MountState` field to `MountPoint`.
- Update `mount()` to initialize `state: MountState::Active`.
- Add `set_mount_state()` method.
- Add `rebind()` method.

### No changes to FileServer trait

The `FileServer` trait is unchanged. Hot-swap is entirely a kernel/namespace concern. Individual servers don't know they're being swapped — they just get destroyed when the kernel calls `destroy_process`.

(Phase 2 adds the `/state` file convention, which *does* extend `FileServer` behavior — but that's a separate bead.)

## File Map

| File | Change |
|------|--------|
| `harmony-microkernel/src/namespace.rs` | Add `MountState`, update `MountPoint`, add `set_mount_state()`, `rebind()` |
| `harmony-microkernel/src/kernel.rs` | Add `hot_swap()`, add `Swapping` check in IPC dispatch |

## Testing Strategy

### namespace.rs tests (~5 tests)
- `rebind_replaces_mount` — mount at path, rebind to new pid, resolve returns new pid
- `rebind_returns_old_mount` — verify old `MountPoint` returned for cleanup
- `rebind_nonexistent_path_fails` — rebind on unmounted path → `NotFound`
- `set_mount_state_swapping` — set state, verify it persists on the mount
- `rebind_resets_state_to_active` — after rebind, state is `Active`

### kernel.rs tests (~4 tests)
- `hot_swap_replaces_server` — spawn echo server at `/srv/echo`, hot-swap with new echo server, verify new server responds to requests
- `hot_swap_destroys_old_process` — verify old PID is gone from process table after swap
- `hot_swap_nonexistent_mount_fails` — hot_swap on bad path → error
- `hot_swap_during_swapping_fails` — mark mount as swapping, attempt hot_swap → `InvalidState`

Tests use `EchoServer` (existing in `echo.rs`) as both old and new servers. The echo server responds deterministically, making it easy to verify which server is active after a swap.

## Future Work (Explicitly Deferred)

- **Phase 2 (harmony-os-lbz):** `/state` file convention, state serialization/transfer, per-server implementations
- **ConfigApplicator integration:** Trigger hot-swaps from NodeConfig diffs (when `services_updated` is non-empty in a `ConfigDiff`)
- **SwapServer control interface:** If Ring 3 needs to trigger swaps via 9P rather than internal calls
- **Capability migration:** Currently capabilities are per-process. A hot-swapped server gets fresh capabilities — clients with open fids to the old server need to re-walk. This is acceptable because `NotReady` already forces clients to retry.
- **Concurrent kernel:** If the kernel becomes multi-threaded, `Swapping` state needs proper synchronization (mutex on mount state, request drain counter). Current design assumes single-threaded cooperative dispatch.
