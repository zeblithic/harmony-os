# 9P VmServer: VM Lifecycle Control Plane

**Date:** 2026-03-27
**Status:** Draft
**Bead:** harmony-os-fej
**Depends on:** harmony-os-48g (VirtIO data plane), harmony-os-ikw (hypervisor)

## Problem

The kernel needs to manage VM lifecycle (create, start, destroy, query state) through the 9P namespace. Currently the only way to interact with VMs is through the raw `Hypervisor::handle()` method and HVC function IDs. The VmServer exposes VM management as files, consistent with the OS's "everything is a 9P file" design.

## Constraints

- **Follow `GenetServer`/`VirtioNetServer` pattern.** Same `FidTracker`, same `FileServer` implementation style.
- **Command pattern for writes.** `ctl` writes produce `VmCommand` values that the kernel executes against the hypervisor. The VmServer itself does NOT hold a `&mut Hypervisor` — this avoids the multiple-`&mut`-borrow problem when multiple VMs exist.
- **YAGNI.** Two files (`ctl`, `config`). No stats counters until the hypervisor tracks them.
- **One server per VM.** Each `VmServer` manages a specific VMID. The kernel mounts one per VM.

## Architecture

The VmServer uses a **command pattern** instead of directly calling the hypervisor. This solves the Rust borrow-checker constraint: multiple `VmServer` instances cannot each hold `&mut Hypervisor` simultaneously.

```
Kernel creates a VM:
  1. kernel calls hypervisor.handle(HVC_VM_CREATE, ...) → gets VMID
  2. kernel constructs VmServer::new(vmid, mac, "vm1")

Kernel processes 9P operations:
  3. write "start 0x40000000 0x44000000" to vm1/ctl
       → VmServer.write() returns Ok(n)
       → VmServer.pending_command() returns Some(VmCommand::Start { entry_ipa, dtb_ipa })
       → kernel calls hypervisor.handle(HVC_VM_START, vmid, entry_ipa, dtb_ipa)
       → kernel calls vm_server.update_state(VmState::Running)

  4. read vm1/ctl
       → VmServer.read() → "running\n"

  5. read vm1/config
       → "vmid: 1\nmac: 02:00:00:00:00:01\n"
```

The VmServer is a **pure 9P parser** — it parses commands, formats state, and tracks fids. It does NOT execute commands or hold hypervisor references.

## File Layout

| File | Crate | Responsibility |
|------|-------|---------------|
| `src/hv_manager.rs` | harmony-microkernel | `VmCommand`, `VmState`, `VmManagerError` types |
| `src/hv_server.rs` | harmony-microkernel | 9P `FileServer` for VM lifecycle |

Modified:
- `harmony-microkernel/src/lib.rs` — add `pub mod hv_manager; pub mod hv_server;`

**Note:** Named `hv_manager`/`hv_server` (not `vm_manager`/`vm_server`) to avoid confusion with the existing `vm/manager.rs` (virtual memory address space manager).

**No hypervisor bridge needed.** The command pattern eliminates the adapter struct — the kernel reads `VmCommand` from the server and calls the hypervisor directly.

## Types

In `harmony-microkernel/src/hv_manager.rs`:

```rust
/// Commands produced by VmServer when the kernel writes to ctl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmCommand {
    /// Start the VM at entry_ipa with DTB at dtb_ipa.
    Start { entry_ipa: u64, dtb_ipa: u64 },
    /// Destroy the VM and free its resources.
    Destroy,
}

/// VM lifecycle state, set by the kernel after executing commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Created,
    Running,
    Halted,
}

impl VmState {
    pub fn as_str(&self) -> &'static str {
        match self {
            VmState::Created => "created\n",
            VmState::Running => "running\n",
            VmState::Halted => "halted\n",
        }
    }
}
```

## HvServer (9P FileServer)

In `harmony-microkernel/src/hv_server.rs`:

```rust
pub struct HvServer {
    vmid: u8,
    mac: [u8; 6],
    state: VmState,
    name: &'static str,      // "vm1", "vm2", etc.
    tracker: FidTracker<()>,
    pending: Option<VmCommand>,
}
```

Not generic — no trait parameter. The server stores the VM's current state directly. The kernel updates it via `update_state()` after executing commands.

### Namespace

```
/dev/vm/vm1/
  ├── ctl      — R/W
  ├── config   — R
```

QPaths: ROOT(0), DIR(1), CTL(2), CONFIG(3).

### Constructor

```rust
impl HvServer {
    /// Create a new VmServer for an existing VM.
    /// The kernel calls HVC_VM_CREATE first, then constructs this server.
    pub fn new(vmid: u8, mac: [u8; 6], name: &'static str) -> Self;

    /// Read and clear the pending command (if any).
    /// Called by the kernel after a successful ctl write.
    pub fn take_pending_command(&mut self) -> Option<VmCommand>;

    /// Update the VM's state after the kernel executes a command.
    pub fn update_state(&mut self, state: VmState);
}
```

### ctl file (R/W)

**read:** Returns the current VM state string (`"created\n"` / `"running\n"` / `"halted\n"`). Uses `slice_at_offset` for proper offset/count handling.

**write:** Parses commands. Returns `IpcError::InvalidArgument` for unrecognized commands or bad hex.
- `"start 0x<entry_ipa> 0x<dtb_ipa>"` — parse both hex IPAs. Example: `"start 0x40000000 0x44000000"`. Stores `VmCommand::Start { entry_ipa, dtb_ipa }` in `self.pending`.
- `"destroy"` — stores `VmCommand::Destroy` in `self.pending`.

The write succeeds (returns byte count) even before the kernel executes the command. The kernel reads `take_pending_command()` in its event loop.

### config file (R)

Read-only. Returns VM metadata formatted as key-value pairs. Uses `slice_at_offset`.

```
vmid: 1
mac: 02:00:00:00:00:01
```

### FileServer Implementation

Same pattern as `VirtioNetServer`:
- **walk:** Dynamic device name via `self.name` string comparison
- **open:** `ctl` is R/W, `config` is read-only
- **clone_fid:** Delegate to `self.tracker.clone_fid()`
- **stat:** CTL size=0 (dynamic), CONFIG size=0 (dynamic)
- **clunk:** Release fid from tracker

## Testing Strategy

All tests use `HvServer` directly — no mocks needed since the server doesn't call out to anything.

| Test | What |
|------|------|
| `walk_to_ctl_and_config` | Walk root → dir → ctl/config, verify QPaths |
| `walk_wrong_name_fails` | Walk root → "wrong" → NotFound |
| `open_ctl_readwrite` | Open ctl R/W succeeds |
| `open_config_write_fails` | Open config for Write → ReadOnly |
| `read_ctl_created` | State=Created, read ctl → "created\n" |
| `read_ctl_running` | update_state(Running), read ctl → "running\n" |
| `read_ctl_halted` | update_state(Halted), read ctl → "halted\n" |
| `read_ctl_with_offset` | Read at offset 4 → partial string |
| `write_ctl_start` | Write "start 0x40000000 0x44000000", verify pending = Start { 0x40000000, 0x44000000 } |
| `write_ctl_destroy` | Write "destroy", verify pending = Destroy |
| `write_ctl_bad_command` | Write "invalid" → InvalidArgument |
| `write_ctl_bad_hex` | Write "start 0xZZZZ 0x0" → InvalidArgument |
| `read_config_format` | Verify "vmid: 1\nmac: 02:00:00:00:00:01\n" |
| `take_pending_clears` | After write "destroy", take_pending returns Some(Destroy), second call returns None |
| `stat_returns_metadata` | Stat on each file, verify FileType and name |

All testable with `cargo test`.

## Out of Scope

- Stats counters (trap_count, hvc_count, uptime) — add when hypervisor tracks them
- VM memory mapping via 9P (HVC_VM_MAP is used directly for now)
- Multiple VMs per HvServer (one server per VM)
- Hot-swap of HvServer (kernel creates/destroys servers with VM lifecycle)
- `HypervisorVmManager` bridge (eliminated by command pattern)
