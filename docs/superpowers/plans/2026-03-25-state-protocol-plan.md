# /state File Convention + State Transfer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `/state` pseudo-file to EchoServer for state serialization, and wire state transfer into `Kernel::hot_swap` so stateful servers preserve data across swaps.

**Architecture:** Servers expose a `state` file in their root directory. The kernel reads state from the old server and writes it to the new server during hot_swap, using existing `FileServer` methods (walk/open/read/write/clunk). Walk-based discovery: if `state` doesn't exist, skip transfer.

**Tech Stack:** Rust, `no_std` + `alloc`, `harmony-microkernel` crate.

**Spec:** `docs/superpowers/specs/2026-03-25-state-protocol-design.md`

---

### Task 1: EchoServer `/state` file

**Files:**
- Modify: `crates/harmony-microkernel/src/echo.rs`

**Context:**
- EchoServer currently has QPath constants: `ROOT=0`, `HELLO=1`, `ECHO=2`.
- Walk handles `"hello"` and `"echo"` from root. Everything else → `NotFound`.
- `echo_data: Vec<u8>` is the transferable state.
- The FidTracker payload is `()` — no NodeKind enum needed, just QPath matching.
- Follow the existing pattern exactly: walk adds fid, open checks mode, read/write dispatch on qpath, stat returns metadata.

- [ ] **Step 1: Write failing tests**

Add to the `#[cfg(test)] mod tests` block in `echo.rs`:

```rust
    #[test]
    fn state_walk_exists() {
        let mut server = EchoServer::new();
        let qpath = server.walk(0, 1, "state").unwrap();
        assert_eq!(qpath, STATE);
    }

    #[test]
    fn state_read_returns_echo_data() {
        let mut server = EchoServer::new();
        // Write some data to the echo file
        server.walk(0, 1, "echo").unwrap();
        server.open(1, OpenMode::Write).unwrap();
        server.write(1, 0, b"preserve me").unwrap();
        server.clunk(1).unwrap();

        // Read state — should return the echo_data bytes
        server.walk(0, 2, "state").unwrap();
        server.open(2, OpenMode::Read).unwrap();
        let state_bytes = server.read(2, 0, 65536).unwrap();
        assert_eq!(state_bytes, b"preserve me");
    }

    #[test]
    fn state_write_restores_data() {
        let mut server = EchoServer::new();

        // Write state bytes directly
        server.walk(0, 1, "state").unwrap();
        server.open(1, OpenMode::Write).unwrap();
        server.write(1, 0, b"restored data").unwrap();
        server.clunk(1).unwrap();

        // Read echo file — should have the restored data
        server.walk(0, 2, "echo").unwrap();
        server.open(2, OpenMode::Read).unwrap();
        let data = server.read(2, 0, 65536).unwrap();
        assert_eq!(data, b"restored data");
    }

    #[test]
    fn state_round_trip() {
        // Simulate hot-swap: old server → read state → new server → write state
        let mut old = EchoServer::new();
        old.walk(0, 1, "echo").unwrap();
        old.open(1, OpenMode::Write).unwrap();
        old.write(1, 0, b"round trip data").unwrap();
        old.clunk(1).unwrap();

        // Read state from old
        old.walk(0, 2, "state").unwrap();
        old.open(2, OpenMode::Read).unwrap();
        let state_bytes = old.read(2, 0, 65536).unwrap();

        // Write state to new
        let mut new = EchoServer::new();
        new.walk(0, 1, "state").unwrap();
        new.open(1, OpenMode::Write).unwrap();
        new.write(1, 0, &state_bytes).unwrap();
        new.clunk(1).unwrap();

        // Verify new server has the data
        new.walk(0, 2, "echo").unwrap();
        new.open(2, OpenMode::Read).unwrap();
        let data = new.read(2, 0, 65536).unwrap();
        assert_eq!(data, b"round trip data");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel echo::tests::state`
Expected: FAIL — `STATE` constant and "state" walk entry don't exist.

- [ ] **Step 3: Implement**

Add `STATE` QPath constant:
```rust
const STATE: QPath = 3;
```

Update `walk` — add `"state"` case:
```rust
        let qpath = match name {
            "hello" => HELLO,
            "echo" => ECHO,
            "state" => STATE,
            _ => return Err(IpcError::NotFound),
        };
```

Update `open` — `State` allows Read, Write, and ReadWrite:
```rust
        // No mode restrictions for STATE — both read and write are valid.
        // (ROOT rejects Write, HELLO rejects Write, ECHO allows all, STATE allows all)
```

No change to the `open` method needed — the existing code only rejects `ROOT` (directory) and `HELLO` (read-only). `STATE` falls through to `mark_open`, which is correct.

Update `read` — add `STATE` case:
```rust
            STATE => &self.echo_data,
```

Update `write` — add `STATE` case:
```rust
            STATE => {
                let len = u32::try_from(data.len()).map_err(|_| IpcError::ResourceExhausted)?;
                self.echo_data = data.to_vec();
                Ok(len)
            }
```

Update `stat` — add `STATE` case:
```rust
            STATE => Ok(FileStat {
                qpath: STATE,
                name: Arc::from("state"),
                size: self.echo_data.len() as u64,
                file_type: FileType::Regular,
            }),
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-microkernel echo`
Expected: all pass (16 existing + 4 new).

- [ ] **Step 5: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/echo.rs
git commit -m "feat(echo): add /state pseudo-file for hot-swap state transfer

Read returns echo_data bytes, write restores them. Reference
implementation of the /state convention — kernel reads from old
server and writes to new server during hot_swap.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `try_transfer_state` helper in kernel.rs

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs`

**Context:**
- The kernel owns `Box<dyn FileServer>` for each process via `processes[pid].server`.
- `allocate_server_fid()` at line 167 returns monotonically increasing fids starting at 1.
- Root fid is always 0 for all servers.
- `clone_fid(0, new_fid)` creates a copy of the root fid — needed to walk to `state` without consuming fid 0.
- The existing walk dispatch (line 432) uses `clone_fid` then multi-step walk. For `/state` we just need one walk component.
- If `walk("state")` returns `NotFound`, the server is stateless — return `Ok(false)`.

- [ ] **Step 1: Add `MAX_STATE_SIZE` constant**

At the top of `kernel.rs` (in the constants section, near the existing `MAX_BINDING_NONCES`):

```rust
/// Maximum state transfer size during hot_swap (4 MB).
const MAX_STATE_SIZE: u32 = 4 * 1024 * 1024;
```

- [ ] **Step 2: Write the `try_transfer_state` helper**

Add to `impl Kernel` (before `hot_swap`):

```rust
    /// Try to transfer state from one server to another via their `/state` files.
    ///
    /// Uses the 9P walk→open→read/write→clunk sequence directly on the
    /// `FileServer` trait objects. If either server doesn't expose a `state`
    /// file (walk returns `NotFound`), returns `Ok(false)` (stateless swap).
    ///
    /// Returns `Ok(true)` if state was transferred, `Err` if transfer failed.
    fn try_transfer_state(
        &mut self,
        old_pid: u32,
        new_pid: u32,
    ) -> Result<bool, IpcError> {
        // ── Read state from old server ──────────────────────────────

        // Allocate temp fids for old server's state file.
        let old_clone_fid = self.allocate_server_fid()?;
        let old_state_fid = self.allocate_server_fid()?;

        let old_server = &mut self
            .processes
            .get_mut(&old_pid)
            .ok_or(IpcError::NotFound)?
            .server;

        // clone_fid(root=0) to get a walk-able fid without consuming root.
        old_server.clone_fid(0, old_clone_fid)?;

        // Walk to "state" — NotFound means server is stateless.
        match old_server.walk(old_clone_fid, old_state_fid, "state") {
            Err(IpcError::NotFound) => {
                let _ = old_server.clunk(old_clone_fid);
                return Ok(false); // stateless — skip transfer
            }
            Err(e) => {
                let _ = old_server.clunk(old_clone_fid);
                return Err(e);
            }
            Ok(_) => {}
        }
        let _ = old_server.clunk(old_clone_fid);

        // Open for read + read all state bytes.
        old_server.open(old_state_fid, OpenMode::Read)?;
        let state_bytes = old_server.read(old_state_fid, 0, MAX_STATE_SIZE)?;
        let _ = old_server.clunk(old_state_fid);

        // ── Write state to new server ───────────────────────────────

        let new_clone_fid = self.allocate_server_fid()?;
        let new_state_fid = self.allocate_server_fid()?;

        let new_server = &mut self
            .processes
            .get_mut(&new_pid)
            .ok_or(IpcError::NotFound)?
            .server;

        new_server.clone_fid(0, new_clone_fid)?;

        match new_server.walk(new_clone_fid, new_state_fid, "state") {
            Err(IpcError::NotFound) => {
                let _ = new_server.clunk(new_clone_fid);
                return Ok(false); // new server doesn't accept state
            }
            Err(e) => {
                let _ = new_server.clunk(new_clone_fid);
                return Err(e);
            }
            Ok(_) => {}
        }
        let _ = new_server.clunk(new_clone_fid);

        new_server.open(new_state_fid, OpenMode::Write)?;
        new_server.write(new_state_fid, 0, &state_bytes)?;
        let _ = new_server.clunk(new_state_fid);

        Ok(true)
    }
```

**NOTE:** The implementer needs to handle the borrow checker carefully — `self.processes.get_mut(&old_pid)` borrows `self.processes` mutably, which conflicts with `self.allocate_server_fid()`. The fid allocations must happen *before* borrowing the process. Read the existing walk() method (line 474-488) for the pattern: allocate fids first, then borrow the server.

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p harmony-microkernel`
Expected: compiles (helper not called yet).

- [ ] **Step 4: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/kernel.rs
git commit -m "feat(kernel): add try_transfer_state helper for /state read/write

Reads state from old server's /state file and writes to new server's
/state file using direct FileServer method calls. Returns Ok(false)
if either server doesn't expose /state (stateless swap).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire state transfer into `hot_swap` + kernel tests

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs`

**Context:**
- `hot_swap` currently: validate → spawn → mark swapping → rebind → destroy.
- State transfer goes between spawn (step 2) and mark swapping (step 3 in current code).
- Need to extract `old_pid` from the mount during validation (step 1) and pass it to `try_transfer_state`.
- If `try_transfer_state` fails, rollback: destroy new process, return error.

- [ ] **Step 1: Write failing tests**

Add to kernel test module:

```rust
    #[test]
    fn hot_swap_transfers_state() {
        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        // Spawn old echo server and write data to it
        let old_echo = Box::new(EchoServer::new());
        let old_pid = kernel.spawn_process("old-echo", old_echo, &[], None).unwrap();
        let client_pid = kernel
            .spawn_process(
                "client",
                Box::new(EchoServer::new()),
                &[("/srv/echo", old_pid, 0)],
                None,
            )
            .unwrap();

        // Grant cap so we can write to old server
        kernel.grant_endpoint_cap(&mut entropy, client_pid, old_pid, 1).unwrap();

        // Walk to echo file, write data
        kernel.walk(client_pid, "/srv/echo/echo", 0, 100, 2).unwrap();
        kernel.open(client_pid, 100, OpenMode::Write).unwrap();
        kernel.write(client_pid, 100, 0, b"hot swap state").unwrap();
        kernel.clunk(client_pid, 100).unwrap();

        // Hot-swap with new echo server
        let new_echo = Box::new(EchoServer::new());
        kernel.hot_swap(client_pid, "/srv/echo", new_echo, "new-echo").unwrap();

        // Grant cap for new server
        let new_pid = kernel.processes.get(&client_pid).unwrap()
            .namespace.resolve("/srv/echo").unwrap().0.target_pid;
        kernel.grant_endpoint_cap(&mut entropy, client_pid, new_pid, 3).unwrap();

        // Read from new server's echo file — should have the transferred state
        kernel.walk(client_pid, "/srv/echo/echo", 0, 200, 4).unwrap();
        kernel.open(client_pid, 200, OpenMode::Read).unwrap();
        let data = kernel.read(client_pid, 200, 0, 65536).unwrap();
        assert_eq!(data, b"hot swap state");
    }

    #[test]
    fn hot_swap_stateless_server_succeeds() {
        // NullServer: a minimal FileServer that doesn't expose /state.
        // walk() always returns NotFound for anything except root.
        struct NullServer {
            tracker: crate::fid_tracker::FidTracker<()>,
        }
        impl NullServer {
            fn new() -> Self {
                Self { tracker: crate::fid_tracker::FidTracker::new(0, ()) }
            }
        }
        impl FileServer for NullServer {
            fn walk(&mut self, fid: Fid, new_fid: Fid, _name: &str) -> Result<QPath, IpcError> {
                let _ = self.tracker.get(fid)?;
                Err(IpcError::NotFound)
            }
            fn open(&mut self, fid: Fid, _mode: OpenMode) -> Result<(), IpcError> {
                let entry = self.tracker.begin_open(fid)?;
                entry.mark_open(_mode);
                Ok(())
            }
            fn read(&mut self, _: Fid, _: u64, _: u32) -> Result<Vec<u8>, IpcError> {
                Err(IpcError::NotFound)
            }
            fn write(&mut self, _: Fid, _: u64, _: &[u8]) -> Result<u32, IpcError> {
                Err(IpcError::NotFound)
            }
            fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
                self.tracker.clunk(fid)
            }
            fn stat(&mut self, _: Fid) -> Result<FileStat, IpcError> {
                Ok(FileStat {
                    qpath: 0,
                    name: Arc::from("/"),
                    size: 0,
                    file_type: FileType::Directory,
                })
            }
            fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
                self.tracker.clone_fid(fid, new_fid)
            }
        }

        let mut entropy = make_test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

        let old_pid = kernel.spawn_process("null", Box::new(NullServer::new()), &[], None).unwrap();
        let client_pid = kernel
            .spawn_process(
                "client",
                Box::new(EchoServer::new()),
                &[("/srv/null", old_pid, 0)],
                None,
            )
            .unwrap();

        // Hot-swap with another NullServer — should succeed (no state transfer)
        let new_null = Box::new(NullServer::new());
        kernel.hot_swap(client_pid, "/srv/null", new_null, "new-null").unwrap();

        // Old server gone, new server mounted — swap completed without crash
        assert!(!kernel.processes.contains_key(&old_pid));
    }
```

**IMPORTANT:** The implementer must adapt these tests to match the actual kernel test infrastructure. Read existing `hot_swap_*` tests for the pattern. The `NullServer` must be defined within the test module scope.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel hot_swap_transfers`
Expected: FAIL — `hot_swap` doesn't call `try_transfer_state` yet.

- [ ] **Step 3: Wire `try_transfer_state` into `hot_swap`**

Modify `hot_swap` to:
1. Extract `old_pid` during validation (step 1) — save it in a local variable.
2. After spawn (step 2), call `try_transfer_state(old_pid, new_pid)`.
3. If state transfer fails, destroy new process and return error.

The key change is in the validation block — extract `old_pid` alongside the other checks:

```rust
        // 1. Validate mount exists, is Active, and is an exact mount path.
        let old_pid;  // extracted here for state transfer
        {
            let process = self.processes.get(&client_pid).ok_or(IpcError::NotFound)?;
            let (mount, remainder) = process.namespace.resolve(mount_path).ok_or(IpcError::NotFound)?;
            if !remainder.is_empty() {
                return Err(IpcError::NotFound);
            }
            if mount.state != crate::namespace::MountState::Active {
                return Err(IpcError::InvalidArgument);
            }
            if mount.target_pid == client_pid {
                return Err(IpcError::InvalidArgument);
            }
            old_pid = mount.target_pid;
        }
```

Then after spawn:

```rust
        // 2. Spawn new process (empty mounts, no VM).
        let new_pid = self.spawn_process(new_server_name, new_server, &[], None)?;

        // 2b. Transfer state from old → new via /state files.
        // If either server is stateless (no /state file), skip silently.
        // If transfer fails, rollback: destroy new process.
        match self.try_transfer_state(old_pid, new_pid) {
            Ok(_) => {} // transferred or stateless — either way, proceed
            Err(e) => {
                let _ = self.destroy_process(new_pid);
                return Err(e);
            }
        }
```

Also remove the separate `old_pid` extraction from step 4 (rebind) since it's now extracted in step 1.

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-microkernel hot_swap`
Expected: all pass (existing + 2 new).

- [ ] **Step 5: Run full workspace tests + clippy + nightly fmt**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/kernel.rs
git commit -m "feat(kernel): wire state transfer into hot_swap via /state files

hot_swap now reads /state from old server and writes to new server
before rebinding. Walk-based discovery: if either server doesn't
expose /state, transfer is silently skipped. EchoServer state
preserved across swaps in end-to-end test.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
