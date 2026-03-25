# 9P Service Hot-Swap Kernel Plumbing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add kernel-level infrastructure to atomically replace a running 9P service with a new one — `MountState`, `Namespace::rebind()`, `Kernel::hot_swap()`, and reject-and-retry for requests during the swap window.

**Architecture:** Mount points gain a `MountState` (Active/Swapping). During hot-swap, the kernel marks the mount as Swapping (new requests get `NotReady`), spawns the new server, atomically rebinds the mount point, and destroys the old server. Single-threaded kernel means quiescence is immediate.

**Tech Stack:** Rust, `no_std` + `alloc`, `harmony-microkernel` crate.

**Spec:** `docs/superpowers/specs/2026-03-25-hot-swap-plumbing-design.md`

---

### Task 1: Add `NotReady` to `IpcError`

**Files:**
- Modify: `crates/harmony-microkernel/src/lib.rs`

**Context:**
- `IpcError` is at lines 78-95 of `lib.rs`. It currently has 11 variants. We need to add `NotReady` for the Swapping rejection.
- The enum derives `Debug, Clone, PartialEq, Eq`.

- [ ] **Step 1: Add the variant**

Add to `IpcError` enum (after `NonceLimitExceeded`):

```rust
    /// The target service is being hot-swapped — retry after a short delay.
    NotReady,
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check -p harmony-microkernel`
Expected: compiles (no code uses `NotReady` yet).

- [ ] **Step 3: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/lib.rs
git commit -m "feat(ipc): add IpcError::NotReady for hot-swap rejection

Returned when a 9P request targets a mount point that is currently
being hot-swapped. Callers should retry after a short delay.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `MountState` + `rebind()` + `set_mount_state()` in namespace.rs

**Files:**
- Modify: `crates/harmony-microkernel/src/namespace.rs`

**Context:**
- `MountPoint` is at line 11, currently `{ target_pid: u32, root_fid: Fid }`.
- `Namespace` is at line 18, holds `BTreeMap<Arc<str>, MountPoint>`.
- `mount()` at line 40 inserts with `target_pid` and `root_fid`.
- Existing tests at lines 100-188. All must continue to pass.

- [ ] **Step 1: Write failing tests**

Add to the `#[cfg(test)] mod tests` block in `namespace.rs`:

```rust
    #[test]
    fn rebind_replaces_mount() {
        let mut ns = Namespace::new();
        ns.mount("/srv/echo", 1, 0).unwrap();
        let old = ns.rebind("/srv/echo", 2, 10).unwrap();
        assert_eq!(old.target_pid, 1);
        assert_eq!(old.root_fid, 0);
        // Resolve now returns the new target
        let (mp, _) = ns.resolve("/srv/echo/hello").unwrap();
        assert_eq!(mp.target_pid, 2);
        assert_eq!(mp.root_fid, 10);
    }

    #[test]
    fn rebind_returns_old_mount() {
        let mut ns = Namespace::new();
        ns.mount("/data", 5, 42).unwrap();
        let old = ns.rebind("/data", 6, 99).unwrap();
        assert_eq!(old.target_pid, 5);
        assert_eq!(old.root_fid, 42);
    }

    #[test]
    fn rebind_nonexistent_path_fails() {
        let mut ns = Namespace::new();
        assert_eq!(
            ns.rebind("/nonexistent", 1, 0),
            Err(crate::IpcError::NotFound)
        );
    }

    #[test]
    fn set_mount_state_swapping() {
        let mut ns = Namespace::new();
        ns.mount("/srv/echo", 1, 0).unwrap();
        ns.set_mount_state("/srv/echo", MountState::Swapping).unwrap();
        let (mp, _) = ns.resolve("/srv/echo").unwrap();
        assert_eq!(mp.state, MountState::Swapping);
    }

    #[test]
    fn rebind_resets_state_to_active() {
        let mut ns = Namespace::new();
        ns.mount("/srv/echo", 1, 0).unwrap();
        ns.set_mount_state("/srv/echo", MountState::Swapping).unwrap();
        ns.rebind("/srv/echo", 2, 10).unwrap();
        let (mp, _) = ns.resolve("/srv/echo").unwrap();
        assert_eq!(mp.state, MountState::Active);
    }

    #[test]
    fn set_mount_state_nonexistent_fails() {
        let mut ns = Namespace::new();
        assert_eq!(
            ns.set_mount_state("/nonexistent", MountState::Active),
            Err(crate::IpcError::NotFound)
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel namespace`
Expected: FAIL — `MountState`, `rebind`, `set_mount_state` don't exist.

- [ ] **Step 3: Implement**

**Add `MountState` enum** (before `MountPoint`):

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

**Update `MountPoint`:**

```rust
#[derive(Debug, Clone)]
pub struct MountPoint {
    pub target_pid: u32,
    pub root_fid: Fid,
    pub state: MountState,
}
```

**Update `mount()` to initialize state:**

Change the `MountPoint` construction in `mount()` (line 52-56):

```rust
        self.mounts.insert(
            Arc::from(path),
            MountPoint {
                target_pid,
                root_fid,
                state: MountState::Active,
            },
        );
```

**Add `set_mount_state` method:**

```rust
    /// Set the lifecycle state of a mount point.
    ///
    /// Returns `NotFound` if no mount exists at `path`.
    pub fn set_mount_state(&mut self, path: &str, state: MountState) -> Result<(), crate::IpcError> {
        let mount = self.mounts.get_mut(path).ok_or(crate::IpcError::NotFound)?;
        mount.state = state;
        Ok(())
    }
```

**Add `rebind` method:**

```rust
    /// Atomically replace the server behind a mount point.
    ///
    /// Returns the old `MountPoint` for cleanup (caller destroys the old process).
    /// Resets mount state to `Active`.
    /// Returns `NotFound` if no mount exists at `path`.
    pub fn rebind(
        &mut self,
        path: &str,
        new_pid: u32,
        new_root_fid: Fid,
    ) -> Result<MountPoint, crate::IpcError> {
        let mount = self.mounts.get_mut(path).ok_or(crate::IpcError::NotFound)?;
        let old = mount.clone();
        mount.target_pid = new_pid;
        mount.root_fid = new_root_fid;
        mount.state = MountState::Active;
        Ok(old)
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-microkernel namespace`
Expected: all pass (10 existing + 6 new).

- [ ] **Step 5: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/namespace.rs
git commit -m "feat(namespace): add MountState, rebind, set_mount_state for hot-swap

MountPoint gains Active/Swapping state. rebind() atomically replaces
the server and resets to Active. set_mount_state() transitions state.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Swapping rejection in kernel walk dispatch

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs`

**Context:**
- The kernel's `walk()` method at line 432 resolves a path via `process.namespace.resolve(path)` (line 450). After resolution, `mount.target_pid` is extracted. This is where the `Swapping` check goes — right after resolve, before any fid allocation or server call.
- The resolve returns `&MountPoint` which now includes `state`.

- [ ] **Step 1: Write a failing test**

Add to the kernel test module (the tests are already inside `#[cfg(test)] mod tests` at the bottom of `kernel.rs`):

```rust
    #[test]
    fn walk_to_swapping_mount_returns_not_ready() {
        let mut kernel = test_kernel();
        let echo = Box::new(crate::echo::EchoServer::new());
        let echo_pid = kernel.spawn_process("echo", echo, &[], None).unwrap();
        let init_pid = 0; // init process
        // Mount echo in init's namespace
        kernel.processes.get_mut(&init_pid).unwrap()
            .namespace.mount("/srv/echo", echo_pid, 0).unwrap();

        // Mark as swapping
        kernel.processes.get_mut(&init_pid).unwrap()
            .namespace.set_mount_state("/srv/echo", crate::namespace::MountState::Swapping).unwrap();

        // Walk should fail with NotReady
        let result = kernel.walk(init_pid, "/srv/echo/hello", 0, 100, 1);
        assert_eq!(result, Err(IpcError::NotReady));
    }
```

Note: This test requires access to `kernel.processes` — check if tests already access it directly. If not, use the existing test helper pattern. The existing tests in `kernel.rs` construct kernels and call public methods. Look at how existing tests mount servers — follow that pattern.

**IMPORTANT:** The implementer should read the existing test helpers at the top of the test module to understand how to construct test kernels and mount servers. The pattern may differ from what's shown above — follow the existing pattern.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-microkernel walk_to_swapping_mount`
Expected: FAIL — no `Swapping` check in `walk()`.

- [ ] **Step 3: Implement the check**

In `kernel.rs` `walk()` method, after `namespace.resolve()` (line 450), add:

```rust
            // Reject requests to mounts being hot-swapped.
            if mount.state == crate::namespace::MountState::Swapping {
                return Err(IpcError::NotReady);
            }
```

This goes inside the block that extracts `target_pid` from the mount (lines 448-456), right after `let (mount, remainder) = process.namespace.resolve(path).ok_or(IpcError::NotFound)?;`.

- [ ] **Step 4: Run test**

Run: `cargo test -p harmony-microkernel walk_to_swapping_mount`
Expected: PASS.

- [ ] **Step 5: Run full workspace tests**

Run: `cargo test --workspace`
Expected: all pass.

- [ ] **Step 6: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/kernel.rs
git commit -m "feat(kernel): reject walk to Swapping mount with NotReady

During hot-swap, new requests to the affected mount return NotReady.
Callers retry after a short delay. Check is in walk() dispatch path
right after namespace resolve.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `Kernel::hot_swap()` method

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs`

**Context:**
- `hot_swap` orchestrates the full sequence: validate mount → spawn new process → mark swapping → rebind → destroy old.
- `spawn_process()` is at line 186. Signature: `(name, server, mounts: &[(&str, u32, Fid)], vm_config: Option<...>)`. For hot-swap we pass `&[]` for mounts and `None` for vm_config.
- `destroy_process()` is at line 241.
- The method takes `client_pid` to identify whose namespace to modify.

- [ ] **Step 1: Write failing tests**

Add to kernel test module:

```rust
    #[test]
    fn hot_swap_replaces_server() {
        let mut kernel = test_kernel();
        // Spawn old echo server
        let old_echo = Box::new(crate::echo::EchoServer::new());
        let old_pid = kernel.spawn_process("old-echo", old_echo, &[], None).unwrap();
        let init_pid = 0;
        kernel.processes.get_mut(&init_pid).unwrap()
            .namespace.mount("/srv/echo", old_pid, 0).unwrap();

        // Hot-swap with new echo server
        let new_echo = Box::new(crate::echo::EchoServer::new());
        kernel.hot_swap(init_pid, "/srv/echo", new_echo, "new-echo").unwrap();

        // Resolve should return a different PID (new server)
        let (mp, _) = kernel.processes.get(&init_pid).unwrap()
            .namespace.resolve("/srv/echo").unwrap();
        assert_ne!(mp.target_pid, old_pid, "should point to new server");
    }

    #[test]
    fn hot_swap_destroys_old_process() {
        let mut kernel = test_kernel();
        let old_echo = Box::new(crate::echo::EchoServer::new());
        let old_pid = kernel.spawn_process("old-echo", old_echo, &[], None).unwrap();
        let init_pid = 0;
        kernel.processes.get_mut(&init_pid).unwrap()
            .namespace.mount("/srv/echo", old_pid, 0).unwrap();

        let new_echo = Box::new(crate::echo::EchoServer::new());
        kernel.hot_swap(init_pid, "/srv/echo", new_echo, "new-echo").unwrap();

        // Old PID should be gone
        assert!(!kernel.processes.contains_key(&old_pid));
    }

    #[test]
    fn hot_swap_nonexistent_mount_fails() {
        let mut kernel = test_kernel();
        let new_echo = Box::new(crate::echo::EchoServer::new());
        let result = kernel.hot_swap(0, "/nonexistent", new_echo, "echo");
        assert_eq!(result, Err(IpcError::NotFound));
    }

    #[test]
    fn hot_swap_during_swapping_fails() {
        let mut kernel = test_kernel();
        let old_echo = Box::new(crate::echo::EchoServer::new());
        let old_pid = kernel.spawn_process("echo", old_echo, &[], None).unwrap();
        let init_pid = 0;
        kernel.processes.get_mut(&init_pid).unwrap()
            .namespace.mount("/srv/echo", old_pid, 0).unwrap();

        // Manually mark as swapping
        kernel.processes.get_mut(&init_pid).unwrap()
            .namespace.set_mount_state("/srv/echo", crate::namespace::MountState::Swapping).unwrap();

        let new_echo = Box::new(crate::echo::EchoServer::new());
        let result = kernel.hot_swap(init_pid, "/srv/echo", new_echo, "echo");
        // Should fail — already swapping
        assert!(result.is_err());
    }
```

**IMPORTANT:** The implementer should adapt these tests to match the existing test infrastructure in `kernel.rs`. The `test_kernel()` helper, how `init_pid` works, and how processes access their namespaces may differ. Read the existing kernel tests to understand the patterns.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel hot_swap`
Expected: FAIL — `hot_swap` doesn't exist.

- [ ] **Step 3: Implement `hot_swap`**

Add to `impl Kernel`:

```rust
    /// Atomically replace a running 9P service with a new one.
    ///
    /// Steps:
    /// 1. Validate mount exists and is Active
    /// 2. Spawn new process with the replacement server
    /// 3. Mark mount as Swapping (new requests → NotReady)
    /// 4. Rebind mount to new process
    /// 5. Destroy old process
    ///
    /// On failure, the old server remains active (no service disruption).
    pub fn hot_swap(
        &mut self,
        client_pid: u32,
        mount_path: &str,
        new_server: Box<dyn FileServer>,
        new_server_name: &str,
    ) -> Result<(), IpcError> {
        // 1. Validate mount exists and is Active.
        {
            let process = self.processes.get(&client_pid).ok_or(IpcError::NotFound)?;
            let (mount, remainder) = process.namespace.resolve(mount_path).ok_or(IpcError::NotFound)?;
            // Must be an exact mount path, not a sub-path resolve
            if !remainder.is_empty() {
                return Err(IpcError::NotFound);
            }
            if mount.state != crate::namespace::MountState::Active {
                return Err(IpcError::InvalidArgument);
            }
        }

        // 2. Spawn new process (empty mounts, no VM).
        let new_pid = self.spawn_process(new_server_name, new_server, &[], None)?;

        // 3. Mark mount as Swapping.
        if let Some(process) = self.processes.get_mut(&client_pid) {
            if let Err(e) = process.namespace.set_mount_state(mount_path, crate::namespace::MountState::Swapping) {
                // Rollback: destroy the new process.
                let _ = self.destroy_process(new_pid);
                return Err(e);
            }
        }

        // 4. Rebind mount to new process.
        let old_mount = {
            let process = self.processes.get_mut(&client_pid).ok_or(IpcError::NotFound)?;
            match process.namespace.rebind(mount_path, new_pid, 0) {
                Ok(old) => old,
                Err(e) => {
                    // Rollback: restore Active state and destroy new process.
                    let _ = process.namespace.set_mount_state(mount_path, crate::namespace::MountState::Active);
                    let _ = self.destroy_process(new_pid);
                    return Err(e);
                }
            }
        };

        // 5. Destroy old process.
        let _ = self.destroy_process(old_mount.target_pid);

        Ok(())
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-microkernel hot_swap`
Expected: all 4 pass.

- [ ] **Step 5: Run full workspace tests + clippy + nightly fmt**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/kernel.rs
git commit -m "feat(kernel): implement hot_swap for atomic 9P service replacement

Validates mount → spawns new process → marks Swapping → rebinds →
destroys old. Rollback on failure preserves old server. Reject-and-
retry during swap window via NotReady on Swapping mounts.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
