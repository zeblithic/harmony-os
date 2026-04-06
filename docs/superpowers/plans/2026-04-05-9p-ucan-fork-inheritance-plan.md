# 9P Namespace + UCAN Fork Inheritance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `Kernel::fork_process()` that creates a child process with a deep copy of the parent's 9P namespace and freshly minted kernel capabilities for the same endpoints.

**Architecture:** New `normalize_mount_states()` on Namespace resets Swapping→Active after clone. New `fork_process()` on Kernel clones namespace, filters expired caps, mints fresh root tokens for the child. Tested via `cargo test` (std); boot code wiring deferred to harmony-os-5gh.

**Tech Stack:** Rust, harmony-microkernel crate, PqUcanToken (ML-DSA-65 signing), BTreeMap-backed namespace

---

## File Structure

| File | Change | Responsibility |
|------|--------|---------------|
| `crates/harmony-microkernel/src/namespace.rs` | Modify | Add `normalize_mount_states()` method |
| `crates/harmony-microkernel/src/kernel.rs` | Modify | Add `fork_process()` method + tests |

---

### Task 1: Namespace — `normalize_mount_states()` + Clone Tests

**Files:**
- Modify: `crates/harmony-microkernel/src/namespace.rs:38-144` (impl block + tests)

- [ ] **Step 1: Write the failing tests**

Add these tests at the end of the `mod tests` block in `namespace.rs` (before the final closing `}`):

```rust
    #[test]
    fn normalize_mount_states_resets_swapping() {
        let mut ns = Namespace::new();
        ns.mount("/srv", 1, 0).unwrap();
        ns.set_mount_state("/srv", MountState::Swapping).unwrap();

        ns.normalize_mount_states();

        let (mp, _) = ns.resolve("/srv").unwrap();
        assert_eq!(mp.state, MountState::Active);
    }

    #[test]
    fn normalize_mount_states_preserves_active() {
        let mut ns = Namespace::new();
        ns.mount("/data", 2, 0).unwrap();

        ns.normalize_mount_states();

        let (mp, _) = ns.resolve("/data").unwrap();
        assert_eq!(mp.state, MountState::Active);
    }

    #[test]
    fn clone_is_deep_copy() {
        let mut ns = Namespace::new();
        ns.mount("/echo", 1, 0).unwrap();
        ns.mount("/data", 2, 5).unwrap();

        let mut cloned = ns.clone();

        // Modify clone — add a new mount
        cloned.mount("/extra", 3, 0).unwrap();

        // Original must be unchanged
        assert!(ns.resolve("/extra").is_none());
        // Clone has all original mounts
        let (mp, _) = cloned.resolve("/echo").unwrap();
        assert_eq!(mp.target_pid, 1);
        let (mp, _) = cloned.resolve("/data").unwrap();
        assert_eq!(mp.target_pid, 2);
        assert_eq!(mp.root_fid, 5);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel -- namespace::tests::normalize_mount_states_resets_swapping namespace::tests::normalize_mount_states_preserves_active namespace::tests::clone_is_deep_copy`

Expected: FAIL — `normalize_mount_states` is not defined.

- [ ] **Step 3: Implement `normalize_mount_states()`**

Add this method to the `impl Namespace` block in `namespace.rs`, after the `resolve` method (before the closing `}` of the impl block at line 144):

```rust
    /// Reset all `Swapping` mounts to `Active`.
    ///
    /// Used after cloning a namespace for a forked child process —
    /// the child should not inherit in-progress hot-swap state.
    pub fn normalize_mount_states(&mut self) {
        for mount in self.mounts.values_mut() {
            if mount.state == MountState::Swapping {
                mount.state = MountState::Active;
            }
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel -- namespace::tests::normalize_mount_states_resets_swapping namespace::tests::normalize_mount_states_preserves_active namespace::tests::clone_is_deep_copy`

Expected: All 3 PASS.

- [ ] **Step 5: Run the full namespace test suite**

Run: `cargo test -p harmony-microkernel -- namespace::tests`

Expected: All tests PASS (existing + new).

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/namespace.rs
git commit -m "feat(namespace): add normalize_mount_states() for fork inheritance"
```

---

### Task 2: Kernel — `fork_process()` with Namespace and Capability Inheritance

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs:90+` (impl block — add method after `grant_endpoint_cap`) and tests section

**Context:** The `Kernel` struct holds `processes: BTreeMap<u32, Process>`, `session_identity: PqPrivateIdentity`, and `next_pid: u32`. The existing `grant_endpoint_cap()` method (lines 296-328) shows how to mint tokens: call `self.session_identity.issue_pq_root_token(entropy, &audience, CapabilityType::Endpoint, resource.as_bytes(), now, now.saturating_add(DEFAULT_CAP_TTL))`. Test helpers: `make_kernel()` returns a kernel, `spawn_test_process()` spawns a process with an EchoServer, `make_test_entropy()` provides deterministic RNG, `setup_kernel_with_echo()` creates kernel + echo server + client with mount + endpoint cap.

- [ ] **Step 1: Write the failing tests**

Add these tests at the end of the `mod tests` block in `kernel.rs` (before the final closing `}`). These use the existing test helpers `make_kernel()`, `spawn_test_process()`, `make_test_entropy()`, and `setup_kernel_with_echo()`.

```rust
    // ── fork_process tests ──────────────────────────────────────────

    #[test]
    fn fork_inherits_namespace() {
        let (mut kernel, client, server) = setup_kernel_with_echo();
        let mut entropy = make_test_entropy();

        // client has mount at "/echo" → server
        let child = kernel
            .fork_process(&mut entropy, client, "child", Box::new(EchoServer::new()), 100)
            .unwrap();

        // Child should have the same mount
        let child_proc = kernel.processes.get(&child).unwrap();
        let (mp, remainder) = child_proc.namespace.resolve("/echo/hello").unwrap();
        assert_eq!(mp.target_pid, server);
        assert_eq!(remainder, "hello");
        assert_eq!(mp.state, crate::namespace::MountState::Active);
    }

    #[test]
    fn fork_namespace_is_independent() {
        let (mut kernel, client, _server) = setup_kernel_with_echo();
        let mut entropy = make_test_entropy();

        let child = kernel
            .fork_process(&mut entropy, client, "child", Box::new(EchoServer::new()), 100)
            .unwrap();

        // Add a mount to parent — child must not see it
        let extra = kernel
            .spawn_process("extra", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        kernel
            .processes
            .get_mut(&client)
            .unwrap()
            .namespace
            .mount("/extra", extra, 0)
            .unwrap();

        let child_proc = kernel.processes.get(&child).unwrap();
        assert!(child_proc.namespace.resolve("/extra").is_none());
    }

    #[test]
    fn fork_normalizes_swapping_mounts() {
        let mut kernel = make_kernel();
        let mut entropy = make_test_entropy();

        let server = kernel
            .spawn_process("server", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        let parent = kernel
            .spawn_process(
                "parent",
                Box::new(EchoServer::new()),
                &[("/srv", server, 0)],
                None,
            )
            .unwrap();
        // Set mount to Swapping
        kernel
            .processes
            .get_mut(&parent)
            .unwrap()
            .namespace
            .set_mount_state("/srv", crate::namespace::MountState::Swapping)
            .unwrap();

        kernel
            .grant_endpoint_cap(&mut entropy, parent, server, 0)
            .unwrap();

        let child = kernel
            .fork_process(&mut entropy, parent, "child", Box::new(EchoServer::new()), 100)
            .unwrap();

        let child_proc = kernel.processes.get(&child).unwrap();
        let (mp, _) = child_proc.namespace.resolve("/srv").unwrap();
        assert_eq!(mp.state, crate::namespace::MountState::Active);
    }

    #[test]
    fn fork_inherits_kernel_capabilities() {
        let (mut kernel, client, server) = setup_kernel_with_echo();
        let mut entropy = make_test_entropy();

        // client already has 1 endpoint cap for server (from setup_kernel_with_echo)
        let child = kernel
            .fork_process(&mut entropy, client, "child", Box::new(EchoServer::new()), 100)
            .unwrap();

        let child_proc = kernel.processes.get(&child).unwrap();
        assert_eq!(child_proc.kernel_capabilities.len(), 1);

        let cap = &child_proc.kernel_capabilities[0];
        assert_eq!(cap.capability, CapabilityType::Endpoint);
        assert_eq!(cap.audience, child_proc.address_hash);
        let resource_str = core::str::from_utf8(&cap.resource).unwrap();
        assert_eq!(resource_str, &alloc::format!("pid:{}", server));
    }

    #[test]
    fn fork_child_caps_verify() {
        let (mut kernel, client, server) = setup_kernel_with_echo();
        let mut entropy = make_test_entropy();

        let child = kernel
            .fork_process(&mut entropy, client, "child", Box::new(EchoServer::new()), 100)
            .unwrap();

        // check_endpoint_cap should succeed for the child
        let child_proc = kernel.processes.get(&child).unwrap();
        let result = kernel.check_endpoint_cap(child_proc, server, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn fork_filters_expired_capabilities() {
        let mut kernel = make_kernel();
        let mut entropy = make_test_entropy();

        let server = kernel
            .spawn_process("server", Box::new(EchoServer::new()), &[], None)
            .unwrap();
        let parent = kernel
            .spawn_process(
                "parent",
                Box::new(EchoServer::new()),
                &[("/srv", server, 0)],
                None,
            )
            .unwrap();

        // Grant cap at time 0 with default TTL
        kernel
            .grant_endpoint_cap(&mut entropy, parent, server, 0)
            .unwrap();

        // Fork at a time WAY past expiry (DEFAULT_CAP_TTL = 1_000_000_000)
        let child = kernel
            .fork_process(
                &mut entropy,
                parent,
                "child",
                Box::new(EchoServer::new()),
                2_000_000_000,
            )
            .unwrap();

        let child_proc = kernel.processes.get(&child).unwrap();
        assert_eq!(child_proc.kernel_capabilities.len(), 0);
    }

    #[test]
    fn fork_empty_parent() {
        let mut kernel = make_kernel();
        let mut entropy = make_test_entropy();

        // Parent with no mounts and no caps
        let parent = kernel
            .spawn_process("parent", Box::new(EchoServer::new()), &[], None)
            .unwrap();

        let child = kernel
            .fork_process(&mut entropy, parent, "child", Box::new(EchoServer::new()), 100)
            .unwrap();

        let child_proc = kernel.processes.get(&child).unwrap();
        assert!(child_proc.kernel_capabilities.is_empty());
        assert!(child_proc.namespace.resolve("/anything").is_none());
    }

    #[test]
    fn fork_nonexistent_parent() {
        let mut kernel = make_kernel();
        let mut entropy = make_test_entropy();

        let result = kernel.fork_process(
            &mut entropy,
            999,
            "orphan",
            Box::new(EchoServer::new()),
            100,
        );
        assert_eq!(result, Err(IpcError::NotFound));
    }

    #[test]
    fn fork_user_caps_not_inherited() {
        let (mut kernel, client, server) = setup_kernel_with_echo();
        let mut entropy = make_test_entropy();

        // Manually push a user capability to the parent
        let audience = kernel.processes.get(&client).unwrap().address_hash;
        let token = kernel
            .session_identity
            .issue_pq_root_token(
                &mut entropy,
                &audience,
                CapabilityType::Endpoint,
                alloc::format!("pid:{}", server).as_bytes(),
                0,
                DEFAULT_CAP_TTL,
            )
            .unwrap();
        let binding = SessionBinding {
            session_address: kernel.session_identity.public_identity().address_hash,
            hardware_address: kernel.hardware_identity.public_identity().address_hash,
            user_address: audience,
            token_hash: token.content_hash(),
            bound_at: 0,
            nonce: [0xAA; 16],
            signature: [0u8; 3309],
        };
        kernel
            .processes
            .get_mut(&client)
            .unwrap()
            .user_capabilities
            .push(BoundCapability { token, binding });

        let child = kernel
            .fork_process(&mut entropy, client, "child", Box::new(EchoServer::new()), 100)
            .unwrap();

        let child_proc = kernel.processes.get(&child).unwrap();
        assert!(child_proc.user_capabilities.is_empty());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel -- kernel::tests::fork_`

Expected: FAIL — `fork_process` is not defined.

- [ ] **Step 3: Implement `fork_process()`**

Add this method to the `impl<P: PageTable> Kernel<P>` block in `kernel.rs`, after the `grant_endpoint_cap` method (after line 328):

```rust
    /// Fork a process: create a child with inherited namespace and
    /// kernel capabilities from the parent.
    ///
    /// The child gets a deep copy of the parent's namespace (all mounts
    /// normalized to `Active`). For each non-expired kernel capability,
    /// a fresh root token is minted with the child's address as audience.
    ///
    /// User capabilities are NOT inherited (they require session re-binding).
    /// No VM address space is created — the caller handles VM setup separately.
    ///
    /// Returns the child's PID on success.
    pub fn fork_process(
        &mut self,
        entropy: &mut (impl EntropySource + CryptoRngCore),
        parent_pid: u32,
        name: &str,
        server: Box<dyn FileServer>,
        now: u64,
    ) -> Result<u32, IpcError> {
        // Look up parent and clone its inheritable state.
        let parent = self.processes.get(&parent_pid).ok_or(IpcError::NotFound)?;
        let mut child_namespace = parent.namespace.clone();
        child_namespace.normalize_mount_states();

        // Collect non-expired parent capabilities for delegation.
        // We need to collect before borrowing self mutably for token minting.
        let parent_caps: Vec<(CapabilityType, Vec<u8>)> = parent
            .kernel_capabilities
            .iter()
            .filter(|cap| cap.expires_at == 0 || cap.expires_at > now)
            .map(|cap| (cap.capability, cap.resource.clone()))
            .collect();

        // Allocate child PID.
        let child_pid = self.next_pid;
        self.next_pid = self
            .next_pid
            .checked_add(1)
            .ok_or(IpcError::ResourceExhausted)?;

        // Derive child address hash from PID (same placeholder as spawn_process).
        let mut address_hash = [0u8; 16];
        address_hash[..4].copy_from_slice(&child_pid.to_be_bytes());

        // Mint fresh kernel capabilities for the child.
        let mut child_caps = Vec::with_capacity(parent_caps.len());
        for (capability, resource) in &parent_caps {
            let cap = self
                .session_identity
                .issue_pq_root_token(
                    entropy,
                    &address_hash,
                    *capability,
                    resource,
                    now,
                    now.saturating_add(DEFAULT_CAP_TTL),
                )
                .map_err(|_| IpcError::PermissionDenied)?;
            child_caps.push(cap);
        }

        self.processes.insert(
            child_pid,
            Process {
                pid: child_pid,
                name: Arc::from(name),
                namespace: child_namespace,
                kernel_capabilities: child_caps,
                user_capabilities: Vec::new(),
                address_hash,
                server,
            },
        );

        Ok(child_pid)
    }
```

- [ ] **Step 4: Run all fork tests**

Run: `cargo test -p harmony-microkernel -- kernel::tests::fork_`

Expected: All 8 PASS.

- [ ] **Step 5: Run the full kernel test suite**

Run: `cargo test -p harmony-microkernel`

Expected: All tests PASS (existing + new).

- [ ] **Step 6: Run clippy**

Run: `cargo clippy -p harmony-microkernel`

Expected: No warnings.

- [ ] **Step 7: Run nightly rustfmt**

Run: `cargo +nightly fmt --all`

Expected: No changes (or formatting applied).

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-microkernel/src/kernel.rs
git commit -m "feat(kernel): fork_process() with namespace + capability inheritance"
```

---

## Self-Review

**1. Spec coverage:**
- Namespace inheritance (deep copy, Plan 9 RFNAMEG) → Task 1 (`normalize_mount_states`) + Task 2 (clone in `fork_process`)
- Capability inheritance (fresh root tokens, same resource/type) → Task 2 (`fork_process` mints tokens)
- Expired cap filtering → Task 2 (`fork_filters_expired_capabilities` test + filter logic)
- User caps not inherited → Task 2 (`fork_user_caps_not_inherited` test + empty `user_capabilities`)
- Nonexistent parent → Task 2 (`fork_nonexistent_parent` test)
- Empty parent → Task 2 (`fork_empty_parent` test)
- Swapping normalization → Task 1 (`normalize_mount_states_resets_swapping` test) + Task 2 (`fork_normalizes_swapping_mounts` test)
- No boot code changes → correct, no boot code files touched
- No Linuxulator changes → correct, no linuxulator files touched

**2. Placeholder scan:** No TBDs, TODOs, placeholders, or vague steps found.

**3. Type consistency:**
- `normalize_mount_states(&mut self)` — consistent between Task 1 implementation and Task 2 usage
- `fork_process(&mut self, entropy, parent_pid, name, server, now) -> Result<u32, IpcError>` — consistent signature throughout
- `MountState::Swapping` / `MountState::Active` — correct enum variants
- `CapabilityType::Endpoint` — correct enum variant matching `grant_endpoint_cap()`
- `DEFAULT_CAP_TTL` — existing constant (1_000_000_000), used correctly
- `IpcError::NotFound` — correct error variant for missing parent
