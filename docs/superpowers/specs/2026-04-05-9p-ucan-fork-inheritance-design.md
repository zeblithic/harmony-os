# 9P Namespace and UCAN Capability Inheritance on Fork

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-9kw

**Goal:** When the microkernel's `Kernel` forks a process, the child inherits a deep copy of the parent's 9P namespace and receives freshly minted kernel capabilities for the same endpoints — so inherited mounts are immediately usable.

**Prerequisite:** Phase 6 process lifecycle (PR #116) and signal delivery (PR #117) merged. The microkernel `Kernel` struct has `Process` with `Namespace` and `kernel_capabilities` fields. Fork handling exists in the x86_64 boot code but does not yet involve the Kernel.

---

## Architecture

One layer of change — the microkernel `Kernel` — plus tests. No boot code changes.

1. **Kernel (`kernel.rs`)** — New `fork_process()` method. Given a `parent_pid`, it creates a child `Process` with:
   - A deep copy of the parent's `Namespace` (mount table cloned, all entries normalized to `Active`)
   - Fresh kernel-issued `PqUcanToken` for each non-expired parent endpoint capability (same resource/type, child's `address_hash` as audience)
   - Empty `user_capabilities` (session re-binding deferred)

2. **Boot code** — No changes. The `Kernel` is not yet wired into the boot path (tracked as harmony-os-5gh). `fork_process()` is exercised via `cargo test` in std. When harmony-os-5gh integrates the Kernel into the boot path, the fork flow will call `fork_process()` instead of `spawn_process()`.

3. **Linuxulator** — No changes. Namespace and capabilities are microkernel concerns, invisible to the Linux compatibility layer.

### Data Flow (future, after harmony-os-5gh wiring)

```
Linuxulator sys_fork()
  → spawn_fn(child_elf, ...)
  → boot code detects pending_fork_child()
  → kernel.fork_process(entropy, parent_pid, child_name, child_server, now)
    → looks up parent Process by pid
    → clones parent.namespace (deep copy, normalize Swapping → Active)
    → for each non-expired parent kernel_cap:
        mint fresh root token (same resource/capability, child's address_hash)
    → registers child Process with inherited state
  → child runs with parent's namespace + endpoint capabilities
```

---

## Namespace Inheritance

### Semantics: Copy (Plan 9 RFNAMEG)

The child gets an independent deep copy of the parent's mount table. Changes in one do not affect the other. Shared namespaces (RFCNAMEG / CLONE_FS) are deferred until concurrent fork/threading is implemented.

### Implementation

`Namespace` already derives `Clone` (namespace.rs:27). `MountPoint` and `MountState` also derive `Clone`. The deep copy is a single `.clone()` call on the parent's namespace.

**Normalization:** After cloning, iterate the mount table and set any `MountState::Swapping` entries to `MountState::Active`. The child gets a clean snapshot — it should not inherit in-progress hot-swap state from the parent.

```rust
let mut child_ns = parent.namespace.clone();
for mount in child_ns.mounts_mut() {
    if mount.state == MountState::Swapping {
        mount.state = MountState::Active;
    }
}
```

**Note:** `Namespace` currently has no `mounts_mut()` method. We need to add a `normalize_mount_states()` method (or equivalent) that encapsulates this iteration internally, keeping `mounts` private.

### What the Child Can Do

- `resolve()` works immediately — path lookups hit the same target PIDs as the parent
- The child still needs an `EndpointCap` for each target PID to send 9P operations (handled by capability inheritance below)
- Child can `mount()` new servers or unmount inherited ones without affecting the parent

---

## Capability Inheritance

### Model: Fresh Root Tokens from Kernel

The kernel is the root authority for kernel-issued capabilities. Rather than implementing UCAN delegation chains (which would require a `delegate_pq()` method that doesn't exist on `PqPrivateIdentity`), the kernel mints fresh root tokens for the child using the existing `issue_pq_root_token()` method.

For each `PqUcanToken` in the parent's `kernel_capabilities`:

1. **Filter expired:** Skip if `token.expires_at != 0 && token.expires_at <= now`
2. **Mint child token:** Call `session_identity.issue_pq_root_token()` with:
   - `audience`: child's `address_hash`
   - `capability`: same as parent token's `capability`
   - `resource`: same as parent token's `resource`
   - `not_before`: `now`
   - `expires_at`: `now + DEFAULT_CAP_TTL`
3. **Push** to child's `kernel_capabilities`

### Why Root Tokens (Not Delegation Chains)

- The kernel signs both parent and child tokens — verifiers can verify either independently
- No cross-repo change needed (`PqPrivateIdentity` in harmony-identity doesn't have `delegate_pq()`)
- `verify_pq_token()` handles root tokens (proof = None) correctly
- `check_endpoint_cap()` already scans `kernel_capabilities` and verifies each — child tokens pass verification exactly like parent tokens
- Delegation chains add value for user-to-user delegation (future work), not kernel-to-process issuance

### User Capabilities

`user_capabilities` (Vec<BoundCapability>) are **not inherited**. These require session binding proofs tied to the parent's identity. Re-binding to the child's identity requires session re-binding logic that doesn't exist yet. The child starts with empty `user_capabilities`.

---

## Kernel API

### New Method: `fork_process()`

```rust
pub fn fork_process(
    &mut self,
    entropy: &mut (impl EntropySource + CryptoRngCore),
    parent_pid: u32,
    name: &str,
    server: Box<dyn FileServer>,
    now: u64,
) -> Result<u32, IpcError>
```

**Parameters:**
- `entropy`: RNG for token nonce generation
- `parent_pid`: PID of the parent process to inherit from
- `name`: child process name
- `server`: child's 9P FileServer implementation
- `now`: current time for token expiry checks and new token bounds

**Returns:** child PID on success, `IpcError::NotFound` if parent_pid doesn't exist.

**Implementation:**

1. Validate `parent_pid` exists in `self.processes`
2. Clone parent's namespace, normalize mount states
3. Iterate parent's `kernel_capabilities`, filter expired, mint fresh tokens for child
4. Allocate child PID from `self.next_pid`
5. Derive child `address_hash` from PID (same placeholder as `spawn_process`)
6. Insert child `Process` with inherited namespace and capabilities

### New Method on Namespace: `normalize_mount_states()`

```rust
impl Namespace {
    /// Reset all Swapping mounts to Active.
    /// Used after cloning a namespace for a forked child process.
    pub fn normalize_mount_states(&mut self) {
        for mount in self.mounts.values_mut() {
            if mount.state == MountState::Swapping {
                mount.state = MountState::Active;
            }
        }
    }
}
```

### No New Callbacks

No changes to the Linuxulator callback interface (`block_fn`, `spawn_fn`, `wake_fn`, etc.). Namespace and capability inheritance is internal to the Kernel.

---

## Testing

### Kernel Tests (kernel.rs, std)

- **fork_inherits_namespace:** Create parent with 2 mounts. Fork. Verify child has same 2 mount entries with correct target_pid, root_fid, and Active state.
- **fork_namespace_is_independent:** Fork parent. Add a mount to child's namespace. Verify parent's namespace is unchanged (deep copy, not shared).
- **fork_normalizes_swapping_mounts:** Create parent with one Active mount and one Swapping mount. Fork. Verify both child mounts are Active.
- **fork_inherits_kernel_capabilities:** Create parent with 2 endpoint caps (for PID 3 and PID 5). Fork. Verify child has 2 caps with child's address_hash as audience, same resource strings, valid signatures.
- **fork_filters_expired_capabilities:** Give parent one valid cap and one expired cap. Fork. Verify child has only 1 cap (the non-expired one).
- **fork_child_caps_verify:** After fork, call `check_endpoint_cap()` on the child for each inherited target PID. Verify all pass verification.
- **fork_empty_parent:** Fork a process with no mounts and no capabilities. Verify child has empty namespace and empty capabilities (no panic on empty iteration).
- **fork_nonexistent_parent:** Call `fork_process()` with invalid parent_pid. Verify returns `IpcError::NotFound`.
- **fork_user_caps_not_inherited:** Give parent user_capabilities. Fork. Verify child's user_capabilities is empty.

### Namespace Tests (namespace.rs)

- **normalize_mount_states_resets_swapping:** Create namespace with Swapping mount. Call `normalize_mount_states()`. Verify mount is Active.
- **normalize_mount_states_preserves_active:** Create namespace with Active mount. Call `normalize_mount_states()`. Verify mount is still Active.
- **clone_is_deep_copy:** Clone namespace. Modify clone (add mount). Verify original unchanged.

### Out of Scope

- Boot code wiring (harmony-os-5gh)
- User capability inheritance (requires session re-binding)
- Shared namespaces (CLONE_FS / RFCNAMEG)
- Capability attenuation on fork
- `PqPrivateIdentity::delegate_pq()` (cross-repo, harmony-identity)
- Concurrent fork races (sequential model)
- On-target integration testing
