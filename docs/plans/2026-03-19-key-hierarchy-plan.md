# Post-Quantum Key Hierarchy Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a four-tier PQ key hierarchy (owner, hardware, session, user) with mutual attestation, session bindings, and Nakaiah integration.

**Architecture:** New `key_hierarchy` module in harmony-microkernel with attestation/binding types and verification functions. Kernel struct gains hardware + session identities. Process capabilities split into kernel-issued and user-submitted. Nakaiah gets `CapChain::Session` variant. Boot code loads/generates hardware key and generates session key.

**Tech Stack:** Rust (no_std), ML-DSA-65 / ML-KEM-768 (`harmony-identity`), BLAKE3 (`harmony-crypto`), existing UCAN infrastructure

**Spec:** `docs/plans/2026-03-19-key-hierarchy-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| Create: `crates/harmony-microkernel/src/key_hierarchy.rs` | `OwnerClaim`, `HardwareAcceptance`, `AttestationPair`, `SessionBinding`, `BoundCapability` types + `verify_attestation`, `verify_session_binding` functions |
| Modify: `crates/harmony-microkernel/src/integrity/nakaiah.rs` | Add `CapChain::Session` variant |
| Modify: `crates/harmony-microkernel/src/kernel.rs` | Restructure `Kernel` struct (hierarchy fields, two capability vectors), update `new()`, `grant_endpoint_cap`, `check_endpoint_cap`, all tests |
| Modify: `crates/harmony-microkernel/src/lib.rs` | Register `key_hierarchy` module |
| Modify: `crates/harmony-microkernel/src/nix_store_server.rs` | Update test `Kernel::new` calls |
| Modify: `crates/harmony-os/src/linuxulator.rs` | Update test `Kernel::new` calls |
| Modify: `crates/harmony-boot/src/main.rs` | Boot sequence: load/generate hardware key, verify attestation, generate session key |

---

### Task 1: Create `key_hierarchy` module with attestation types

**Files:**
- Create: `crates/harmony-microkernel/src/key_hierarchy.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

This task creates the data structures and verification functions for mutual attestation and session binding. All types, serialization (`signable_bytes`), and verification logic in one focused module.

- [ ] **Step 1: Create `key_hierarchy.rs` with types and signable_bytes**

Create the module with:
- `OwnerClaim` struct (owner_address, hardware_address, claimed_at, owner_index, nonce, signature)
- `HardwareAcceptance` struct (hardware_address, owner_address, accepted_at, owner_claim_hash, signature)
- `AttestationPair` struct
- `SessionBinding` struct (session_address, user_address, user_token_hash, hardware_address, bound_at, nonce, signature)
- `BoundCapability` struct (token: PqUcanToken, binding: SessionBinding)
- `signable_bytes()` method on `OwnerClaim`, `HardwareAcceptance`, `SessionBinding` — big-endian, fixed field order, excludes signature
- `content_hash()` on `OwnerClaim` — BLAKE3 of full wire format: `[signable_bytes][3309B signature]` = `[16+16+8+4+16][3309]` = 3369 bytes total
- Error types: `AttestationError`, `BindingError`

All signatures are `[u8; 3309]` (ML-DSA-65 fixed size). Use `harmony_crypto::hash::blake3_hash` for content hashing.

**Note:** The `verify_session_binding` signature adds a `token_hash` parameter not present in the design doc's function signature. This is correct — the design doc's verification step list (step 4: "binding.user_token_hash == token.content_hash()") requires it, but the design doc's function signature omitted it. The plan's signature is the accurate one.

**Note:** Uses `BTreeSet<[u8; 16]>` instead of the design doc's `HashSet<[u8; 16]>` — `BTreeSet` is available via `alloc::collections` in `no_std` without requiring `hashbrown`. The `kernel` feature already uses `BTreeMap` throughout.

- [ ] **Step 2: Add `verify_attestation` function**

```rust
pub fn verify_attestation(
    pair: &AttestationPair,
    owner_pubkey: &PqIdentity,
    hardware_pubkey: &PqIdentity,
) -> Result<(), AttestationError>
```

Checks:
1. `owner_claim.owner_address == owner_pubkey.address_hash`
2. `owner_claim.hardware_address == hardware_pubkey.address_hash`
3. Owner's ML-DSA-65 signature valid over `owner_claim.signable_bytes()`
4. `hardware_acceptance.owner_claim_hash == owner_claim.content_hash()`
5. `hardware_acceptance.hardware_address == hardware_pubkey.address_hash`
6. `hardware_acceptance.owner_address == owner_pubkey.address_hash`
7. Hardware's ML-DSA-65 signature valid over `hardware_acceptance.signable_bytes()`

- [ ] **Step 3: Add `verify_session_binding` function**

```rust
pub fn verify_session_binding(
    binding: &SessionBinding,
    session_pubkey: &PqIdentity,
    hardware_address: &[u8; 16],
    token_hash: &[u8; 32],
    used_nonces: &BTreeSet<[u8; 16]>,
) -> Result<(), BindingError>
```

Checks:
1. `binding.session_address == session_pubkey.address_hash`
2. `binding.hardware_address == *hardware_address`
3. `binding.user_token_hash == *token_hash`
4. `binding.nonce` not in `used_nonces`
5. Session's ML-DSA-65 signature valid over `binding.signable_bytes()`

Use `BTreeSet` (not `HashSet`) since we're in `#[cfg(feature = "kernel")]` context with `alloc` but `hashbrown` may not be available outside tests.

- [ ] **Step 4: Register module in lib.rs**

Add `#[cfg(feature = "kernel")] pub mod key_hierarchy;` to `crates/harmony-microkernel/src/lib.rs`.

- [ ] **Step 5: Add tests for attestation and binding verification**

Tests (in `key_hierarchy.rs` `#[cfg(test)] mod tests`):
- `valid_attestation_passes` — create owner + hardware identities, sign claim + acceptance, verify
- `attestation_wrong_owner_signer_rejected`
- `attestation_wrong_hardware_signer_rejected`
- `attestation_mismatched_addresses_rejected`
- `attestation_tampered_claim_hash_rejected`
- `valid_session_binding_passes`
- `session_binding_wrong_session_key_rejected`
- `session_binding_wrong_hardware_rejected`
- `session_binding_wrong_token_hash_rejected`
- `session_binding_replayed_nonce_rejected`
- `owner_claim_nonce_replay_rejected` — same nonce in two claims → second rejected
- `bound_capability_full_chain_passes` — create owner→user UCAN + session binding, verify both
- `bound_capability_revoked_ucan_rejected` — revoke the underlying UCAN → bound cap fails
- `kernel_issued_cap_no_binding_needed` — PqUcanToken signed by session key verifies without SessionBinding
- `ucan_issued_by_hardware_key_rejected` — UCAN with issuer=hardware_address (bypassing owner) → rejected by check_endpoint_cap because issuer is not the owner

Use `KernelEntropy` test RNG pattern from existing tests.

- [ ] **Step 6: Verify it compiles and tests pass**

Run: `cargo test --workspace`
Expected: All tests pass including new key_hierarchy tests.

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/key_hierarchy.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(microkernel): add key_hierarchy module — attestation, session binding, verification"
```

---

### Task 2: Add `CapChain::Session` variant to Nakaiah

**Independent of Task 1** — can execute in parallel if needed.

**Files:**
- Modify: `crates/harmony-microkernel/src/integrity/nakaiah.rs`

- [ ] **Step 1: Add `Session` variant to `CapChain`**

```rust
pub enum CapChain {
    Owner,
    ReadOnly { granted_by: u32 },
    ReadWrite { granted_by: u32 },
    /// Session-scoped access to encrypted-ephemeral frames.
    /// Invalidated when the session key is zeroized at shutdown.
    Session { session_address: [u8; 16] },
}
```

Update `CapChain::permits` — `Session` permits read + write (same as `ReadWrite`).

- [ ] **Step 2: Add test for Session variant**

```rust
#[test]
fn session_chain_permits_read_and_write() {
    let chain = CapChain::Session { session_address: [0xAA; 16] };
    assert!(chain.permits(AccessOp::Read));
    assert!(chain.permits(AccessOp::Write));
    assert!(!chain.permits(AccessOp::Execute));
}
```

- [ ] **Step 3: Verify tests pass**

Run: `cargo test -p harmony-microkernel -- nakaiah`
Expected: All Nakaiah tests pass including new Session test.

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/integrity/nakaiah.rs
git commit -m "feat(nakaiah): add CapChain::Session variant for encrypted-ephemeral frames"
```

---

### Task 3: Restructure `Kernel` — key hierarchy, two capability vectors

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs`

This is the largest task. The `Kernel` struct changes, `Process` splits capabilities, `new()` takes hierarchy params, `grant_endpoint_cap` uses session key, `check_endpoint_cap` checks both vectors.

- [ ] **Step 1: Update imports and Kernel struct**

Add imports for `key_hierarchy` types. Replace single `identity` with `hardware_identity`, `session_identity`, `attestation`. Add `used_binding_nonces: BTreeSet<[u8; 16]>`.

```rust
use crate::key_hierarchy::{
    AttestationPair, BoundCapability, SessionBinding,
    verify_session_binding, BindingError,
};

pub struct Kernel<P: PageTable> {
    processes: BTreeMap<u32, Process>,
    next_pid: u32,
    hardware_identity: PqPrivateIdentity,
    session_identity: PqPrivateIdentity,
    attestation: AttestationPair,
    used_binding_nonces: BTreeSet<[u8; 16]>,
    identity_store: PqMemoryIdentityStore,
    proof_store: PqMemoryProofStore,
    revocations: MemoryRevocationSet,
    fid_owners: BTreeMap<(u32, Fid), (u32, Fid)>,
    next_server_fid: Fid,
    vm: AddressSpaceManager<P>,
    lyll: Lyll,
    nakaiah: Nakaiah,
}
```

- [ ] **Step 2: Update `Process` — split capabilities**

```rust
pub struct Process {
    pub pid: u32,
    pub name: Arc<str>,
    pub(crate) namespace: Namespace,
    /// Kernel-issued capabilities (signed by session key, no binding needed).
    pub(crate) kernel_capabilities: Vec<PqUcanToken>,
    /// User-submitted capabilities (require session binding).
    pub(crate) user_capabilities: Vec<BoundCapability>,
    pub(crate) address_hash: [u8; 16],
    server: Box<dyn FileServer>,
}
```

- [ ] **Step 3: Rewrite `Kernel::new`**

```rust
pub fn new(
    hardware_identity: PqPrivateIdentity,
    session_identity: PqPrivateIdentity,
    attestation: AttestationPair,
    vm: AddressSpaceManager<P>,
) -> Self
```

Insert both hardware and session public identities into `identity_store`. The rest of construction (Lyll, Nakaiah, fid state) is unchanged.

- [ ] **Step 4: Update `grant_endpoint_cap`**

Change from `self.identity.issue_pq_root_token(...)` to `self.session_identity.issue_pq_root_token(...)`. Push result to `process.kernel_capabilities` (not `user_capabilities`).

- [ ] **Step 5: Update `check_endpoint_cap`**

Change the signature to take `&Process` directly instead of `&[PqUcanToken]`:

```rust
pub(crate) fn check_endpoint_cap(
    &self,
    process: &Process,
    target_pid: u32,
    now: u64,
) -> Result<(), IpcError>
```

Inside, check both vectors:
1. Scan `process.kernel_capabilities` — for each, `verify_pq_token` (existing path, issuer must be session key)
2. Scan `process.user_capabilities` — for each `BoundCapability`, `verify_pq_token` on `.token` THEN `verify_session_binding` on `.binding`
3. Either vector producing a valid match → Ok

Update the call site in `walk()` (~line 344) to pass `&process` instead of `&process.capabilities`.

- [ ] **Step 6: Update `spawn_process`**

Initialize both `kernel_capabilities: Vec::new()` and `user_capabilities: Vec::new()` in the new `Process`.

- [ ] **Step 7: Update all tests — create test helper for hierarchy**

Create a test helper that generates a hardware identity, session identity, and a minimal `AttestationPair`:

```rust
fn make_test_hierarchy(entropy: &mut impl CryptoRngCore) -> (PqPrivateIdentity, PqPrivateIdentity, AttestationPair) {
    // Generate owner, hardware, session identities
    // Create OwnerClaim signed by owner, HardwareAcceptance signed by hardware
    // Return (hardware_identity, session_identity, attestation_pair)
}
```

**Important:** There is NO existing `make_kernel` helper — each test calls `Kernel::new` directly. The `make_test_hierarchy` helper you create will be called from each test. There are ~24 `Kernel::new` calls in kernel.rs tests. Update each to `Kernel::new(hw, session, attestation, make_test_vm())` using the helper to generate `(hw, session, attestation)`.

Also update `make_test_entropy` to return a deterministic-but-distinct seed per call (the existing PRNG pattern works — each test creates its own `make_test_entropy()`).

- [ ] **Step 8: Update nix_store_server.rs and linuxulator.rs tests**

Same pattern — update `Kernel::new` calls to use the hierarchy constructor.

- [ ] **Step 9: Verify everything compiles and passes**

Run: `cargo test --workspace`
Expected: All tests pass.

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean.

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-microkernel/src/kernel.rs crates/harmony-microkernel/src/nix_store_server.rs crates/harmony-os/src/linuxulator.rs
git commit -m "feat(microkernel): restructure Kernel for key hierarchy

Kernel now holds hardware_identity, session_identity, and
AttestationPair instead of a single PqPrivateIdentity.

Process capabilities split into kernel_capabilities (session-key-signed,
no binding) and user_capabilities (BoundCapability with session binding).

grant_endpoint_cap uses session key. check_endpoint_cap verifies both
capability vectors."
```

---

### Task 4: Update boot sequence — generate hierarchy keys

**Files:**
- Modify: `crates/harmony-boot/src/main.rs`

The boot code in `kernel_continue` currently generates a single PQ identity via `runtime.generate_pq_identity()`. After this change it generates separate hardware and session identities, establishing the hierarchy keys at boot time.

**Important:** The `ring2`/`ring3` feature blocks in `main.rs` do NOT construct a `Kernel` on bare metal — the comment at line 473 says "The Kernel requires `std` (identity stores), so on bare metal we bypass it." There is no `Kernel::new` call to update in the boot code. This task only updates the identity generation and serial logging to reflect the hierarchy.

**Note:** Persistent storage for the hardware key is not yet implemented. For now, the hardware key is generated fresh each boot (same behavior as before). Actual persistence and provisioning are follow-up work.

- [ ] **Step 1: Update `kernel_continue` identity generation**

Replace the single `runtime.generate_pq_identity()` call with:
1. Generate hardware identity (placeholder — generates fresh each boot)
2. Generate session identity (ephemeral, always fresh)
3. Log both address hashes to serial
4. Call `runtime.generate_pq_identity()` continues to set the runtime's PQ identity (used for Reticulum-level PQ operations)

Add `// TODO: load hardware key from persistent storage` and `// TODO: verify attestation pair` comments for future work.

- [ ] **Step 2: Verify QEMU boot still passes**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean.

Run: `cargo test --workspace`
Expected: All tests pass.

The QEMU boot test should still pass — identity generation changes don't affect the milestone patterns.

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(boot): generate hardware + session identity keys at boot

Placeholder: hardware key generated fresh each boot (no persistent
storage yet). Session key is ephemeral as designed. Attestation
verification and Kernel integration are follow-up work."
```

---

### Task 5: Push and create PR

**Files:**
- No file changes.

- [ ] **Step 1: Push branch**

```bash
git push -u origin jake-os-key-hierarchy
```

- [ ] **Step 2: Create PR**

```bash
gh pr create --title "feat(microkernel): four-tier PQ key hierarchy with mutual attestation" --body "$(cat <<'EOF'
## Summary

Implements harmony-os-5gh: four-tier post-quantum key hierarchy.

### Key tiers
- **Owner** — accountability root, claims hardware, delegates to users (offline)
- **Hardware** — platform identity, immutable, mutually attested with owner
- **Session** — ephemeral per-boot, signs session bindings, owns encrypted-ephemeral memory
- **User** — long-lived, authority from owner, activated per-session

### What's new
- `key_hierarchy` module: `OwnerClaim`, `HardwareAcceptance`, `SessionBinding`, `BoundCapability`, `AttestationPair` types + verification functions
- `CapChain::Session` variant in Nakaiah for encrypted-ephemeral frames
- `Kernel` restructured: hardware + session identities, attestation pair, split capability vectors
- Boot sequence generates hierarchy (placeholder: test attestation, no persistent storage yet)

### What's deferred
- Persistent hardware key storage
- Owner provisioning UX (serial/USB/QR)
- Hardware key rotation (harmony-os-s9t)
- TPM integration (harmony-os-sgx)

## Test plan

- [x] `cargo test --workspace` — all tests pass
- [x] `cargo clippy --workspace --all-targets -- -D warnings` — clean
- [x] `cargo fmt --all -- --check` — clean
- [ ] `cargo xtask qemu-test` — both architectures pass

Closes harmony-os-5gh

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Close bead after CI passes**

```bash
bd close harmony-os-5gh --reason "Key hierarchy implemented: owner/hardware/session/user tiers, mutual attestation, session bindings, Nakaiah integration. Persistent storage + provisioning UX are follow-up."
```
