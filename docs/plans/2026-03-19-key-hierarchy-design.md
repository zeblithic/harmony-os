# Post-Quantum Key Hierarchy — Design

**Date:** 2026-03-19
**Status:** Proposed
**Bead:** harmony-os-5gh

## Problem

The harmony-os kernel currently holds a single `PqPrivateIdentity` — generated at boot, ephemeral, used for all UCAN token issuance. This flat model has no hardware binding, no owner accountability, no forward secrecy separation, and no defense in depth. A compromised key exposes everything.

## Solution

A four-tier post-quantum key hierarchy with mutual attestation between owner and hardware, persistent user delegation, and ephemeral session bindings. Each tier is a `PqPrivateIdentity` (ML-DSA-65 / ML-KEM-768) with a distinct lifecycle and trust purpose.

## Key Tiers

| Tier | Lifecycle | Storage | Purpose |
|------|-----------|---------|---------|
| **Owner** | Long-lived, persisted offline | External (USB, air-gapped) — never on-node | Accountability root. Claims hardware, delegates to users. |
| **Hardware** | Generated once on first boot, immutable | On-node persistent storage | Platform identity. "This physical machine." |
| **Session** | Generated at boot, zeroized at shutdown | Memory only — never persisted | Forward secrecy. Signs session bindings, owns encrypted-ephemeral memory. |
| **User** | Long-lived, in user's control | User-managed (may be on a different device) | End-user identity. Authority from owner, activated per-session. |

### What the Session Key Does and Does Not Do

The session key handles two things:
1. **Signing session bindings** — activating user authority for this boot cycle
2. **Owning encrypted-ephemeral memory** — Nakaiah's `FrameClassification::ENCRYPTED | EPHEMERAL` zone

The session key **never** encrypts persistent data. All persistent encryption uses the hardware key or user key. Data encrypted to the session key dies when the session key is zeroized at shutdown.

## Mutual Attestation

The owner-hardware relationship requires mutual attestation — both sides must sign. Neither key alone is sufficient to operate the system.

The attestation ceremony happens over a **physically-authenticated channel** (serial, USB, QR code). The specific transport mechanism is out of scope for this spec (tracked as a future provisioning UX bead). The data structures and verification logic are defined here; the delivery mechanism is not.

### Owner Claims Hardware

```rust
pub struct OwnerClaim {
    /// Owner's PQ address hash.
    pub owner_address: [u8; 16],
    /// Hardware identity's PQ address hash.
    pub hardware_address: [u8; 16],
    /// When the claim was made (Unix timestamp, seconds).
    pub claimed_at: u64,
    /// Owner index (0 = primary). Reserved for future multi-owner extension.
    /// Current implementation only accepts index 0.
    pub owner_index: u32,
    /// Random nonce for replay protection.
    pub nonce: [u8; 16],
    /// ML-DSA-65 signature by the owner over the signable fields.
    pub signature: [u8; 3309],
}
```

### Hardware Accepts Owner

```rust
pub struct HardwareAcceptance {
    /// Hardware identity's PQ address hash.
    pub hardware_address: [u8; 16],
    /// Owner's PQ address hash.
    pub owner_address: [u8; 16],
    /// When the acceptance was recorded (Unix timestamp, seconds).
    pub accepted_at: u64,
    /// BLAKE3 hash of the corresponding OwnerClaim (binds to specific claim).
    pub owner_claim_hash: [u8; 32],
    /// ML-DSA-65 signature by the hardware over the signable fields.
    pub signature: [u8; 3309],
}
```

### Attestation Pair

```rust
pub struct AttestationPair {
    pub owner_claim: OwnerClaim,
    pub hardware_acceptance: HardwareAcceptance,
}
```

Both signatures are verified at boot. If either is missing or invalid, the node boots in **unclaimed mode** (see below).

### Wire Format

All attestation and binding structs use big-endian, fixed field order serialization. The `signable_bytes()` method returns all fields except `signature` in wire order. This is the same pattern used by `PqUcanToken`.

**OwnerClaim signable bytes:**
```
[16B owner_address][16B hardware_address][8B claimed_at][4B owner_index][16B nonce]
```

**HardwareAcceptance signable bytes:**
```
[16B hardware_address][16B owner_address][8B accepted_at][32B owner_claim_hash]
```

**SessionBinding signable bytes:**
```
[16B session_address][16B user_address][32B user_token_hash][16B hardware_address][8B bound_at][16B nonce]
```

### Storage

The attestation pair is persisted alongside the hardware key. Claims are stored as `Vec<OwnerClaim>` / `Vec<HardwareAcceptance>` to allow future multi-owner extension. The current implementation only accepts `owner_index == 0`.

## UCAN Delegation Chains

Three chains operate simultaneously:

### Chain 1: Platform Attestation (Hardware ↔ Owner)

```
Owner ──OwnerClaim──→ Hardware
Hardware ──HardwareAcceptance──→ Owner
```

Standalone signed attestation documents, not UCAN tokens. Verified once at boot.

### Chain 2: User Authority (Owner → User)

```
Owner ──UCAN(root)──→ User
  capability: Identity | Content | Compute | ...
  resource: scoped per user
  expires_at: long-lived (weeks/months)
```

Standard UCAN delegation via the existing `issue_pq_root_token` / `delegate` API. Persistent — survives reboots because neither the owner key nor user key is ephemeral.

### Chain 3: Session Binding (Session ← User)

```rust
pub struct SessionBinding {
    /// This boot's session key address hash.
    pub session_address: [u8; 16],
    /// User being activated.
    pub user_address: [u8; 16],
    /// BLAKE3 hash of the user's UCAN from Chain 2.
    pub user_token_hash: [u8; 32],
    /// Hardware this session runs on (ties binding to specific node).
    pub hardware_address: [u8; 16],
    /// When the binding was created (Unix timestamp, seconds).
    pub bound_at: u64,
    /// Random nonce for intra-session replay protection.
    pub nonce: [u8; 16],
    /// ML-DSA-65 signature by the session key.
    pub signature: [u8; 3309],
}
```

The session key signs a binding that says "user X with token Y is active on this machine during this session."

**Binding cardinality:** 1:1 — each `SessionBinding` commits to exactly one UCAN (via `user_token_hash`). A user with N capability tokens needs N session bindings. This is intentional: it prevents a single binding from granting broader access than the specific token it commits to.

**Replay protection:** Each binding has a `nonce: [u8; 16]` filled from CSPRNG. The kernel maintains a per-session `HashSet<[u8; 16]>` of used nonces. A replayed binding (same nonce) is rejected.

### Verification at Syscall Time

Session bindings are verified by a dedicated function (not `verify_pq_token`, which is for UCAN chains):

```rust
/// Verify a session binding against the current session key.
///
/// This is NOT a UCAN token — it has its own verification path.
/// The session public key is available directly from the kernel's
/// `session_identity` field (no identity store lookup needed).
pub fn verify_session_binding(
    binding: &SessionBinding,
    session_pubkey: &PqIdentity,
    hardware_address: &[u8; 16],
    used_nonces: &HashSet<[u8; 16]>,
) -> Result<(), BindingError>;
```

Full capability check at walk time:

1. User presents their UCAN token (Chain 2) + session binding (Chain 3)
2. Kernel verifies UCAN signature chain back to owner (`verify_pq_token` — existing)
3. Kernel verifies session binding via `verify_session_binding`:
   - Signature valid against current session public key
   - `binding.hardware_address` matches this node's hardware key
   - `binding.user_token_hash == token.content_hash()`
   - `binding.nonce` not in `used_nonces` set
4. All pass → capability granted; nonce added to used set

**Revocation timing:** Revocation takes effect at next `walk` (lazy check), not per-syscall. This matches the existing `check_endpoint_cap` behavior where capability verification gates session setup. Open fids remain valid until clunked. This is a deliberate choice — per-syscall verification would add unacceptable overhead to every 9P operation.

### Security Properties

- **Stolen UCAN** is useless without a session binding (attacker needs the session key, which is memory-only)
- **Stolen session binding** is useless after reboot (new session key invalidates it)
- **Replayed session binding** is rejected within a session (nonce uniqueness)
- **Owner revocation** invalidates user authority — session bindings become invalid because the underlying UCAN fails verification (step 2)
- **Hardware compromise** is visible — the mutual attestation ties authority to a specific hardware identity; a different machine can't impersonate

## Kernel Integration

### Kernel Struct Changes

```rust
pub struct Kernel<P: PageTable> {
    // Key hierarchy (replaces single `identity: PqPrivateIdentity`)
    hardware_identity: PqPrivateIdentity,
    session_identity: PqPrivateIdentity,
    attestation: AttestationPair,

    // Nonce tracking for session binding replay protection
    used_binding_nonces: HashSet<[u8; 16]>,

    // Existing stores — populated with owner + hardware + user identities
    identity_store: PqMemoryIdentityStore,
    proof_store: PqMemoryProofStore,
    revocations: MemoryRevocationSet,

    // Process capabilities
    processes: BTreeMap<u32, Process>,
    // ... (VM, Lyll, Nakaiah, IPC state unchanged)
}
```

### Constructor

```rust
impl<P: PageTable> Kernel<P> {
    /// Create a kernel with the key hierarchy.
    ///
    /// `hardware_identity` and `attestation` are loaded from persistent
    /// storage before this call (or generated on first boot).
    /// `session_identity` is generated fresh by the caller.
    pub fn new(
        hardware_identity: PqPrivateIdentity,
        session_identity: PqPrivateIdentity,
        attestation: AttestationPair,
        vm: AddressSpaceManager<P>,
    ) -> Self;
}
```

The caller (boot code in `kernel_continue`) handles I/O — loading the hardware key and attestation from persistent storage, generating the session key. The `Kernel` constructor receives them as values, preserving the sans-I/O pattern.

### Two Capability Flows

**User-submitted capabilities** use `BoundCapability`:

```rust
pub struct BoundCapability {
    /// Owner → User UCAN (Chain 2).
    pub token: PqUcanToken,
    /// Session activation (Chain 3).
    pub binding: SessionBinding,
}
```

**Kernel-internal grants** (e.g., `grant_endpoint_cap`) continue to issue `PqUcanToken` signed by the **session key**. No session binding is needed because the kernel trusts itself — the session key is the kernel's own ephemeral identity. Kernel-issued tokens have `issuer == session_identity.address_hash`.

```rust
pub struct Process {
    pub pid: u32,
    pub name: Arc<str>,
    pub(crate) namespace: Namespace,
    /// User-submitted capabilities (require session binding).
    pub(crate) user_capabilities: Vec<BoundCapability>,
    /// Kernel-issued capabilities (signed by session key, no binding needed).
    pub(crate) kernel_capabilities: Vec<PqUcanToken>,
    pub(crate) address_hash: [u8; 16],
    server: Box<dyn FileServer>,
}
```

`check_endpoint_cap` checks both vectors — kernel caps via `verify_pq_token` (existing), user caps via `verify_pq_token` + `verify_session_binding`.

### Nakaiah Integration

The session key becomes Nakaiah's authority for the encrypted-ephemeral zone:

- New `CapChain` variant: `CapChain::Session { session_address: [u8; 16] }` for encrypted-ephemeral frames
- At shutdown, session key zeroized → all encrypted-ephemeral frames with `CapChain::Session` become inaccessible
- Encrypted-durable frames use `CapChain::Owner` with the hardware key or user key — persist across reboots
- Lyll is unchanged — public memory auditing does not touch the key hierarchy

### Boot Sequence

```
kernel_main:                                    ← bootloader stack (~16KB)
  1. serial, PIT, heap
  2. allocate 2MB stack, switch RSP
kernel_continue:                                ← 2MB heap stack
  3. load hardware identity from persistent storage
     (or generate + persist on first boot)
  4. verify attestation pair (owner claim + hardware acceptance)
     missing or invalid → unclaimed mode (restricted)
  5. generate session identity (ephemeral PQ keypair)
  6. RDRAND, Ed25519 compat identity
  7. VirtIO, netstack
  8. event loop
     - users present UCANs + request session binding
     - kernel verifies UCAN chain, signs session binding
```

### Unclaimed Mode

When no valid attestation pair exists (first boot, or owner key not yet presented):

- Serial output active (for provisioning)
- No network interfaces registered
- No user delegation possible
- Hardware identity's **16-byte address hash** displayed on serial in hex (32 characters — practical for manual verification). The full 3136-byte PQ public key is available via a provisioning protocol (out of scope for this spec).

## What Does NOT Change

- `verify_pq_token` — unchanged, still verifies UCAN chains
- `PqMemoryIdentityStore` / `PqMemoryProofStore` — still used, populated with more identities
- Lyll — unchanged (public memory integrity is independent of key hierarchy)
- `UnikernelRuntime` — `generate_pq_identity()` becomes the session key generator
- `harmony-boot-aarch64` — same hierarchy model, different boot mechanics
- Reticulum wire compatibility — Ed25519 identity unchanged, separate from hierarchy

## Testing

| Test | Verifies |
|------|----------|
| Attestation pair creation + verification | Owner signs claim, hardware signs acceptance, both verify |
| Invalid attestation rejected | Wrong signer, mismatched addresses, tampered fields |
| OwnerClaim replay rejected | Same nonce reused in different claim → rejected |
| Session binding creation + verification | Session key signs binding, kernel verifies |
| Stale session binding rejected | Binding from previous session (different session_address) fails |
| Session binding replay rejected | Same nonce reused within session → rejected |
| Session binding wrong hardware rejected | binding.hardware_address != node's hardware key → rejected |
| Session binding mismatched token hash | binding.user_token_hash != token.content_hash() → rejected |
| BoundCapability full chain verification | UCAN valid + binding valid + hashes match + hardware matches |
| Kernel-issued cap bypasses binding | Session-key-signed PqUcanToken verified without SessionBinding |
| Revoked UCAN invalidates bound capability | Owner revokes → BoundCapability check fails at UCAN step |
| Hardware key not in owner's UCAN chain | UCAN issued by hardware key directly (bypassing owner) → rejected |
| Unclaimed mode | No attestation → restricted boot, no network, no delegation |
| Nakaiah ephemeral zone uses session key | CapChain::Session for encrypted-ephemeral frames, zeroized at shutdown |
| Hardware identity persistence | Generate on first boot, reload on subsequent boots |

## Out of Scope

| What | Tracking | Rationale |
|------|----------|-----------|
| Hardware key rotation (KERI pre-rotation) | `harmony-os-s9t` | Depends on `harmony-eo2` in core |
| TPM-sealed hardware key | `harmony-os-sgx` | Sub-project 2 (hardware security) |
| Multi-owner (M-of-N threshold) | Future bead | Extension of `owner_index` model |
| Per-device/per-peer key proliferation | Future bead | Sub-project 3 |
| Owner provisioning UX / transport | Future bead | Mechanism, not model |
| Attestation claim expiry policy | Future bead | No max-age enforced in v1 |
| Ed25519 compat for attestation | Not needed | Attestation is Harmony-native only |
