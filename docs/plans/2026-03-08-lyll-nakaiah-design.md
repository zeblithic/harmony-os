# Lyll & Nakaiah — Memory Integrity Subsystem Design

## Goal

Add two cooperative memory integrity guardians to Ring 2's microkernel: **Lyll**
(probabilistic auditor for public memory) and **Nakaiah** (deterministic escort
for private/encrypted memory). Together they provide Byzantine-fault-tolerant
memory verification through bidirectional mutual checking.

## Philosophy

Memory is split into public and private space. Public space is fast — Lyll does
random spot-checks (1-5% sampling rate) that are statistically robust across
billions of accesses. Private space is intentionally expensive — Nakaiah
verifies every single access (content integrity + capability chain
authorization). This cost asymmetry is a *feature*: it nudges programs toward
working in the open unless they genuinely need protection.

Lyll and Nakaiah are "twin employees" of the system. They fully trust but
verify each other. Lyll co-verifies Nakaiah before every private operation.
Nakaiah randomly checks in on Lyll to verify she's actually doing her job.
To compromise the system, an attacker must simultaneously compromise both
in a way that each looks normal to the other at unpredictable times —
exponentially harder than compromising either alone.

The "good shepherd" principle: we protect data while we have it, dispose of it
properly when we can't, and never keep someone's encrypted data around without
their knowledge or consent.

## Memory Layout

```
┌─────────────────────────────────────────────────────────────┐
│                    Physical Memory                          │
├─────────────────────────────────────┬───────────────────────┤
│         PUBLIC (75%)                │    KERNEL (25%)        │
│      Lyll's domain                  │   Nakaiah's domain     │
│                                     │                        │
│  ┌──────────┐  ┌──────────────┐     │  ┌─────────┐ ┌──────┐ │
│  │ Durable  │  │  Ephemeral   │     │  │Durable  │ │Ephem.│ │
│  │ LFU 50%  │  │  LRU  25%   │     │  │LFU 12.5%│ │6.25% │ │
│  │          │  │              │     │  │encrypted│ │encr. │ │
│  └──────────┘  └──────────────┘     │  └─────────┘ └──────┘ │
│  (soft budget)  (soft budget)       │  ┌─────────────────┐  │
│                                     │  │Admin 6.25%      │  │
│                                     │  │(Lyll+Nakaiah     │  │
│                                     │  │ own state)       │  │
│                                     │  └─────────────────┘  │
├─────────────────────────────────────┴───────────────────────┤
│  Hard physical boundary — enforced by separate allocators   │
└─────────────────────────────────────────────────────────────┘
```

### Partitioning Strategy

- **Hard physical partition** between public (75%) and kernel (25%) memory.
  Two separate `BuddyAllocator` instances. Kernel memory is only accessible
  from kernel-space code.
- **Soft budgets within each partition** for sub-zones (durable/ephemeral/admin).
  Tracked by `CapTracker` as accounting limits, not physical boundaries.
  Within a partition, sub-zones can borrow from each other.

### FrameClassification Mapping

The existing 2-bit `FrameClassification` maps directly to the four data zones:

| Bits | Classification | Zone | Cache Policy |
|------|---------------|------|-------------|
| `00` | Public, durable | Lyll LFU (50%) | Frequency-weighted |
| `01` | Public, ephemeral | Lyll LRU (25%) | Recency-weighted |
| `10` | Encrypted, durable | Nakaiah LFU (12.5%) | Frequency-weighted, zeroize on evict |
| `11` | Encrypted, ephemeral | Nakaiah LRU (6.25%) | Recency-weighted, zeroize on evict |

The physical partition (public vs kernel buddy) determines which domain owns
the frame. The classification bits determine cache policy and cleanup behavior
within that domain.

## Architecture: Approach 2 — Separate Subsystems with Event Hooks

Lyll and Nakaiah are independent modules under `integrity/`, sibling to `vm/`.
The `Kernel` struct orchestrates by emitting structured events that both
subsystems consume. Each owns its own state.

```
crates/harmony-microkernel/src/
├── kernel.rs                    // Kernel<P> — orchestrates VM + integrity
├── vm/
│   ├── mod.rs                   // + MemoryZone enum, ContentHash type
│   ├── manager.rs               // AddressSpaceManager<P> — buddy_public + buddy_kernel
│   ├── buddy.rs                 // BuddyAllocator (unchanged, two instances)
│   ├── cap_tracker.rs           // + zone-aware soft budgets
│   ├── page_table.rs            // (unchanged)
│   └── mock.rs                  // (unchanged)
│
├── integrity/                   // NEW
│   ├── mod.rs                   // IntegrityEvent, IntegrityVerdict, shared types
│   ├── lyll.rs                  // Lyll: spot-checks, hash registry, co-verification
│   ├── nakaiah.rs               // Nakaiah: per-access escort, capability chains, access log
│   └── quarantine.rs            // QuarantineRecord, shared quarantine registry
```

### What Changes in Existing Code

| File | Change | Reason |
|------|--------|--------|
| `vm/mod.rs` | Add `MemoryZone` enum, `ContentHash` type | Shared types |
| `vm/manager.rs` | Add `buddy_kernel` field, route allocations by zone | Hard partition |
| `vm/cap_tracker.rs` | Zone-aware soft budget tracking | Sub-zone limits |
| `kernel.rs` | Add `lyll: Lyll`, `nakaiah: Nakaiah` fields, emit `IntegrityEvent`s | Orchestration |

### What Does NOT Change

- `PageTable` trait and implementations (x86_64, aarch64, mock)
- `BuddyAllocator` internals
- 9P IPC layer
- Linuxulator (calls kernel VM methods which now emit integrity events internally)

## Event Model

### Event Types

```rust
/// Events emitted by the Kernel to the integrity subsystem.
enum IntegrityEvent {
    /// A frame was mapped into a process's address space.
    FrameMapped { pid: u32, paddr: PhysAddr, class: FrameClassification, content_hash: ContentHash },
    /// A frame is being accessed (private space only — public uses page faults).
    FrameAccessing { pid: u32, paddr: PhysAddr, operation: AccessOp },
    /// A frame was unmapped.
    FrameUnmapped { paddr: PhysAddr, class: FrameClassification },
    /// A write completed to a public frame (Lyll updates snapshot hash).
    FrameWritten { paddr: PhysAddr, new_hash: ContentHash },
    /// Timer tick — drives Lyll's periodic sweep and Nakaiah's random check-ins.
    TimerTick,
}

enum AccessOp { Read, Write, Execute }

/// Verdicts returned by the integrity subsystem.
enum IntegrityVerdict {
    /// Access is permitted.
    Allow,
    /// Frame is suspicious — quarantine and investigate.
    Quarantine { paddr: PhysAddr, reason: ViolationReason },
    /// Accessor is unauthorized or data is tampered — kill the process.
    Kill { pid: u32, reason: ViolationReason },
    /// A guardian itself is compromised — full kernel panic.
    Panic { reason: ViolationReason },
}
```

### Event Flows

**Public memory access (Lyll only):**

```
1. Access arrives at mapped public frame
2. IF frame is in Lyll's spot-check sample (1-5%):
   a. Page fault fires (frame was marked not-present)
   b. Lyll hashes frame content
   c. Compares against baseline (CID for durable, snapshot for ephemeral)
   d. Match → re-mark present, continue
   e. Mismatch → QUARANTINE frame, notify admin
3. IF frame is not sampled: zero overhead, direct access
```

**Private memory access (Nakaiah + Lyll co-verification):**

```
1. Access arrives at kernel-space encrypted frame
2. Lyll verifies Nakaiah's state first:
   a. Hash Nakaiah's state → matches expected snapshot?
   b. Mismatch → PANIC (Nakaiah is compromised)
3. Nakaiah verifies the access:
   a. Content integrity: hash frame → matches stored hash?
   b. Authorization: capability chain valid for this pid + operation?
   c. Both pass → allow access
   d. Either fails → KILL accessor process
4. Nakaiah appends receipt to access log
5. Both update their snapshots of each other's state hash
6. IF Nakaiah's random check-in triggers (~1% of ops):
   a. Nakaiah verifies Lyll's state hash
   b. Nakaiah spot-checks Lyll's behavior (sampling real? quarantine real?)
   c. Mismatch → PANIC (Lyll is compromised)
```

## Lyll — The Auditor

### State

```rust
pub struct Lyll {
    /// Expected content hashes for all public frames.
    /// Durable: CID-derived (immutable). Ephemeral: write-barrier snapshots.
    hash_registry: BTreeMap<PhysAddr, HashEntry>,

    /// Snapshot hash of Nakaiah's state (for co-verification).
    nakaiah_state_hash: ContentHash,

    /// Frames currently marked not-present for spot-check sampling.
    sampled_frames: BTreeSet<PhysAddr>,

    /// Quarantined frames pending admin investigation.
    quarantine: Vec<QuarantineRecord>,

    /// Self-state hash — Nakaiah verifies this on random check-ins.
    /// Recomputed after every state mutation.
    state_hash: ContentHash,

    /// Sampling configuration.
    config: LyllConfig,
}
```

### Hash Entry Types

```rust
enum HashEntry {
    /// CID-derived — immutable, set at map time. For content-addressed durable pages.
    CidBacked { cid: [u8; 32] },
    /// Snapshot — updated on every write. For writable ephemeral pages.
    Snapshot { hash: [u8; 32], generation: u64 },
}
```

### Spot-Check Schedule

| Tier | Strategy | Rate | Mechanism |
|------|----------|------|-----------|
| Public durable (LFU) | Page-fault interposition | 1-5% of frames | Mark random frames not-present; verify on fault |
| Public ephemeral (LRU) | Periodic sweep | Timer-driven | Background hash checks, no page faults |
| Kernel space (Nakaiah's) | Co-verification | 100% of Nakaiah ops | Hash Nakaiah's state before each private access |

Lyll rotates which frames are sampled on a configurable interval. Over time
every frame gets checked.

## Nakaiah — The Bodyguard

### State

```rust
pub struct Nakaiah {
    /// Content integrity hashes for every encrypted frame.
    integrity_registry: BTreeMap<PhysAddr, [u8; 32]>,

    /// Capability chains: (pid, paddr) → delegation chain authorizing access.
    capability_chains: BTreeMap<(u32, PhysAddr), CapChain>,

    /// Append-only access log. Hash-chained: each entry includes hash of previous.
    access_log: AccessLog,

    /// Self-state hash — Lyll verifies this before every private operation.
    state_hash: ContentHash,

    /// Snapshot of Lyll's expected state hash (for random check-ins).
    lyll_state_hash: ContentHash,

    /// Check-in probability (e.g., 0.01 = 1% of operations).
    lyll_checkin_rate: f32,
}
```

### Per-Access Verification

```
Nakaiah.verify_access(pid, paddr, op) → IntegrityVerdict
│
├─ 1. Content integrity: hash(frame_contents) == integrity_registry[paddr]?
│     NO → Kill { pid, ContentTampered }
│
├─ 2. Capability chain: valid chain for (pid, paddr, op)?
│     Traces back to frame owner's key? Covers this operation type?
│     NO → Kill { pid, UnauthorizedAccess }
│
├─ 3. Append receipt to access log (hash-chained)
│
└─ 4. Recompute state_hash
```

### Eviction Policy

| Sub-zone | Policy | On evict |
|----------|--------|----------|
| Encrypted durable (LFU) | Least-frequently-used | Zeroize. Owner key present → charge storage. No owner key → burn (dispose + log receipt). |
| Encrypted ephemeral (LRU) | Least-recently-used | Zeroize. NEVER persist. Remove all traces. No receipts preserved. |

## Bidirectional Mutual Verification

Neither Lyll nor Nakaiah can verify themselves — a compromised guardian might
not know (or might hide) that it's compromised. Each verifies the other.

### What Lyll checks about Nakaiah (before every private op):

1. `nakaiah.state_hash` matches Lyll's stored snapshot

### What Nakaiah checks about Lyll (random check-ins, ~1% of ops):

1. `lyll.state_hash` matches Nakaiah's stored snapshot
2. **Sampling is real** — pick a random frame from `lyll.sampled_frames`,
   verify it's actually marked not-present in the page table
3. **Quarantine is real** — if quarantine has entries, verify those frames
   are actually unmapped from all processes
4. **Hash registry isn't stale** — pick a random entry, independently hash
   the frame content, verify it matches Lyll's stored hash

### Why this works:

A compromised Lyll could be designed to look perfect during the specific
co-verification interaction (always report correct state hash). But Nakaiah's
random check-ins verify Lyll's *normal operations* — is she actually sampling?
Are quarantined frames actually unmapped? This is the "great in the office but
a dirtbag on the streets" protection.

### Violation taxonomy:

| Detector | Detects | Verdict |
|----------|---------|---------|
| Lyll spot-check | Public frame tampered | Quarantine |
| Lyll co-verify | Nakaiah state tampered | Panic |
| Nakaiah access verify | Private frame tampered or unauthorized | Kill accessor |
| Nakaiah check-in | Lyll state tampered or not doing her job | Panic |

## Quarantine

```rust
struct QuarantineRecord {
    paddr: PhysAddr,
    expected_hash: [u8; 32],
    actual_hash: [u8; 32],
    owner_pid: u32,
    mapped_pids: Vec<u32>,
    timestamp: u64,
    zone: MemoryZone,
}
```

Quarantined frames are unmapped from all processes but NOT freed. A privileged
admin process can inspect quarantine records for forensic investigation.

## Kernel Orchestration

```rust
impl<P: PageTable> Kernel<P> {
    pub fn vm_map_region(&mut self, pid: u32, vaddr: VirtAddr, len: usize,
                         flags: PageFlags, class: FrameClassification)
                         -> Result<(), VmError> {
        // 1. VM manager maps (picks correct buddy by zone)
        self.vm.map_region(pid, vaddr, len, flags, class)?;

        // 2. Compute content hash
        let content_hash = /* hash frame contents */;

        // 3. Notify Lyll (registers hash baseline)
        self.lyll.on_event(IntegrityEvent::FrameMapped {
            pid, paddr, class, content_hash,
        });

        // 4. If encrypted, also register with Nakaiah
        if class.contains(FrameClassification::ENCRYPTED) {
            self.nakaiah.register_frame(paddr, content_hash, /* cap_chain */);
        }

        Ok(())
    }
}
```

## Testing Strategy (~68 tests)

### Lyll tests (~25)

| Category | Count | Verifies |
|----------|-------|----------|
| Hash registry | 5 | CID immutability, snapshot updates, cleanup on unmap |
| Spot-check sampling | 5 | Configured rate, rotation, full coverage over time |
| Violation detection | 4 | Tampered frames quarantined, correct frames pass |
| Co-verification of Nakaiah | 4 | Valid state passes, tampered state → panic |
| Quarantine management | 3 | Frames quarantined, unmapped, full forensic records |
| Config | 2 | Sampling rate, timer interval |
| Edge cases | 2 | Zero frames, unmap during rotation |

### Nakaiah tests (~25)

| Category | Count | Verifies |
|----------|-------|----------|
| Content integrity | 5 | Valid hash passes, tampered → kill, updates on write |
| Capability chains | 6 | Valid chain allows, expired/wrong/missing → kill, op-type enforcement |
| Access log | 4 | Receipts append, hash-chained, monotonic, ephemeral no-preserve |
| State hashing | 4 | Changes on mutation, stable otherwise, independently verifiable |
| Eviction | 4 | Durable zeroize+log, ephemeral zeroize+purge, burn unclaimed, charge owner |
| Edge cases | 2 | Concurrent access, unmap in flight |

### Nakaiah check-ins of Lyll (~8)

| Test | Verifies |
|------|----------|
| Healthy Lyll passes check-in | Happy path |
| Tampered Lyll state hash detected | State integrity |
| Lyll not actually sampling detected | Behavioral verification |
| Fake quarantine detected | Quarantine integrity |
| Stale hash registry detected | Registry freshness |
| Mutual state update cycle | Both snapshots stay in sync |
| No deadlock under concurrent ops | Ordering safety |
| Check-in rate matches config | Statistical accuracy |

### Integration tests (~10)

| Test | Verifies |
|------|----------|
| Full public access cycle | Map → sample → verify → pass |
| Full private access cycle | Map encrypted → co-verify → escort → pass |
| Public corruption detected | Tamper → spot-check → quarantine |
| Private corruption detected | Tamper → access → kill |
| Nakaiah compromise detected | Tamper Nakaiah state → co-verify → panic |
| Lyll compromise detected | Tamper Lyll state → Nakaiah check-in → panic |
| Dual-partition allocation | Public/kernel buddies isolated |
| Eviction zeroize | Fill encrypted → evict → verify zeroed |
| Burn unclaimed data | No owner key → disposal receipt |
| Process destroy cleanup | Mixed frames → destroy → all cleaned up |
| Zone budget enforcement | Exhaust durable → fail → ephemeral still works |
