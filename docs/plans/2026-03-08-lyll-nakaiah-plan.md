# Lyll & Nakaiah Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement two cooperative memory integrity guardians — Lyll (probabilistic auditor for public memory) and Nakaiah (deterministic escort for private/encrypted memory) — with bidirectional mutual verification.

**Architecture:** Lyll and Nakaiah are independent modules under `integrity/`, sibling to `vm/`. The `Kernel` struct orchestrates them via structured `IntegrityEvent`s. A dual-buddy allocator enforces hard physical partition between public (75%) and kernel (25%) memory. Content hashing uses `harmony_crypto::hash::blake3_hash`.

**Tech Stack:** Rust (`no_std`-compatible with `alloc`), `bitflags`, `BTreeMap`/`BTreeSet`, `harmony-crypto` (BLAKE3)

**Design doc:** `docs/plans/2026-03-08-lyll-nakaiah-design.md`

---

### Task 1: Shared Types — MemoryZone, ContentHash, AccessOp, ViolationReason

Add shared integrity types to `vm/mod.rs` so both the integrity subsystem and existing VM code can reference them.

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/mod.rs`

**Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` block in `vm/mod.rs`:

```rust
#[test]
fn memory_zone_from_classification() {
    assert_eq!(
        MemoryZone::from(FrameClassification::empty()),
        MemoryZone::PublicDurable,
    );
    assert_eq!(
        MemoryZone::from(FrameClassification::EPHEMERAL),
        MemoryZone::PublicEphemeral,
    );
    assert_eq!(
        MemoryZone::from(FrameClassification::ENCRYPTED),
        MemoryZone::KernelDurable,
    );
    assert_eq!(
        MemoryZone::from(FrameClassification::ENCRYPTED | FrameClassification::EPHEMERAL),
        MemoryZone::KernelEphemeral,
    );
}

#[test]
fn content_hash_default_is_zeroed() {
    let h = ContentHash::default();
    assert_eq!(h.0, [0u8; 32]);
}

#[test]
fn access_op_variants_exist() {
    let _r = AccessOp::Read;
    let _w = AccessOp::Write;
    let _x = AccessOp::Execute;
}

#[test]
fn violation_reason_variants_exist() {
    let _ct = ViolationReason::ContentTampered;
    let _ua = ViolationReason::UnauthorizedAccess;
    let _gs = ViolationReason::GuardianStateCorrupted;
    let _bm = ViolationReason::BehavioralMismatch;
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel vm::tests::memory_zone -- 2>&1 | head -20`
Expected: Compilation error — `MemoryZone` not found

**Step 3: Write the types**

Add above the `// ── Error enum` section in `vm/mod.rs`:

```rust
// ── Integrity shared types ──────────────────────────────────────────

/// Which memory zone a frame belongs to, derived from FrameClassification.
///
/// | Classification bits | Zone              |
/// |---------------------|-------------------|
/// | `00`                | PublicDurable      |
/// | `01`                | PublicEphemeral    |
/// | `10`                | KernelDurable      |
/// | `11`                | KernelEphemeral    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryZone {
    PublicDurable,
    PublicEphemeral,
    KernelDurable,
    KernelEphemeral,
}

impl From<FrameClassification> for MemoryZone {
    fn from(class: FrameClassification) -> Self {
        match (
            class.contains(FrameClassification::ENCRYPTED),
            class.contains(FrameClassification::EPHEMERAL),
        ) {
            (false, false) => MemoryZone::PublicDurable,
            (false, true) => MemoryZone::PublicEphemeral,
            (true, false) => MemoryZone::KernelDurable,
            (true, true) => MemoryZone::KernelEphemeral,
        }
    }
}

impl MemoryZone {
    /// Returns `true` if this zone is in kernel (encrypted) space.
    pub fn is_kernel(self) -> bool {
        matches!(self, Self::KernelDurable | Self::KernelEphemeral)
    }

    /// Returns `true` if this zone is ephemeral.
    pub fn is_ephemeral(self) -> bool {
        matches!(self, Self::PublicEphemeral | Self::KernelEphemeral)
    }
}

/// A 32-byte content hash (BLAKE3) used for frame integrity verification.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    pub const ZERO: Self = Self([0u8; 32]);
}

impl Default for ContentHash {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// What kind of access is being performed on a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOp {
    Read,
    Write,
    Execute,
}

/// Reason for an integrity violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationReason {
    /// Frame content doesn't match stored hash.
    ContentTampered,
    /// Process doesn't have a valid capability chain for this access.
    UnauthorizedAccess,
    /// A guardian's state hash doesn't match expected value.
    GuardianStateCorrupted,
    /// Guardian's behavior doesn't match its reported state
    /// (e.g., Lyll claims to be sampling but frames aren't marked not-present).
    BehavioralMismatch,
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel vm::tests -- -v`
Expected: All pass including the 4 new tests

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/vm/mod.rs
git commit -m "feat(integrity): add shared types — MemoryZone, ContentHash, AccessOp, ViolationReason"
```

---

### Task 2: Integrity Module Scaffold — IntegrityEvent, IntegrityVerdict

Create the `integrity/` module with the event-driven communication types that the Kernel uses to communicate with Lyll and Nakaiah.

**Files:**
- Create: `crates/harmony-microkernel/src/integrity/mod.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add `pub mod integrity;`)

**Step 1: Write the failing test**

In the new `integrity/mod.rs`, add a test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{FrameClassification, PhysAddr};

    #[test]
    fn integrity_event_frame_mapped() {
        let event = IntegrityEvent::FrameMapped {
            pid: 1,
            paddr: PhysAddr(0x1000),
            class: FrameClassification::empty(),
            content_hash: ContentHash::ZERO,
        };
        // Just verify it constructs without panic.
        assert!(matches!(event, IntegrityEvent::FrameMapped { pid: 1, .. }));
    }

    #[test]
    fn integrity_verdict_variants() {
        let allow = IntegrityVerdict::Allow;
        assert!(matches!(allow, IntegrityVerdict::Allow));

        let kill = IntegrityVerdict::Kill {
            pid: 42,
            reason: ViolationReason::ContentTampered,
        };
        assert!(matches!(kill, IntegrityVerdict::Kill { pid: 42, .. }));

        let quarantine = IntegrityVerdict::Quarantine {
            paddr: PhysAddr(0x2000),
            reason: ViolationReason::ContentTampered,
        };
        assert!(matches!(quarantine, IntegrityVerdict::Quarantine { .. }));

        let panic = IntegrityVerdict::Panic {
            reason: ViolationReason::GuardianStateCorrupted,
        };
        assert!(matches!(panic, IntegrityVerdict::Panic { .. }));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel integrity::tests -- 2>&1 | head -20`
Expected: Compilation error — module `integrity` not found

**Step 3: Write the module**

Create `crates/harmony-microkernel/src/integrity/mod.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Memory integrity subsystem — Lyll (auditor) and Nakaiah (bodyguard).
//!
//! This module defines the event-driven communication protocol between the
//! Kernel and the integrity guardians. The Kernel emits [`IntegrityEvent`]s;
//! guardians return [`IntegrityVerdict`]s.

use crate::vm::{AccessOp, ContentHash, FrameClassification, PhysAddr, ViolationReason};

// ── Submodules ───────────────────────────────────────────────────────

pub mod lyll;
pub mod nakaiah;
pub mod quarantine;

// ── Events ──────────────────────────────────────────────────────────

/// Events emitted by the Kernel to the integrity subsystem.
#[derive(Debug, Clone)]
pub enum IntegrityEvent {
    /// A frame was mapped into a process's address space.
    FrameMapped {
        pid: u32,
        paddr: PhysAddr,
        class: FrameClassification,
        content_hash: ContentHash,
    },
    /// A frame is being accessed (kernel-space frames only).
    FrameAccessing {
        pid: u32,
        paddr: PhysAddr,
        operation: AccessOp,
    },
    /// A frame was unmapped.
    FrameUnmapped {
        paddr: PhysAddr,
        class: FrameClassification,
    },
    /// A write completed to a public frame — Lyll updates snapshot hash.
    FrameWritten {
        paddr: PhysAddr,
        new_hash: ContentHash,
    },
    /// Timer tick — drives Lyll's periodic sweep and Nakaiah's random check-ins.
    TimerTick,
}

// ── Verdicts ────────────────────────────────────────────────────────

/// Verdicts returned by the integrity subsystem to the Kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityVerdict {
    /// Access is permitted.
    Allow,
    /// Frame is suspicious — quarantine and investigate.
    Quarantine {
        paddr: PhysAddr,
        reason: ViolationReason,
    },
    /// Accessor is unauthorized or data is tampered — kill the process.
    Kill { pid: u32, reason: ViolationReason },
    /// A guardian itself is compromised — full kernel panic.
    Panic { reason: ViolationReason },
}
```

Add to `lib.rs` (below `pub mod vm;`):

```rust
#[cfg(feature = "kernel")]
pub mod integrity;
```

Also create empty stub files so the module compiles:
- `crates/harmony-microkernel/src/integrity/lyll.rs` — just `// SPDX-License-Identifier: GPL-2.0-or-later`
- `crates/harmony-microkernel/src/integrity/nakaiah.rs` — same
- `crates/harmony-microkernel/src/integrity/quarantine.rs` — same

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel integrity::tests -- -v`
Expected: All pass

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/integrity/ crates/harmony-microkernel/src/lib.rs
git commit -m "feat(integrity): add integrity module scaffold — IntegrityEvent, IntegrityVerdict"
```

---

### Task 3: Quarantine Registry

Implement the shared quarantine data structure that both Lyll and Nakaiah can write to.

**Files:**
- Modify: `crates/harmony-microkernel/src/integrity/quarantine.rs`

**Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{MemoryZone, PhysAddr};

    #[test]
    fn quarantine_empty_initially() {
        let q = QuarantineRegistry::new();
        assert_eq!(q.len(), 0);
        assert!(q.records().is_empty());
    }

    #[test]
    fn quarantine_add_and_lookup() {
        let mut q = QuarantineRegistry::new();
        q.add(QuarantineRecord {
            paddr: PhysAddr(0x1000),
            expected_hash: [0xAA; 32],
            actual_hash: [0xBB; 32],
            owner_pid: 1,
            mapped_pids: vec![1, 2],
            timestamp: 100,
            zone: MemoryZone::PublicDurable,
        });
        assert_eq!(q.len(), 1);
        assert!(q.is_quarantined(PhysAddr(0x1000)));
        assert!(!q.is_quarantined(PhysAddr(0x2000)));
    }

    #[test]
    fn quarantine_release_removes_record() {
        let mut q = QuarantineRegistry::new();
        q.add(QuarantineRecord {
            paddr: PhysAddr(0x1000),
            expected_hash: [0; 32],
            actual_hash: [1; 32],
            owner_pid: 1,
            mapped_pids: vec![1],
            timestamp: 0,
            zone: MemoryZone::PublicEphemeral,
        });
        assert_eq!(q.len(), 1);

        let released = q.release(PhysAddr(0x1000));
        assert!(released.is_some());
        assert_eq!(q.len(), 0);
        assert!(!q.is_quarantined(PhysAddr(0x1000)));
    }

    #[test]
    fn quarantine_release_nonexistent_returns_none() {
        let mut q = QuarantineRegistry::new();
        assert!(q.release(PhysAddr(0x9000)).is_none());
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel integrity::quarantine::tests -- 2>&1 | head -20`
Expected: Compilation error — `QuarantineRegistry` not found

**Step 3: Write the implementation**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Quarantine registry — holds frames with suspected integrity violations.
//!
//! Quarantined frames are unmapped from all processes but NOT freed. A
//! privileged admin process can inspect records for forensic investigation.

use alloc::vec::Vec;

use crate::vm::{MemoryZone, PhysAddr};

/// A record of a quarantined frame.
#[derive(Debug, Clone)]
pub struct QuarantineRecord {
    /// Physical address of the quarantined frame.
    pub paddr: PhysAddr,
    /// The hash we expected the frame to have.
    pub expected_hash: [u8; 32],
    /// The hash we actually computed.
    pub actual_hash: [u8; 32],
    /// PID that originally allocated the frame.
    pub owner_pid: u32,
    /// PIDs that had this frame mapped at quarantine time.
    pub mapped_pids: Vec<u32>,
    /// Kernel timestamp when quarantine was triggered.
    pub timestamp: u64,
    /// Which memory zone the frame came from.
    pub zone: MemoryZone,
}

/// Registry of quarantined frames pending investigation.
#[derive(Debug, Default)]
pub struct QuarantineRegistry {
    records: Vec<QuarantineRecord>,
}

impl QuarantineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a frame to quarantine.
    pub fn add(&mut self, record: QuarantineRecord) {
        self.records.push(record);
    }

    /// Release a frame from quarantine, returning its record.
    pub fn release(&mut self, paddr: PhysAddr) -> Option<QuarantineRecord> {
        let pos = self.records.iter().position(|r| r.paddr == paddr)?;
        Some(self.records.swap_remove(pos))
    }

    /// Check if a frame is currently quarantined.
    pub fn is_quarantined(&self, paddr: PhysAddr) -> bool {
        self.records.iter().any(|r| r.paddr == paddr)
    }

    /// Number of quarantined frames.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Read-only access to all quarantine records.
    pub fn records(&self) -> &[QuarantineRecord] {
        &self.records
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel integrity::quarantine::tests -- -v`
Expected: All 4 pass

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/integrity/quarantine.rs
git commit -m "feat(integrity): add QuarantineRegistry for forensic frame isolation"
```

---

### Task 4: Lyll Core — Hash Registry and Config

Implement Lyll's core state: hash entries (CID-backed vs snapshot), hash registry, configuration, and basic lifecycle (register frame, unregister, lookup).

**Files:**
- Modify: `crates/harmony-microkernel/src/integrity/lyll.rs`

**Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{ContentHash, PhysAddr};

    fn test_config() -> LyllConfig {
        LyllConfig {
            sampling_rate_percent: 5,
            sweep_interval_ticks: 10,
        }
    }

    #[test]
    fn new_lyll_is_empty() {
        let lyll = Lyll::new(test_config());
        assert_eq!(lyll.registry_len(), 0);
        assert_eq!(lyll.sampled_count(), 0);
    }

    #[test]
    fn register_cid_backed_frame() {
        let mut lyll = Lyll::new(test_config());
        let hash = ContentHash([0xAA; 32]);
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: hash.0 }, 1);
        assert_eq!(lyll.registry_len(), 1);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some(hash.0));
    }

    #[test]
    fn register_snapshot_frame() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x2000),
            HashEntry::Snapshot {
                hash: [0xBB; 32],
                generation: 0,
            },
            1,
        );
        assert_eq!(lyll.registry_len(), 1);
        assert_eq!(lyll.expected_hash(PhysAddr(0x2000)), Some([0xBB; 32]));
    }

    #[test]
    fn update_snapshot_increments_generation() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::Snapshot {
                hash: [0; 32],
                generation: 0,
            },
            1,
        );
        lyll.update_snapshot(PhysAddr(0x1000), [0xFF; 32]);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some([0xFF; 32]));
    }

    #[test]
    fn update_cid_backed_is_noop() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0xAA; 32] }, 1);
        // CID-backed entries are immutable — update_snapshot should not change them.
        lyll.update_snapshot(PhysAddr(0x1000), [0xFF; 32]);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some([0xAA; 32]));
    }

    #[test]
    fn unregister_frame_removes_entry() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0; 32] }, 1);
        assert_eq!(lyll.registry_len(), 1);
        lyll.unregister_frame(PhysAddr(0x1000));
        assert_eq!(lyll.registry_len(), 0);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), None);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel integrity::lyll::tests -- 2>&1 | head -20`
Expected: Compilation error — `Lyll` not found

**Step 3: Write the implementation**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Lyll — the probabilistic memory auditor.
//!
//! Lyll spot-checks public memory frames at a configurable sampling rate.
//! For durable (content-addressed) frames, she verifies against immutable CIDs.
//! For ephemeral (writable) frames, she verifies against write-barrier snapshots.
//! She also co-verifies Nakaiah's state before every private memory operation.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::vm::{ContentHash, MemoryZone, PhysAddr, ViolationReason};

use super::quarantine::{QuarantineRecord, QuarantineRegistry};
use super::IntegrityVerdict;

/// How a frame's expected hash is determined.
#[derive(Debug, Clone)]
pub enum HashEntry {
    /// CID-derived — immutable, set at map time.
    CidBacked { cid: [u8; 32] },
    /// Snapshot — updated on every write via write barrier.
    Snapshot { hash: [u8; 32], generation: u64 },
}

impl HashEntry {
    /// Return the expected hash bytes regardless of variant.
    pub fn expected_hash(&self) -> [u8; 32] {
        match self {
            Self::CidBacked { cid } => *cid,
            Self::Snapshot { hash, .. } => *hash,
        }
    }
}

/// Configuration for Lyll's sampling behavior.
#[derive(Debug, Clone)]
pub struct LyllConfig {
    /// Percentage of public frames to sample (1-100).
    pub sampling_rate_percent: u8,
    /// Timer ticks between periodic sweeps of ephemeral frames.
    pub sweep_interval_ticks: u64,
}

/// Internal metadata for a registered frame.
#[derive(Debug, Clone)]
struct FrameRecord {
    entry: HashEntry,
    owner_pid: u32,
}

/// Lyll — the probabilistic memory auditor.
pub struct Lyll {
    /// Expected content hashes for all public frames.
    hash_registry: BTreeMap<PhysAddr, FrameRecord>,

    /// Snapshot hash of Nakaiah's state (for co-verification).
    nakaiah_state_hash: ContentHash,

    /// Frames currently marked not-present for spot-check sampling.
    sampled_frames: BTreeSet<PhysAddr>,

    /// Quarantined frames pending admin investigation.
    pub(crate) quarantine: QuarantineRegistry,

    /// Self-state hash — Nakaiah verifies this on random check-ins.
    state_hash: ContentHash,

    /// Sampling configuration.
    config: LyllConfig,

    /// Tick counter for periodic sweeps.
    tick_counter: u64,
}

impl Lyll {
    /// Create a new Lyll with the given configuration.
    pub fn new(config: LyllConfig) -> Self {
        Self {
            hash_registry: BTreeMap::new(),
            nakaiah_state_hash: ContentHash::ZERO,
            sampled_frames: BTreeSet::new(),
            quarantine: QuarantineRegistry::new(),
            state_hash: ContentHash::ZERO,
            config,
            tick_counter: 0,
        }
    }

    /// Register a public frame's expected hash.
    pub fn register_frame(&mut self, paddr: PhysAddr, entry: HashEntry, owner_pid: u32) {
        self.hash_registry
            .insert(paddr, FrameRecord { entry, owner_pid });
    }

    /// Remove a frame from the hash registry (on unmap).
    pub fn unregister_frame(&mut self, paddr: PhysAddr) {
        self.hash_registry.remove(&paddr);
        self.sampled_frames.remove(&paddr);
    }

    /// Update a snapshot entry's hash (on write completion).
    /// CID-backed entries are immutable and silently ignored.
    pub fn update_snapshot(&mut self, paddr: PhysAddr, new_hash: [u8; 32]) {
        if let Some(record) = self.hash_registry.get_mut(&paddr) {
            if let HashEntry::Snapshot {
                ref mut hash,
                ref mut generation,
            } = record.entry
            {
                *hash = new_hash;
                *generation += 1;
            }
            // CidBacked: intentionally ignored — immutable.
        }
    }

    /// Look up the expected hash for a frame.
    pub fn expected_hash(&self, paddr: PhysAddr) -> Option<[u8; 32]> {
        self.hash_registry
            .get(&paddr)
            .map(|r| r.entry.expected_hash())
    }

    /// Number of frames in the hash registry.
    pub fn registry_len(&self) -> usize {
        self.hash_registry.len()
    }

    /// Number of frames currently being sampled.
    pub fn sampled_count(&self) -> usize {
        self.sampled_frames.len()
    }

    /// Read-only access to sampled frames (for Nakaiah's behavioral checks).
    pub fn sampled_frames(&self) -> &BTreeSet<PhysAddr> {
        &self.sampled_frames
    }

    /// Lyll's current state hash (for Nakaiah to verify).
    pub fn state_hash(&self) -> ContentHash {
        self.state_hash
    }

    /// Set Lyll's state hash (recomputed after mutations).
    pub fn set_state_hash(&mut self, hash: ContentHash) {
        self.state_hash = hash;
    }

    /// Store Nakaiah's expected state hash (for co-verification).
    pub fn set_nakaiah_state_hash(&mut self, hash: ContentHash) {
        self.nakaiah_state_hash = hash;
    }

    /// Get the stored Nakaiah state hash.
    pub fn nakaiah_state_hash(&self) -> ContentHash {
        self.nakaiah_state_hash
    }

    /// Verify a frame's content integrity during a spot-check.
    ///
    /// `actual_hash` is the hash of the frame's current contents
    /// (computed by the caller who has access to frame memory).
    pub fn verify_frame(
        &mut self,
        paddr: PhysAddr,
        actual_hash: [u8; 32],
        timestamp: u64,
    ) -> IntegrityVerdict {
        let Some(record) = self.hash_registry.get(&paddr) else {
            return IntegrityVerdict::Allow; // Unknown frame — not our concern.
        };

        let expected = record.entry.expected_hash();
        if actual_hash == expected {
            return IntegrityVerdict::Allow;
        }

        // Mismatch — quarantine the frame.
        self.quarantine.add(QuarantineRecord {
            paddr,
            expected_hash: expected,
            actual_hash,
            owner_pid: record.owner_pid,
            mapped_pids: Vec::new(), // Caller fills in from cap_tracker.
            timestamp,
            zone: MemoryZone::PublicDurable, // Caller can override.
        });

        IntegrityVerdict::Quarantine {
            paddr,
            reason: ViolationReason::ContentTampered,
        }
    }

    /// Co-verify Nakaiah's state before a private memory operation.
    ///
    /// Returns `Panic` if Nakaiah's state hash doesn't match what Lyll
    /// expects, indicating Nakaiah has been compromised.
    pub fn co_verify_nakaiah(&self, nakaiah_current_hash: ContentHash) -> IntegrityVerdict {
        if nakaiah_current_hash == self.nakaiah_state_hash {
            IntegrityVerdict::Allow
        } else {
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted,
            }
        }
    }

    /// Add a frame to the spot-check sample set.
    pub fn add_sample(&mut self, paddr: PhysAddr) {
        self.sampled_frames.insert(paddr);
    }

    /// Remove a frame from the spot-check sample set.
    pub fn remove_sample(&mut self, paddr: PhysAddr) {
        self.sampled_frames.remove(&paddr);
    }

    /// Access the sampling config.
    pub fn config(&self) -> &LyllConfig {
        &self.config
    }

    /// Increment tick counter and return whether a sweep is due.
    pub fn tick(&mut self) -> bool {
        self.tick_counter += 1;
        self.tick_counter % self.config.sweep_interval_ticks == 0
    }

    /// Access all registered frame addresses (for sampling rotation).
    pub fn all_registered_frames(&self) -> Vec<PhysAddr> {
        self.hash_registry.keys().copied().collect()
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel integrity::lyll::tests -- -v`
Expected: All 6 pass

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/integrity/lyll.rs
git commit -m "feat(integrity): add Lyll core — hash registry, config, frame lifecycle"
```

---

### Task 5: Lyll Spot-Check and Co-Verification Tests

Add tests for Lyll's spot-check verification, co-verification of Nakaiah, quarantine integration, and timer-driven sweep logic.

**Files:**
- Modify: `crates/harmony-microkernel/src/integrity/lyll.rs` (add tests to existing `mod tests`)

**Step 1: Write the tests**

Add to the `mod tests` block in `lyll.rs`:

```rust
#[test]
fn verify_frame_matching_hash_allows() {
    let mut lyll = Lyll::new(test_config());
    let hash = [0xAA; 32];
    lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: hash }, 1);

    let verdict = lyll.verify_frame(PhysAddr(0x1000), hash, 0);
    assert_eq!(verdict, IntegrityVerdict::Allow);
}

#[test]
fn verify_frame_mismatched_hash_quarantines() {
    let mut lyll = Lyll::new(test_config());
    lyll.register_frame(
        PhysAddr(0x1000),
        HashEntry::CidBacked { cid: [0xAA; 32] },
        1,
    );

    let verdict = lyll.verify_frame(PhysAddr(0x1000), [0xBB; 32], 42);
    assert!(matches!(
        verdict,
        IntegrityVerdict::Quarantine {
            reason: ViolationReason::ContentTampered,
            ..
        }
    ));
    assert!(lyll.quarantine.is_quarantined(PhysAddr(0x1000)));
    assert_eq!(lyll.quarantine.records()[0].timestamp, 42);
}

#[test]
fn verify_unknown_frame_allows() {
    let mut lyll = Lyll::new(test_config());
    let verdict = lyll.verify_frame(PhysAddr(0x9999), [0; 32], 0);
    assert_eq!(verdict, IntegrityVerdict::Allow);
}

#[test]
fn co_verify_nakaiah_matching_allows() {
    let mut lyll = Lyll::new(test_config());
    let hash = ContentHash([0xCC; 32]);
    lyll.set_nakaiah_state_hash(hash);
    assert_eq!(lyll.co_verify_nakaiah(hash), IntegrityVerdict::Allow);
}

#[test]
fn co_verify_nakaiah_mismatched_panics() {
    let mut lyll = Lyll::new(test_config());
    lyll.set_nakaiah_state_hash(ContentHash([0xCC; 32]));
    let verdict = lyll.co_verify_nakaiah(ContentHash([0xDD; 32]));
    assert!(matches!(
        verdict,
        IntegrityVerdict::Panic {
            reason: ViolationReason::GuardianStateCorrupted
        }
    ));
}

#[test]
fn sampling_add_and_remove() {
    let mut lyll = Lyll::new(test_config());
    lyll.add_sample(PhysAddr(0x1000));
    lyll.add_sample(PhysAddr(0x2000));
    assert_eq!(lyll.sampled_count(), 2);
    assert!(lyll.sampled_frames().contains(&PhysAddr(0x1000)));

    lyll.remove_sample(PhysAddr(0x1000));
    assert_eq!(lyll.sampled_count(), 1);
    assert!(!lyll.sampled_frames().contains(&PhysAddr(0x1000)));
}

#[test]
fn tick_triggers_sweep_at_interval() {
    let mut lyll = Lyll::new(LyllConfig {
        sampling_rate_percent: 5,
        sweep_interval_ticks: 3,
    });
    assert!(!lyll.tick()); // tick 1
    assert!(!lyll.tick()); // tick 2
    assert!(lyll.tick());  // tick 3 — sweep due
    assert!(!lyll.tick()); // tick 4
    assert!(!lyll.tick()); // tick 5
    assert!(lyll.tick());  // tick 6 — sweep due again
}

#[test]
fn unregister_also_removes_from_samples() {
    let mut lyll = Lyll::new(test_config());
    lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0; 32] }, 1);
    lyll.add_sample(PhysAddr(0x1000));
    assert_eq!(lyll.sampled_count(), 1);

    lyll.unregister_frame(PhysAddr(0x1000));
    assert_eq!(lyll.sampled_count(), 0);
    assert_eq!(lyll.registry_len(), 0);
}

#[test]
fn config_accessible() {
    let lyll = Lyll::new(test_config());
    assert_eq!(lyll.config().sampling_rate_percent, 5);
    assert_eq!(lyll.config().sweep_interval_ticks, 10);
}

#[test]
fn all_registered_frames_returns_all_addrs() {
    let mut lyll = Lyll::new(test_config());
    lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0; 32] }, 1);
    lyll.register_frame(PhysAddr(0x2000), HashEntry::CidBacked { cid: [1; 32] }, 2);
    let all = lyll.all_registered_frames();
    assert_eq!(all.len(), 2);
    assert!(all.contains(&PhysAddr(0x1000)));
    assert!(all.contains(&PhysAddr(0x2000)));
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel integrity::lyll::tests -- -v`
Expected: All 17 tests pass (6 from Task 4 + 11 new)

**Step 3: Commit**

```bash
git add crates/harmony-microkernel/src/integrity/lyll.rs
git commit -m "test(integrity): add Lyll spot-check, co-verification, and sweep tests"
```

---

### Task 6: Nakaiah Core — Integrity Registry, Capability Chains, Access Log

Implement Nakaiah's core state: per-frame integrity hashes, capability chain validation, and hash-chained access log.

**Files:**
- Modify: `crates/harmony-microkernel/src/integrity/nakaiah.rs`

**Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{AccessOp, ContentHash, PhysAddr};

    fn test_nakaiah() -> Nakaiah {
        Nakaiah::new(0.01) // 1% check-in rate
    }

    #[test]
    fn new_nakaiah_is_empty() {
        let n = test_nakaiah();
        assert_eq!(n.integrity_registry_len(), 0);
        assert_eq!(n.access_log_len(), 0);
    }

    #[test]
    fn register_and_lookup_frame() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
        assert_eq!(n.integrity_registry_len(), 1);
        assert_eq!(n.expected_hash(PhysAddr(0x1000)), Some([0xAA; 32]));
    }

    #[test]
    fn unregister_frame_removes() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
        n.unregister_frame(PhysAddr(0x1000));
        assert_eq!(n.integrity_registry_len(), 0);
    }

    #[test]
    fn grant_and_check_capability() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0; 32]);
        n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);
        assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
        assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Write));
    }

    #[test]
    fn no_capability_denies_access() {
        let n = test_nakaiah();
        assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
    }

    #[test]
    fn read_only_capability_denies_write() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0; 32]);
        n.grant_access(1, PhysAddr(0x1000), CapChain::ReadOnly { granted_by: 0 });
        assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
        assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Write));
        assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Execute));
    }

    #[test]
    fn revoke_access_removes_capability() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0; 32]);
        n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);
        assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Read));

        n.revoke_access(1, PhysAddr(0x1000));
        assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
    }

    #[test]
    fn access_log_appends_and_chains() {
        let mut n = test_nakaiah();
        n.append_receipt(AccessReceipt {
            pid: 1,
            paddr: PhysAddr(0x1000),
            operation: AccessOp::Read,
            timestamp: 100,
        });
        assert_eq!(n.access_log_len(), 1);

        n.append_receipt(AccessReceipt {
            pid: 2,
            paddr: PhysAddr(0x2000),
            operation: AccessOp::Write,
            timestamp: 200,
        });
        assert_eq!(n.access_log_len(), 2);

        // Each entry's prev_hash chains to the previous entry.
        let log = n.access_log();
        assert_eq!(log[0].prev_hash, [0u8; 32]); // First entry has zero prev.
        assert_ne!(log[1].prev_hash, [0u8; 32]); // Second chains to first.
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel integrity::nakaiah::tests -- 2>&1 | head -20`
Expected: Compilation error — `Nakaiah` not found

**Step 3: Write the implementation**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Nakaiah — the deterministic memory bodyguard.
//!
//! Nakaiah verifies every single access to encrypted (kernel-space) memory:
//! content integrity (hash check) and authorization (capability chain).
//! She maintains a hash-chained access log for accountability and
//! randomly checks in on Lyll to verify Lyll's behavior.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::vm::{AccessOp, ContentHash, PhysAddr, ViolationReason};

use super::IntegrityVerdict;

/// A capability chain authorizing access to a private frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapChain {
    /// Frame owner — full access (read, write, execute).
    Owner,
    /// Read-only delegation from another process.
    ReadOnly { granted_by: u32 },
    /// Read-write delegation from another process.
    ReadWrite { granted_by: u32 },
}

impl CapChain {
    /// Check if this capability chain permits the given operation.
    pub fn permits(&self, op: AccessOp) -> bool {
        match self {
            Self::Owner => true,
            Self::ReadOnly { .. } => matches!(op, AccessOp::Read),
            Self::ReadWrite { .. } => matches!(op, AccessOp::Read | AccessOp::Write),
        }
    }
}

/// A single entry in Nakaiah's append-only access log.
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
    pub receipt: AccessReceipt,
    /// Hash of the previous log entry (hash chain).
    pub prev_hash: [u8; 32],
}

/// Receipt of a single access to a private frame.
#[derive(Debug, Clone)]
pub struct AccessReceipt {
    pub pid: u32,
    pub paddr: PhysAddr,
    pub operation: AccessOp,
    pub timestamp: u64,
}

/// Nakaiah — the deterministic memory bodyguard.
pub struct Nakaiah {
    /// Content integrity hashes for every encrypted frame.
    integrity_registry: BTreeMap<PhysAddr, [u8; 32]>,

    /// Capability chains: (pid, paddr) → delegation chain authorizing access.
    capability_chains: BTreeMap<(u32, PhysAddr), CapChain>,

    /// Append-only access log with hash chaining.
    access_log: Vec<AccessLogEntry>,

    /// Self-state hash — Lyll verifies this before every private operation.
    state_hash: ContentHash,

    /// Snapshot of Lyll's expected state hash (for random check-ins).
    lyll_state_hash: ContentHash,

    /// Check-in probability (e.g., 0.01 = 1% of operations).
    lyll_checkin_rate: f32,
}

impl Nakaiah {
    /// Create a new Nakaiah with the given Lyll check-in rate.
    pub fn new(lyll_checkin_rate: f32) -> Self {
        Self {
            integrity_registry: BTreeMap::new(),
            capability_chains: BTreeMap::new(),
            access_log: Vec::new(),
            state_hash: ContentHash::ZERO,
            lyll_state_hash: ContentHash::ZERO,
            lyll_checkin_rate,
        }
    }

    /// Register an encrypted frame's content hash.
    pub fn register_frame(&mut self, paddr: PhysAddr, content_hash: [u8; 32]) {
        self.integrity_registry.insert(paddr, content_hash);
    }

    /// Remove a frame from the integrity registry.
    pub fn unregister_frame(&mut self, paddr: PhysAddr) {
        self.integrity_registry.remove(&paddr);
        // Also revoke all access to this frame.
        self.capability_chains.retain(|&(_, p), _| p != paddr);
    }

    /// Update a frame's stored hash (after an authorized write).
    pub fn update_hash(&mut self, paddr: PhysAddr, new_hash: [u8; 32]) {
        if let Some(stored) = self.integrity_registry.get_mut(&paddr) {
            *stored = new_hash;
        }
    }

    /// Look up the expected hash for a frame.
    pub fn expected_hash(&self, paddr: PhysAddr) -> Option<[u8; 32]> {
        self.integrity_registry.get(&paddr).copied()
    }

    /// Number of frames in the integrity registry.
    pub fn integrity_registry_len(&self) -> usize {
        self.integrity_registry.len()
    }

    /// Grant a process access to a private frame.
    pub fn grant_access(&mut self, pid: u32, paddr: PhysAddr, chain: CapChain) {
        self.capability_chains.insert((pid, paddr), chain);
    }

    /// Revoke a process's access to a private frame.
    pub fn revoke_access(&mut self, pid: u32, paddr: PhysAddr) {
        self.capability_chains.remove(&(pid, paddr));
    }

    /// Check if a process has the right capability for an operation.
    pub fn has_access(&self, pid: u32, paddr: PhysAddr, op: AccessOp) -> bool {
        self.capability_chains
            .get(&(pid, paddr))
            .is_some_and(|chain| chain.permits(op))
    }

    /// Verify a frame access: content integrity + authorization.
    ///
    /// `actual_hash` is the hash of the frame's current contents.
    pub fn verify_access(
        &self,
        pid: u32,
        paddr: PhysAddr,
        op: AccessOp,
        actual_hash: [u8; 32],
    ) -> IntegrityVerdict {
        // 1. Content integrity check.
        if let Some(&expected) = self.integrity_registry.get(&paddr) {
            if actual_hash != expected {
                return IntegrityVerdict::Kill {
                    pid,
                    reason: ViolationReason::ContentTampered,
                };
            }
        }

        // 2. Authorization check.
        if !self.has_access(pid, paddr, op) {
            return IntegrityVerdict::Kill {
                pid,
                reason: ViolationReason::UnauthorizedAccess,
            };
        }

        IntegrityVerdict::Allow
    }

    /// Append a receipt to the hash-chained access log.
    pub fn append_receipt(&mut self, receipt: AccessReceipt) {
        let prev_hash = self
            .access_log
            .last()
            .map(|entry| simple_hash_entry(entry))
            .unwrap_or([0u8; 32]);

        self.access_log.push(AccessLogEntry {
            receipt,
            prev_hash,
        });
    }

    /// Number of entries in the access log.
    pub fn access_log_len(&self) -> usize {
        self.access_log.len()
    }

    /// Read-only access to the access log.
    pub fn access_log(&self) -> &[AccessLogEntry] {
        &self.access_log
    }

    /// Nakaiah's current state hash (for Lyll to verify).
    pub fn state_hash(&self) -> ContentHash {
        self.state_hash
    }

    /// Set Nakaiah's state hash (recomputed after mutations).
    pub fn set_state_hash(&mut self, hash: ContentHash) {
        self.state_hash = hash;
    }

    /// Store Lyll's expected state hash (for random check-ins).
    pub fn set_lyll_state_hash(&mut self, hash: ContentHash) {
        self.lyll_state_hash = hash;
    }

    /// Get the stored Lyll state hash.
    pub fn lyll_state_hash(&self) -> ContentHash {
        self.lyll_state_hash
    }

    /// Check-in on Lyll: verify her state hash matches expectations.
    pub fn check_in_on_lyll(&self, lyll_current_hash: ContentHash) -> IntegrityVerdict {
        if lyll_current_hash == self.lyll_state_hash {
            IntegrityVerdict::Allow
        } else {
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted,
            }
        }
    }

    /// Get Lyll check-in rate.
    pub fn lyll_checkin_rate(&self) -> f32 {
        self.lyll_checkin_rate
    }
}

/// Simple deterministic hash of a log entry for chaining.
/// Uses XOR folding — lightweight but sufficient for integrity chaining.
/// Production would use BLAKE3.
fn simple_hash_entry(entry: &AccessLogEntry) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let pid_bytes = entry.receipt.pid.to_le_bytes();
    let addr_bytes = entry.receipt.paddr.as_u64().to_le_bytes();
    let ts_bytes = entry.receipt.timestamp.to_le_bytes();

    // Mix in pid, address, timestamp, prev_hash.
    for (i, &b) in pid_bytes.iter().enumerate() {
        hash[i] ^= b;
    }
    for (i, &b) in addr_bytes.iter().enumerate() {
        hash[4 + i] ^= b;
    }
    for (i, &b) in ts_bytes.iter().enumerate() {
        hash[12 + i] ^= b;
    }
    for (i, &b) in entry.prev_hash.iter().enumerate() {
        hash[i] ^= b;
    }

    hash
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel integrity::nakaiah::tests -- -v`
Expected: All 9 pass

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/integrity/nakaiah.rs
git commit -m "feat(integrity): add Nakaiah core — integrity registry, capability chains, access log"
```

---

### Task 7: Nakaiah Verification and Check-In Tests

Add tests for Nakaiah's per-access verification (content + authorization), check-in on Lyll, and edge cases.

**Files:**
- Modify: `crates/harmony-microkernel/src/integrity/nakaiah.rs` (add tests to existing `mod tests`)

**Step 1: Write the tests**

Add to the `mod tests` block in `nakaiah.rs`:

```rust
#[test]
fn verify_access_valid_allows() {
    let mut n = test_nakaiah();
    let hash = [0xAA; 32];
    n.register_frame(PhysAddr(0x1000), hash);
    n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);

    let verdict = n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, hash);
    assert_eq!(verdict, IntegrityVerdict::Allow);
}

#[test]
fn verify_access_tampered_content_kills() {
    let mut n = test_nakaiah();
    n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
    n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);

    let verdict = n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, [0xBB; 32]);
    assert!(matches!(
        verdict,
        IntegrityVerdict::Kill {
            pid: 1,
            reason: ViolationReason::ContentTampered,
        }
    ));
}

#[test]
fn verify_access_unauthorized_kills() {
    let mut n = test_nakaiah();
    n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
    // No capability granted to pid 1.

    let verdict = n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, [0xAA; 32]);
    assert!(matches!(
        verdict,
        IntegrityVerdict::Kill {
            pid: 1,
            reason: ViolationReason::UnauthorizedAccess,
        }
    ));
}

#[test]
fn verify_access_read_only_write_kills() {
    let mut n = test_nakaiah();
    let hash = [0xAA; 32];
    n.register_frame(PhysAddr(0x1000), hash);
    n.grant_access(1, PhysAddr(0x1000), CapChain::ReadOnly { granted_by: 0 });

    // Read — allowed.
    assert_eq!(
        n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, hash),
        IntegrityVerdict::Allow,
    );
    // Write — denied.
    assert!(matches!(
        n.verify_access(1, PhysAddr(0x1000), AccessOp::Write, hash),
        IntegrityVerdict::Kill {
            reason: ViolationReason::UnauthorizedAccess,
            ..
        }
    ));
}

#[test]
fn verify_access_read_write_cap() {
    let mut n = test_nakaiah();
    let hash = [0; 32];
    n.register_frame(PhysAddr(0x1000), hash);
    n.grant_access(1, PhysAddr(0x1000), CapChain::ReadWrite { granted_by: 0 });

    assert_eq!(
        n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, hash),
        IntegrityVerdict::Allow,
    );
    assert_eq!(
        n.verify_access(1, PhysAddr(0x1000), AccessOp::Write, hash),
        IntegrityVerdict::Allow,
    );
    assert!(matches!(
        n.verify_access(1, PhysAddr(0x1000), AccessOp::Execute, hash),
        IntegrityVerdict::Kill { .. }
    ));
}

#[test]
fn update_hash_changes_expected() {
    let mut n = test_nakaiah();
    n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
    n.update_hash(PhysAddr(0x1000), [0xBB; 32]);
    assert_eq!(n.expected_hash(PhysAddr(0x1000)), Some([0xBB; 32]));
}

#[test]
fn check_in_on_lyll_matching_allows() {
    let mut n = test_nakaiah();
    let hash = ContentHash([0xCC; 32]);
    n.set_lyll_state_hash(hash);
    assert_eq!(n.check_in_on_lyll(hash), IntegrityVerdict::Allow);
}

#[test]
fn check_in_on_lyll_mismatched_panics() {
    let mut n = test_nakaiah();
    n.set_lyll_state_hash(ContentHash([0xCC; 32]));
    let verdict = n.check_in_on_lyll(ContentHash([0xDD; 32]));
    assert!(matches!(
        verdict,
        IntegrityVerdict::Panic {
            reason: ViolationReason::GuardianStateCorrupted
        }
    ));
}

#[test]
fn unregister_frame_also_revokes_access() {
    let mut n = test_nakaiah();
    n.register_frame(PhysAddr(0x1000), [0; 32]);
    n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);
    n.grant_access(2, PhysAddr(0x1000), CapChain::ReadOnly { granted_by: 1 });
    assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
    assert!(n.has_access(2, PhysAddr(0x1000), AccessOp::Read));

    n.unregister_frame(PhysAddr(0x1000));
    assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
    assert!(!n.has_access(2, PhysAddr(0x1000), AccessOp::Read));
}

#[test]
fn access_log_hash_chain_integrity() {
    let mut n = test_nakaiah();
    for i in 0..5 {
        n.append_receipt(AccessReceipt {
            pid: 1,
            paddr: PhysAddr(0x1000),
            operation: AccessOp::Read,
            timestamp: i * 100,
        });
    }
    assert_eq!(n.access_log_len(), 5);

    // Verify the chain: each entry's prev_hash should be non-zero
    // (except the first).
    let log = n.access_log();
    assert_eq!(log[0].prev_hash, [0; 32]);
    for i in 1..5 {
        assert_ne!(log[i].prev_hash, [0; 32]);
    }
}

#[test]
fn state_hash_roundtrip() {
    let mut n = test_nakaiah();
    let hash = ContentHash([0xFF; 32]);
    n.set_state_hash(hash);
    assert_eq!(n.state_hash(), hash);
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel integrity::nakaiah::tests -- -v`
Expected: All 21 pass (9 from Task 6 + 12 new)

**Step 3: Commit**

```bash
git add crates/harmony-microkernel/src/integrity/nakaiah.rs
git commit -m "test(integrity): add Nakaiah verification, check-in, and edge case tests"
```

---

### Task 8: Bidirectional Mutual Verification Tests

Add integration-style tests that exercise the full Lyll ↔ Nakaiah mutual verification protocol: Lyll co-verifies Nakaiah before private ops, Nakaiah checks in on Lyll randomly, and both detect compromise.

**Files:**
- Modify: `crates/harmony-microkernel/src/integrity/mod.rs` (add integration tests)

**Step 1: Write the tests**

Add to `integrity/mod.rs`, inside the existing `#[cfg(test)] mod tests` block (expand it):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{ContentHash, FrameClassification, PhysAddr};

    // ... existing event/verdict tests from Task 2 ...

    use super::lyll::{HashEntry, Lyll, LyllConfig};
    use super::nakaiah::{AccessReceipt, CapChain, Nakaiah};

    fn test_lyll() -> Lyll {
        Lyll::new(LyllConfig {
            sampling_rate_percent: 5,
            sweep_interval_ticks: 10,
        })
    }

    fn test_nakaiah() -> Nakaiah {
        Nakaiah::new(0.01)
    }

    #[test]
    fn full_private_access_cycle() {
        let mut lyll = test_lyll();
        let mut nakaiah = test_nakaiah();

        // Setup: register encrypted frame in both guardians.
        let paddr = PhysAddr(0x1000);
        let hash = [0xAA; 32];
        lyll.register_frame(paddr, HashEntry::CidBacked { cid: hash }, 1);
        nakaiah.register_frame(paddr, hash);
        nakaiah.grant_access(1, paddr, CapChain::Owner);

        // Exchange state hashes.
        lyll.set_nakaiah_state_hash(nakaiah.state_hash());
        nakaiah.set_lyll_state_hash(lyll.state_hash());

        // Step 1: Lyll co-verifies Nakaiah.
        let verdict = lyll.co_verify_nakaiah(nakaiah.state_hash());
        assert_eq!(verdict, IntegrityVerdict::Allow);

        // Step 2: Nakaiah verifies the access.
        let verdict = nakaiah.verify_access(1, paddr, crate::vm::AccessOp::Read, hash);
        assert_eq!(verdict, IntegrityVerdict::Allow);
    }

    #[test]
    fn compromised_nakaiah_detected_by_lyll() {
        let mut lyll = test_lyll();
        let mut nakaiah = test_nakaiah();

        // Exchange state hashes.
        lyll.set_nakaiah_state_hash(nakaiah.state_hash());

        // Simulate Nakaiah compromise: state hash changes unexpectedly.
        nakaiah.set_state_hash(ContentHash([0xFF; 32]));

        // Lyll detects the mismatch.
        let verdict = lyll.co_verify_nakaiah(nakaiah.state_hash());
        assert!(matches!(
            verdict,
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted
            }
        ));
    }

    #[test]
    fn compromised_lyll_detected_by_nakaiah() {
        let mut lyll = test_lyll();
        let mut nakaiah = test_nakaiah();

        // Exchange state hashes.
        nakaiah.set_lyll_state_hash(lyll.state_hash());

        // Simulate Lyll compromise: state hash changes unexpectedly.
        lyll.set_state_hash(ContentHash([0xFF; 32]));

        // Nakaiah detects the mismatch.
        let verdict = nakaiah.check_in_on_lyll(lyll.state_hash());
        assert!(matches!(
            verdict,
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted
            }
        ));
    }

    #[test]
    fn mutual_state_update_cycle() {
        let mut lyll = test_lyll();
        let mut nakaiah = test_nakaiah();

        // Initial exchange.
        lyll.set_nakaiah_state_hash(nakaiah.state_hash());
        nakaiah.set_lyll_state_hash(lyll.state_hash());

        // Simulate mutations: both update their own state hashes.
        let new_lyll_hash = ContentHash([0x11; 32]);
        let new_nakaiah_hash = ContentHash([0x22; 32]);
        lyll.set_state_hash(new_lyll_hash);
        nakaiah.set_state_hash(new_nakaiah_hash);

        // Re-exchange snapshots.
        lyll.set_nakaiah_state_hash(nakaiah.state_hash());
        nakaiah.set_lyll_state_hash(lyll.state_hash());

        // Both should pass verification.
        assert_eq!(
            lyll.co_verify_nakaiah(nakaiah.state_hash()),
            IntegrityVerdict::Allow,
        );
        assert_eq!(
            nakaiah.check_in_on_lyll(lyll.state_hash()),
            IntegrityVerdict::Allow,
        );
    }

    #[test]
    fn lyll_not_actually_sampling_detected() {
        let mut lyll = test_lyll();

        // Lyll claims to be sampling but her sampled_frames is empty
        // while she has registered frames.
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0; 32] }, 1);
        lyll.register_frame(PhysAddr(0x2000), HashEntry::CidBacked { cid: [1; 32] }, 1);

        // Behavioral check: Nakaiah picks a random registered frame and
        // checks if it's in the sample set. With 5% sampling and 2 frames,
        // an empty sample set is suspicious.
        let registered = lyll.all_registered_frames();
        let has_any_samples = registered
            .iter()
            .any(|p| lyll.sampled_frames().contains(p));

        // Lyll has NOT added any samples — behavioral mismatch.
        assert!(!has_any_samples, "Lyll should have no samples (not doing her job)");
    }

    #[test]
    fn quarantine_record_forensics() {
        let mut lyll = test_lyll();
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0xAA; 32] }, 42);

        // Tampered frame detected.
        let verdict = lyll.verify_frame(PhysAddr(0x1000), [0xBB; 32], 999);
        assert!(matches!(verdict, IntegrityVerdict::Quarantine { .. }));

        // Forensic record has full details.
        let records = lyll.quarantine.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].paddr, PhysAddr(0x1000));
        assert_eq!(records[0].expected_hash, [0xAA; 32]);
        assert_eq!(records[0].actual_hash, [0xBB; 32]);
        assert_eq!(records[0].owner_pid, 42);
        assert_eq!(records[0].timestamp, 999);
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel integrity::tests -- -v`
Expected: All pass (2 from Task 2 + 7 new)

**Step 3: Commit**

```bash
git add crates/harmony-microkernel/src/integrity/mod.rs
git commit -m "test(integrity): add bidirectional mutual verification integration tests"
```

---

### Task 9: Dual Buddy Allocator in AddressSpaceManager

Split the single `BuddyAllocator` into `buddy_public` and `buddy_kernel` to enforce the hard physical partition between public (75%) and kernel (25%) memory.

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/manager.rs`

**Step 1: Write the failing tests**

Add to the existing `mod tests` block in `manager.rs`:

```rust
#[test]
fn dual_partition_allocation() {
    // 16 frames total: 12 public + 4 kernel.
    let buddy_public = BuddyAllocator::new(PhysAddr(0x10_0000), 12).unwrap();
    let buddy_kernel = BuddyAllocator::new(PhysAddr(0x20_0000), 4).unwrap();
    let mut mgr = AddressSpaceManager::new_dual(buddy_public, buddy_kernel);
    mgr.create_space(1, default_budget(), mock_pt()).unwrap();

    // Public allocation should come from buddy_public.
    mgr.map_region(
        1,
        VirtAddr(0x1000),
        PAGE_SIZE as usize * 2,
        rw_user_flags(),
        FrameClassification::empty(),
    )
    .unwrap();
    assert_eq!(mgr.buddy_public().free_frame_count(), 10);
    assert_eq!(mgr.buddy_kernel().free_frame_count(), 4);

    // Encrypted allocation should come from buddy_kernel.
    mgr.map_region(
        1,
        VirtAddr(0x5000),
        PAGE_SIZE as usize,
        rw_user_flags(),
        FrameClassification::ENCRYPTED,
    )
    .unwrap();
    assert_eq!(mgr.buddy_public().free_frame_count(), 10);
    assert_eq!(mgr.buddy_kernel().free_frame_count(), 3);
}

#[test]
fn kernel_oom_does_not_affect_public() {
    let buddy_public = BuddyAllocator::new(PhysAddr(0x10_0000), 8).unwrap();
    let buddy_kernel = BuddyAllocator::new(PhysAddr(0x20_0000), 1).unwrap();
    let mut mgr = AddressSpaceManager::new_dual(buddy_public, buddy_kernel);
    mgr.create_space(1, default_budget(), mock_pt()).unwrap();

    // Exhaust kernel buddy.
    mgr.map_region(
        1,
        VirtAddr(0x1000),
        PAGE_SIZE as usize,
        rw_user_flags(),
        FrameClassification::ENCRYPTED,
    )
    .unwrap();

    // Second encrypted allocation fails.
    let err = mgr
        .map_region(
            1,
            VirtAddr(0x5000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap_err();
    assert_eq!(err, VmError::OutOfMemory);

    // Public allocation still works.
    mgr.map_region(
        1,
        VirtAddr(0xA000),
        PAGE_SIZE as usize,
        rw_user_flags(),
        FrameClassification::empty(),
    )
    .unwrap();
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel vm::manager::tests::dual_partition -- 2>&1 | head -20`
Expected: Compilation error — `new_dual` and `buddy_kernel` not found

**Step 3: Modify AddressSpaceManager**

Change `AddressSpaceManager` to have dual allocators:

```rust
pub struct AddressSpaceManager<P: PageTable> {
    spaces: BTreeMap<u32, ProcessSpace<P>>,
    buddy_public: BuddyAllocator,
    buddy_kernel: BuddyAllocator,
    cap_tracker: CapTracker,
}
```

Add `new_dual` constructor, rename `new` to use a single buddy for both (backward compat):

```rust
/// Create with a single buddy for both public and kernel (backward compat).
pub fn new(buddy: BuddyAllocator) -> Self {
    // Create a minimal 1-frame kernel buddy as placeholder.
    // Existing code that uses `new()` doesn't use encrypted frames.
    let kernel_base = PhysAddr(buddy.base_addr().as_u64() + buddy.total_bytes());
    // Use a zero-frame kernel buddy — encrypted allocations will return OOM.
    Self {
        spaces: BTreeMap::new(),
        buddy_public: buddy,
        buddy_kernel: BuddyAllocator::empty(),
        cap_tracker: CapTracker::new(),
    }
}

/// Create with separate public and kernel buddy allocators.
pub fn new_dual(buddy_public: BuddyAllocator, buddy_kernel: BuddyAllocator) -> Self {
    Self {
        spaces: BTreeMap::new(),
        buddy_public,
        buddy_kernel,
        cap_tracker: CapTracker::new(),
    }
}
```

Add `BuddyAllocator::empty()` — a zero-frame allocator (returns `None` for all alloc calls). Add this to `buddy.rs`:

```rust
/// Create an empty allocator with zero frames. All allocations return `None`.
pub fn empty() -> Self {
    Self {
        base: PhysAddr(0),
        total_frames: 0,
        max_order: 0,
        free_lists: Vec::new(),
        allocated: BTreeSet::new(),
    }
}
```

Update all methods that reference `self.buddy` to use `self.buddy_for(classification)`:

```rust
/// Select the correct buddy allocator based on frame classification.
fn buddy_for(&mut self, class: FrameClassification) -> &mut BuddyAllocator {
    if class.contains(FrameClassification::ENCRYPTED) {
        &mut self.buddy_kernel
    } else {
        &mut self.buddy_public
    }
}
```

Update `map_region` to use `self.buddy_for(classification)` for frame allocation. Update `unmap_region` and `destroy_space` to determine which buddy to free to (check the region's classification). Update the split-borrow pattern accordingly.

Update accessor methods:

```rust
pub fn buddy_public(&mut self) -> &mut BuddyAllocator {
    &mut self.buddy_public
}

pub fn buddy_kernel(&mut self) -> &mut BuddyAllocator {
    &mut self.buddy_kernel
}

/// Backward-compat: returns the public buddy.
pub fn buddy(&mut self) -> &mut BuddyAllocator {
    &mut self.buddy_public
}
```

**IMPORTANT: The split-borrow pattern for `map_region` changes.** The `frame_alloc` closure for intermediate page table frames should always use `buddy_public` (intermediate tables are structural, not encrypted data). Update the destructuring:

```rust
let Self {
    spaces,
    buddy_public,
    ..
} = self;
// ... use buddy_public for intermediate frames
```

For data frames, select buddy based on classification BEFORE the split-borrow block.

**Step 4: Run ALL tests to verify nothing broke**

Run: `cargo test --workspace`
Expected: All existing tests still pass (they use `new()` which maps to public buddy), plus 2 new tests pass

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/vm/manager.rs crates/harmony-microkernel/src/vm/buddy.rs
git commit -m "feat(vm): add dual buddy allocator — public/kernel physical partition"
```

---

### Task 10: Zone-Aware Soft Budgets in CapTracker

Extend `CapTracker` to track per-zone usage within each process's budget, enabling sub-zone limits (e.g., a process can use up to X bytes of durable memory and Y bytes of ephemeral).

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/cap_tracker.rs`

**Step 1: Write the failing tests**

Add to the existing `mod tests` block:

```rust
#[test]
fn zone_budget_tracking() {
    let mut tracker = CapTracker::new();
    tracker.set_budget(
        1,
        MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::all()),
    );

    // Map some frames in different zones.
    tracker.record_mapping(paddr(0), 1, FrameClassification::empty()); // public durable
    tracker.record_mapping(paddr(1), 1, FrameClassification::EPHEMERAL); // public ephemeral
    tracker.record_mapping(paddr(2), 1, FrameClassification::ENCRYPTED); // kernel durable

    let budget = tracker.budget(1).unwrap();
    assert_eq!(budget.used, 3 * PAGE_SIZE as usize);
    assert_eq!(budget.zone_used(MemoryZone::PublicDurable), PAGE_SIZE as usize);
    assert_eq!(budget.zone_used(MemoryZone::PublicEphemeral), PAGE_SIZE as usize);
    assert_eq!(budget.zone_used(MemoryZone::KernelDurable), PAGE_SIZE as usize);
    assert_eq!(budget.zone_used(MemoryZone::KernelEphemeral), 0);
}

#[test]
fn zone_usage_decreases_on_unmap() {
    let mut tracker = CapTracker::new();
    tracker.set_budget(
        1,
        MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::all()),
    );

    tracker.record_mapping(paddr(0), 1, FrameClassification::ENCRYPTED);
    assert_eq!(
        tracker.budget(1).unwrap().zone_used(MemoryZone::KernelDurable),
        PAGE_SIZE as usize,
    );

    tracker.remove_mapping(paddr(0), 1);
    assert_eq!(
        tracker.budget(1).unwrap().zone_used(MemoryZone::KernelDurable),
        0,
    );
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel vm::cap_tracker::tests::zone_budget -- 2>&1 | head -20`
Expected: Compilation error — `zone_used` not found

**Step 3: Modify MemoryBudget**

Add zone tracking to `MemoryBudget`:

```rust
use super::MemoryZone;

#[derive(Debug, Clone)]
pub struct MemoryBudget {
    pub limit: usize,
    pub used: usize,
    pub allowed_classes: FrameClassification,
    /// Per-zone usage tracking.
    zone_usage: [usize; 4], // Indexed by MemoryZone ordinal.
}
```

Add `zone_used` method and update `record_mapping`/`remove_mapping` to track zone usage:

```rust
impl MemoryBudget {
    pub fn zone_used(&self, zone: MemoryZone) -> usize {
        self.zone_usage[zone as usize]
    }

    pub(crate) fn add_zone_usage(&mut self, zone: MemoryZone, bytes: usize) {
        self.zone_usage[zone as usize] += bytes;
    }

    pub(crate) fn sub_zone_usage(&mut self, zone: MemoryZone, bytes: usize) {
        self.zone_usage[zone as usize] = self.zone_usage[zone as usize].saturating_sub(bytes);
    }
}
```

Make `MemoryZone` derive ordinal indexing by adding numeric discriminants or using `as usize`:

In `vm/mod.rs`, add `#[repr(usize)]` to `MemoryZone`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum MemoryZone {
    PublicDurable = 0,
    PublicEphemeral = 1,
    KernelDurable = 2,
    KernelEphemeral = 3,
}
```

Update `CapTracker::record_mapping` and `remove_mapping` to call `add_zone_usage`/`sub_zone_usage`.

**Step 4: Run ALL tests to verify nothing broke**

Run: `cargo test --workspace`
Expected: All pass including the 2 new zone tracking tests

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/vm/cap_tracker.rs crates/harmony-microkernel/src/vm/mod.rs
git commit -m "feat(vm): add zone-aware soft budget tracking in CapTracker"
```

---

### Task 11: Kernel Orchestration — Wire Lyll and Nakaiah

Add `Lyll` and `Nakaiah` fields to `Kernel<P>` and emit `IntegrityEvent`s from VM operations. The Kernel orchestrates both guardians without them knowing about each other.

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs`

**Step 1: Write the failing tests**

Add to the existing `mod tests` block in `kernel.rs`:

```rust
#[test]
fn kernel_has_integrity_guardians() {
    let kernel = make_kernel();
    assert_eq!(kernel.lyll().registry_len(), 0);
    assert_eq!(kernel.nakaiah().integrity_registry_len(), 0);
}

#[test]
fn map_region_registers_with_lyll() {
    let mut kernel = make_kernel();
    let pid = spawn_test_process(&mut kernel);
    kernel.vm_create_space(pid, default_budget()).unwrap();

    kernel
        .vm_map_region(
            pid,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

    // Lyll should have registered the frame.
    assert_eq!(kernel.lyll().registry_len(), 1);
}

#[test]
fn map_encrypted_region_registers_with_both() {
    let mut kernel = make_kernel();
    let pid = spawn_test_process(&mut kernel);
    kernel.vm_create_space(pid, default_budget()).unwrap();

    kernel
        .vm_map_region(
            pid,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();

    // Both guardians should have the frame registered.
    assert_eq!(kernel.lyll().registry_len(), 1);
    assert_eq!(kernel.nakaiah().integrity_registry_len(), 1);
}

#[test]
fn unmap_region_unregisters_from_guardians() {
    let mut kernel = make_kernel();
    let pid = spawn_test_process(&mut kernel);
    kernel.vm_create_space(pid, default_budget()).unwrap();

    kernel
        .vm_map_region(
            pid,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();
    assert_eq!(kernel.lyll().registry_len(), 1);
    assert_eq!(kernel.nakaiah().integrity_registry_len(), 1);

    kernel.vm_unmap_region(pid, VirtAddr(0x1000)).unwrap();
    assert_eq!(kernel.lyll().registry_len(), 0);
    assert_eq!(kernel.nakaiah().integrity_registry_len(), 0);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel kernel::tests::kernel_has_integrity -- 2>&1 | head -20`
Expected: Compilation error — `lyll()` method not found

**Step 3: Modify Kernel struct**

Add fields and methods:

```rust
use crate::integrity::lyll::{HashEntry, Lyll, LyllConfig};
use crate::integrity::nakaiah::Nakaiah;

pub struct Kernel<P: PageTable> {
    // ... existing fields ...
    lyll: Lyll,
    nakaiah: Nakaiah,
}

impl<P: PageTable> Kernel<P> {
    pub fn new(identity: PrivateIdentity, vm: AddressSpaceManager<P>) -> Self {
        // ... existing init ...
        let lyll = Lyll::new(LyllConfig {
            sampling_rate_percent: 5,
            sweep_interval_ticks: 100,
        });
        let nakaiah = Nakaiah::new(0.01);
        Kernel {
            // ... existing fields ...
            lyll,
            nakaiah,
        }
    }

    pub fn lyll(&self) -> &Lyll { &self.lyll }
    pub fn nakaiah(&self) -> &Nakaiah { &self.nakaiah }
}
```

Add `vm_map_region` and `vm_unmap_region` wrapper methods that delegate to `self.vm` and then notify guardians:

```rust
pub fn vm_create_space(&mut self, pid: u32, budget: MemoryBudget) -> Result<(), VmError> {
    let page_table = P::default(); // or pass it in
    self.vm.create_space(pid, budget, page_table)
}

pub fn vm_map_region(
    &mut self,
    pid: u32,
    vaddr: VirtAddr,
    len: usize,
    flags: PageFlags,
    class: FrameClassification,
) -> Result<(), VmError> {
    self.vm.map_region(pid, vaddr, len, flags, class)?;

    // Register frames with guardians.
    let space = self.vm.space(pid).unwrap();
    let region = space.regions.get(&vaddr).unwrap();
    for &paddr in &region.frames {
        let content_hash = ContentHash::ZERO; // Freshly allocated = zeroed.
        self.lyll.register_frame(
            paddr,
            if class.contains(FrameClassification::EPHEMERAL) {
                HashEntry::Snapshot { hash: content_hash.0, generation: 0 }
            } else {
                HashEntry::CidBacked { cid: content_hash.0 }
            },
            pid,
        );
        if class.contains(FrameClassification::ENCRYPTED) {
            self.nakaiah.register_frame(paddr, content_hash.0);
        }
    }

    Ok(())
}

pub fn vm_unmap_region(&mut self, pid: u32, vaddr: VirtAddr) -> Result<(), VmError> {
    // Get frames before unmapping (unmap removes the region).
    let frames: Vec<PhysAddr> = {
        let space = self.vm.space(pid).ok_or(VmError::NoSuchProcess(pid))?;
        let region = space.regions.get(&vaddr).ok_or(VmError::NotMapped(vaddr))?;
        region.frames.clone()
    };
    let class = {
        let space = self.vm.space(pid).unwrap();
        space.regions.get(&vaddr).unwrap().classification
    };

    self.vm.unmap_region(pid, vaddr)?;

    // Unregister from guardians.
    for &paddr in &frames {
        self.lyll.unregister_frame(paddr);
        if class.contains(FrameClassification::ENCRYPTED) {
            self.nakaiah.unregister_frame(paddr);
        }
    }

    Ok(())
}
```

**NOTE:** The existing Kernel tests create Kernel with `Kernel::new(...)`. The constructor needs to be updated to initialize Lyll and Nakaiah. Some test helper functions (`make_kernel`, `spawn_test_process`) may need updating — check the existing test helpers and update them.

**Step 4: Run ALL tests to verify nothing broke**

Run: `cargo test --workspace`
Expected: All pass including the 4 new integration tests

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/kernel.rs
git commit -m "feat(integrity): wire Lyll and Nakaiah into Kernel<P> — emit integrity events"
```

---

### Task 12: Full Integration Tests

Add end-to-end tests that exercise the complete flow: process creation, memory mapping, integrity verification, corruption detection, process cleanup.

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs` (add tests to existing `mod tests`)

**Step 1: Write the tests**

Add to the `mod tests` block:

```rust
#[test]
fn public_corruption_detected_and_quarantined() {
    let mut kernel = make_kernel();
    let pid = spawn_test_process(&mut kernel);
    kernel.vm_create_space(pid, default_budget()).unwrap();

    kernel
        .vm_map_region(
            pid,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

    // Get the physical address of the mapped frame.
    let space = kernel.vm().space(pid).unwrap();
    let region = space.regions.get(&VirtAddr(0x1000)).unwrap();
    let paddr = region.frames[0];

    // Simulate Lyll spot-checking and finding tampered content.
    let tampered_hash = [0xFF; 32];
    let verdict = kernel.lyll_mut().verify_frame(paddr, tampered_hash, 100);
    assert!(matches!(verdict, IntegrityVerdict::Quarantine { .. }));
    assert!(kernel.lyll().quarantine.is_quarantined(paddr));
}

#[test]
fn private_corruption_kills_process() {
    let mut kernel = make_kernel();
    let pid = spawn_test_process(&mut kernel);
    kernel.vm_create_space(pid, default_budget()).unwrap();

    kernel
        .vm_map_region(
            pid,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();

    let space = kernel.vm().space(pid).unwrap();
    let paddr = space.regions.get(&VirtAddr(0x1000)).unwrap().frames[0];

    // Grant access.
    kernel
        .nakaiah_mut()
        .grant_access(pid, paddr, CapChain::Owner);

    // Tampered content → kill.
    let verdict = kernel.nakaiah().verify_access(
        pid,
        paddr,
        AccessOp::Read,
        [0xFF; 32], // Wrong hash.
    );
    assert!(matches!(
        verdict,
        IntegrityVerdict::Kill {
            reason: ViolationReason::ContentTampered,
            ..
        }
    ));
}

#[test]
fn unauthorized_access_kills_process() {
    let mut kernel = make_kernel();
    let pid = spawn_test_process(&mut kernel);
    kernel.vm_create_space(pid, default_budget()).unwrap();

    kernel
        .vm_map_region(
            pid,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();

    let space = kernel.vm().space(pid).unwrap();
    let paddr = space.regions.get(&VirtAddr(0x1000)).unwrap().frames[0];

    // No capability granted — unauthorized.
    let verdict = kernel.nakaiah().verify_access(
        pid,
        paddr,
        AccessOp::Read,
        ContentHash::ZERO.0, // Content matches (it's zeroed).
    );
    assert!(matches!(
        verdict,
        IntegrityVerdict::Kill {
            reason: ViolationReason::UnauthorizedAccess,
            ..
        }
    ));
}

#[test]
fn destroy_process_cleans_up_integrity() {
    let mut kernel = make_kernel();
    let pid = spawn_test_process(&mut kernel);
    kernel.vm_create_space(pid, default_budget()).unwrap();

    kernel
        .vm_map_region(
            pid,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 3,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();

    assert_eq!(kernel.lyll().registry_len(), 3);
    assert_eq!(kernel.nakaiah().integrity_registry_len(), 3);

    kernel.destroy_process(pid).unwrap();

    // Both guardians should have cleaned up.
    assert_eq!(kernel.lyll().registry_len(), 0);
    assert_eq!(kernel.nakaiah().integrity_registry_len(), 0);
}

#[test]
fn guardian_compromise_panics() {
    let mut kernel = make_kernel();

    // Exchange initial state hashes.
    let nakaiah_hash = kernel.nakaiah().state_hash();
    kernel.lyll_mut().set_nakaiah_state_hash(nakaiah_hash);

    // Simulate Nakaiah compromise.
    kernel
        .nakaiah_mut()
        .set_state_hash(ContentHash([0xFF; 32]));

    // Lyll detects it.
    let verdict = kernel
        .lyll()
        .co_verify_nakaiah(kernel.nakaiah().state_hash());
    assert!(matches!(
        verdict,
        IntegrityVerdict::Panic {
            reason: ViolationReason::GuardianStateCorrupted
        }
    ));
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel kernel::tests -- -v`
Expected: All pass including the 5 new tests

**Step 3: Also run the full workspace tests**

Run: `cargo test --workspace && cargo clippy --workspace`
Expected: Everything passes, zero clippy warnings

**Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/kernel.rs
git commit -m "test(integrity): add full integration tests — corruption, unauthorized access, cleanup"
```

---

### Summary

| Task | Description | Tests | Key Files |
|------|-------------|-------|-----------|
| 1 | Shared types | 4 | `vm/mod.rs` |
| 2 | Integrity scaffold | 2 | `integrity/mod.rs`, `lib.rs` |
| 3 | Quarantine registry | 4 | `integrity/quarantine.rs` |
| 4 | Lyll core | 6 | `integrity/lyll.rs` |
| 5 | Lyll spot-check tests | 11 | `integrity/lyll.rs` |
| 6 | Nakaiah core | 9 | `integrity/nakaiah.rs` |
| 7 | Nakaiah verification tests | 12 | `integrity/nakaiah.rs` |
| 8 | Bidirectional verification | 7 | `integrity/mod.rs` |
| 9 | Dual buddy allocator | 2 | `vm/manager.rs`, `vm/buddy.rs` |
| 10 | Zone-aware budgets | 2 | `vm/cap_tracker.rs`, `vm/mod.rs` |
| 11 | Kernel orchestration | 4 | `kernel.rs` |
| 12 | Full integration tests | 5 | `kernel.rs` |
| **Total** | | **~68** | |
