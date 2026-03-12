# Zenoh NAR Publish & Mesh Fetch — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** After NARs are fetched and imported, publish them via Zenoh so peers can retrieve /nix/store paths from the mesh instead of cache.nixos.org.

**Architecture:** Two new Ring 3 modules (`NarPublisher` for the publish direction, `MeshNarSource` for the receive direction) using injectable traits for Zenoh I/O, integrated with the existing `NixStoreFetcher` pipeline. The fetcher's return type changes to communicate successful imports to the caller.

**Tech Stack:** Rust, `harmony-content` (dag, blob, chunker, cid), `harmony-zenoh` (namespace), `harmony-microkernel` (NixStoreServer), `hex` crate for CID hex encoding.

---

### Task 1: Add `hex` dependency to `harmony-os`

We need `hex::encode` to convert ContentId bytes to hex strings for Zenoh key expressions.

**Files:**
- Modify: `crates/harmony-os/Cargo.toml`

**Step 1: Add hex dependency**

In `crates/harmony-os/Cargo.toml`, add `hex` as a dependency gated on the `std` feature, alongside the other optional deps:

```toml
# Under [features] → std list, add:
"dep:hex",

# Under [dependencies], add:
hex = { version = "0.4", optional = true }
```

The `std` feature list should look like:
```toml
std = [
    "harmony-microkernel/kernel",
    "dep:harmony-crypto", "harmony-crypto/std",
    "dep:harmony-identity", "harmony-identity/std",
    "dep:harmony-reticulum", "harmony-reticulum/std",
    "dep:harmony-zenoh",
    "dep:harmony-content",
    "dep:harmony-compute",
    "dep:harmony-workflow",
    "dep:ureq",
    "dep:xz2",
    "dep:sha2",
    "dep:hex",
]
```

**Step 2: Verify it compiles**

Run: `cargo test -p harmony-os --no-run`
Expected: Compiles successfully.

**Step 3: Commit**

```bash
git add crates/harmony-os/Cargo.toml
git commit -m "chore(os): add hex dependency for CID-to-key-expression conversion"
```

---

### Task 2: NarPublisher — trait and struct skeleton with tests

Create the publisher module with `ContentAnnouncer` trait, `NarPublisher` struct, and failing tests.

**Files:**
- Create: `crates/harmony-os/src/nar_publisher.rs`
- Modify: `crates/harmony-os/src/lib.rs`

**Step 1: Write the failing tests first**

Create `crates/harmony-os/src/nar_publisher.rs` with the test module and a minimal module structure:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! NarPublisher — publishes imported NARs to the Harmony mesh via Zenoh.
//!
//! After a NAR is fetched from cache.nixos.org and imported into
//! [`NixStoreServer`], the publisher chunks it into a content-addressed
//! Merkle DAG and announces it on the mesh so peers can retrieve the
//! same store path without re-fetching from the old internet.

use std::collections::HashMap;

use harmony_content::blob::{BlobStore, MemoryBlobStore};
use harmony_content::chunker::ChunkerConfig;
use harmony_content::cid::ContentId;
use harmony_content::dag;

// ── ContentAnnouncer trait ──────────────────────────────────────────

/// Injectable trait for announcing content on the Zenoh mesh.
///
/// Production implementations wrap a Zenoh session. Tests use a mock
/// that collects announcements for assertion.
pub trait ContentAnnouncer {
    /// Announce content availability at `key_expr` with `payload`.
    fn announce(&self, key_expr: &str, payload: &[u8]) -> Result<(), String>;
}

// ── NarPublisher ────────────────────────────────────────────────────

/// Publishes imported NARs to the Harmony content mesh.
///
/// Chunks NAR bytes into a Merkle DAG via [`dag::ingest`], stores blobs
/// in an in-memory [`BlobStore`], and announces the root CID + individual
/// blobs via the injected [`ContentAnnouncer`].
pub struct NarPublisher<A: ContentAnnouncer> {
    announcer: A,
    blob_store: MemoryBlobStore,
    chunker_config: ChunkerConfig,
    /// Maps store path name → root ContentId for lookup by peers.
    published_paths: HashMap<String, ContentId>,
}

impl<A: ContentAnnouncer> NarPublisher<A> {
    /// Create a new publisher with the given announcer.
    pub fn new(announcer: A) -> Self {
        Self {
            announcer,
            blob_store: MemoryBlobStore::new(),
            chunker_config: ChunkerConfig::DEFAULT,
            published_paths: HashMap::new(),
        }
    }

    /// Publish a NAR to the mesh.
    ///
    /// Chunks the NAR into a Merkle DAG, stores all blobs locally, and
    /// announces the store path mapping and each blob's availability.
    ///
    /// Returns the root [`ContentId`] on success, or a string error on failure.
    /// Publishing is best-effort — failures are logged but do not affect
    /// the local NixStoreServer import.
    pub fn publish(&mut self, store_path_name: &str, nar_bytes: &[u8]) -> Result<ContentId, String> {
        // 1. Chunk the NAR into a Merkle DAG.
        let root_cid = dag::ingest(nar_bytes, &self.chunker_config, &mut self.blob_store)
            .map_err(|e| format!("ingest failed: {e}"))?;

        // 2. Record the store path → root CID mapping.
        self.published_paths
            .insert(store_path_name.to_string(), root_cid);

        // 3. Extract store hash for the Zenoh key.
        let store_hash = &store_path_name[..32.min(store_path_name.len())];
        let nix_store_key = format!("harmony/nix/store/{store_hash}");

        // 4. Announce the store path → root CID mapping.
        let root_cid_hex = hex::encode(root_cid.to_bytes());
        self.announcer
            .announce(&nix_store_key, root_cid_hex.as_bytes())
            .map_err(|e| format!("announce store path failed: {e}"))?;

        // 5. Announce each blob in the DAG.
        let blob_cids = dag::walk(&root_cid, &self.blob_store)
            .map_err(|e| format!("DAG walk failed: {e}"))?;
        for cid in &blob_cids {
            let cid_hex = hex::encode(cid.to_bytes());
            let announce_key = harmony_zenoh::namespace::announce::key(&cid_hex);
            let size_bytes = self
                .blob_store
                .get(cid)
                .map(|d| d.len() as u64)
                .unwrap_or(0);
            self.announcer
                .announce(&announce_key, &size_bytes.to_le_bytes())
                .map_err(|e| format!("announce blob failed: {e}"))?;
        }

        // 6. If root is a bundle, also announce the bundle itself.
        if root_cid != blob_cids.first().copied().unwrap_or(root_cid) || blob_cids.len() > 1 {
            let root_hex = hex::encode(root_cid.to_bytes());
            let root_announce_key = harmony_zenoh::namespace::announce::key(&root_hex);
            let root_size = self
                .blob_store
                .get(&root_cid)
                .map(|d| d.len() as u64)
                .unwrap_or(0);
            self.announcer
                .announce(&root_announce_key, &root_size.to_le_bytes())
                .map_err(|e| format!("announce root bundle failed: {e}"))?;
        }

        Ok(root_cid)
    }

    /// Look up the root CID for a published store path.
    pub fn get_root_cid(&self, store_path_name: &str) -> Option<&ContentId> {
        self.published_paths.get(store_path_name)
    }

    /// Get a blob by its CID from the local store.
    pub fn get_blob(&self, cid: &ContentId) -> Option<&[u8]> {
        self.blob_store.get(cid)
    }

    /// Read-only view of all published paths and their root CIDs.
    pub fn published_paths(&self) -> &HashMap<String, ContentId> {
        &self.published_paths
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Mock announcer that records all announcements.
    struct MockAnnouncer {
        announcements: Rc<RefCell<Vec<(String, Vec<u8>)>>>,
    }

    impl MockAnnouncer {
        fn new() -> (Self, Rc<RefCell<Vec<(String, Vec<u8>)>>>) {
            let announcements = Rc::new(RefCell::new(Vec::new()));
            (
                Self {
                    announcements: Rc::clone(&announcements),
                },
                announcements,
            )
        }
    }

    impl ContentAnnouncer for MockAnnouncer {
        fn announce(&self, key_expr: &str, payload: &[u8]) -> Result<(), String> {
            self.announcements
                .borrow_mut()
                .push((key_expr.to_string(), payload.to_vec()));
            Ok(())
        }
    }

    /// Build a minimal NAR for testing (reuse from nix_store_fetcher tests).
    fn nar_string(s: &[u8]) -> Vec<u8> {
        let len = s.len() as u64;
        let padded_len = (s.len() + 7) & !7;
        let mut buf = Vec::with_capacity(8 + padded_len);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s);
        buf.resize(buf.len() + (padded_len - s.len()), 0);
        buf
    }

    fn build_test_nar(contents: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&nar_string(b"nix-archive-1"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"regular"));
        buf.extend_from_slice(&nar_string(b"contents"));
        buf.extend_from_slice(&nar_string(contents));
        buf.extend_from_slice(&nar_string(b")"));
        buf
    }

    #[test]
    fn publish_small_nar() {
        let (announcer, announcements) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"hello mesh");
        let store_path = "abc12345678901234567890123456789-hello-pkg";

        let root_cid = publisher.publish(store_path, &nar).unwrap();

        // Root CID should be recorded in published_paths.
        assert_eq!(publisher.get_root_cid(store_path), Some(&root_cid));

        // Should have at least 2 announcements: store path mapping + blob.
        let ann = announcements.borrow();
        assert!(ann.len() >= 2, "expected at least 2 announcements, got {}", ann.len());

        // First announcement should be the store path → root CID mapping.
        assert_eq!(ann[0].0, "harmony/nix/store/abc12345678901234567890123456789");
        let announced_cid_hex = String::from_utf8(ann[0].1.clone()).unwrap();
        assert_eq!(announced_cid_hex, hex::encode(root_cid.to_bytes()));
    }

    #[test]
    fn publish_records_root_cid() {
        let (announcer, _) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"test content");
        let store_path = "abc12345678901234567890123456789-test-pkg";

        let root_cid = publisher.publish(store_path, &nar).unwrap();

        assert_eq!(publisher.get_root_cid(store_path), Some(&root_cid));
        assert!(publisher.get_blob(&root_cid).is_some());
    }

    #[test]
    fn publish_blob_announcements_use_correct_key_format() {
        let (announcer, announcements) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"key format test");
        let store_path = "abc12345678901234567890123456789-key-test";

        publisher.publish(store_path, &nar).unwrap();

        let ann = announcements.borrow();
        // All announcements after the first should use harmony/announce/{cid_hex}
        for (key, _) in ann.iter().skip(1) {
            assert!(
                key.starts_with("harmony/announce/"),
                "blob announcement key should start with harmony/announce/, got: {key}"
            );
        }
    }

    #[test]
    fn publish_empty_nar_fails() {
        let (announcer, _) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let store_path = "abc12345678901234567890123456789-empty";

        let result = publisher.publish(store_path, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn publish_announcer_failure_propagates() {
        struct FailAnnouncer;
        impl ContentAnnouncer for FailAnnouncer {
            fn announce(&self, _key: &str, _payload: &[u8]) -> Result<(), String> {
                Err("zenoh unavailable".into())
            }
        }

        let mut publisher = NarPublisher::new(FailAnnouncer);
        let nar = build_test_nar(b"will fail");
        let store_path = "abc12345678901234567890123456789-fail-test";

        let result = publisher.publish(store_path, &nar);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("zenoh unavailable"));
    }

    #[test]
    fn round_trip_blob_data() {
        let (announcer, _) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"round trip data");
        let store_path = "abc12345678901234567890123456789-roundtrip";

        let root_cid = publisher.publish(store_path, &nar).unwrap();

        // Reassemble from the publisher's blob store should recover original NAR.
        let recovered = dag::reassemble(&root_cid, &publisher.blob_store).unwrap();
        assert_eq!(recovered, nar);
    }
}
```

**Step 2: Register the module in lib.rs**

Add to `crates/harmony-os/src/lib.rs`, after the `nix_store_fetcher` line:

```rust
#[cfg(feature = "std")]
pub mod nar_publisher;
```

**Step 3: Run tests to verify they pass**

Run: `cargo test -p harmony-os nar_publisher`
Expected: All 6 tests pass.

**Step 4: Commit**

```bash
git add crates/harmony-os/src/nar_publisher.rs crates/harmony-os/src/lib.rs
git commit -m "feat(os): add NarPublisher with ContentAnnouncer trait for mesh NAR publishing"
```

---

### Task 3: MeshNarSource — trait and struct skeleton with tests

Create the mesh fetch module with `ContentQuerier` trait, `MeshNarFetch` trait, `MeshNarSource` struct, and tests.

**Files:**
- Create: `crates/harmony-os/src/mesh_nar_source.rs`
- Modify: `crates/harmony-os/src/lib.rs`

**Step 1: Write the module with tests**

Create `crates/harmony-os/src/mesh_nar_source.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! MeshNarSource — fetches NARs from the Harmony mesh before falling back
//! to cache.nixos.org.
//!
//! When a Nix store path miss occurs, `MeshNarSource` queries the mesh
//! for the store path's root CID, walks the content DAG to fetch all
//! blobs, and reassembles the original NAR bytes. If any step fails or
//! the path is not available on the mesh, returns `None` so the caller
//! can fall back to the HTTP fetch from cache.nixos.org.

use harmony_content::blob::{BlobStore, MemoryBlobStore};
use harmony_content::cid::ContentId;
use harmony_content::dag;

// ── ContentQuerier trait ────────────────────────────────────────────

/// Injectable trait for querying content from the Zenoh mesh.
///
/// Production implementations wrap a Zenoh session's `get()` operation.
/// Tests use a mock that returns pre-loaded data.
pub trait ContentQuerier {
    /// Query the mesh for data at `key_expr`.
    ///
    /// Returns `Ok(Some(data))` if a peer replies, `Ok(None)` if no peer
    /// has the content, or `Err` on network failure.
    fn query(&self, key_expr: &str) -> Result<Option<Vec<u8>>, String>;
}

// ── MeshNarFetch trait ──────────────────────────────────────────────

/// Trait for fetching NAR bytes from the mesh.
///
/// Used by `NixStoreFetcher` as `Option<Box<dyn MeshNarFetch>>` to
/// optionally try the mesh before falling back to cache.nixos.org.
pub trait MeshNarFetch {
    /// Try to fetch a NAR from the mesh by store path name.
    ///
    /// Returns `Some(nar_bytes)` if the mesh has it, `None` otherwise.
    fn fetch_nar(&self, store_path_name: &str) -> Option<Vec<u8>>;
}

// ── MeshNarSource ───────────────────────────────────────────────────

/// Fetches NARs from the Harmony content mesh via Zenoh queries.
pub struct MeshNarSource<Q: ContentQuerier> {
    querier: Q,
}

impl<Q: ContentQuerier> MeshNarSource<Q> {
    /// Create a new mesh NAR source with the given querier.
    pub fn new(querier: Q) -> Self {
        Self { querier }
    }

    /// Query the mesh for a store path's root CID, fetch all blobs,
    /// and reassemble the NAR.
    fn try_fetch(&self, store_path_name: &str) -> Result<Option<Vec<u8>>, String> {
        // 1. Extract store hash.
        if store_path_name.len() < 33 || store_path_name.as_bytes()[32] != b'-' {
            return Ok(None); // Malformed store path, skip mesh.
        }
        let store_hash = &store_path_name[..32];

        // 2. Query for root CID mapping.
        let nix_store_key = format!("harmony/nix/store/{store_hash}");
        let root_cid_hex = match self.querier.query(&nix_store_key)? {
            Some(data) => String::from_utf8(data).map_err(|e| e.to_string())?,
            None => return Ok(None), // Not on mesh.
        };

        // 3. Decode root CID from hex.
        let cid_bytes: [u8; 32] = hex::decode(&root_cid_hex)
            .map_err(|e| format!("invalid root CID hex: {e}"))?
            .try_into()
            .map_err(|_| "root CID hex is not 32 bytes".to_string())?;
        let root_cid = ContentId::from_bytes(cid_bytes);

        // 4. Fetch root blob/bundle from mesh.
        let root_fetch_key =
            harmony_zenoh::namespace::content::fetch_key(&root_cid_hex);
        let root_data = match self.querier.query(&root_fetch_key)? {
            Some(data) => data,
            None => return Ok(None), // Root blob not available.
        };

        // 5. Build a temporary store and populate it by walking the DAG.
        let mut store = MemoryBlobStore::new();
        store.store(root_cid, root_data);

        // 6. Recursively fetch child blobs.
        self.fetch_children(&root_cid, &mut store)?;

        // 7. Reassemble the NAR from the DAG.
        let nar_bytes = dag::reassemble(&root_cid, &store)
            .map_err(|e| format!("DAG reassembly failed: {e}"))?;

        Ok(Some(nar_bytes))
    }

    /// Recursively fetch all child blobs/bundles in a DAG.
    fn fetch_children(&self, cid: &ContentId, store: &mut MemoryBlobStore) -> Result<(), String> {
        use harmony_content::cid::CidType;
        match cid.cid_type() {
            CidType::Blob => {
                // Leaf — already in store if we got here, or needs fetching.
                if store.get(cid).is_none() {
                    let cid_hex = hex::encode(cid.to_bytes());
                    let fetch_key =
                        harmony_zenoh::namespace::content::fetch_key(&cid_hex);
                    let data = self
                        .querier
                        .query(&fetch_key)?
                        .ok_or_else(|| format!("mesh missing blob {cid_hex}"))?;
                    store.store(*cid, data);
                }
            }
            CidType::Bundle(_) => {
                // Parse bundle to find children, fetch each.
                let bundle_data = store
                    .get(cid)
                    .ok_or_else(|| "bundle not in store".to_string())?
                    .to_vec(); // Clone to release borrow.
                let children = harmony_content::bundle::parse_bundle(&bundle_data)
                    .map_err(|e| format!("parse bundle failed: {e}"))?;
                for child in children {
                    if child.cid_type() == CidType::InlineMetadata {
                        continue; // Metadata entries don't carry data.
                    }
                    // Fetch child if not already in store.
                    if store.get(child).is_none() {
                        let child_hex = hex::encode(child.to_bytes());
                        let fetch_key =
                            harmony_zenoh::namespace::content::fetch_key(&child_hex);
                        let data = self
                            .querier
                            .query(&fetch_key)?
                            .ok_or_else(|| format!("mesh missing {child_hex}"))?;
                        store.store(*child, data);
                    }
                    // Recurse for nested bundles.
                    self.fetch_children(child, store)?;
                }
            }
            CidType::InlineMetadata => {} // Skip.
            _ => {} // Reserved types — skip.
        }
        Ok(())
    }
}

impl<Q: ContentQuerier> MeshNarFetch for MeshNarSource<Q> {
    fn fetch_nar(&self, store_path_name: &str) -> Option<Vec<u8>> {
        match self.try_fetch(store_path_name) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("[mesh-nar] mesh fetch failed for {store_path_name}: {e}");
                None
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_content::blob::BlobStore;
    use harmony_content::chunker::ChunkerConfig;
    use std::collections::HashMap;

    /// Mock querier backed by a HashMap.
    struct MockQuerier {
        data: HashMap<String, Vec<u8>>,
    }

    impl MockQuerier {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
            }
        }

        fn insert(&mut self, key: &str, value: Vec<u8>) {
            self.data.insert(key.to_string(), value);
        }
    }

    impl ContentQuerier for MockQuerier {
        fn query(&self, key_expr: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.data.get(key_expr).cloned())
        }
    }

    /// Build a minimal NAR.
    fn nar_string(s: &[u8]) -> Vec<u8> {
        let len = s.len() as u64;
        let padded_len = (s.len() + 7) & !7;
        let mut buf = Vec::with_capacity(8 + padded_len);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s);
        buf.resize(buf.len() + (padded_len - s.len()), 0);
        buf
    }

    fn build_test_nar(contents: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&nar_string(b"nix-archive-1"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"regular"));
        buf.extend_from_slice(&nar_string(b"contents"));
        buf.extend_from_slice(&nar_string(contents));
        buf.extend_from_slice(&nar_string(b")"));
        buf
    }

    /// Populate a mock querier with all blobs from a published NAR's DAG.
    ///
    /// This simulates what NarPublisher would have announced + what a
    /// queryable peer would serve.
    fn populate_querier_from_nar(
        querier: &mut MockQuerier,
        store_path_name: &str,
        nar_bytes: &[u8],
    ) -> ContentId {
        let mut store = MemoryBlobStore::new();
        let config = ChunkerConfig::DEFAULT;
        let root_cid = harmony_content::dag::ingest(nar_bytes, &config, &mut store).unwrap();

        // Store path → root CID mapping.
        let store_hash = &store_path_name[..32];
        let root_cid_hex = hex::encode(root_cid.to_bytes());
        querier.insert(
            &format!("harmony/nix/store/{store_hash}"),
            root_cid_hex.as_bytes().to_vec(),
        );

        // Root blob/bundle data.
        let root_fetch_key =
            harmony_zenoh::namespace::content::fetch_key(&root_cid_hex);
        let root_data = store.get(&root_cid).unwrap().to_vec();
        querier.insert(&root_fetch_key, root_data);

        // All leaf blobs.
        let blob_cids = harmony_content::dag::walk(&root_cid, &store).unwrap();
        for cid in &blob_cids {
            let cid_hex = hex::encode(cid.to_bytes());
            let fetch_key =
                harmony_zenoh::namespace::content::fetch_key(&cid_hex);
            let data = store.get(cid).unwrap().to_vec();
            querier.insert(&fetch_key, data);
        }

        root_cid
    }

    #[test]
    fn fetch_from_mesh_round_trip() {
        let nar = build_test_nar(b"mesh round trip");
        let store_path = "abc12345678901234567890123456789-mesh-test";

        let mut querier = MockQuerier::new();
        populate_querier_from_nar(&mut querier, store_path, &nar);

        let source = MeshNarSource::new(querier);
        let result = source.fetch_nar(store_path);

        assert_eq!(result, Some(nar));
    }

    #[test]
    fn fetch_returns_none_when_not_on_mesh() {
        let querier = MockQuerier::new(); // Empty — nothing on mesh.
        let source = MeshNarSource::new(querier);
        let store_path = "abc12345678901234567890123456789-missing";

        assert_eq!(source.fetch_nar(store_path), None);
    }

    #[test]
    fn fetch_returns_none_for_malformed_store_path() {
        let querier = MockQuerier::new();
        let source = MeshNarSource::new(querier);

        // Too short.
        assert_eq!(source.fetch_nar("short"), None);
        // No hyphen at position 32.
        assert_eq!(
            source.fetch_nar("abc12345678901234567890123456789xno_hyphen"),
            None
        );
    }

    #[test]
    fn fetch_returns_none_when_root_blob_missing() {
        let store_path = "abc12345678901234567890123456789-partial";
        let mut querier = MockQuerier::new();

        // Insert only the store path → CID mapping, but not the actual blob.
        let fake_cid = [0u8; 32];
        let cid_hex = hex::encode(fake_cid);
        querier.insert(
            "harmony/nix/store/abc12345678901234567890123456789",
            cid_hex.as_bytes().to_vec(),
        );

        let source = MeshNarSource::new(querier);
        assert_eq!(source.fetch_nar(store_path), None);
    }

    #[test]
    fn mesh_nar_fetch_trait_returns_none_on_error() {
        struct FailQuerier;
        impl ContentQuerier for FailQuerier {
            fn query(&self, _key: &str) -> Result<Option<Vec<u8>>, String> {
                Err("network error".into())
            }
        }

        let source = MeshNarSource::new(FailQuerier);
        let store_path = "abc12345678901234567890123456789-fail";

        // MeshNarFetch::fetch_nar should return None (not panic).
        assert_eq!(source.fetch_nar(store_path), None);
    }
}
```

**Step 2: Register the module in lib.rs**

Add to `crates/harmony-os/src/lib.rs`, after the `nar_publisher` line:

```rust
#[cfg(feature = "std")]
pub mod mesh_nar_source;
```

**Step 3: Run tests**

Run: `cargo test -p harmony-os mesh_nar_source`
Expected: All 5 tests pass.

**Step 4: Commit**

```bash
git add crates/harmony-os/src/mesh_nar_source.rs crates/harmony-os/src/lib.rs
git commit -m "feat(os): add MeshNarSource with ContentQuerier trait for mesh NAR fetch"
```

---

### Task 4: Integrate MeshNarFetch into NixStoreFetcher

Modify the fetcher to optionally try the mesh first, and change return type to communicate successful imports.

**Files:**
- Modify: `crates/harmony-os/src/nix_store_fetcher.rs`

**Step 1: Write the failing test for mesh-first fetch**

Add to the `tests` module in `nix_store_fetcher.rs`:

```rust
    // ── Test: mesh-first fetch skips HTTP ────────────────────────────

    #[test]
    fn mesh_first_skips_http() {
        use crate::mesh_nar_source::MeshNarFetch;

        struct MockMesh {
            nar: Vec<u8>,
        }
        impl MeshNarFetch for MockMesh {
            fn fetch_nar(&self, _store_path_name: &str) -> Option<Vec<u8>> {
                Some(self.nar.clone())
            }
        }

        let nar = build_test_nar(b"from mesh");

        // Empty HTTP mock — if mesh works, HTTP should never be called.
        let mock_http = MockHttp {
            responses: HashMap::new(),
        };
        let mock_mesh = MockMesh { nar: nar.clone() };

        let mut fetcher = NixStoreFetcher::with_mesh(Box::new(mock_http), Box::new(mock_mesh));
        let mut server = NixStoreServer::new();

        let store_path_name = "abc12345678901234567890123456789-mesh-pkg";
        use harmony_microkernel::FileServer;
        let _ = server.walk(0, 1, store_path_name);

        let imported = fetcher.process_misses(&mut server);

        // Should have imported from mesh.
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].0, store_path_name);
        assert_eq!(imported[0].1, nar);

        // Store path should be available.
        let qp = server.walk(0, 2, store_path_name).unwrap();
        assert_ne!(qp, 0);
    }

    // ── Test: mesh miss falls back to HTTP ──────────────────────────

    #[test]
    fn mesh_miss_falls_back_to_http() {
        use crate::mesh_nar_source::MeshNarFetch;

        struct EmptyMesh;
        impl MeshNarFetch for EmptyMesh {
            fn fetch_nar(&self, _store_path_name: &str) -> Option<Vec<u8>> {
                None // Not on mesh.
            }
        }

        let nar_bytes = build_test_nar(b"from http fallback");
        let hash = Sha256::digest(&nar_bytes);
        let hash_b32 = encode_nix_base32(hash.as_slice());
        let compressed = compress_xz(&nar_bytes);

        let store_hash = "abc12345678901234567890123456789";
        let store_path_name = format!("{}-fallback-pkg", store_hash);
        let narinfo_text = format!(
            "StorePath: /nix/store/{}\nURL: nar/fb.nar.xz\nCompression: xz\nNarHash: sha256:{}\nNarSize: {}\n",
            store_path_name, hash_b32, nar_bytes.len()
        );

        let mut responses = HashMap::new();
        responses.insert(
            format!("https://cache.nixos.org/{}.narinfo", store_hash),
            Ok(narinfo_text.into_bytes()),
        );
        responses.insert(
            "https://cache.nixos.org/nar/fb.nar.xz".to_string(),
            Ok(compressed),
        );

        let mock_http = MockHttp { responses };
        let mock_mesh = EmptyMesh;

        let mut fetcher = NixStoreFetcher::with_mesh(Box::new(mock_http), Box::new(mock_mesh));
        let mut server = NixStoreServer::new();

        use harmony_microkernel::FileServer;
        let _ = server.walk(0, 1, &store_path_name);

        let imported = fetcher.process_misses(&mut server);

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].0, store_path_name);
    }

    // ── Test: process_misses returns imported pairs ──────────────────

    #[test]
    fn process_misses_returns_imported_pairs() {
        let nar_bytes = build_test_nar(b"return test");
        let hash = Sha256::digest(&nar_bytes);
        let hash_b32 = encode_nix_base32(hash.as_slice());
        let compressed = compress_xz(&nar_bytes);

        let store_hash = "abc12345678901234567890123456789";
        let store_path_name = format!("{}-return-test", store_hash);
        let narinfo_text = format!(
            "StorePath: /nix/store/{}\nURL: nar/ret.nar.xz\nCompression: xz\nNarHash: sha256:{}\nNarSize: {}\n",
            store_path_name, hash_b32, nar_bytes.len()
        );

        let mut responses = HashMap::new();
        responses.insert(
            format!("https://cache.nixos.org/{}.narinfo", store_hash),
            Ok(narinfo_text.into_bytes()),
        );
        responses.insert(
            "https://cache.nixos.org/nar/ret.nar.xz".to_string(),
            Ok(compressed),
        );

        let mock = MockHttp { responses };
        let mut fetcher = NixStoreFetcher::new(Box::new(mock));
        let mut server = NixStoreServer::new();

        use harmony_microkernel::FileServer;
        let _ = server.walk(0, 1, &store_path_name);

        let imported = fetcher.process_misses(&mut server);

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].0, store_path_name);
        assert_eq!(imported[0].1, nar_bytes);
    }
```

**Step 2: Modify NixStoreFetcher struct and constructor**

Add the mesh field and `with_mesh` constructor:

```rust
use crate::mesh_nar_source::MeshNarFetch;

pub struct NixStoreFetcher {
    http: Box<dyn HttpClient>,
    mesh: Option<Box<dyn MeshNarFetch>>,
    cache_url: String,
    failed: HashSet<String>,
}

impl NixStoreFetcher {
    pub fn new(http: Box<dyn HttpClient>) -> Self {
        Self {
            http,
            mesh: None,
            cache_url: String::from("https://cache.nixos.org"),
            failed: HashSet::new(),
        }
    }

    /// Create a fetcher with both HTTP and mesh sources.
    pub fn with_mesh(http: Box<dyn HttpClient>, mesh: Box<dyn MeshNarFetch>) -> Self {
        Self {
            http,
            mesh: Some(mesh),
            cache_url: String::from("https://cache.nixos.org"),
            failed: HashSet::new(),
        }
    }
```

**Step 3: Change process_misses return type**

Change `process_misses` and `process_misses_shared` to return `Vec<(String, Vec<u8>)>`:

```rust
    pub fn process_misses(&mut self, server: &mut NixStoreServer) -> Vec<(String, Vec<u8>)> {
        let misses = server.drain_misses();
        self.process_miss_list(misses, |name, nar| {
            if server.has_store_path(name) {
                return Ok(());
            }
            server.import_nar(name, nar).map_err(|e| format!("{:?}", e))
        })
    }

    pub fn process_misses_shared(&mut self, server: &Arc<Mutex<NixStoreServer>>) -> Vec<(String, Vec<u8>)> {
        let misses = server
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain_misses();
        self.process_miss_list(misses, |name, nar| {
            let mut guard = server.lock().unwrap_or_else(|e| e.into_inner());
            if guard.has_store_path(name) {
                return Ok(());
            }
            guard.import_nar(name, nar).map_err(|e| format!("{:?}", e))
        })
    }
```

**Step 4: Update process_miss_list to try mesh first and collect results**

```rust
    fn process_miss_list<F>(&mut self, misses: Vec<Arc<str>>, mut import_fn: F) -> Vec<(String, Vec<u8>)>
    where
        F: FnMut(&str, Vec<u8>) -> Result<(), String>,
    {
        let mut imported = Vec::new();
        for name in &misses {
            let name_str = name.to_string();
            if self.failed.contains(&name_str) {
                continue;
            }

            // Try mesh first (if available).
            let fetch_result = if let Some(ref mesh) = self.mesh {
                if let Some(nar_bytes) = mesh.fetch_nar(&name_str) {
                    Ok(nar_bytes)
                } else {
                    // Mesh miss — fall back to HTTP.
                    self.fetch_nar(&name_str)
                }
            } else {
                self.fetch_nar(&name_str)
            };

            match fetch_result {
                Ok(nar_bytes) => {
                    let nar_clone = nar_bytes.clone();
                    if let Err(e) = import_fn(&name_str, nar_bytes) {
                        eprintln!("[nix-fetcher] import failed for {}: {}", name_str, e);
                        self.failed.insert(name_str);
                    } else {
                        imported.push((name_str, nar_clone));
                    }
                }
                Err(e) => {
                    eprintln!("[nix-fetcher] fetch failed for {}: {:?}", name_str, e);
                    if !matches!(e, FetchError::Network(_)) {
                        self.failed.insert(name_str);
                    }
                }
            }
        }
        imported
    }
```

**Step 5: Update existing tests**

Existing tests call `process_misses` without capturing the return value. They will still compile since Rust allows ignoring return values, but update `fetch_and_import_success` to also verify the return:

```rust
    #[test]
    fn fetch_and_import_success() {
        // ... (existing setup unchanged) ...

        // Process misses — should fetch and import.
        let imported = fetcher.process_misses(&mut server);

        // Verify the return value includes the imported path.
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].0, store_path_name);

        // ... (rest of existing assertions unchanged) ...
    }
```

**Step 6: Run all tests**

Run: `cargo test -p harmony-os`
Expected: All tests pass (existing + 3 new).

**Step 7: Commit**

```bash
git add crates/harmony-os/src/nix_store_fetcher.rs
git commit -m "feat(os): integrate MeshNarFetch into NixStoreFetcher with mesh-first fetch"
```

---

### Task 5: End-to-end integration test — publish then fetch from mesh

Write a test that exercises the full round-trip: publish a NAR → query it back via MeshNarSource → verify bytes match.

**Files:**
- Modify: `crates/harmony-os/src/mesh_nar_source.rs` (add integration test)

**Step 1: Write the integration test**

Add to the `tests` module in `mesh_nar_source.rs`:

```rust
    /// End-to-end: publish via NarPublisher, then fetch via MeshNarSource.
    ///
    /// This simulates the full mesh round-trip: one node publishes,
    /// another node queries. The mock querier is populated with exactly
    /// the data that NarPublisher's announcements would make available.
    #[test]
    fn end_to_end_publish_then_fetch() {
        use crate::nar_publisher::{ContentAnnouncer, NarPublisher};

        // ── Publish side ────────────────────────────────────────────
        struct NoopAnnouncer;
        impl ContentAnnouncer for NoopAnnouncer {
            fn announce(&self, _key: &str, _payload: &[u8]) -> Result<(), String> {
                Ok(())
            }
        }

        let nar = build_test_nar(b"end-to-end mesh test data");
        let store_path = "abc12345678901234567890123456789-e2e-test";

        let mut publisher = NarPublisher::new(NoopAnnouncer);
        let root_cid = publisher.publish(store_path, &nar).unwrap();

        // ── Populate mock querier with publisher's blob store ────────
        let mut querier = MockQuerier::new();

        // Store path → root CID mapping.
        let store_hash = &store_path[..32];
        let root_cid_hex = hex::encode(root_cid.to_bytes());
        querier.insert(
            &format!("harmony/nix/store/{store_hash}"),
            root_cid_hex.as_bytes().to_vec(),
        );

        // Root blob/bundle.
        let root_fetch_key =
            harmony_zenoh::namespace::content::fetch_key(&root_cid_hex);
        querier.insert(
            &root_fetch_key,
            publisher.get_blob(&root_cid).unwrap().to_vec(),
        );

        // All leaf blobs.
        let blob_cids =
            harmony_content::dag::walk(&root_cid, &publisher.blob_store).unwrap();
        for cid in &blob_cids {
            let cid_hex = hex::encode(cid.to_bytes());
            let fetch_key =
                harmony_zenoh::namespace::content::fetch_key(&cid_hex);
            querier.insert(
                &fetch_key,
                publisher.get_blob(cid).unwrap().to_vec(),
            );
        }

        // ── Fetch side ──────────────────────────────────────────────
        let source = MeshNarSource::new(querier);
        let fetched = source.fetch_nar(store_path);

        assert_eq!(fetched, Some(nar));
    }
```

Note: this test accesses `publisher.blob_store` directly. Add a `pub` accessor if needed:

In `nar_publisher.rs`, the `blob_store` field can be made accessible via the existing `get_blob` method + `dag::walk`. But for the test we need direct access. The simplest approach: make `NarPublisher` expose the blob store for tests only, or use `get_blob` with `dag::walk` (which we already have). The test above uses `publisher.get_blob(cid)` which is already public, plus `publisher.blob_store` directly for `dag::walk`. We need to either:

(a) Make `blob_store` pub (it's an internal store, not great), or
(b) Add a `pub fn walk_dag(&self, root: &ContentId) -> Result<Vec<ContentId>, String>` method, or
(c) Access via a `pub fn blob_store(&self) -> &MemoryBlobStore` getter.

Option (c) is cleanest. Add to `NarPublisher`:

```rust
    /// Access the backing blob store (for integration testing and queries).
    pub fn blob_store(&self) -> &MemoryBlobStore {
        &self.blob_store
    }
```

Then the test uses `publisher.blob_store()` instead of `publisher.blob_store`.

**Step 2: Run the test**

Run: `cargo test -p harmony-os end_to_end_publish_then_fetch`
Expected: PASS

**Step 3: Commit**

```bash
git add crates/harmony-os/src/mesh_nar_source.rs crates/harmony-os/src/nar_publisher.rs
git commit -m "test(os): add end-to-end integration test for publish → mesh fetch round-trip"
```

---

### Task 6: Full workspace verification

Run all quality gates.

**Step 1: Run all tests**

Run: `cargo test --workspace`
Expected: All tests pass (including all existing tests from harmony-microkernel, harmony-unikernel).

**Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: Zero warnings.

**Step 3: Run rustfmt**

Run: `cargo fmt --all -- --check`
Expected: No formatting issues.

**Step 4: Fix any issues found in steps 1-3**

If any tests fail, clippy warnings appear, or formatting issues exist, fix them.

**Step 5: Commit fixes (if any)**

```bash
git add -A
git commit -m "style: apply formatting and clippy fixes"
```

---

## File Summary

| Action | File | Purpose |
|--------|------|---------|
| Create | `crates/harmony-os/src/nar_publisher.rs` | NarPublisher + ContentAnnouncer trait |
| Create | `crates/harmony-os/src/mesh_nar_source.rs` | MeshNarSource + ContentQuerier + MeshNarFetch traits |
| Modify | `crates/harmony-os/src/nix_store_fetcher.rs` | Optional mesh, return Vec, mesh-first logic |
| Modify | `crates/harmony-os/src/lib.rs` | Register new modules |
| Modify | `crates/harmony-os/Cargo.toml` | Add hex dependency |
