// SPDX-License-Identifier: GPL-2.0-or-later

//! NarPublisher — publish NAR archives into the Harmony mesh via content-addressed DAG.
//!
//! Chunks a NAR file into a Merkle DAG using [`harmony_content::dag::ingest`],
//! announces the store-path-to-CID mapping and each blob's availability via a
//! pluggable [`ContentAnnouncer`] trait (backed by Zenoh in production).

use std::collections::HashMap;

use harmony_content::blob::{BlobStore, MemoryBlobStore};
use harmony_content::chunker::ChunkerConfig;
use harmony_content::cid::{CidType, ContentId};
use harmony_content::dag;
use harmony_zenoh::namespace::announce;

/// Trait for announcing content availability on the mesh.
///
/// Production implementations publish via Zenoh; tests inject a mock.
pub trait ContentAnnouncer {
    /// Announce a payload under the given key expression.
    fn announce(&self, key_expr: &str, payload: &[u8]) -> Result<(), String>;
}

/// Publishes NAR archives into the Harmony content mesh.
///
/// Chunks NAR data into a content-addressed Merkle DAG, stores the blobs
/// locally, and announces both the store-path mapping and individual blob
/// availability via a [`ContentAnnouncer`].
pub struct NarPublisher<A: ContentAnnouncer> {
    announcer: A,
    blob_store: MemoryBlobStore,
    chunker_config: ChunkerConfig,
    published_paths: HashMap<String, ContentId>,
}

impl<A: ContentAnnouncer> NarPublisher<A> {
    /// Create a new publisher with the given announcer and default chunker config.
    pub fn new(announcer: A) -> Self {
        Self {
            announcer,
            blob_store: MemoryBlobStore::new(),
            chunker_config: ChunkerConfig::DEFAULT,
            published_paths: HashMap::new(),
        }
    }

    /// Publish a NAR archive, returning its root content ID.
    ///
    /// 1. Chunks the NAR via `dag::ingest`
    /// 2. Records the store-path-to-root-CID mapping
    /// 3. Announces the store path mapping on `harmony/nix/store/{store_hash}`
    /// 4. Walks the DAG and announces each blob on `harmony/announce/{cid_hex}`
    /// 5. If the root is a bundle (multi-chunk), announces the bundle itself
    pub fn publish(
        &mut self,
        store_path_name: &str,
        nar_bytes: &[u8],
    ) -> Result<ContentId, String> {
        // Validate store path format FIRST — before any mutation.
        if store_path_name.len() < 33 || store_path_name.as_bytes()[32] != b'-' {
            return Err(format!(
                "store path name does not have expected '<32-char-hash>-<name>' format: {:?}",
                store_path_name
            ));
        }
        let store_hash = &store_path_name[..32];

        // Ingest into the DAG (blob_store mutation is harmless on error —
        // content-addressed blobs are just cached data, not mappings).
        let root_cid = dag::ingest(nar_bytes, &self.chunker_config, &mut self.blob_store)
            .map_err(|e| format!("ingest failed: {e}"))?;

        // Announce store path mapping: key = harmony/nix/store/{store_hash},
        // payload = root CID as hex.
        let root_cid_hex = hex::encode(root_cid.to_bytes());
        let store_key = format!("harmony/nix/store/{store_hash}");
        self.announcer
            .announce(&store_key, root_cid_hex.as_bytes())?;

        // Walk the DAG to collect all leaf blob CIDs.
        let blob_cids =
            dag::walk(&root_cid, &self.blob_store).map_err(|e| format!("DAG walk failed: {e}"))?;

        // Announce each blob.
        for cid in &blob_cids {
            let cid_hex = hex::encode(cid.to_bytes());
            let blob_key = announce::key(&cid_hex);
            let size = cid.payload_size();
            let size_str = size.to_string();
            self.announcer.announce(&blob_key, size_str.as_bytes())?;
        }

        // If root is a bundle (multi-chunk), announce the bundle itself.
        if matches!(root_cid.cid_type(), CidType::Bundle(_)) {
            let bundle_key = announce::key(&root_cid_hex);
            let bundle_size = root_cid.payload_size();
            let bundle_size_str = bundle_size.to_string();
            self.announcer
                .announce(&bundle_key, bundle_size_str.as_bytes())?;
        }

        // Record the mapping only after all announces succeed — prevents
        // get_root_cid() from returning data for an unannounced path.
        self.published_paths
            .insert(store_path_name.to_string(), root_cid);

        Ok(root_cid)
    }

    /// Look up the root CID for a previously published store path.
    pub fn get_root_cid(&self, store_path_name: &str) -> Option<&ContentId> {
        self.published_paths.get(store_path_name)
    }

    /// Retrieve blob data by CID from the local store.
    pub fn get_blob(&self, cid: &ContentId) -> Option<&[u8]> {
        self.blob_store.get(cid)
    }

    /// Read-only view of all published store-path-to-CID mappings.
    pub fn published_paths(&self) -> &HashMap<String, ContentId> {
        &self.published_paths
    }

    /// Read-only access to the underlying blob store (needed for integration tests).
    pub fn blob_store(&self) -> &MemoryBlobStore {
        &self.blob_store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    // ── NAR construction helpers ────────────────────────────────────

    /// Encode a byte slice as a NAR string: 8-byte LE length + data + zero-padding to 8-byte boundary.
    fn nar_string(s: &[u8]) -> Vec<u8> {
        let len = s.len() as u64;
        let padded_len = (s.len() + 7) & !7;
        let mut buf = Vec::with_capacity(8 + padded_len);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s);
        buf.resize(buf.len() + (padded_len - s.len()), 0);
        buf
    }

    /// Build a minimal NAR archive containing a single regular file.
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

    // ── Mock announcer ──────────────────────────────────────────────

    struct MockAnnouncer {
        announcements: Rc<RefCell<Vec<(String, Vec<u8>)>>>,
    }

    impl MockAnnouncer {
        fn new() -> (Self, Rc<RefCell<Vec<(String, Vec<u8>)>>>) {
            let log = Rc::new(RefCell::new(Vec::new()));
            let announcer = MockAnnouncer {
                announcements: Rc::clone(&log),
            };
            (announcer, log)
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

    /// Mock announcer that always fails.
    struct FailingAnnouncer;

    impl ContentAnnouncer for FailingAnnouncer {
        fn announce(&self, _key_expr: &str, _payload: &[u8]) -> Result<(), String> {
            Err("zenoh unavailable".to_string())
        }
    }

    // ── Tests ───────────────────────────────────────────────────────

    #[test]
    fn publish_small_nar() {
        let (announcer, log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);

        let nar = build_test_nar(b"hello mesh");
        let store_path = "abc12345678901234567890123456789-test-pkg";
        let root_cid = publisher.publish(store_path, &nar).unwrap();

        // Root CID must be recorded.
        assert_eq!(publisher.get_root_cid(store_path), Some(&root_cid));

        let announcements = log.borrow();

        // At least 2 announcements: store path mapping + at least one blob.
        assert!(
            announcements.len() >= 2,
            "expected at least 2 announcements, got {}",
            announcements.len()
        );

        // First announcement must be the store path mapping.
        assert_eq!(
            announcements[0].0,
            "harmony/nix/store/abc12345678901234567890123456789"
        );
    }

    #[test]
    fn publish_records_root_cid() {
        let (announcer, _log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);

        let nar = build_test_nar(b"check cid");
        let store_path = "xyz12345678901234567890123456789-cid-pkg";
        let root_cid = publisher.publish(store_path, &nar).unwrap();

        // get_root_cid returns the same CID.
        assert_eq!(publisher.get_root_cid(store_path), Some(&root_cid));

        // get_blob returns data for the root CID.
        assert!(publisher.get_blob(&root_cid).is_some());
    }

    #[test]
    fn publish_blob_announcements_use_correct_key_format() {
        let (announcer, log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);

        let nar = build_test_nar(b"key format check");
        let store_path = "fmt12345678901234567890123456789-fmt-pkg";
        publisher.publish(store_path, &nar).unwrap();

        let announcements = log.borrow();

        // All announcements after the first (store path mapping) must use
        // the announce key format.
        for (key, _) in announcements.iter().skip(1) {
            assert!(
                key.starts_with("harmony/announce/"),
                "blob announcement key should start with 'harmony/announce/', got: {key}"
            );
        }
    }

    #[test]
    fn publish_empty_nar_fails() {
        let (announcer, _log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);

        let store_path = "emp12345678901234567890123456789-empty-pkg";
        let result = publisher.publish(store_path, &[]);

        assert!(result.is_err(), "publishing empty data should fail");
    }

    #[test]
    fn publish_announcer_failure_propagates() {
        let mut publisher = NarPublisher::new(FailingAnnouncer);

        let nar = build_test_nar(b"will fail");
        let store_path = "fail2345678901234567890123456789-fail-pkg";
        let result = publisher.publish(store_path, &nar);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("zenoh unavailable"),
            "error should contain 'zenoh unavailable', got: {err}"
        );

        // Announcer failure must not leak state — no mapping should exist.
        assert!(publisher.published_paths().is_empty());
        assert!(publisher.get_root_cid(store_path).is_none());
    }

    #[test]
    fn round_trip_blob_data() {
        let (announcer, _log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);

        let nar = build_test_nar(b"round trip data");
        let store_path = "rnd12345678901234567890123456789-round-pkg";
        let root_cid = publisher.publish(store_path, &nar).unwrap();

        // Reassemble from the publisher's blob store should recover original NAR.
        let recovered = dag::reassemble(&root_cid, publisher.blob_store()).unwrap();
        assert_eq!(recovered, nar);
    }

    #[test]
    fn publish_rejects_malformed_store_path() {
        let (announcer, _log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"test");

        // Too short.
        let result = publisher.publish("short", &nar);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("format"));

        // 33+ chars but no hyphen at position 32.
        let no_hyphen = "abcdefghijklmnopqrstuvwxyz012345Xrest";
        let result = publisher.publish(no_hyphen, &nar);
        assert!(result.is_err());

        // Exactly 32 chars (missing hyphen + name).
        let result = publisher.publish("abc12345678901234567890123456789", &nar);
        assert!(result.is_err());
    }

    #[test]
    fn publish_validation_failure_does_not_leak_state() {
        let (announcer, log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"should not leak");

        // Attempt to publish with a malformed store path.
        let result = publisher.publish("short", &nar);
        assert!(result.is_err());

        // No mappings should exist — validation failed before mutation.
        assert!(publisher.published_paths().is_empty());

        // No announcements should have been made.
        assert!(log.borrow().is_empty());
    }
}
