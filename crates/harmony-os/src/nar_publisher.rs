// SPDX-License-Identifier: GPL-2.0-or-later

//! NarPublisher — publish NAR archives into the Harmony mesh via content-addressed DAG.
//!
//! Chunks a NAR file into a Merkle DAG using [`harmony_content::dag::ingest`],
//! announces the store-path-to-CID mapping and each book's availability via a
//! pluggable [`ContentAnnouncer`] trait (backed by Zenoh in production).

use std::collections::HashMap;

use harmony_content::book::{BookStore, MemoryBookStore};
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
/// Chunks NAR data into a content-addressed Merkle DAG, stores the books
/// locally, and announces both the store-path mapping and individual book
/// availability via a [`ContentAnnouncer`].
///
/// Generic over the book store backend: defaults to [`MemoryBookStore`]
/// for backward compatibility, but accepts [`DiskBookStore`](crate::disk_book_store::DiskBookStore)
/// (or any `BookStore` impl) for durable book storage across restarts.
///
/// **Persistence scope:** Only the underlying book chunks are persisted
/// by the store backend. The in-memory `published_paths` map (store-path
/// → root CID) is **not** written to disk and will be empty after a
/// process restart. Callers that need to restore the mapping must
/// re-publish paths or separately persist this mapping.
/// [`PersistentNarStore`](crate::persistent_nar_store::PersistentNarStore)
/// handles the NAR-level persistence independently.
pub struct NarPublisher<A: ContentAnnouncer, S: BookStore = MemoryBookStore> {
    announcer: A,
    book_store: S,
    chunker_config: ChunkerConfig,
    published_paths: HashMap<String, ContentId>,
}

impl<A: ContentAnnouncer> NarPublisher<A, MemoryBookStore> {
    /// Create a new publisher with the given announcer, in-memory book store,
    /// and default chunker config.
    pub fn new(announcer: A) -> Self {
        Self {
            announcer,
            book_store: MemoryBookStore::new(),
            chunker_config: ChunkerConfig::DEFAULT,
            published_paths: HashMap::new(),
        }
    }
}

impl<A: ContentAnnouncer, S: BookStore> NarPublisher<A, S> {
    /// Create a new publisher with a caller-provided book store.
    pub fn with_store(announcer: A, store: S) -> Self {
        Self {
            announcer,
            book_store: store,
            chunker_config: ChunkerConfig::DEFAULT,
            published_paths: HashMap::new(),
        }
    }

    /// Publish a NAR archive, returning its root content ID.
    ///
    /// 1. Chunks the NAR via `dag::ingest`
    /// 2. Records the store-path-to-root-CID mapping
    /// 3. Announces the store path mapping on `harmony/nix/store/{store_hash}`
    ///    (payload = `<cid_hex>` for no refs, or `<cid_hex>\n<ref1>\n<ref2>...`)
    /// 4. Walks the DAG and announces each book on `harmony/announce/{cid_hex}`
    /// 5. If the root is a bundle (multi-chunk), announces the bundle itself
    pub fn publish(
        &mut self,
        store_path_name: &str,
        nar_bytes: &[u8],
        references: Option<Vec<String>>,
    ) -> Result<ContentId, String> {
        // Validate store path format FIRST — before any mutation.
        if store_path_name.len() < 33 || store_path_name.as_bytes()[32] != b'-' {
            return Err(format!(
                "store path name does not have expected '<32-char-hash>-<name>' format: {:?}",
                store_path_name
            ));
        }
        let store_hash = &store_path_name[..32];

        // Ingest into the DAG (book_store mutation is harmless on error —
        // content-addressed books are just cached data, not mappings).
        let root_cid = dag::ingest(nar_bytes, &self.chunker_config, &mut self.book_store)
            .map_err(|e| format!("ingest failed: {e}"))?;

        // Announce store path mapping: key = harmony/nix/store/{store_hash},
        // payload = root CID as hex, optionally followed by newline-separated
        // references (e.g. `<cid_hex>\n<ref1>\n<ref2>`).
        let root_cid_hex = hex::encode(root_cid.to_bytes());
        let store_key = format!("harmony/nix/store/{store_hash}");
        let mut payload = root_cid_hex.clone();
        if let Some(refs) = &references {
            // Trailing \n distinguishes Some(vec![]) from None:
            // - None → "cid_hex" (no newline)
            // - Some(vec![]) → "cid_hex\n" (newline, no refs)
            // - Some(refs) → "cid_hex\nref1\nref2"
            payload.push('\n');
            for (i, r) in refs.iter().enumerate() {
                assert!(
                    !r.contains('\n') && !r.contains('\r') && !r.contains('\0'),
                    "reference must not contain control characters: {r:?}"
                );
                if i > 0 {
                    payload.push('\n');
                }
                payload.push_str(r);
            }
        }
        self.announcer.announce(&store_key, payload.as_bytes())?;

        // Walk the DAG to collect all leaf book CIDs.
        let book_cids =
            dag::walk(&root_cid, &self.book_store).map_err(|e| format!("DAG walk failed: {e}"))?;

        // Announce each book.
        for cid in &book_cids {
            let cid_hex = hex::encode(cid.to_bytes());
            let book_key = announce::key(&cid_hex);
            let size = cid.payload_size();
            let size_str = size.to_string();
            self.announcer.announce(&book_key, size_str.as_bytes())?;
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

    /// Retrieve book data by CID from the local store.
    pub fn get_book(&self, cid: &ContentId) -> Option<&[u8]> {
        self.book_store.get(cid)
    }

    /// Read-only view of all published store-path-to-CID mappings.
    pub fn published_paths(&self) -> &HashMap<String, ContentId> {
        &self.published_paths
    }

    /// Read-only access to the underlying book store.
    pub fn book_store(&self) -> &S {
        &self.book_store
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

    type AnnouncementLog = Rc<RefCell<Vec<(String, Vec<u8>)>>>;

    struct MockAnnouncer {
        announcements: AnnouncementLog,
    }

    impl MockAnnouncer {
        fn new() -> (Self, AnnouncementLog) {
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
        let root_cid = publisher.publish(store_path, &nar, None).unwrap();

        // Root CID must be recorded.
        assert_eq!(publisher.get_root_cid(store_path), Some(&root_cid));

        let announcements = log.borrow();

        // At least 2 announcements: store path mapping + at least one book.
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
        let root_cid = publisher.publish(store_path, &nar, None).unwrap();

        // get_root_cid returns the same CID.
        assert_eq!(publisher.get_root_cid(store_path), Some(&root_cid));

        // get_book returns data for the root CID.
        assert!(publisher.get_book(&root_cid).is_some());
    }

    #[test]
    fn publish_book_announcements_use_correct_key_format() {
        let (announcer, log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);

        let nar = build_test_nar(b"key format check");
        let store_path = "fmt12345678901234567890123456789-fmt-pkg";
        publisher.publish(store_path, &nar, None).unwrap();

        let announcements = log.borrow();

        // All announcements after the first (store path mapping) must use
        // the announce key format.
        for (key, _) in announcements.iter().skip(1) {
            assert!(
                key.starts_with("harmony/announce/"),
                "book announcement key should start with 'harmony/announce/', got: {key}"
            );
        }
    }

    #[test]
    fn publish_empty_nar_fails() {
        let (announcer, _log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);

        let store_path = "emp12345678901234567890123456789-empty-pkg";
        let result = publisher.publish(store_path, &[], None);

        assert!(result.is_err(), "publishing empty data should fail");
    }

    #[test]
    fn publish_announcer_failure_propagates() {
        let mut publisher = NarPublisher::new(FailingAnnouncer);

        let nar = build_test_nar(b"will fail");
        let store_path = "fail2345678901234567890123456789-fail-pkg";
        let result = publisher.publish(store_path, &nar, None);

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
        let root_cid = publisher.publish(store_path, &nar, None).unwrap();

        // Reassemble from the publisher's book store should recover original NAR.
        let recovered = dag::reassemble(&root_cid, publisher.book_store()).unwrap();
        assert_eq!(recovered, nar);
    }

    #[test]
    fn publish_rejects_malformed_store_path() {
        let (announcer, _log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"test");

        // Too short.
        let result = publisher.publish("short", &nar, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("format"));

        // 33+ chars but no hyphen at position 32.
        let no_hyphen = "abcdefghijklmnopqrstuvwxyz012345Xrest";
        let result = publisher.publish(no_hyphen, &nar, None);
        assert!(result.is_err());

        // Exactly 32 chars (missing hyphen + name).
        let result = publisher.publish("abc12345678901234567890123456789", &nar, None);
        assert!(result.is_err());
    }

    #[test]
    fn publish_validation_failure_does_not_leak_state() {
        let (announcer, log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"should not leak");

        // Attempt to publish with a malformed store path.
        let result = publisher.publish("short", &nar, None);
        assert!(result.is_err());

        // No mappings should exist — validation failed before mutation.
        assert!(publisher.published_paths().is_empty());

        // No announcements should have been made.
        assert!(log.borrow().is_empty());
    }

    // ── DiskBookStore integration ──────────────────────────────────

    #[test]
    fn publish_with_disk_book_store() {
        use crate::disk_book_store::DiskBookStore;
        let tmp = tempfile::TempDir::new().unwrap();
        let disk_store = DiskBookStore::open(tmp.path()).unwrap();

        let (announcer, _log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::with_store(announcer, disk_store);

        let nar = build_test_nar(b"persistent publish");
        let store_path = "dsk12345678901234567890123456789-disk-pkg";
        let root_cid = publisher.publish(store_path, &nar, None).unwrap();

        // Books should be on disk.
        let file_count = std::fs::read_dir(tmp.path()).unwrap().count();
        assert!(file_count >= 1, "at least one book file on disk");

        // Round-trip: reassemble from persistent store.
        let recovered = dag::reassemble(&root_cid, publisher.book_store()).unwrap();
        assert_eq!(recovered, nar);
    }

    #[test]
    fn publish_with_references_encodes_in_payload() {
        let (announcer, log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"ref test");
        let store_path = "abc12345678901234567890123456789-ref-pkg";
        let refs = Some(vec!["dep123-glibc".to_string(), "dep456-gcc".to_string()]);
        publisher.publish(store_path, &nar, refs).unwrap();
        let announcements = log.borrow();
        let payload = String::from_utf8(announcements[0].1.clone()).unwrap();
        let lines: Vec<&str> = payload.lines().collect();
        assert!(lines.len() >= 3, "expected CID + 2 refs, got {lines:?}");
        assert_eq!(lines[0].len(), 64); // CID hex
        assert_eq!(lines[1], "dep123-glibc");
        assert_eq!(lines[2], "dep456-gcc");
    }

    #[test]
    fn publish_without_references_single_line_payload() {
        let (announcer, log) = MockAnnouncer::new();
        let mut publisher = NarPublisher::new(announcer);
        let nar = build_test_nar(b"no ref");
        let store_path = "abc12345678901234567890123456789-noref-pkg";
        publisher.publish(store_path, &nar, None).unwrap();
        let announcements = log.borrow();
        let payload = String::from_utf8(announcements[0].1.clone()).unwrap();
        assert!(
            !payload.contains('\n'),
            "no-ref payload should be single line"
        );
    }
}
