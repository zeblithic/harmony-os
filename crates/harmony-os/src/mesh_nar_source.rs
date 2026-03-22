// SPDX-License-Identifier: GPL-2.0-or-later

//! Mesh NAR source — fetch Nix store paths from the Harmony mesh network.
//!
//! Uses the content-addressed DAG layer (`harmony-content`) and Zenoh key
//! expressions (`harmony-zenoh`) to locate and reassemble NAR archives that
//! have been published to the mesh by [`NarPublisher`](super::nar_publisher).
//!
//! The [`ContentQuerier`] trait abstracts the actual Zenoh query transport,
//! allowing full unit testing with an in-memory mock.

use std::collections::HashSet;

use harmony_content::book::{BookStore, MemoryBookStore};
use harmony_content::bundle;
use harmony_content::cid::{CidType, ContentId};
use harmony_content::dag;
use harmony_zenoh::namespace::content;

// ── ContentQuerier trait ────────────────────────────────────────────

/// Abstract query interface for fetching data from the mesh network.
///
/// Production implementations issue Zenoh `get` queries; test code can
/// use a simple `HashMap`-backed mock.
pub trait ContentQuerier {
    /// Query the mesh for the value at the given key expression.
    ///
    /// Returns `Ok(Some(bytes))` if found, `Ok(None)` if not present,
    /// or `Err` on transport/protocol errors.
    fn query(&self, key_expr: &str) -> Result<Option<Vec<u8>>, String>;
}

// ── MeshNarFetch trait ──────────────────────────────────────────────

/// Trait for fetching NAR bytes from the mesh, used by `NixStoreFetcher`
/// as an alternative source before falling back to HTTP binary caches.
pub trait MeshNarFetch {
    /// Attempt to fetch a NAR archive for the given store path name.
    ///
    /// Returns `Some(nar_bytes)` on success, `None` if the path is not
    /// available on the mesh or any error occurs.
    fn fetch_nar(&self, store_path_name: &str) -> Option<Vec<u8>>;
}

// ── MeshNarSource ───────────────────────────────────────────────────

/// Fetches NAR archives from the Harmony mesh network.
///
/// Given a Nix store path name (e.g. `abc...xyz-hello-2.12.1`), queries
/// the mesh for the root CID mapping, fetches all DAG nodes, and
/// reassembles the original NAR bytes.
///
/// # Trust model
///
/// Every fetched book is content-verified by its CID (the CID *is* the
/// hash of the data). However, the store-path → root-CID mapping is
/// currently unauthenticated: a malicious peer could announce a
/// different root CID for a given store hash. This is acceptable for
/// now because:
///
/// - `NixStoreFetcher` falls back to HTTP (with narinfo hash
///   verification) if mesh-sourced import fails
/// - Future work will add UCAN-signed announcements (separate bead)
///
/// Do **not** trust mesh-sourced NARs in security-critical contexts
/// without additional verification.
pub struct MeshNarSource<Q: ContentQuerier> {
    querier: Q,
}

impl<Q: ContentQuerier> MeshNarSource<Q> {
    /// Create a new mesh NAR source backed by the given querier.
    pub fn new(querier: Q) -> Self {
        Self { querier }
    }

    /// Attempt to fetch a NAR from the mesh, returning the reassembled bytes.
    ///
    /// Returns `Ok(Some(nar_bytes))` on success, `Ok(None)` if the store
    /// path is not published on the mesh, or `Err` on protocol errors.
    pub fn try_fetch(&self, store_path_name: &str) -> Result<Option<Vec<u8>>, String> {
        // 1. Validate store path format: at least 33 chars, hyphen at position 32.
        if store_path_name.len() < 33 || store_path_name.as_bytes()[32] != b'-' {
            return Ok(None);
        }
        let store_hash = &store_path_name[..32];

        // 2. Query the store path mapping to get the root CID hex.
        let mapping_key = format!("harmony/nix/store/{store_hash}");
        let root_cid_hex_bytes = match self.querier.query(&mapping_key)? {
            Some(bytes) => bytes,
            None => return Ok(None), // Not published on the mesh.
        };

        // 3. Decode the root CID from hex.
        let root_cid_hex = String::from_utf8(root_cid_hex_bytes)
            .map_err(|e| format!("root CID hex is not valid UTF-8: {e}"))?;
        let root_cid_bytes: [u8; 32] = hex::decode(&root_cid_hex)
            .map_err(|e| format!("failed to decode root CID hex: {e}"))?
            .try_into()
            .map_err(|v: Vec<u8>| format!("root CID is {} bytes, expected 32", v.len()))?;
        let root_cid = ContentId::from_bytes(root_cid_bytes);

        // 4. Fetch the root book/bundle from the mesh.
        let fetch_key = content::fetch_key(&root_cid_hex);
        let root_data = match self.querier.query(&fetch_key)? {
            Some(data) => data,
            None => return Ok(None), // Root book missing from mesh.
        };

        // 5. Build a temporary store, populate with root data.
        let mut store = MemoryBookStore::new();
        store.store(root_cid, root_data);

        // 6. Recursively fetch all children (with cycle guard).
        let mut visited = HashSet::new();
        self.fetch_children(&root_cid, &mut store, &mut visited)?;

        // 7. Reassemble the original data.
        let reassembled = dag::reassemble(&root_cid, &store)
            .map_err(|e| format!("DAG reassembly failed: {e:?}"))?;

        Ok(Some(reassembled))
    }

    /// Recursively fetch all DAG children that are not yet in the store.
    ///
    /// The `visited` set prevents infinite recursion from malicious or
    /// buggy peers that return self-referential bundle CIDs.
    fn fetch_children(
        &self,
        cid: &ContentId,
        store: &mut MemoryBookStore,
        visited: &mut HashSet<ContentId>,
    ) -> Result<(), String> {
        if !visited.insert(*cid) {
            return Ok(()); // Already processed — break potential cycle.
        }

        match cid.cid_type() {
            CidType::Book if !store.contains(cid) => {
                // Leaf node — fetch if not already present.
                let cid_hex = hex::encode(cid.to_bytes());
                let key = content::fetch_key(&cid_hex);
                let data = self
                    .querier
                    .query(&key)?
                    .ok_or_else(|| format!("mesh missing book {cid_hex}"))?;
                store.store(*cid, data);
            }
            CidType::Book => { /* already in store */ }
            CidType::Bundle(_) => {
                // Interior node — parse children, fetch each, then recurse.
                let bundle_data = store
                    .get(cid)
                    .ok_or_else(|| format!("bundle {cid:?} not in store"))?
                    .to_vec(); // Clone to release borrow on store.
                let children = bundle::parse_bundle(&bundle_data)
                    .map_err(|e| format!("failed to parse bundle: {e:?}"))?;

                for child in children {
                    if child.cid_type() == CidType::InlineData {
                        continue; // Metadata entries carry no data.
                    }
                    if !store.contains(child) {
                        let child_hex = hex::encode(child.to_bytes());
                        let key = content::fetch_key(&child_hex);
                        let data = self
                            .querier
                            .query(&key)?
                            .ok_or_else(|| format!("mesh missing {child_hex}"))?;
                        store.store(*child, data);
                    }
                    self.fetch_children(child, store, visited)?;
                }
            }
            CidType::InlineData => {
                // Skip — metadata entries don't carry data.
            }
            _ => {
                // Reserved types — skip.
            }
        }
        Ok(())
    }
}

impl<Q: ContentQuerier> MeshNarFetch for MeshNarSource<Q> {
    fn fetch_nar(&self, store_path_name: &str) -> Option<Vec<u8>> {
        match self.try_fetch(store_path_name) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("[mesh-nar] fetch failed for {store_path_name}: {e}");
                None
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use harmony_content::chunker::ChunkerConfig;

    // ── Mock querier ────────────────────────────────────────────────

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

    // ── Error querier (always returns Err) ──────────────────────────

    struct ErrorQuerier;

    impl ContentQuerier for ErrorQuerier {
        fn query(&self, _key_expr: &str) -> Result<Option<Vec<u8>>, String> {
            Err("simulated network failure".into())
        }
    }

    // ── Test helper: populate a MockQuerier with a NAR's DAG ────────

    /// Ingest data into a [`MemoryBookStore`], then populate a MockQuerier
    /// with all the key-value pairs needed to fetch it from the mesh.
    fn populate_querier_from_data(data: &[u8], store_path_name: &str) -> MockQuerier {
        let mut store = MemoryBookStore::new();

        // Use a small chunker config so even modest test data gets split.
        let config = ChunkerConfig {
            min_chunk: 64,
            avg_chunk: 128,
            max_chunk: 256,
        };

        let root_cid = dag::ingest(data, &config, &mut store).unwrap();
        let root_cid_hex = hex::encode(root_cid.to_bytes());

        let mut map = HashMap::new();

        // Store path mapping: harmony/nix/store/{store_hash} → root CID hex.
        let store_hash = &store_path_name[..32];
        let mapping_key = format!("harmony/nix/store/{store_hash}");
        map.insert(mapping_key, root_cid_hex.as_bytes().to_vec());

        // Insert root book/bundle under its fetch key.
        let root_fetch_key = content::fetch_key(&root_cid_hex);
        map.insert(root_fetch_key, store.get(&root_cid).unwrap().to_vec());

        // Walk the DAG and insert every node under its fetch key.
        insert_dag_nodes(&root_cid, &store, &mut map);

        MockQuerier { data: map }
    }

    /// Recursively insert all DAG nodes into the map.
    fn insert_dag_nodes(
        cid: &ContentId,
        store: &MemoryBookStore,
        map: &mut HashMap<String, Vec<u8>>,
    ) {
        match cid.cid_type() {
            CidType::Book => {
                if let Some(data) = store.get(cid) {
                    let hex_key = hex::encode(cid.to_bytes());
                    let fetch_key = content::fetch_key(&hex_key);
                    map.entry(fetch_key).or_insert_with(|| data.to_vec());
                }
            }
            CidType::Bundle(_) => {
                if let Some(bundle_data) = store.get(cid) {
                    let hex_key = hex::encode(cid.to_bytes());
                    let fetch_key = content::fetch_key(&hex_key);
                    map.entry(fetch_key).or_insert_with(|| bundle_data.to_vec());

                    if let Ok(children) = bundle::parse_bundle(bundle_data) {
                        for child in children {
                            if child.cid_type() != CidType::InlineData {
                                insert_dag_nodes(child, store, map);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // ── NAR construction helper ─────────────────────────────────────

    /// Encode a byte slice as a NAR string: 8-byte LE length + data + padding.
    fn nar_string(s: &[u8]) -> Vec<u8> {
        let len = s.len() as u64;
        let padded_len = (s.len() + 7) & !7;
        let mut buf = Vec::with_capacity(8 + padded_len);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s);
        let padding = padded_len - s.len();
        buf.resize(buf.len() + padding, 0);
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

    // ── Tests ───────────────────────────────────────────────────────

    #[test]
    fn fetch_from_mesh_round_trip() {
        let store_path_name = "abc12345678901234567890123456789-hello-pkg";
        let nar_bytes = build_test_nar(b"hello from the mesh network");

        let querier = populate_querier_from_data(&nar_bytes, store_path_name);
        let source = MeshNarSource::new(querier);

        let result = source.try_fetch(store_path_name).unwrap();
        assert_eq!(result, Some(nar_bytes));
    }

    #[test]
    fn fetch_returns_none_when_not_on_mesh() {
        let querier = MockQuerier {
            data: HashMap::new(),
        };
        let source = MeshNarSource::new(querier);

        let store_path_name = "abc12345678901234567890123456789-missing-pkg";
        let result = source.try_fetch(store_path_name).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn fetch_returns_none_for_malformed_store_path() {
        let querier = MockQuerier {
            data: HashMap::new(),
        };
        let source = MeshNarSource::new(querier);

        // Too short.
        assert_eq!(source.try_fetch("short").unwrap(), None);

        // 33+ chars but no hyphen at position 32.
        let no_hyphen = "abcdefghijklmnopqrstuvwxyz012345Xrest";
        assert_eq!(source.try_fetch(no_hyphen).unwrap(), None);
    }

    #[test]
    fn fetch_returns_none_when_root_book_missing() {
        let store_path_name = "abc12345678901234567890123456789-ghost-pkg";

        // Create a valid CID mapping but don't populate the actual book.
        let mut map = HashMap::new();
        let fake_cid = ContentId::for_book(b"phantom data", Default::default()).unwrap();
        let fake_hex = hex::encode(fake_cid.to_bytes());
        let store_hash = &store_path_name[..32];
        map.insert(
            format!("harmony/nix/store/{store_hash}"),
            fake_hex.as_bytes().to_vec(),
        );
        // Intentionally do NOT insert the fetch key for the book.

        let querier = MockQuerier { data: map };
        let source = MeshNarSource::new(querier);

        let result = source.try_fetch(store_path_name).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn mesh_nar_fetch_trait_returns_none_on_error() {
        let source = MeshNarSource::new(ErrorQuerier);

        let store_path_name = "abc12345678901234567890123456789-error-pkg";
        // MeshNarFetch::fetch_nar should return None (not panic) on error.
        let result = source.fetch_nar(store_path_name);
        assert_eq!(result, None);
    }

    /// End-to-end: publish via NarPublisher, then fetch via MeshNarSource.
    #[test]
    fn end_to_end_publish_then_fetch() {
        use crate::nar_publisher::{ContentAnnouncer, NarPublisher};

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

        // Populate mock querier with publisher's book store data.
        let mut querier = MockQuerier::new();
        let store_hash = &store_path[..32];
        let root_cid_hex = hex::encode(root_cid.to_bytes());

        // Store path → root CID mapping.
        querier.insert(
            &format!("harmony/nix/store/{store_hash}"),
            root_cid_hex.as_bytes().to_vec(),
        );

        // Root book/bundle.
        let root_fetch_key = content::fetch_key(&root_cid_hex);
        querier.insert(
            &root_fetch_key,
            publisher.get_book(&root_cid).unwrap().to_vec(),
        );

        // All leaf books via dag::walk on publisher's book store.
        let book_cids = dag::walk(&root_cid, publisher.book_store()).unwrap();
        for cid in &book_cids {
            let cid_hex = hex::encode(cid.to_bytes());
            let fetch_key = content::fetch_key(&cid_hex);
            querier.insert(&fetch_key, publisher.get_book(cid).unwrap().to_vec());
        }

        // Fetch side.
        let source = MeshNarSource::new(querier);
        let fetched = source.fetch_nar(store_path);
        assert_eq!(fetched, Some(nar));
    }
}
