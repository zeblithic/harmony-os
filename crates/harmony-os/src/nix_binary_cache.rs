// SPDX-License-Identifier: GPL-2.0-or-later

//! BinaryCacheServer — sans-I/O Nix binary cache protocol handler.
//!
//! Routes request paths to narinfo responses, raw NAR data, or cache
//! metadata. Records misses for background fetch by NixStoreFetcher.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use harmony_microkernel::nar::NarError;
use harmony_microkernel::nix_store_server::NixStoreServer;

use crate::narinfo::serialize_narinfo;

/// Response from a binary cache request.
#[derive(Debug, PartialEq, Eq)]
pub enum CacheResponse {
    /// narinfo text (Content-Type: text/x-nix-narinfo).
    Narinfo(String),
    /// Raw NAR bytes (Content-Type: application/x-nix-nar).
    ///
    /// This clones the full NAR blob from `NixStoreServer`. The expected
    /// usage is write-to-socket-then-drop — callers should not retain the
    /// `Vec` longer than necessary.
    NarData(Vec<u8>),
    /// nix-cache-info metadata (Content-Type: text/x-nix-cache-info).
    CacheInfo(String),
    /// Store path not found. Miss recorded for background fetch.
    NotFound,
    /// Malformed request path.
    BadRequest,
}

/// Entry in the hash index: full store path name + precomputed NAR SHA-256.
struct IndexEntry {
    name: Arc<str>,
    nar_sha256: [u8; 32],
    nar_size: u64,
}

/// Sans-I/O Nix binary cache protocol handler.
pub struct BinaryCacheServer {
    server: NixStoreServer,
    /// 32-char store hash → precomputed narinfo data.
    hash_index: HashMap<String, IndexEntry>,
    misses: BTreeSet<String>,
}

/// Validate that a hash string is 32 lowercase-alphanumeric characters.
/// Nix store hashes use the nix base32 alphabet (subset of lowercase + digits).
fn is_valid_store_hash(hash: &str) -> bool {
    hash.len() == 32
        && hash
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

impl BinaryCacheServer {
    /// Create a new binary cache server from an existing NixStoreServer.
    ///
    /// Builds the hash index (including precomputed SHA-256 digests) by
    /// scanning existing store path names.
    pub fn new(server: NixStoreServer) -> Self {
        let mut hash_index = HashMap::new();
        for name in server.store_path_names() {
            if name.len() >= 33 && name.as_bytes()[32] == b'-' {
                let hash = name[..32].to_string();
                let nar_blob = server.get_nar_blob(name).unwrap();
                let sha256: [u8; 32] = Sha256::digest(nar_blob).into();
                let nar_size = nar_blob.len() as u64;
                hash_index.insert(
                    hash,
                    IndexEntry {
                        name: Arc::clone(name),
                        nar_sha256: sha256,
                        nar_size,
                    },
                );
            }
        }
        Self {
            server,
            hash_index,
            misses: BTreeSet::new(),
        }
    }

    /// Handle a binary cache request path.
    pub fn handle_request(&mut self, path: &str) -> CacheResponse {
        if path == "/nix-cache-info" {
            return CacheResponse::CacheInfo(
                "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n".to_string(),
            );
        }

        if let Some(hash) = path
            .strip_suffix(".narinfo")
            .and_then(|p| p.strip_prefix('/'))
        {
            if !is_valid_store_hash(hash) {
                return CacheResponse::BadRequest;
            }
            return match self.hash_index.get(hash) {
                Some(entry) => {
                    let text = serialize_narinfo(&entry.name, &entry.nar_sha256, entry.nar_size);
                    CacheResponse::Narinfo(text)
                }
                None => {
                    self.misses.insert(hash.to_string());
                    CacheResponse::NotFound
                }
            };
        }

        if let Some(rest) = path.strip_prefix("/nar/") {
            let name = match rest.strip_suffix(".nar") {
                Some(n) => n,
                None => return CacheResponse::BadRequest,
            };
            return match self.server.get_nar_blob(name) {
                Some(blob) => CacheResponse::NarData(blob.to_vec()),
                None => CacheResponse::NotFound,
            };
        }

        CacheResponse::NotFound
    }

    /// Drain recorded miss hashes for background fetch processing.
    ///
    /// Returns 32-character store hash strings (not full store path names).
    /// These **cannot** be passed directly to `NixStoreFetcher::fetch_nar`,
    /// which expects the full `<hash>-<name>` format. A consumer must:
    ///
    /// 1. Fetch `{cache_url}/{hash}.narinfo` to discover the full `StorePath`
    /// 2. Fetch + decompress + verify the NAR via the existing fetcher logic
    /// 3. Call [`Self::import_nar`] with the full name and NAR bytes
    pub fn drain_misses(&mut self) -> Vec<String> {
        core::mem::take(&mut self.misses).into_iter().collect()
    }

    /// Import a NAR into the underlying server and update the hash index.
    pub fn import_nar(&mut self, name: &str, nar_bytes: Vec<u8>) -> Result<(), NarError> {
        let sha256: [u8; 32] = Sha256::digest(&nar_bytes).into();
        let nar_size = nar_bytes.len() as u64;
        self.server.import_nar(name, nar_bytes)?;
        if name.len() >= 33 && name.as_bytes()[32] == b'-' {
            let hash = name[..32].to_string();
            self.misses.remove(&hash);
            self.hash_index.insert(
                hash,
                IndexEntry {
                    name: Arc::from(name),
                    nar_sha256: sha256,
                    nar_size,
                },
            );
        }
        Ok(())
    }

    /// Check whether a store path is available.
    pub fn has_store_path(&self, name: &str) -> bool {
        self.server.has_store_path(name)
    }

    /// Drain miss events from the underlying 9P server.
    ///
    /// These are full store-path-name misses recorded by `NixStoreServer`
    /// when clients walk non-existent paths via the kernel's 9P layer —
    /// distinct from the hash-only misses from [`Self::drain_misses`].
    pub fn drain_store_misses(&mut self) -> Vec<Arc<str>> {
        self.server.drain_misses()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_server() -> BinaryCacheServer {
        BinaryCacheServer::new(NixStoreServer::new())
    }

    // NAR construction helper — local copy, since harmony-microkernel's
    // test helpers are pub(crate) and #[cfg(test)] (inaccessible from here).
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

    fn build_server_with_nar(name: &str, content: &[u8]) -> BinaryCacheServer {
        let mut nix = NixStoreServer::new();
        nix.import_nar(name, build_test_nar(content)).unwrap();
        BinaryCacheServer::new(nix)
    }

    #[test]
    fn handle_cache_info() {
        let mut srv = build_server();
        let resp = srv.handle_request("/nix-cache-info");
        match resp {
            CacheResponse::CacheInfo(text) => {
                assert!(text.contains("StoreDir: /nix/store"));
                assert!(text.contains("WantMassQuery: 0"));
                assert!(text.contains("Priority: 30"));
            }
            other => panic!("expected CacheInfo, got {other:?}"),
        }
    }

    #[test]
    fn handle_narinfo_request() {
        let mut srv = build_server_with_nar("abc12345678901234567890123456789-hello", b"data");
        let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
        match resp {
            CacheResponse::Narinfo(text) => {
                assert!(
                    text.contains("StorePath: /nix/store/abc12345678901234567890123456789-hello")
                );
                assert!(text.contains("URL: nar/abc12345678901234567890123456789-hello.nar"));
                assert!(text.contains("Compression: none"));
                assert!(text.contains("NarHash: sha256:"));
                assert!(text.contains("NarSize:"));
            }
            other => panic!("expected Narinfo, got {other:?}"),
        }
    }

    #[test]
    fn handle_narinfo_not_found_records_miss() {
        let mut srv = build_server();
        let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
        assert_eq!(resp, CacheResponse::NotFound);
        let misses = srv.drain_misses();
        assert_eq!(misses, vec!["abc12345678901234567890123456789"]);
    }

    #[test]
    fn handle_narinfo_bad_hash_length() {
        let mut srv = build_server();
        // Too short.
        assert_eq!(
            srv.handle_request("/abc.narinfo"),
            CacheResponse::BadRequest
        );
        // Non-alphanumeric chars.
        assert_eq!(
            srv.handle_request("/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.narinfo"),
            CacheResponse::BadRequest
        );
        // Uppercase rejected (nix base32 is lowercase only).
        assert_eq!(
            srv.handle_request("/ABCDEF00ABCDEF00ABCDEF00ABCDEF00.narinfo"),
            CacheResponse::BadRequest
        );
    }

    #[test]
    fn handle_nar_data_request() {
        let name = "abc12345678901234567890123456789-hello";
        let content = b"nar file content";
        let mut srv = build_server_with_nar(name, content);
        let resp = srv.handle_request(&format!("/nar/{name}.nar"));
        match resp {
            CacheResponse::NarData(bytes) => {
                assert!(!bytes.is_empty());
                assert_eq!(bytes, build_test_nar(content));
            }
            other => panic!("expected NarData, got {other:?}"),
        }
    }

    #[test]
    fn handle_nar_not_found() {
        let mut srv = build_server();
        let resp = srv.handle_request("/nar/nonexistent-pkg.nar");
        assert_eq!(resp, CacheResponse::NotFound);
    }

    #[test]
    fn handle_nar_missing_suffix() {
        let mut srv = build_server();
        // Missing .nar suffix is a malformed request, not a lookup miss.
        assert_eq!(
            srv.handle_request("/nar/some-package"),
            CacheResponse::BadRequest
        );
    }

    #[test]
    fn hash_index_populated_on_import() {
        let mut srv = build_server();
        let name = "imp12345678901234567890123456789-imported";
        srv.import_nar(name, build_test_nar(b"imported data"))
            .unwrap();
        let resp = srv.handle_request("/imp12345678901234567890123456789.narinfo");
        match resp {
            CacheResponse::Narinfo(text) => assert!(text.contains(name)),
            other => panic!("expected Narinfo after import, got {other:?}"),
        }
    }

    #[test]
    fn import_after_miss() {
        let mut srv = build_server();
        let hash = "mis12345678901234567890123456789";
        let name = format!("{hash}-recovered");
        assert_eq!(
            srv.handle_request(&format!("/{hash}.narinfo")),
            CacheResponse::NotFound
        );
        let misses = srv.drain_misses();
        assert_eq!(misses, vec![hash]);
        srv.import_nar(&name, build_test_nar(b"recovered")).unwrap();
        match srv.handle_request(&format!("/{hash}.narinfo")) {
            CacheResponse::Narinfo(text) => assert!(text.contains(&name)),
            other => panic!("expected Narinfo after import, got {other:?}"),
        }
        assert!(srv.drain_misses().is_empty());
    }

    #[test]
    fn import_clears_stale_miss() {
        let mut srv = build_server();
        let hash = "stl12345678901234567890123456789";
        let name = format!("{hash}-stale");

        // Miss recorded.
        srv.handle_request(&format!("/{hash}.narinfo"));

        // Import WITHOUT draining first — the miss should be cleared by import.
        srv.import_nar(&name, build_test_nar(b"no longer missing"))
            .unwrap();

        // drain_misses must NOT return the now-imported hash.
        assert!(
            srv.drain_misses().is_empty(),
            "import_nar should clear the stale miss"
        );
    }

    #[test]
    fn has_store_path() {
        let name = "has12345678901234567890123456789-check";
        let mut srv = build_server();
        assert!(!srv.has_store_path(name));
        srv.import_nar(name, build_test_nar(b"check")).unwrap();
        assert!(srv.has_store_path(name));
    }

    #[test]
    fn drain_misses_deduplicates() {
        let mut srv = build_server();
        let hash = "dup12345678901234567890123456789";
        srv.handle_request(&format!("/{hash}.narinfo"));
        srv.handle_request(&format!("/{hash}.narinfo"));
        let misses = srv.drain_misses();
        assert_eq!(misses.len(), 1);
    }
}
