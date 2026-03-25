// SPDX-License-Identifier: GPL-2.0-or-later

//! BinaryCacheServer — sans-I/O Nix binary cache protocol handler.
//!
//! Routes request paths to narinfo responses, raw NAR data, or cache
//! metadata. Records misses for background fetch by NixStoreFetcher.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use harmony_identity::PrivateIdentity;
use sha2::{Digest, Sha256};

use harmony_microkernel::nar::NarError;
use harmony_microkernel::nix_store_server::NixStoreServer;

use crate::narinfo::{compute_narinfo_fingerprint, serialize_narinfo};
use crate::nix_base32::encode_nix_base32;

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
    references: Option<Vec<String>>,
}

/// Sans-I/O Nix binary cache protocol handler.
pub struct BinaryCacheServer {
    server: NixStoreServer,
    /// 32-char store hash → precomputed narinfo data.
    hash_index: HashMap<String, IndexEntry>,
    misses: BTreeSet<String>,
    signing: Option<(String, PrivateIdentity)>,
}

/// Validate that a hash string is 32 lowercase-alphanumeric characters.
/// Nix store hashes use the nix base32 alphabet (subset of lowercase + digits).
fn is_valid_store_hash(hash: &str) -> bool {
    hash.len() == 32
        && hash
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Sanitize a reference list: drop entries that are empty, contain NUL,
/// or contain any whitespace. These would corrupt space-separated or
/// newline-separated serialization formats.
///
/// If all entries are invalid and dropped, returns `None` (unknown) rather
/// than `Some(vec![])` (zero deps) to preserve three-state semantics.
fn sanitize_refs(refs: Option<Vec<String>>) -> Option<Vec<String>> {
    refs.and_then(|r| {
        let orig_len = r.len();
        let filtered: Vec<String> = r
            .into_iter()
            .filter(|s| !s.is_empty() && !s.contains('\0') && !s.chars().any(|c| c.is_whitespace()))
            .collect();
        if filtered.len() < orig_len && filtered.is_empty() {
            // All entries were invalid — treat as unknown rather than zero-deps.
            None
        } else {
            Some(filtered)
        }
    })
}

impl BinaryCacheServer {
    /// Create a new binary cache server from an existing NixStoreServer.
    ///
    /// Builds the hash index (including precomputed SHA-256 digests) by
    /// scanning existing store path names.
    pub fn new(server: NixStoreServer) -> Self {
        Self::new_with_refs(server, std::collections::HashMap::new())
    }

    /// Create a new binary cache server from an existing NixStoreServer with
    /// pre-populated reference metadata.
    ///
    /// `ref_map` maps full store path names (e.g. `<hash>-<name>`) to their
    /// list of runtime references. Any name not present in the map will have
    /// `None` references in the index.
    pub fn new_with_refs(
        server: NixStoreServer,
        ref_map: std::collections::HashMap<String, Vec<String>>,
    ) -> Self {
        let mut hash_index = HashMap::new();
        for name in server.store_path_names() {
            if name.len() >= 33 && name.as_bytes()[32] == b'-' {
                let hash = name[..32].to_string();
                let nar_blob = server.get_nar_blob(name).unwrap();
                let sha256: [u8; 32] = Sha256::digest(nar_blob).into();
                let nar_size = nar_blob.len() as u64;
                let references = sanitize_refs(ref_map.get(name.as_ref()).cloned());
                hash_index.insert(
                    hash,
                    IndexEntry {
                        name: Arc::clone(name),
                        nar_sha256: sha256,
                        nar_size,
                        references,
                    },
                );
            }
        }
        Self {
            server,
            hash_index,
            misses: BTreeSet::new(),
            signing: None,
        }
    }

    /// Create a binary cache server with signing and pre-populated references.
    pub fn new_with_signing(
        server: NixStoreServer,
        ref_map: std::collections::HashMap<String, Vec<String>>,
        key_name: String,
        identity: PrivateIdentity,
    ) -> Self {
        let mut srv = Self::new_with_refs(server, ref_map);
        srv.signing = Some((key_name, identity));
        srv
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
                    let sig = self.signing.as_ref().and_then(|(key_name, identity)| {
                        let hash_b32 = encode_nix_base32(&entry.nar_sha256);
                        let nar_hash = format!("sha256:{hash_b32}");
                        let fingerprint = compute_narinfo_fingerprint(
                            &entry.name,
                            &nar_hash,
                            entry.nar_size,
                            entry.references.as_deref(),
                        )?;
                        let sig_bytes = identity.sign(fingerprint.as_bytes());
                        let sig_b64 = BASE64.encode(sig_bytes);
                        Some(format!("{key_name}:{sig_b64}"))
                    });
                    let text = serialize_narinfo(
                        &entry.name,
                        &entry.nar_sha256,
                        entry.nar_size,
                        entry.references.as_deref(),
                        sig.as_deref(),
                    );
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
    ///
    /// References are validated: any entry that is empty, contains NUL, or
    /// contains whitespace is silently dropped. This guards against
    /// untrusted sources (e.g. mesh peers) injecting invalid references
    /// that would panic `serialize_narinfo`.
    pub fn import_nar(
        &mut self,
        name: &str,
        nar_bytes: Vec<u8>,
        references: Option<Vec<String>>,
    ) -> Result<(), NarError> {
        // Sanitize references at the boundary — drop invalid entries.
        let references = sanitize_refs(references);

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
                    references,
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
        srv.import_nar(name, build_test_nar(b"imported data"), None)
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
        srv.import_nar(&name, build_test_nar(b"recovered"), None)
            .unwrap();
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
        srv.import_nar(&name, build_test_nar(b"no longer missing"), None)
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
        srv.import_nar(name, build_test_nar(b"check"), None)
            .unwrap();
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

    #[test]
    fn narinfo_includes_references() {
        let name = "abc12345678901234567890123456789-hello";
        let refs = Some(vec!["dep12345678901234567890123456789-glibc".to_string()]);
        let mut srv = build_server();
        srv.import_nar(name, build_test_nar(b"data"), refs).unwrap();
        let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
        match resp {
            CacheResponse::Narinfo(text) => {
                assert!(text.contains("References: dep12345678901234567890123456789-glibc\n"));
            }
            other => panic!("expected Narinfo, got {other:?}"),
        }
    }

    #[test]
    fn narinfo_omits_references_when_none() {
        let name = "abc12345678901234567890123456789-hello";
        let mut srv = build_server();
        srv.import_nar(name, build_test_nar(b"data"), None).unwrap();
        let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
        match resp {
            CacheResponse::Narinfo(text) => {
                assert!(!text.contains("References"));
            }
            other => panic!("expected Narinfo, got {other:?}"),
        }
    }

    #[test]
    fn new_with_refs_populates_references() {
        let mut nix = NixStoreServer::new();
        let name = "abc12345678901234567890123456789-hello";
        nix.import_nar(name, build_test_nar(b"data")).unwrap();

        let mut ref_map = std::collections::HashMap::new();
        ref_map.insert(name.to_string(), vec!["dep123-glibc".to_string()]);

        let mut srv = BinaryCacheServer::new_with_refs(nix, ref_map);
        let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
        match resp {
            CacheResponse::Narinfo(text) => {
                assert!(text.contains("References: dep123-glibc\n"));
            }
            other => panic!("expected Narinfo, got {other:?}"),
        }
    }

    #[test]
    fn signed_narinfo_contains_sig_line() {
        use harmony_identity::PrivateIdentity;
        use rand::rngs::OsRng;

        let identity = PrivateIdentity::generate(&mut OsRng);
        let name = "abc12345678901234567890123456789-hello";
        let refs = vec!["dep12345678901234567890123456789-glibc".to_string()];

        let mut nix = NixStoreServer::new();
        nix.import_nar(name, build_test_nar(b"data")).unwrap();
        let mut ref_map = std::collections::HashMap::new();
        ref_map.insert(name.to_string(), refs);
        let mut srv =
            BinaryCacheServer::new_with_signing(nix, ref_map, "test-key-1".to_string(), identity);
        let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
        match resp {
            CacheResponse::Narinfo(text) => {
                assert!(
                    text.contains("Sig: test-key-1:"),
                    "missing Sig line: {text}"
                );
                let sig_line = text.lines().find(|l| l.starts_with("Sig: ")).unwrap();
                let sig_value = sig_line.strip_prefix("Sig: ").unwrap();
                assert!(sig_value.contains(':'), "sig should be keyname:base64");
            }
            other => panic!("expected Narinfo, got {other:?}"),
        }
    }

    #[test]
    fn unsigned_server_no_sig_line() {
        let name = "abc12345678901234567890123456789-hello";
        let mut srv = build_server_with_nar(name, b"data");
        let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
        match resp {
            CacheResponse::Narinfo(text) => {
                assert!(
                    !text.contains("Sig:"),
                    "should not have Sig without signing key"
                );
            }
            other => panic!("expected Narinfo, got {other:?}"),
        }
    }

    #[test]
    fn signing_skipped_when_no_references() {
        use harmony_identity::PrivateIdentity;
        use rand::rngs::OsRng;

        let identity = PrivateIdentity::generate(&mut OsRng);
        let mut nix = NixStoreServer::new();
        let name = "abc12345678901234567890123456789-noref";
        nix.import_nar(name, build_test_nar(b"data")).unwrap();
        let mut srv = BinaryCacheServer::new_with_signing(
            nix,
            std::collections::HashMap::new(),
            "test-key-1".to_string(),
            identity,
        );
        let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
        match resp {
            CacheResponse::Narinfo(text) => {
                assert!(!text.contains("Sig:"), "should not sign without references");
            }
            other => panic!("expected Narinfo, got {other:?}"),
        }
    }

    #[test]
    fn signature_verifies_against_public_key() {
        use crate::narinfo::{compute_narinfo_fingerprint, NarInfo};
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use harmony_identity::PrivateIdentity;
        use rand::rngs::OsRng;

        let identity = PrivateIdentity::generate(&mut OsRng);
        let public = identity.identity.clone();
        let name = "abc12345678901234567890123456789-verify";
        let refs = vec!["dep12345678901234567890123456789-glibc".to_string()];

        let mut nix = NixStoreServer::new();
        nix.import_nar(name, build_test_nar(b"verify data"))
            .unwrap();
        let mut ref_map = std::collections::HashMap::new();
        ref_map.insert(name.to_string(), refs);
        let mut srv = BinaryCacheServer::new_with_signing(
            nix,
            ref_map,
            "harmony-test-1".to_string(),
            identity,
        );
        let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
        let text = match resp {
            CacheResponse::Narinfo(t) => t,
            other => panic!("expected Narinfo, got {other:?}"),
        };

        let parsed = NarInfo::parse(&text).unwrap();
        let sig_str = parsed.sig.expect("expected Sig field");
        let (_key_name, sig_b64) = sig_str.split_once(':').expect("sig format is key:base64");
        let sig_bytes: [u8; 64] = BASE64.decode(sig_b64).unwrap().try_into().unwrap();

        let fingerprint = compute_narinfo_fingerprint(
            name,
            &parsed.nar_hash,
            parsed.nar_size,
            parsed.references.as_deref(),
        )
        .unwrap();

        public
            .verify(fingerprint.as_bytes(), &sig_bytes)
            .expect("signature should verify");
    }
}
