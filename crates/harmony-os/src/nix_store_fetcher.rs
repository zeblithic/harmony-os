// SPDX-License-Identifier: GPL-2.0-or-later

//! NixStoreFetcher — lazy fetch orchestrator for the Nix store bridge.
//!
//! Drains cache misses from [`NixStoreServer`], fetches narinfo + NAR from
//! an upstream binary cache, decompresses, verifies the hash, and imports.
//! HTTP is injectable via the [`HttpClient`] trait for testability.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harmony_microkernel::nix_store_server::NixStoreServer;
use sha2::{Digest, Sha256};
use xz2::read::XzDecoder;

use crate::mesh_nar_source::MeshNarFetch;
use crate::narinfo::NarInfo;
use crate::nix_base32::decode_nix_base32;

// ── Error type ───────────────────────────────────────────────────────

/// Errors during fetch operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The requested resource was not found (HTTP 404 or similar).
    NotFound,
    /// A network-level error occurred.
    Network(String),
    /// Failed to parse narinfo response.
    NarInfo(String),
    /// Failed to decompress XZ data.
    Decompress(String),
    /// NAR hash does not match the expected hash from narinfo.
    HashMismatch,
    /// Failed to decode Nix base32 hash.
    Base32(String),
    /// Failed to import NAR into the store server.
    Import(String),
}

// ── HttpClient trait ─────────────────────────────────────────────────

/// Injectable HTTP client trait for testability.
pub trait HttpClient {
    /// Perform an HTTP GET and return the response body.
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError>;
}

// ── UreqHttpClient ──────────────────────────────────────────────────

/// Production HTTP client using `ureq` with timeouts and body size limits.
pub struct UreqHttpClient {
    agent: ureq::Agent,
}

impl UreqHttpClient {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(120)))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl Default for UreqHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for UreqHttpClient {
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let mut response = self.agent.get(url).call().map_err(|e| match e {
            ureq::Error::StatusCode(404) => FetchError::NotFound,
            other => FetchError::Network(other.to_string()),
        })?;
        response
            .body_mut()
            .with_config()
            .limit(256 * 1024 * 1024) // 256 MB — NAR files can be large
            .read_to_vec()
            .map_err(|e| FetchError::Network(e.to_string()))
    }
}

// ── NixStoreFetcher ──────────────────────────────────────────────────

/// Ring 3 lazy fetch orchestrator for [`NixStoreServer`].
///
/// Periodically drains cache misses from the store server, fetches the
/// corresponding narinfo and NAR from an upstream binary cache, and
/// imports the decompressed + verified NAR into the server.
pub struct NixStoreFetcher {
    http: Box<dyn HttpClient>,
    mesh: Option<Box<dyn MeshNarFetch>>,
    cache_url: String,
    /// Store path names that have already failed to fetch. Prevents
    /// repeated fetch attempts for the same path.
    failed: HashSet<String>,
}

impl NixStoreFetcher {
    /// Create a new fetcher backed by the given HTTP client.
    ///
    /// `cache_url` defaults to `"https://cache.nixos.org"`.
    pub fn new(http: Box<dyn HttpClient>) -> Self {
        Self {
            http,
            mesh: None,
            cache_url: String::from("https://cache.nixos.org"),
            failed: HashSet::new(),
        }
    }

    /// Create a new fetcher that tries the mesh network first, falling
    /// back to HTTP on mesh miss.
    pub fn with_mesh(http: Box<dyn HttpClient>, mesh: Box<dyn MeshNarFetch>) -> Self {
        Self {
            http,
            mesh: Some(mesh),
            cache_url: String::from("https://cache.nixos.org"),
            failed: HashSet::new(),
        }
    }

    /// Read-only view of paths that have permanently failed to fetch.
    pub fn failed_paths(&self) -> &HashSet<String> {
        &self.failed
    }

    /// Process all pending misses: drain, deduplicate, fetch, import.
    ///
    /// Returns a list of `(store_path_name, nar_bytes)` for each
    /// successfully imported path, so callers can publish to the mesh.
    pub fn process_misses(&mut self, server: &mut NixStoreServer) -> Vec<(String, Vec<u8>)> {
        let misses = server.drain_misses();
        self.process_miss_list(misses, |name, nar| {
            // Skip if already imported (race: kernel re-recorded a miss
            // for a path imported in a previous cycle).
            if server.has_store_path(name) {
                return Ok(false); // Not newly imported — don't re-publish.
            }
            server
                .import_nar(name, nar)
                .map(|()| true)
                .map_err(|e| format!("{:?}", e))
        })
    }

    /// Process misses from a shared (Arc<Mutex>) server, releasing the lock
    /// during HTTP I/O so the kernel thread isn't blocked.
    ///
    /// Returns a list of `(store_path_name, nar_bytes)` for each
    /// successfully imported path, so callers can publish to the mesh.
    pub fn process_misses_shared(
        &mut self,
        server: &Arc<Mutex<NixStoreServer>>,
    ) -> Vec<(String, Vec<u8>)> {
        let misses = server
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain_misses();
        self.process_miss_list(misses, |name, nar| {
            let mut guard = server.lock().unwrap_or_else(|e| e.into_inner());
            // Skip if already imported (race: kernel re-recorded a miss
            // for a path imported in a previous cycle).
            if guard.has_store_path(name) {
                return Ok(false); // Not newly imported — don't re-publish.
            }
            guard
                .import_nar(name, nar)
                .map(|()| true)
                .map_err(|e| format!("{:?}", e))
        })
    }

    /// Fetch and import each miss via caller-provided closure.
    /// Misses are already deduplicated by `drain_misses()` (BTreeSet).
    ///
    /// If a mesh source is configured, each path is tried there first;
    /// on mesh miss (or mesh import failure) the fetcher falls back to
    /// the upstream HTTP cache.
    ///
    /// Returns `(store_path_name, nar_bytes)` for every *newly* imported path.
    fn process_miss_list<F>(
        &mut self,
        misses: Vec<Arc<str>>,
        mut import_fn: F,
    ) -> Vec<(String, Vec<u8>)>
    where
        F: FnMut(&str, Vec<u8>) -> Result<bool, String>,
    {
        let mut imported = Vec::new();
        for name in &misses {
            let name_str = name.to_string();
            if self.failed.contains(&name_str) {
                continue;
            }

            // Try mesh first (if available).
            let mut nar_bytes = None;
            if let Some(ref mesh) = self.mesh {
                if let Some(mesh_nar) = mesh.fetch_nar(&name_str) {
                    nar_bytes = Some(mesh_nar);
                }
            }

            // Fall back to HTTP if mesh didn't provide data.
            if nar_bytes.is_none() {
                match self.fetch_nar(&name_str) {
                    Ok(http_nar) => nar_bytes = Some(http_nar),
                    Err(e) => {
                        eprintln!("[nix-fetcher] fetch failed for {}: {:?}", name_str, e);
                        if !matches!(e, FetchError::Network(_)) {
                            self.failed.insert(name_str);
                        }
                        continue;
                    }
                }
            }

            let nar_bytes = nar_bytes.unwrap();
            match import_fn(&name_str, nar_bytes.clone()) {
                Ok(true) => {
                    // Newly imported — include for mesh publishing.
                    imported.push((name_str, nar_bytes));
                }
                Ok(false) => {
                    // Already present — skip re-publishing.
                }
                Err(e) => {
                    // If mesh data failed import, try HTTP before blacklisting.
                    if self.mesh.is_some() {
                        eprintln!(
                            "[nix-fetcher] mesh import failed for {}, trying HTTP: {}",
                            name_str, e
                        );
                        match self.fetch_nar(&name_str) {
                            Ok(http_nar) => match import_fn(&name_str, http_nar.clone()) {
                                Ok(true) => {
                                    imported.push((name_str, http_nar));
                                    continue;
                                }
                                Ok(false) => continue,
                                Err(e2) => {
                                    eprintln!(
                                        "[nix-fetcher] HTTP import also failed for {}: {}",
                                        name_str, e2
                                    );
                                }
                            },
                            Err(e2) => {
                                eprintln!(
                                    "[nix-fetcher] HTTP fallback fetch failed for {}: {:?}",
                                    name_str, e2
                                );
                            }
                        }
                    } else {
                        eprintln!("[nix-fetcher] import failed for {}: {}", name_str, e);
                    }
                    self.failed.insert(name_str);
                }
            }
        }
        imported
    }

    /// Fetch a single store path: narinfo -> NAR -> decompress -> verify.
    ///
    /// Returns the decompressed, verified NAR bytes on success.
    fn fetch_nar(&self, store_path_name: &str) -> Result<Vec<u8>, FetchError> {
        // 1. Extract store hash (first 32 chars, followed by `-`).
        if store_path_name.len() < 33 || store_path_name.as_bytes()[32] != b'-' {
            return Err(FetchError::NarInfo(
                "store path name does not have expected '<32-char-hash>-<name>' format".into(),
            ));
        }
        let store_hash = &store_path_name[..32];

        // 2. Fetch narinfo.
        let narinfo_url = format!("{}/{}.narinfo", self.cache_url, store_hash);
        let narinfo_bytes = self.http.get(&narinfo_url)?;
        let narinfo_text =
            String::from_utf8(narinfo_bytes).map_err(|e| FetchError::NarInfo(e.to_string()))?;
        let narinfo =
            NarInfo::parse(&narinfo_text).map_err(|e| FetchError::NarInfo(format!("{:?}", e)))?;

        // 3. Check compression — we only support xz.
        if narinfo.compression != "xz" {
            return Err(FetchError::NarInfo(format!(
                "unsupported compression: {}",
                narinfo.compression
            )));
        }

        // 4. Fetch NAR — validate URL is a safe relative path.
        if narinfo.url.contains("://") || narinfo.url.starts_with('/') || narinfo.url.contains("..")
        {
            return Err(FetchError::NarInfo(format!(
                "narinfo URL is not a safe relative path: {:?}",
                narinfo.url
            )));
        }
        let nar_url = format!("{}/{}", self.cache_url, narinfo.url);
        let compressed_nar = self.http.get(&nar_url)?;

        // 5. Decompress xz (bounded to nar_size + 1 to prevent decompression bombs).
        let nar_bytes = decompress_xz(&compressed_nar, narinfo.nar_size)?;

        // 6. Validate decompressed size against NarSize.
        if nar_bytes.len() as u64 != narinfo.nar_size {
            return Err(FetchError::Decompress(format!(
                "decompressed size {} != expected NarSize {}",
                nar_bytes.len(),
                narinfo.nar_size
            )));
        }

        // 7. Verify SHA-256 hash.
        verify_nar_hash(&nar_bytes, &narinfo.nar_hash)?;

        Ok(nar_bytes)
    }
}

// ── Helper functions ─────────────────────────────────────────────────

/// Decompress xz-compressed data, reading at most `nar_size + 1` bytes
/// to prevent decompression bombs from exhausting memory.
fn decompress_xz(data: &[u8], nar_size: u64) -> Result<Vec<u8>, FetchError> {
    use std::io::Read;
    let decoder = XzDecoder::new(data);
    let mut buf = Vec::new();
    // Read at most nar_size + 1 bytes so oversized streams are caught
    // by the size check in fetch_nar rather than exhausting memory.
    decoder
        .take(nar_size.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| FetchError::Decompress(e.to_string()))?;
    Ok(buf)
}

/// Verify that the SHA-256 hash of `nar_bytes` matches the expected hash.
///
/// `expected` is in the format `"sha256:<nix-base32-hash>"`.
fn verify_nar_hash(nar_bytes: &[u8], expected: &str) -> Result<(), FetchError> {
    let hash_str = expected
        .strip_prefix("sha256:")
        .ok_or_else(|| FetchError::NarInfo("NarHash does not start with sha256:".into()))?;

    let expected_bytes =
        decode_nix_base32(hash_str).map_err(|e| FetchError::Base32(format!("{:?}", e)))?;

    if expected_bytes.len() != 32 {
        return Err(FetchError::NarInfo(format!(
            "NarHash decoded to {} bytes, expected 32 (SHA-256)",
            expected_bytes.len()
        )));
    }

    let actual = Sha256::digest(nar_bytes);

    if actual.as_slice() == expected_bytes.as_slice() {
        Ok(())
    } else {
        Err(FetchError::HashMismatch)
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── NAR construction helper ──────────────────────────────────────

    /// Encode a byte slice as a NAR string: 8-byte LE length + data + zero-padding to 8-byte boundary.
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

    // ── Nix base32 encoder (test helper) ─────────────────────────────

    fn encode_nix_base32(bytes: &[u8]) -> String {
        use crate::nix_base32::NIX_BASE32_CHARS;
        let hash_size = bytes.len();
        let nchar = (hash_size * 8).div_ceil(5);
        let mut out = String::with_capacity(nchar);
        for i in (0..nchar).rev() {
            let mut digit: u8 = 0;
            for j in (0..5).rev() {
                let bit_pos = i * 5 + j;
                digit <<= 1;
                if bit_pos / 8 < hash_size {
                    digit |= (bytes[bit_pos / 8] >> (bit_pos % 8)) & 1;
                }
            }
            out.push(NIX_BASE32_CHARS[digit as usize] as char);
        }
        out
    }

    // ── XZ compression helper ────────────────────────────────────────

    fn compress_xz(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        use xz2::write::XzEncoder;
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    // ── MockHttp ─────────────────────────────────────────────────────

    struct MockHttp {
        responses: HashMap<String, Result<Vec<u8>, FetchError>>,
    }

    impl HttpClient for MockHttp {
        fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
            self.responses
                .get(url)
                .cloned()
                .unwrap_or(Err(FetchError::NotFound))
        }
    }

    // ── Test: successful fetch and import ────────────────────────────

    #[test]
    fn fetch_and_import_success() {
        // Build a test NAR.
        let nar_bytes = build_test_nar(b"hello from nix");

        // Compute SHA-256 of the decompressed NAR.
        let hash = Sha256::digest(&nar_bytes);
        let hash_b32 = encode_nix_base32(hash.as_slice());

        // Compress with xz.
        let compressed = compress_xz(&nar_bytes);

        // Build narinfo.
        let store_hash = "abc12345678901234567890123456789";
        let store_path_name = format!("{}-test-pkg", store_hash);
        let narinfo_text = format!(
            "StorePath: /nix/store/{}\nURL: nar/test.nar.xz\nCompression: xz\nNarHash: sha256:{}\nNarSize: {}\n",
            store_path_name, hash_b32, nar_bytes.len()
        );

        // Set up mock HTTP.
        let mut responses = HashMap::new();
        responses.insert(
            format!("https://cache.nixos.org/{}.narinfo", store_hash),
            Ok(narinfo_text.into_bytes()),
        );
        responses.insert(
            "https://cache.nixos.org/nar/test.nar.xz".to_string(),
            Ok(compressed),
        );

        let mock = MockHttp { responses };
        let mut fetcher = NixStoreFetcher::new(Box::new(mock));
        let mut server = NixStoreServer::new();

        // Trigger a miss by walking a non-existent store path.
        use harmony_microkernel::FileServer;
        let _ = server.walk(0, 1, &store_path_name);

        // Process misses — should fetch and import.
        let imported = fetcher.process_misses(&mut server);
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].0, store_path_name);

        // Verify the store path is now available.
        let qp = server.walk(0, 2, &store_path_name).unwrap();
        assert_ne!(qp, 0);

        // Verify we can read the file contents.
        server.open(2, harmony_microkernel::OpenMode::Read).unwrap();
        let data = server.read(2, 0, 1024).unwrap();
        assert_eq!(data, b"hello from nix");

        // Verify no failures recorded.
        assert!(fetcher.failed_paths().is_empty());
    }

    // ── Test: 404 records failure ────────────────────────────────────

    #[test]
    fn fetch_404_records_failure() {
        // Empty mock — all URLs return NotFound.
        let mock = MockHttp {
            responses: HashMap::new(),
        };
        let mut fetcher = NixStoreFetcher::new(Box::new(mock));
        let mut server = NixStoreServer::new();

        // The store path name must be >= 32 chars for the hash extraction.
        let store_path_name = "abc12345678901234567890123456789-missing-pkg";

        // Trigger a miss.
        use harmony_microkernel::FileServer;
        let _ = server.walk(0, 1, store_path_name);

        // Process misses.
        fetcher.process_misses(&mut server);

        // Verify the name is in the failed set.
        assert!(fetcher.failed_paths().contains(store_path_name));
    }

    // ── Test: hash mismatch records failure ──────────────────────────

    #[test]
    fn hash_mismatch_records_failure() {
        // Build a test NAR.
        let nar_bytes = build_test_nar(b"some content");

        // Compute a WRONG hash — hash of different data.
        let wrong_hash = Sha256::digest(b"completely different data");
        let wrong_hash_b32 = encode_nix_base32(wrong_hash.as_slice());

        // Compress with xz.
        let compressed = compress_xz(&nar_bytes);

        // Build narinfo with wrong hash.
        let store_hash = "abc12345678901234567890123456789";
        let store_path_name = format!("{}-bad-hash-pkg", store_hash);
        let narinfo_text = format!(
            "StorePath: /nix/store/{}\nURL: nar/bad.nar.xz\nCompression: xz\nNarHash: sha256:{}\nNarSize: {}\n",
            store_path_name, wrong_hash_b32, nar_bytes.len()
        );

        // Set up mock HTTP.
        let mut responses = HashMap::new();
        responses.insert(
            format!("https://cache.nixos.org/{}.narinfo", store_hash),
            Ok(narinfo_text.into_bytes()),
        );
        responses.insert(
            "https://cache.nixos.org/nar/bad.nar.xz".to_string(),
            Ok(compressed),
        );

        let mock = MockHttp { responses };
        let mut fetcher = NixStoreFetcher::new(Box::new(mock));
        let mut server = NixStoreServer::new();

        // Trigger a miss.
        use harmony_microkernel::FileServer;
        let _ = server.walk(0, 1, &store_path_name);

        // Process misses.
        fetcher.process_misses(&mut server);

        // Verify the store path is NOT available (walk still fails).
        assert_eq!(
            server.walk(0, 3, &store_path_name),
            Err(harmony_microkernel::IpcError::NotFound)
        );

        // Verify name is in the failed set.
        assert!(fetcher.failed_paths().contains(store_path_name.as_str()));
    }

    // ── Test: SharedNixStoreServer + NixStoreFetcher integration ────

    #[test]
    fn shared_server_fetch_and_walk() {
        use harmony_microkernel::nix_store_server::SharedNixStoreServer;

        // Build test NAR + responses (reuse existing helpers from this test module).
        let nar = build_test_nar(b"shared test data");
        let hash = sha2::Sha256::digest(&nar);
        let nix_b32 = encode_nix_base32(&hash);
        let store_hash = "abc12345678901234567890123456789";
        let store_path_name = format!("{store_hash}-shared-test");

        let narinfo = format!(
            "StorePath: /nix/store/{store_path_name}\n\
             URL: nar/test.nar.xz\n\
             Compression: xz\n\
             NarHash: sha256:{nix_b32}\n\
             NarSize: {}\n",
            nar.len()
        );

        let nar_xz = compress_xz(&nar);

        let mut responses = std::collections::HashMap::new();
        responses.insert(
            format!("https://cache.nixos.org/{store_hash}.narinfo"),
            Ok(narinfo.into_bytes()),
        );
        responses.insert(
            "https://cache.nixos.org/nar/test.nar.xz".to_string(),
            Ok(nar_xz),
        );
        let http = MockHttp { responses };

        // Set up shared server via constructor (inner is private).
        let (mut wrapper, shared) = SharedNixStoreServer::new(NixStoreServer::new());

        // Walk miss through wrapper — records the miss.
        use harmony_microkernel::FileServer;
        assert_eq!(
            wrapper.walk(0, 1, &store_path_name),
            Err(harmony_microkernel::IpcError::NotFound)
        );

        // Fetcher processes misses via process_misses_shared — lock is NOT
        // held during HTTP I/O.
        let mut fetcher = NixStoreFetcher::new(Box::new(http));
        fetcher.process_misses_shared(&shared);

        // Now walk through the wrapper should succeed.
        let qp = wrapper.walk(0, 2, &store_path_name).unwrap();
        assert_ne!(qp, 0);

        // Read the file through the wrapper.
        wrapper
            .open(2, harmony_microkernel::OpenMode::Read)
            .unwrap();
        let data = wrapper.read(2, 0, 1024).unwrap();
        assert_eq!(data, b"shared test data");
    }

    // ── Test: UreqHttpClient smoke test ─────────────────────────────

    #[test]
    fn ureq_client_exists() {
        // Smoke test: UreqHttpClient can be constructed with timeouts.
        let _client = UreqHttpClient::new();
    }

    // ── Mesh mock helpers ───────────────────────────────────────────

    use crate::mesh_nar_source::MeshNarFetch;

    struct MockMesh {
        nar: Vec<u8>,
    }
    impl MeshNarFetch for MockMesh {
        fn fetch_nar(&self, _: &str) -> Option<Vec<u8>> {
            Some(self.nar.clone())
        }
    }

    struct EmptyMesh;
    impl MeshNarFetch for EmptyMesh {
        fn fetch_nar(&self, _: &str) -> Option<Vec<u8>> {
            None
        }
    }

    // ── Test: mesh first skips HTTP ─────────────────────────────────

    #[test]
    fn mesh_first_skips_http() {
        // Build a valid NAR that the mesh will provide directly.
        let nar_bytes = build_test_nar(b"mesh-provided content");

        // Empty HTTP mock — every URL returns 404.
        let mock_http = MockHttp {
            responses: HashMap::new(),
        };

        let mock_mesh = MockMesh {
            nar: nar_bytes.clone(),
        };

        let mut fetcher = NixStoreFetcher::with_mesh(Box::new(mock_http), Box::new(mock_mesh));
        let mut server = NixStoreServer::new();

        let store_path_name = "abc12345678901234567890123456789-mesh-pkg";

        // Trigger a miss.
        use harmony_microkernel::FileServer;
        let _ = server.walk(0, 1, store_path_name);

        // Process — mesh provides NAR, HTTP is never consulted.
        let imported = fetcher.process_misses(&mut server);
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].0, store_path_name);
        assert_eq!(imported[0].1, nar_bytes);

        // Verify import succeeded — store path is available.
        let qp = server.walk(0, 2, store_path_name).unwrap();
        assert_ne!(qp, 0);

        assert!(fetcher.failed_paths().is_empty());
    }

    // ── Test: mesh miss falls back to HTTP ──────────────────────────

    #[test]
    fn mesh_miss_falls_back_to_http() {
        // Build valid NAR + narinfo for the HTTP path.
        let nar_bytes = build_test_nar(b"http-fallback content");
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
        // Mesh always returns None.
        let mock_mesh = EmptyMesh;

        let mut fetcher = NixStoreFetcher::with_mesh(Box::new(mock_http), Box::new(mock_mesh));
        let mut server = NixStoreServer::new();

        // Trigger a miss.
        use harmony_microkernel::FileServer;
        let _ = server.walk(0, 1, &store_path_name);

        // Process — mesh misses, HTTP succeeds.
        let imported = fetcher.process_misses(&mut server);
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].0, store_path_name);

        // Verify the store path is now available.
        let qp = server.walk(0, 2, &store_path_name).unwrap();
        assert_ne!(qp, 0);

        assert!(fetcher.failed_paths().is_empty());
    }

    // ── Test: process_misses returns imported pairs ──────────────────

    #[test]
    fn process_misses_returns_imported_pairs() {
        // Standard HTTP fetch (no mesh). Verify the return Vec.
        let nar_bytes = build_test_nar(b"return-test content");
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

        // Trigger a miss.
        use harmony_microkernel::FileServer;
        let _ = server.walk(0, 1, &store_path_name);

        let imported = fetcher.process_misses(&mut server);
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].0, store_path_name);
        assert_eq!(imported[0].1, nar_bytes);
    }
}
