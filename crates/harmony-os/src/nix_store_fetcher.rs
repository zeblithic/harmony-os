// SPDX-License-Identifier: GPL-2.0-or-later

//! NixStoreFetcher — lazy fetch orchestrator for the Nix store bridge.
//!
//! Drains cache misses from [`NixStoreServer`], fetches narinfo + NAR from
//! an upstream binary cache, decompresses, verifies the hash, and imports.
//! HTTP is injectable via the [`HttpClient`] trait for testability.

use std::collections::HashSet;

use harmony_microkernel::nix_store_server::NixStoreServer;
use sha2::{Digest, Sha256};
use xz2::read::XzDecoder;

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

/// Production HTTP client using `ureq`.
pub struct UreqHttpClient;

impl UreqHttpClient {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UreqHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for UreqHttpClient {
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let response = ureq::get(url).call().map_err(|e| match e {
            ureq::Error::StatusCode(404) => FetchError::NotFound,
            other => FetchError::Network(other.to_string()),
        })?;
        response
            .into_body()
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
    cache_url: String,
    /// Store path names that have already failed to fetch. Prevents
    /// repeated fetch attempts for the same path.
    pub failed: HashSet<String>,
}

impl NixStoreFetcher {
    /// Create a new fetcher backed by the given HTTP client.
    ///
    /// `cache_url` defaults to `"https://cache.nixos.org"`.
    pub fn new(http: Box<dyn HttpClient>) -> Self {
        Self {
            http,
            cache_url: String::from("https://cache.nixos.org"),
            failed: HashSet::new(),
        }
    }

    /// Process all pending misses: drain, deduplicate, fetch, import.
    pub fn process_misses(&mut self, server: &mut NixStoreServer) {
        let misses = server.drain_misses();

        // Deduplicate — a store path may have been walked multiple times
        // before the fetcher runs.
        let mut seen = HashSet::new();
        for name in &misses {
            let name_str = name.to_string();
            if self.failed.contains(&name_str) {
                continue;
            }
            if !seen.insert(name_str.clone()) {
                continue;
            }
            if let Err(_e) = self.fetch_and_import(&name_str, server) {
                self.failed.insert(name_str);
            }
        }
    }

    /// Fetch a single store path: narinfo -> NAR -> decompress -> verify -> import.
    fn fetch_and_import(
        &self,
        store_path_name: &str,
        server: &mut NixStoreServer,
    ) -> Result<(), FetchError> {
        // 1. Extract store hash (first 32 chars of store path name).
        if store_path_name.len() < 32 {
            return Err(FetchError::NarInfo(
                "store path name too short for hash extraction".into(),
            ));
        }
        let store_hash = &store_path_name[..32];

        // 2. Fetch narinfo.
        let narinfo_url = format!("{}/{}.narinfo", self.cache_url, store_hash);
        let narinfo_bytes = self.http.get(&narinfo_url)?;
        let narinfo_text = String::from_utf8(narinfo_bytes)
            .map_err(|e| FetchError::NarInfo(e.to_string()))?;
        let narinfo =
            NarInfo::parse(&narinfo_text).map_err(|e| FetchError::NarInfo(format!("{:?}", e)))?;

        // 3. Fetch NAR.
        let nar_url = format!("{}/{}", self.cache_url, narinfo.url);
        let compressed_nar = self.http.get(&nar_url)?;

        // 4. Decompress xz.
        let nar_bytes = decompress_xz(&compressed_nar)?;

        // 5. Verify SHA-256 hash.
        verify_nar_hash(&nar_bytes, &narinfo.nar_hash)?;

        // 6. Import into server.
        server
            .import_nar(store_path_name, nar_bytes)
            .map_err(|e| FetchError::Import(format!("{:?}", e)))?;

        Ok(())
    }
}

// ── Helper functions ─────────────────────────────────────────────────

/// Decompress xz-compressed data.
fn decompress_xz(data: &[u8]) -> Result<Vec<u8>, FetchError> {
    use std::io::Read;
    let mut decoder = XzDecoder::new(data);
    let mut buf = Vec::new();
    decoder
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
        fetcher.process_misses(&mut server);

        // Verify the store path is now available.
        let qp = server.walk(0, 2, &store_path_name).unwrap();
        assert_ne!(qp, 0);

        // Verify we can read the file contents.
        server.open(2, harmony_microkernel::OpenMode::Read).unwrap();
        let data = server.read(2, 0, 1024).unwrap();
        assert_eq!(data, b"hello from nix");

        // Verify failed set is empty (success case).
        assert!(fetcher.failed.is_empty());
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
        assert!(fetcher.failed.contains(store_path_name));
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
        assert!(fetcher.failed.contains(store_path_name.as_str()));
    }

    // ── Test: UreqHttpClient smoke test ─────────────────────────────

    #[test]
    fn ureq_client_exists() {
        // Smoke test: UreqHttpClient can be constructed.
        let _client = UreqHttpClient::new();
    }
}
