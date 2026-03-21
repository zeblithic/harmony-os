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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheResponse {
    /// narinfo text (Content-Type: text/x-nix-narinfo).
    Narinfo(String),
    /// Raw NAR bytes (Content-Type: application/x-nix-nar).
    NarData(Vec<u8>),
    /// nix-cache-info metadata (Content-Type: text/x-nix-cache-info).
    CacheInfo(String),
    /// Store path not found. Miss recorded for background fetch.
    NotFound,
    /// Malformed request path.
    BadRequest,
}

/// Sans-I/O Nix binary cache protocol handler.
pub struct BinaryCacheServer {
    server: NixStoreServer,
    hash_index: HashMap<String, Arc<str>>,
    misses: BTreeSet<String>,
}

impl BinaryCacheServer {
    pub fn new(server: NixStoreServer) -> Self {
        let mut hash_index = HashMap::new();
        for name in server.store_path_names() {
            if name.len() >= 32 {
                let hash = name[..32].to_string();
                hash_index.insert(hash, Arc::clone(name));
            }
        }
        Self {
            server,
            hash_index,
            misses: BTreeSet::new(),
        }
    }

    pub fn handle_request(&mut self, path: &str) -> CacheResponse {
        if path == "/nix-cache-info" {
            return CacheResponse::CacheInfo(
                "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n".to_string(),
            );
        }

        if let Some(hash) = path
            .strip_suffix(".narinfo")
            .and_then(|p| p.strip_prefix('/'))
        {
            if hash.len() != 32 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return CacheResponse::BadRequest;
            }
            return match self.hash_index.get(hash) {
                Some(full_name) => {
                    let nar_blob = self.server.get_nar_blob(full_name).unwrap();
                    let sha256 = Sha256::digest(nar_blob);
                    let text =
                        serialize_narinfo(full_name, sha256.as_slice(), nar_blob.len() as u64);
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
                None => return CacheResponse::NotFound,
            };
            return match self.server.get_nar_blob(name) {
                Some(blob) => CacheResponse::NarData(blob.to_vec()),
                None => CacheResponse::NotFound,
            };
        }

        CacheResponse::NotFound
    }

    pub fn drain_misses(&mut self) -> Vec<String> {
        core::mem::take(&mut self.misses).into_iter().collect()
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
                assert!(text.contains("WantMassQuery: 1"));
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
        assert_eq!(
            srv.handle_request("/abc.narinfo"),
            CacheResponse::BadRequest
        );
        assert_eq!(
            srv.handle_request("/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.narinfo"),
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
}
