// SPDX-License-Identifier: GPL-2.0-or-later

//! BinaryCacheServer — sans-I/O Nix binary cache protocol handler.
//!
//! Routes request paths to narinfo responses, raw NAR data, or cache
//! metadata. Records misses for background fetch by NixStoreFetcher.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use harmony_microkernel::nar::NarError;
use harmony_microkernel::nix_store_server::NixStoreServer;

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
        CacheResponse::NotFound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_server() -> BinaryCacheServer {
        BinaryCacheServer::new(NixStoreServer::new())
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
}
