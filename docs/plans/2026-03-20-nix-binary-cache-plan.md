# Nix Binary Cache Protocol Layer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a sans-I/O `BinaryCacheServer` that serves narinfo + NAR data from NixStoreServer, with O(1) hash-indexed lookups and miss recording for background fetch.

**Architecture:** Three layered additions — (1) nix_base32 encoder extracted from test helper, (2) narinfo serializer as a free function, (3) BinaryCacheServer struct that routes requests, generates narinfo on the fly, and records misses. Two small accessor methods added to NixStoreServer in harmony-microkernel.

**Tech Stack:** Rust, harmony-microkernel (NixStoreServer), sha2 (SHA-256), no new dependencies.

**Spec:** `docs/specs/2026-03-20-nix-binary-cache-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `crates/harmony-microkernel/src/nix_store_server.rs` | Modify | Add `get_nar_blob()` and `store_path_names()` public accessors |
| `crates/harmony-os/src/nix_base32.rs` | Modify | Add `encode_nix_base32()` public function |
| `crates/harmony-os/src/narinfo.rs` | Modify | Add `serialize_narinfo()` free function |
| `crates/harmony-os/src/nix_binary_cache.rs` | Create | `BinaryCacheServer`, `CacheResponse`, request routing, miss recording |
| `crates/harmony-os/src/lib.rs` | Modify | Add `nix_binary_cache` module declaration |

---

## Task 1: NixStoreServer Accessors

**Files:**
- Modify: `crates/harmony-microkernel/src/nix_store_server.rs` (after line 168, the `drain_misses` method)

- [ ] **Step 1: Write failing tests for new accessors**

In the existing `mod tests` block (after `duplicate_misses_are_deduplicated` test, ~line 768), add:

```rust
#[test]
fn get_nar_blob_returns_raw_bytes() {
    let mut srv = NixStoreServer::new();
    let nar = nar_regular_file(b"blob content", false);
    srv.import_nar("abc123-hello", nar.clone()).unwrap();

    let blob = srv.get_nar_blob("abc123-hello").unwrap();
    assert_eq!(blob, &nar);

    // Non-existent path returns None.
    assert!(srv.get_nar_blob("nonexistent").is_none());
}

#[test]
fn store_path_names_iterates_all() {
    let mut srv = NixStoreServer::new();
    srv.import_nar("aaa-first", build_test_nar(b"a")).unwrap();
    srv.import_nar("zzz-last", build_test_nar(b"z")).unwrap();

    let names: Vec<&str> = srv.store_path_names().map(|n| n.as_ref()).collect();
    assert_eq!(names, vec!["aaa-first", "zzz-last"]); // BTreeMap = sorted
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel get_nar_blob_returns_raw_bytes store_path_names_iterates_all`
Expected: Compilation error — methods don't exist yet.

- [ ] **Step 3: Implement the accessors**

Add after `drain_misses` (around line 168):

```rust
/// Retrieve the raw NAR blob for a store path.
pub fn get_nar_blob(&self, name: &str) -> Option<&[u8]> {
    self.store_paths.get(name).map(|sp| sp.nar_blob.as_slice())
}

/// Iterate over all imported store path names.
pub fn store_path_names(&self) -> impl Iterator<Item = &Arc<str>> {
    self.store_paths.keys()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel get_nar_blob store_path_names`
Expected: PASS

- [ ] **Step 5: Commit**

```
git add crates/harmony-microkernel/src/nix_store_server.rs
git commit -m "feat: add get_nar_blob() and store_path_names() to NixStoreServer"
```

---

## Task 2: nix_base32 Encoder

**Files:**
- Modify: `crates/harmony-os/src/nix_base32.rs`

- [ ] **Step 1: Write failing tests for the encoder**

Add to the existing `mod tests` block (after `empty_input` test, ~line 94):

```rust
#[test]
fn encode_known_sha256() {
    // SHA-256 of empty string — must match the decode test vector above.
    let hash_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let hash_bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hash_hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();

    let encoded = encode_nix_base32(&hash_bytes);
    assert_eq!(encoded, "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73");
}

#[test]
fn encode_decode_round_trip() {
    let data = b"round trip test data for nix b32";
    let encoded = encode_nix_base32(data);
    let decoded = decode_nix_base32(&encoded).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn encode_empty() {
    assert_eq!(encode_nix_base32(&[]), "");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os nix_base32`
Expected: Compilation error — `encode_nix_base32` not found.

- [ ] **Step 3: Implement the encoder**

Add after `decode_nix_base32` (before the `NixBase32Error` enum, ~line 51). This is extracted from the test helper in `nix_store_fetcher.rs:427-443`:

```rust
/// Encode bytes as a Nix base32 string.
///
/// Inverse of [`decode_nix_base32`]. Uses the same non-standard alphabet
/// and LSB-first bit ordering within each 5-bit group.
pub fn encode_nix_base32(bytes: &[u8]) -> alloc::string::String {
    let hash_size = bytes.len();
    if hash_size == 0 {
        return alloc::string::String::new();
    }
    let nchar = (hash_size * 8).div_ceil(5);
    let mut out = alloc::string::String::with_capacity(nchar);
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os nix_base32`
Expected: All 7 tests PASS (4 existing + 3 new).

- [ ] **Step 5: Update nix_store_fetcher.rs to use public encoder**

Replace the test-only `encode_nix_base32` function in `nix_store_fetcher.rs:427-443` with an import of the public one:

```rust
// Replace the local fn with:
use crate::nix_base32::encode_nix_base32;
```

Remove the local `fn encode_nix_base32` from the test module.

- [ ] **Step 6: Run full test suite to verify no regressions**

Run: `cargo test -p harmony-os`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```
git add crates/harmony-os/src/nix_base32.rs crates/harmony-os/src/nix_store_fetcher.rs
git commit -m "feat: extract nix_base32 encoder to public API"
```

---

## Task 3: Narinfo Serializer

**Files:**
- Modify: `crates/harmony-os/src/narinfo.rs`

- [ ] **Step 1: Write failing tests for serialize_narinfo**

Add to the existing `mod tests` block (after `explicit_compression_field` test, ~line 141). These tests need `cfg(feature = "std")` since they use `sha2`:

```rust
#[cfg(feature = "std")]
mod serialize_tests {
    use super::super::*;

    #[test]
    fn serialize_minimal_narinfo() {
        let hash = sha2::Sha256::digest(b"test nar data");
        let text = serialize_narinfo("abc123-hello", hash.as_slice(), 13);

        assert!(text.contains("StorePath: /nix/store/abc123-hello\n"));
        assert!(text.contains("URL: nar/abc123-hello.nar\n"));
        assert!(text.contains("Compression: none\n"));
        assert!(text.contains("NarHash: sha256:"));
        assert!(text.contains("NarSize: 13\n"));
    }

    #[test]
    fn serialize_round_trip() {
        let nar_data = b"some nar content for round trip";
        let hash = sha2::Sha256::digest(nar_data);
        let text = serialize_narinfo("xyz789-world", hash.as_slice(), nar_data.len() as u64);

        // Parse it back with the existing parser.
        let parsed = NarInfo::parse(&text).unwrap();
        assert_eq!(parsed.url, "nar/xyz789-world.nar");
        assert_eq!(parsed.compression, "none");
        assert_eq!(parsed.nar_size, nar_data.len() as u64);
        assert!(parsed.nar_hash.starts_with("sha256:"));
    }

    #[test]
    fn serialize_store_path_format() {
        let hash = sha2::Sha256::digest(b"data");
        let text = serialize_narinfo("test123-pkg", hash.as_slice(), 4);
        // StorePath must start with /nix/store/
        let store_line = text.lines().find(|l| l.starts_with("StorePath:")).unwrap();
        assert_eq!(store_line, "StorePath: /nix/store/test123-pkg");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os narinfo::tests::serialize_tests`
Expected: Compilation error — `serialize_narinfo` not found, `sha2` not imported.

- [ ] **Step 3: Implement serialize_narinfo**

Add after the `NarInfo` impl block (around line 62), gated on `std` since it uses `sha2` via the nix_base32 encoder:

```rust
/// Generate a minimal unsigned narinfo string.
///
/// Produces 5 fields: StorePath, URL, Compression, NarHash, NarSize.
/// The NAR is served uncompressed (`Compression: none`).
///
/// `nar_sha256` must be the raw 32-byte SHA-256 digest of the NAR blob.
#[cfg(feature = "std")]
pub fn serialize_narinfo(store_path_name: &str, nar_sha256: &[u8], nar_size: u64) -> String {
    use crate::nix_base32::encode_nix_base32;

    let hash_b32 = encode_nix_base32(nar_sha256);
    format!(
        "StorePath: /nix/store/{store_path_name}\n\
         URL: nar/{store_path_name}.nar\n\
         Compression: none\n\
         NarHash: sha256:{hash_b32}\n\
         NarSize: {nar_size}\n"
    )
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os narinfo`
Expected: All narinfo tests PASS (6 existing + 3 new).

- [ ] **Step 5: Commit**

```
git add crates/harmony-os/src/narinfo.rs
git commit -m "feat: add serialize_narinfo() for binary cache protocol"
```

---

## Task 4: BinaryCacheServer — Core Struct + CacheInfo

**Files:**
- Create: `crates/harmony-os/src/nix_binary_cache.rs`
- Modify: `crates/harmony-os/src/lib.rs` (add module declaration)

- [ ] **Step 1: Create module file with struct, enum, and CacheInfo test**

```rust
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
///
/// Serves narinfo and NAR data from a local [`NixStoreServer`],
/// recording misses for background fetch by `NixStoreFetcher`.
pub struct BinaryCacheServer {
    server: NixStoreServer,
    hash_index: HashMap<String, Arc<str>>,
    misses: BTreeSet<String>,
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
```

- [ ] **Step 2: Add module declaration to lib.rs**

Add after the `persistent_nar_store` declaration:

```rust
#[cfg(feature = "std")]
pub mod nix_binary_cache;
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p harmony-os nix_binary_cache`
Expected: Compilation error — no `new()` or `handle_request()` methods.

- [ ] **Step 4: Implement new() and handle_request() with CacheInfo routing**

Add to `nix_binary_cache.rs`:

```rust
impl BinaryCacheServer {
    /// Create a new binary cache server from an existing NixStoreServer.
    ///
    /// Builds the hash index by scanning existing store path names.
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

    /// Handle a binary cache request path.
    pub fn handle_request(&mut self, path: &str) -> CacheResponse {
        if path == "/nix-cache-info" {
            return CacheResponse::CacheInfo(
                "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n".to_string(),
            );
        }

        // Placeholder — remaining routes added in subsequent tasks.
        CacheResponse::NotFound
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p harmony-os nix_binary_cache`
Expected: PASS

- [ ] **Step 6: Commit**

```
git add crates/harmony-os/src/nix_binary_cache.rs crates/harmony-os/src/lib.rs
git commit -m "feat: BinaryCacheServer skeleton with nix-cache-info"
```

---

## Task 5: BinaryCacheServer — Narinfo Routing

**Files:**
- Modify: `crates/harmony-os/src/nix_binary_cache.rs`

- [ ] **Step 1: Write failing tests for narinfo requests**

Add to `mod tests`:

```rust
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
fn handle_narinfo_request() {
    let mut srv = build_server_with_nar("abc12345678901234567890123456789-hello", b"data");
    let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
    match resp {
        CacheResponse::Narinfo(text) => {
            assert!(text.contains("StorePath: /nix/store/abc12345678901234567890123456789-hello"));
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
    assert_eq!(srv.handle_request("/abc.narinfo"), CacheResponse::BadRequest);
    // Non-hex chars.
    assert_eq!(
        srv.handle_request("/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.narinfo"),
        CacheResponse::BadRequest
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os nix_binary_cache`
Expected: FAIL — narinfo routing not implemented yet, `drain_misses` doesn't exist.

- [ ] **Step 3: Implement narinfo routing + drain_misses**

Update `handle_request` and add `drain_misses`:

```rust
use sha2::{Digest, Sha256};
use crate::narinfo::serialize_narinfo;

// In handle_request, after the cache-info check:
if let Some(hash) = path.strip_suffix(".narinfo").and_then(|p| p.strip_prefix('/')) {
    // Validate: must be exactly 32 hex chars.
    if hash.len() != 32 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return CacheResponse::BadRequest;
    }
    return match self.hash_index.get(hash) {
        Some(full_name) => {
            let nar_blob = self.server.get_nar_blob(full_name).unwrap();
            let sha256 = Sha256::digest(nar_blob);
            let text = serialize_narinfo(full_name, sha256.as_slice(), nar_blob.len() as u64);
            CacheResponse::Narinfo(text)
        }
        None => {
            self.misses.insert(hash.to_string());
            CacheResponse::NotFound
        }
    };
}

// drain_misses method:
pub fn drain_misses(&mut self) -> Vec<String> {
    core::mem::take(&mut self.misses).into_iter().collect()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os nix_binary_cache`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```
git add crates/harmony-os/src/nix_binary_cache.rs
git commit -m "feat: BinaryCacheServer narinfo routing with hash index"
```

---

## Task 6: BinaryCacheServer — NAR Data Routing

**Files:**
- Modify: `crates/harmony-os/src/nix_binary_cache.rs`

- [ ] **Step 1: Write failing tests for NAR data requests**

```rust
#[test]
fn handle_nar_data_request() {
    let name = "abc12345678901234567890123456789-hello";
    let content = b"nar file content";
    let mut srv = build_server_with_nar(name, content);

    let resp = srv.handle_request(&format!("/nar/{name}.nar"));
    match resp {
        CacheResponse::NarData(bytes) => {
            // The NAR data is the full NAR archive, not just the file content.
            // Verify it's non-empty and matches what NixStoreServer has.
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os nix_binary_cache::tests::handle_nar`
Expected: FAIL — NAR routing not implemented.

- [ ] **Step 3: Implement NAR data routing**

In `handle_request`, after the narinfo routing:

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os nix_binary_cache`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```
git add crates/harmony-os/src/nix_binary_cache.rs
git commit -m "feat: BinaryCacheServer NAR data serving"
```

---

## Task 7: BinaryCacheServer — Import + Remaining API

**Files:**
- Modify: `crates/harmony-os/src/nix_binary_cache.rs`

- [ ] **Step 1: Write failing tests for import_nar and hash index lifecycle**

```rust
#[test]
fn hash_index_populated_on_import() {
    let mut srv = build_server();
    let name = "imp12345678901234567890123456789-imported";

    srv.import_nar(name, build_test_nar(b"imported data")).unwrap();

    // Narinfo should now be servable.
    let resp = srv.handle_request("/imp12345678901234567890123456789.narinfo");
    match resp {
        CacheResponse::Narinfo(text) => {
            assert!(text.contains(name));
        }
        other => panic!("expected Narinfo after import, got {other:?}"),
    }
}

#[test]
fn import_after_miss() {
    let mut srv = build_server();
    let hash = "mis12345678901234567890123456789";
    let name = format!("{hash}-recovered");

    // First request: miss.
    assert_eq!(srv.handle_request(&format!("/{hash}.narinfo")), CacheResponse::NotFound);
    let misses = srv.drain_misses();
    assert_eq!(misses, vec![hash]);

    // Import the NAR (simulating background fetch).
    srv.import_nar(&name, build_test_nar(b"recovered")).unwrap();

    // Second request: hit.
    match srv.handle_request(&format!("/{hash}.narinfo")) {
        CacheResponse::Narinfo(text) => assert!(text.contains(&name)),
        other => panic!("expected Narinfo after import, got {other:?}"),
    }

    // No new misses.
    assert!(srv.drain_misses().is_empty());
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
    assert_eq!(misses.len(), 1); // BTreeSet deduplicates
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os nix_binary_cache`
Expected: Compilation error — `import_nar`, `has_store_path` don't exist.

- [ ] **Step 3: Implement import_nar, has_store_path, server_mut**

```rust
/// Import a NAR into the underlying server and update the hash index.
pub fn import_nar(&mut self, name: &str, nar_bytes: Vec<u8>) -> Result<(), NarError> {
    self.server.import_nar(name, nar_bytes)?;
    if name.len() >= 32 {
        let hash = name[..32].to_string();
        self.hash_index.insert(hash, Arc::from(name));
    }
    Ok(())
}

/// Check whether a store path is available.
pub fn has_store_path(&self, name: &str) -> bool {
    self.server.has_store_path(name)
}

/// Mutable access to the underlying NixStoreServer.
///
/// Escape hatch for callers that need direct 9P interaction
/// (e.g., NixStoreFetcher's process_misses).
pub fn server_mut(&mut self) -> &mut NixStoreServer {
    &mut self.server
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os nix_binary_cache`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```
git add crates/harmony-os/src/nix_binary_cache.rs
git commit -m "feat: BinaryCacheServer import_nar with hash index update"
```

---

## Task 8: Quality Gates + Claim Bead

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All tests PASS, count increased by ~15-20.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: No warnings.

- [ ] **Step 3: Run format check**

Run: `cargo fmt --all -- --check`
Expected: Clean.

- [ ] **Step 4: Claim bead and create branch**

```
bd update harmony-os-q9d --claim --status in_progress
git checkout -b jake-os-nix-binary-cache
git push -u origin jake-os-nix-binary-cache
```

Note: The implementer should have created this branch before Task 1 per the standard workflow. If working in-session, rebase all commits onto the branch before pushing.

- [ ] **Step 5: Create PR**

```
gh pr create --title "feat: sans-I/O Nix binary cache protocol layer" --body "..."
```
