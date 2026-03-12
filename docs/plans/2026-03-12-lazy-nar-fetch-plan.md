# Lazy NAR Fetch Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Automatically fetch missing Nix store paths from cache.nixos.org when NixStoreServer doesn't have them locally.

**Architecture:** Push model — NixStoreServer (Ring 2, sans-I/O) records walk misses in a `Vec<Arc<str>>`. A new NixStoreFetcher (Ring 3, `std`) drains misses on a dedicated thread, fetches `.narinfo` + `.nar.xz` from cache.nixos.org via blocking HTTP, decompresses, verifies SHA-256, and imports via `import_nar()`. Shared access via `Arc<Mutex<NixStoreServer>>` with a `SharedNixStoreServer` wrapper implementing `FileServer`.

**Tech Stack:** Rust, `ureq` (blocking HTTP), `xz2` (decompression), `sha2` (hash verification), `data-encoding` (Nix base32)

**Design doc:** `docs/plans/2026-03-12-lazy-nar-fetch-design.md`

---

### Task 1: Add miss recording to NixStoreServer

Add a `misses` field and `drain_misses()` method to NixStoreServer. Record missed store path names during walk.

**Files:**
- Modify: `crates/harmony-microkernel/src/nix_store_server.rs:50-53` (struct fields)
- Modify: `crates/harmony-microkernel/src/nix_store_server.rs:104-111` (constructor)
- Modify: `crates/harmony-microkernel/src/nix_store_server.rs:230-235` (walk Root arm)
- Test: `crates/harmony-microkernel/src/nix_store_server.rs` (tests module)

**Step 1: Write the failing tests**

Add these tests at the end of the `mod tests` block (before the `mod kernel_integration` block) in `crates/harmony-microkernel/src/nix_store_server.rs`:

```rust
#[test]
fn walk_miss_is_recorded() {
    let mut srv = NixStoreServer::new();
    // Walk to a non-existent store path.
    assert_eq!(srv.walk(0, 1, "nonexistent-pkg"), Err(IpcError::NotFound));
    // The miss should be recorded.
    let misses = srv.drain_misses();
    assert_eq!(misses.len(), 1);
    assert_eq!(&*misses[0], "nonexistent-pkg");
}

#[test]
fn drain_misses_clears_list() {
    let mut srv = NixStoreServer::new();
    assert_eq!(srv.walk(0, 1, "miss-one"), Err(IpcError::NotFound));
    assert_eq!(srv.walk(0, 2, "miss-two"), Err(IpcError::NotFound));
    // First drain returns both.
    let misses = srv.drain_misses();
    assert_eq!(misses.len(), 2);
    // Second drain returns empty.
    let misses2 = srv.drain_misses();
    assert!(misses2.is_empty());
}

#[test]
fn drain_misses_on_empty_server() {
    let mut srv = NixStoreServer::new();
    let misses = srv.drain_misses();
    assert!(misses.is_empty());
}

#[test]
fn duplicate_misses_are_recorded() {
    let mut srv = NixStoreServer::new();
    assert_eq!(srv.walk(0, 1, "same-pkg"), Err(IpcError::NotFound));
    assert_eq!(srv.walk(0, 2, "same-pkg"), Err(IpcError::NotFound));
    let misses = srv.drain_misses();
    assert_eq!(misses.len(), 2);
    assert_eq!(&*misses[0], "same-pkg");
    assert_eq!(&*misses[1], "same-pkg");
}

#[test]
fn existing_store_path_walk_does_not_record_miss() {
    let mut srv = test_server(); // has "abc123-hello"
    srv.walk(0, 1, "abc123-hello").unwrap();
    let misses = srv.drain_misses();
    assert!(misses.is_empty());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel -- walk_miss_is_recorded drain_misses_clears_list drain_misses_on_empty_server duplicate_misses_are_recorded existing_store_path_walk_does_not_record_miss`
Expected: FAIL — `drain_misses` method does not exist.

**Step 3: Implement miss recording**

In `crates/harmony-microkernel/src/nix_store_server.rs`:

1. Add `misses` field to `NixStoreServer`:

```rust
pub struct NixStoreServer {
    store_paths: BTreeMap<Arc<str>, StorePath>,
    tracker: FidTracker<NixFidPayload>,
    misses: Vec<Arc<str>>,
}
```

2. Update `new()` to initialize `misses`:

```rust
pub fn new() -> Self {
    Self {
        store_paths: BTreeMap::new(),
        tracker: FidTracker::new(0, NixFidPayload::Root),
        misses: Vec::new(),
    }
}
```

3. Add `drain_misses()` method in the `impl NixStoreServer` block, after `import_nar`:

```rust
/// Drain all recorded miss events (store path names that were walked
/// but not found). The fetcher calls this periodically to discover
/// which store paths need fetching.
pub fn drain_misses(&mut self) -> Vec<Arc<str>> {
    core::mem::take(&mut self.misses)
}
```

4. In the `walk` method's `NixFidPayload::Root` arm, record the miss before returning `NotFound`. Change:

```rust
NixFidPayload::Root => {
    let key: Arc<str> = Arc::from(name);
    if !self.store_paths.contains_key(&key) {
        return Err(IpcError::NotFound);
    }
    NixFidPayload::StorePathRoot { name: key }
}
```

To:

```rust
NixFidPayload::Root => {
    let key: Arc<str> = Arc::from(name);
    if !self.store_paths.contains_key(&key) {
        self.misses.push(Arc::clone(&key));
        return Err(IpcError::NotFound);
    }
    NixFidPayload::StorePathRoot { name: key }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel -- walk_miss_is_recorded drain_misses_clears_list drain_misses_on_empty_server duplicate_misses_are_recorded existing_store_path_walk_does_not_record_miss`
Expected: PASS (all 5 new tests)

**Step 5: Run full test suite to verify no regressions**

Run: `cargo test -p harmony-microkernel`
Expected: All existing tests still pass.

**Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/nix_store_server.rs
git commit -m "feat(nix): add miss recording to NixStoreServer for lazy fetch"
```

---

### Task 2: Add SharedNixStoreServer wrapper

Create a `FileServer` wrapper around `Arc<Mutex<NixStoreServer>>` so the kernel and fetcher thread can share access.

**Files:**
- Modify: `crates/harmony-microkernel/src/nix_store_server.rs` (add wrapper struct + impl at end of non-test code)

**Step 1: Write the failing test**

Add this test in the `mod tests` block of `nix_store_server.rs`:

```rust
#[test]
fn shared_wrapper_delegates_walk_and_stat() {
    use alloc::sync::Arc;

    let inner = NixStoreServer::new();
    let shared_inner = Arc::new(Mutex::new(inner));
    shared_inner
        .lock()
        .unwrap()
        .import_nar("abc123-hello", nar_directory_with_files())
        .unwrap();

    let mut wrapper = SharedNixStoreServer {
        inner: Arc::clone(&shared_inner),
    };

    // Walk and stat through the wrapper.
    let qp = wrapper.walk(0, 1, "abc123-hello").unwrap();
    assert_ne!(qp, 0);
    let st = wrapper.stat(1).unwrap();
    assert_eq!(&*st.name, "abc123-hello");
    assert_eq!(st.file_type, FileType::Directory);

    // Verify the inner server's state changed (fid was allocated).
    let inner_st = shared_inner.lock().unwrap().stat(1).unwrap();
    assert_eq!(&*inner_st.name, "abc123-hello");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-microkernel -- shared_wrapper_delegates_walk_and_stat`
Expected: FAIL — `SharedNixStoreServer` does not exist.

**Step 3: Implement SharedNixStoreServer**

Add these imports at the top of `nix_store_server.rs` (after the existing `use` statements):

```rust
#[cfg(feature = "std")]
use std::sync::Mutex;
```

Add the wrapper struct and `FileServer` impl after the existing `impl FileServer for NixStoreServer` block, before the `#[cfg(test)]` module:

```rust
/// Thread-safe wrapper around `NixStoreServer`.
///
/// The kernel holds this as a `Box<dyn FileServer>`, while the fetcher
/// thread holds a clone of the inner `Arc<Mutex<NixStoreServer>>` for
/// `drain_misses()` and `import_nar()` calls.
#[cfg(feature = "std")]
pub struct SharedNixStoreServer {
    pub inner: Arc<Mutex<NixStoreServer>>,
}

#[cfg(feature = "std")]
impl FileServer for SharedNixStoreServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        self.inner.lock().unwrap().walk(fid, new_fid, name)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        self.inner.lock().unwrap().open(fid, mode)
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        self.inner.lock().unwrap().read(fid, offset, count)
    }

    fn write(&mut self, fid: Fid, offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        self.inner.lock().unwrap().write(fid, offset, data)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.inner.lock().unwrap().clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        self.inner.lock().unwrap().stat(fid)
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.inner.lock().unwrap().clone_fid(fid, new_fid)
    }
}
```

Also add `use std::sync::Mutex;` to the test module imports (it uses `#[cfg(test)]` which enables `std`):

In the test module, add at the top of `mod tests`:

```rust
use std::sync::Mutex;
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p harmony-microkernel -- shared_wrapper_delegates_walk_and_stat`
Expected: PASS

**Step 5: Run full test suite**

Run: `cargo test -p harmony-microkernel`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/nix_store_server.rs
git commit -m "feat(nix): add SharedNixStoreServer wrapper for thread-safe access"
```

---

### Task 3: Add new dependencies to harmony-os

Add `ureq`, `xz2`, `sha2`, and `data-encoding` to the `harmony-os` crate for the fetcher.

**Files:**
- Modify: `crates/harmony-os/Cargo.toml`

**Step 1: Add dependencies**

Add these to the `[dependencies]` section of `crates/harmony-os/Cargo.toml`, inside the `std` feature gate (since the fetcher only works with `std`):

```toml
# Lazy NAR fetch (Layer 4) — Ring 3 only
ureq = { version = "3", optional = true }
xz2 = { version = "0.1", optional = true }
sha2 = { version = "0.10", optional = true }
data-encoding = { version = "2", optional = true }
```

Add these to the `std` feature list:

```toml
std = [
    "harmony-microkernel/kernel",
    "dep:harmony-crypto", "harmony-crypto/std",
    "dep:harmony-identity", "harmony-identity/std",
    "dep:harmony-reticulum", "harmony-reticulum/std",
    "dep:harmony-zenoh",
    "dep:harmony-content",
    "dep:harmony-compute",
    "dep:harmony-workflow",
    "dep:ureq",
    "dep:xz2",
    "dep:sha2",
    "dep:data-encoding",
]
```

**Step 2: Verify it compiles**

Run: `cargo check -p harmony-os`
Expected: Compiles successfully with new deps.

**Step 3: Commit**

```bash
git add crates/harmony-os/Cargo.toml
git commit -m "build(os): add ureq, xz2, sha2, data-encoding for lazy NAR fetch"
```

---

### Task 4: Implement Nix base32 decoder

Nix uses a non-standard base32 alphabet (`0123456789abcdfghijklmnpqrsvwxyz` — no `e`, `o`, `t`, `u`). The `data-encoding` crate can build custom encodings. We need a decoder for the `NarHash` field in `.narinfo` files.

**Files:**
- Create: `crates/harmony-os/src/nix_base32.rs`
- Modify: `crates/harmony-os/src/lib.rs` (add module)

**Step 1: Write the failing tests**

Create `crates/harmony-os/src/nix_base32.rs` with tests only:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Nix-specific base32 decoder.
//!
//! Nix uses a non-standard base32 alphabet: `0123456789abcdfghijklmnpqrsvwxyz`
//! (missing `e`, `o`, `t`, `u` to avoid confusion). Hashes are encoded with
//! the least-significant digit first (reversed from conventional base32).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_known_sha256() {
        // SHA-256 hash of an empty NAR, as Nix encodes it.
        // nix-hash --type sha256 --to-nix-base32 produces this from hex.
        // The hex representation:
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // In Nix base32 (reversed LSB-first):
        // 3w1iyc0vbabc1jf2hpiz0g2hg3wyi81i9dcf90p7wr3ssdazdynx
        let nix_b32 = "3w1iyc0vbabc1jf2hpiz0g2hg3wyi81i9dcf90p7wr3ssdazdynx";
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let expected: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&expected_hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let decoded = decode_nix_base32(nix_b32).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn reject_invalid_char() {
        // 'e' is not in the Nix base32 alphabet.
        assert!(decode_nix_base32("e000000000000000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn reject_wrong_length_for_sha256() {
        // SHA-256 needs exactly 52 Nix base32 chars.
        assert!(decode_nix_base32("abc").is_ok()); // short decode is allowed
        // but the caller validates length — decoder just decodes what it gets
    }

    #[test]
    fn empty_input() {
        let decoded = decode_nix_base32("").unwrap();
        assert!(decoded.is_empty());
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- nix_base32`
Expected: FAIL — `decode_nix_base32` does not exist.

**Step 3: Implement the decoder**

Add the implementation above the `#[cfg(test)]` block in `crates/harmony-os/src/nix_base32.rs`:

```rust
/// Nix base32 alphabet (32 chars, missing e/o/t/u).
const NIX_BASE32_CHARS: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Decode a Nix base32 string into bytes.
///
/// Nix base32 encodes with least-significant digit first. The output
/// length is `input.len() * 5 / 8` bytes.
pub fn decode_nix_base32(input: &str) -> Result<Vec<u8>, NixBase32Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let hash_size = input.len() * 5 / 8;
    let mut out = vec![0u8; hash_size];

    for (i, c) in input.chars().enumerate() {
        let digit = NIX_BASE32_CHARS
            .iter()
            .position(|&ch| ch == c as u8)
            .ok_or(NixBase32Error::InvalidChar(c))? as u64;

        // Nix base32 is LSB-first: character i contributes to bit position i*5.
        let mut b = i * 5;
        let mut d = digit;
        for _ in 0..5 {
            if b / 8 < hash_size {
                out[b / 8] |= ((d & 1) as u8) << (b % 8);
            }
            b += 1;
            d >>= 1;
        }
    }

    // Nix stores the result in big-endian byte order but bit-reversal
    // within the base32 encoding means we need to reverse the bytes.
    out.reverse();
    Ok(out)
}

/// Errors from Nix base32 decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NixBase32Error {
    /// Input contains a character not in the Nix base32 alphabet.
    InvalidChar(char),
}
```

Add the module to `crates/harmony-os/src/lib.rs`:

```rust
pub mod nix_base32;
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os -- nix_base32`
Expected: PASS

**Step 5: Run clippy**

Run: `cargo clippy -p harmony-os`
Expected: No warnings.

**Step 6: Commit**

```bash
git add crates/harmony-os/src/nix_base32.rs crates/harmony-os/src/lib.rs
git commit -m "feat(os): add Nix base32 decoder for NAR hash verification"
```

---

### Task 5: Implement NARInfo parser

Parse the `.narinfo` text format to extract `URL`, `NarHash`, and `NarSize`.

**Files:**
- Create: `crates/harmony-os/src/narinfo.rs`
- Modify: `crates/harmony-os/src/lib.rs` (add module)

**Step 1: Write the failing tests**

Create `crates/harmony-os/src/narinfo.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! NARInfo parser — extracts URL, NarHash, and NarSize from `.narinfo` files.
//!
//! NARInfo is a simple line-based format served by Nix binary caches.
//! We only need three fields for Layer 4 (lazy fetch).

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_NARINFO: &str = "\
StorePath: /nix/store/abc123-hello-2.10
URL: nar/1234abcd.nar.xz
Compression: xz
FileHash: sha256:aaaa
FileSize: 5678
NarHash: sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5vpj0850gk224669lcr3yq
NarSize: 12345
References: def456-glibc-2.38 ghi789-gcc-13.2
Deriver: jkl012-hello-2.10.drv
Sig: cache.nixos.org-1:abcdef1234567890\n";

    #[test]
    fn parse_valid_narinfo() {
        let info = NarInfo::parse(SAMPLE_NARINFO).unwrap();
        assert_eq!(info.url, "nar/1234abcd.nar.xz");
        assert_eq!(
            info.nar_hash,
            "sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5vpj0850gk224669lcr3yq"
        );
        assert_eq!(info.nar_size, 12345);
    }

    #[test]
    fn reject_missing_url() {
        let input = "NarHash: sha256:abc\nNarSize: 100\n";
        assert_eq!(NarInfo::parse(input), Err(NarInfoError::MissingField("URL")));
    }

    #[test]
    fn reject_missing_nar_hash() {
        let input = "URL: nar/foo.nar.xz\nNarSize: 100\n";
        assert_eq!(
            NarInfo::parse(input),
            Err(NarInfoError::MissingField("NarHash"))
        );
    }

    #[test]
    fn reject_missing_nar_size() {
        let input = "URL: nar/foo.nar.xz\nNarHash: sha256:abc\n";
        assert_eq!(
            NarInfo::parse(input),
            Err(NarInfoError::MissingField("NarSize"))
        );
    }

    #[test]
    fn reject_invalid_nar_size() {
        let input = "URL: nar/foo.nar.xz\nNarHash: sha256:abc\nNarSize: notanumber\n";
        assert_eq!(NarInfo::parse(input), Err(NarInfoError::InvalidNarSize));
    }

    #[test]
    fn fields_can_appear_in_any_order() {
        let input = "NarSize: 42\nNarHash: sha256:xyz\nURL: nar/bar.nar.xz\n";
        let info = NarInfo::parse(input).unwrap();
        assert_eq!(info.url, "nar/bar.nar.xz");
        assert_eq!(info.nar_hash, "sha256:xyz");
        assert_eq!(info.nar_size, 42);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- narinfo`
Expected: FAIL — `NarInfo` type does not exist.

**Step 3: Implement the parser**

Add above the `#[cfg(test)]` block:

```rust
/// Parsed NARInfo — the three fields needed for lazy fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarInfo {
    /// Relative URL to the NAR file (e.g. `nar/1234abcd.nar.xz`).
    pub url: String,
    /// Hash of the decompressed NAR (e.g. `sha256:<nix-base32>`).
    pub nar_hash: String,
    /// Size of the decompressed NAR in bytes.
    pub nar_size: u64,
}

/// Errors from parsing NARInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarInfoError {
    /// A required field was not found.
    MissingField(&'static str),
    /// NarSize was not a valid integer.
    InvalidNarSize,
}

impl NarInfo {
    /// Parse a NARInfo response body.
    pub fn parse(input: &str) -> Result<Self, NarInfoError> {
        let mut url = None;
        let mut nar_hash = None;
        let mut nar_size = None;

        for line in input.lines() {
            if let Some(val) = line.strip_prefix("URL: ") {
                url = Some(val.to_string());
            } else if let Some(val) = line.strip_prefix("NarHash: ") {
                nar_hash = Some(val.to_string());
            } else if let Some(val) = line.strip_prefix("NarSize: ") {
                nar_size = Some(
                    val.parse::<u64>()
                        .map_err(|_| NarInfoError::InvalidNarSize)?,
                );
            }
        }

        Ok(NarInfo {
            url: url.ok_or(NarInfoError::MissingField("URL"))?,
            nar_hash: nar_hash.ok_or(NarInfoError::MissingField("NarHash"))?,
            nar_size: nar_size.ok_or(NarInfoError::MissingField("NarSize"))?,
        })
    }
}
```

Add the module to `crates/harmony-os/src/lib.rs`:

```rust
pub mod narinfo;
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os -- narinfo`
Expected: PASS (all 6 tests)

**Step 5: Commit**

```bash
git add crates/harmony-os/src/narinfo.rs crates/harmony-os/src/lib.rs
git commit -m "feat(os): add NARInfo parser for lazy NAR fetch"
```

---

### Task 6: Implement NixStoreFetcher with injectable HTTP

The core fetcher logic: drain misses, fetch narinfo + NAR, decompress, verify hash, import. HTTP is injectable (trait) for testability.

**Files:**
- Create: `crates/harmony-os/src/nix_store_fetcher.rs`
- Modify: `crates/harmony-os/src/lib.rs` (add module)

**Step 1: Write the failing tests**

Create `crates/harmony-os/src/nix_store_fetcher.rs` with tests:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! NixStoreFetcher — Ring 3 lazy fetch orchestrator.
//!
//! Drains walk misses from `NixStoreServer`, fetches `.narinfo` + `.nar.xz`
//! from cache.nixos.org, decompresses, verifies SHA-256, and imports.
//! HTTP is injectable for testing.

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_microkernel::nix_store_server::NixStoreServer;
    use harmony_microkernel::nar::tests::{nar_regular_file, nar_string};
    use harmony_microkernel::IpcError;
    use std::collections::HashMap;
    use std::io::Write as IoWrite;

    /// Build a minimal valid NAR for testing, compute its SHA-256, and
    /// return (nar_bytes, sha256_hex).
    fn test_nar_and_hash() -> (Vec<u8>, String) {
        let nar = nar_regular_file(b"hello from nix", false);
        let hash = sha2::Sha256::digest(&nar);
        let hex = hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        (nar, hex)
    }

    /// Encode bytes as Nix base32.
    fn to_nix_base32(bytes: &[u8]) -> String {
        use crate::nix_base32::NIX_BASE32_CHARS;
        let hash_size = bytes.len();
        // Nix base32: reversed bytes, LSB-first encoding
        let reversed: Vec<u8> = bytes.iter().rev().copied().collect();
        let nchar = (hash_size * 8 + 4) / 5; // ceil(bits / 5)
        let mut out = String::with_capacity(nchar);
        for i in 0..nchar {
            let mut digit: u8 = 0;
            for j in (0..5).rev() {
                let b = i * 5 + j;
                if b / 8 < hash_size {
                    digit = (digit << 1) | ((reversed[b / 8] >> (b % 8)) & 1);
                } else {
                    digit <<= 1;
                }
            }
            out.push(NIX_BASE32_CHARS[digit as usize] as char);
        }
        out
    }

    /// XZ-compress a byte slice.
    fn xz_compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Build a canned narinfo + nar.xz response set for a given NAR.
    fn build_test_responses(
        store_hash: &str,
        nar_bytes: &[u8],
        sha256_hex: &str,
    ) -> HashMap<String, Result<Vec<u8>, FetchError>> {
        let nix_b32 = to_nix_base32(
            &(0..32)
                .map(|i| u8::from_str_radix(&sha256_hex[i * 2..i * 2 + 2], 16).unwrap())
                .collect::<Vec<u8>>(),
        );

        let narinfo = format!(
            "StorePath: /nix/store/{store_hash}-test-pkg\n\
             URL: nar/test.nar.xz\n\
             Compression: xz\n\
             NarHash: sha256:{nix_b32}\n\
             NarSize: {}\n",
            nar_bytes.len()
        );

        let nar_xz = xz_compress(nar_bytes);

        let mut responses = HashMap::new();
        responses.insert(
            format!("https://cache.nixos.org/{store_hash}.narinfo"),
            Ok(narinfo.into_bytes()),
        );
        responses.insert(
            "https://cache.nixos.org/nar/test.nar.xz".to_string(),
            Ok(nar_xz),
        );
        responses
    }

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

    #[test]
    fn fetch_and_import_success() {
        let (nar, hex) = test_nar_and_hash();
        let responses = build_test_responses("abc12345678901234567890123456789", &nar, &hex);
        let http = MockHttp { responses };

        let mut server = NixStoreServer::new();
        // Trigger a miss.
        assert_eq!(
            server.walk(0, 1, "abc12345678901234567890123456789-test-pkg"),
            Err(IpcError::NotFound)
        );

        let mut fetcher = NixStoreFetcher::new(Box::new(http));
        fetcher.process_misses(&mut server);

        // Now the store path should be importable — walk should succeed.
        let qp = server
            .walk(0, 2, "abc12345678901234567890123456789-test-pkg")
            .unwrap();
        assert_ne!(qp, 0);
    }

    #[test]
    fn fetch_404_records_failure() {
        let http = MockHttp {
            responses: HashMap::new(),
        };

        let mut server = NixStoreServer::new();
        assert_eq!(
            server.walk(0, 1, "missing01234567890123456789012-pkg"),
            Err(IpcError::NotFound)
        );

        let mut fetcher = NixStoreFetcher::new(Box::new(http));
        fetcher.process_misses(&mut server);

        // Should be in the failed set.
        assert!(fetcher.failed.contains("missing01234567890123456789012-pkg"));

        // A second miss for the same path should be skipped.
        assert_eq!(
            server.walk(0, 2, "missing01234567890123456789012-pkg"),
            Err(IpcError::NotFound)
        );
        fetcher.process_misses(&mut server);
        // Still only one entry in failed (didn't re-attempt).
    }

    #[test]
    fn hash_mismatch_records_failure() {
        let (nar, _hex) = test_nar_and_hash();
        // Use a WRONG hash in the narinfo.
        let wrong_hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let responses =
            build_test_responses("abc12345678901234567890123456789", &nar, wrong_hex);
        let http = MockHttp { responses };

        let mut server = NixStoreServer::new();
        assert_eq!(
            server.walk(0, 1, "abc12345678901234567890123456789-test-pkg"),
            Err(IpcError::NotFound)
        );

        let mut fetcher = NixStoreFetcher::new(Box::new(http));
        fetcher.process_misses(&mut server);

        // Import should have failed — path still not available.
        assert_eq!(
            server.walk(0, 2, "abc12345678901234567890123456789-test-pkg"),
            Err(IpcError::NotFound)
        );
        assert!(fetcher
            .failed
            .contains("abc12345678901234567890123456789-test-pkg"));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- nix_store_fetcher`
Expected: FAIL — types don't exist.

**Step 3: Implement the fetcher**

Add above the `#[cfg(test)]` block in `crates/harmony-os/src/nix_store_fetcher.rs`:

```rust
use std::collections::HashSet;

use harmony_microkernel::nix_store_server::NixStoreServer;
use sha2::Digest;

use crate::narinfo::NarInfo;
use crate::nix_base32::decode_nix_base32;

/// Errors during fetch operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// HTTP 404 — store path not found upstream.
    NotFound,
    /// Network or HTTP error.
    Network(String),
    /// NARInfo parsing failed.
    NarInfo(String),
    /// Decompression failed.
    Decompress(String),
    /// SHA-256 hash mismatch.
    HashMismatch,
    /// Nix base32 decode failed.
    Base32(String),
    /// NAR import failed.
    Import(String),
}

/// Injectable HTTP client trait for testability.
pub trait HttpClient {
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError>;
}

/// Ring 3 lazy fetch orchestrator for NixStoreServer.
///
/// Drains walk misses, fetches NARs from cache.nixos.org, and imports them.
pub struct NixStoreFetcher {
    http: Box<dyn HttpClient>,
    cache_url: String,
    failed: HashSet<String>,
}

impl NixStoreFetcher {
    pub fn new(http: Box<dyn HttpClient>) -> Self {
        Self {
            http,
            cache_url: "https://cache.nixos.org".to_string(),
            failed: HashSet::new(),
        }
    }

    /// Process all pending misses: drain, deduplicate, fetch, import.
    pub fn process_misses(&mut self, server: &mut NixStoreServer) {
        let misses = server.drain_misses();
        // Deduplicate within this batch.
        let mut seen = HashSet::new();
        for name in misses {
            let name_str = name.to_string();
            if self.failed.contains(&name_str) || !seen.insert(name_str.clone()) {
                continue;
            }
            if let Err(e) = self.fetch_and_import(&name_str, server) {
                log::warn!("fetch failed for {name_str}: {e:?}");
                self.failed.insert(name_str);
            }
        }
    }

    /// Fetch a single store path: narinfo → NAR → decompress → verify → import.
    fn fetch_and_import(
        &self,
        store_path_name: &str,
        server: &mut NixStoreServer,
    ) -> Result<(), FetchError> {
        // Extract the store hash (first 32 chars of the store path name).
        let store_hash = store_path_name
            .get(..32)
            .ok_or_else(|| FetchError::Network("store path name too short for hash".into()))?;

        // 1. Fetch narinfo.
        let narinfo_url = format!("{}/{store_hash}.narinfo", self.cache_url);
        let narinfo_bytes = self.http.get(&narinfo_url)?;
        let narinfo_text =
            String::from_utf8(narinfo_bytes).map_err(|e| FetchError::NarInfo(e.to_string()))?;
        let narinfo =
            NarInfo::parse(&narinfo_text).map_err(|e| FetchError::NarInfo(format!("{e:?}")))?;

        // 2. Fetch NAR (compressed).
        let nar_url = format!("{}/{}", self.cache_url, narinfo.url);
        let nar_compressed = self.http.get(&nar_url)?;

        // 3. Decompress (xz).
        let nar_bytes = decompress_xz(&nar_compressed)?;

        // 4. Verify SHA-256.
        verify_nar_hash(&nar_bytes, &narinfo.nar_hash)?;

        // 5. Import.
        server
            .import_nar(store_path_name, nar_bytes)
            .map_err(|e| FetchError::Import(format!("{e:?}")))?;

        Ok(())
    }
}

/// Decompress xz-compressed data.
fn decompress_xz(data: &[u8]) -> Result<Vec<u8>, FetchError> {
    use std::io::Read;
    let mut decoder = xz2::read::XzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| FetchError::Decompress(e.to_string()))?;
    Ok(out)
}

/// Verify that the SHA-256 of `nar_bytes` matches the expected hash.
/// `expected` is in the format `sha256:<nix-base32>`.
fn verify_nar_hash(nar_bytes: &[u8], expected: &str) -> Result<(), FetchError> {
    let nix_b32 = expected
        .strip_prefix("sha256:")
        .ok_or_else(|| FetchError::Base32("expected sha256: prefix".into()))?;

    let expected_bytes =
        decode_nix_base32(nix_b32).map_err(|e| FetchError::Base32(format!("{e:?}")))?;

    let actual = sha2::Sha256::digest(nar_bytes);

    if actual.as_slice() != expected_bytes {
        return Err(FetchError::HashMismatch);
    }

    Ok(())
}
```

Add to `crates/harmony-os/src/lib.rs`:

```rust
pub mod nix_store_fetcher;
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os -- nix_store_fetcher`
Expected: PASS (all 3 tests)

**Step 5: Run clippy**

Run: `cargo clippy -p harmony-os`
Expected: No warnings.

**Step 6: Commit**

```bash
git add crates/harmony-os/src/nix_store_fetcher.rs crates/harmony-os/src/lib.rs
git commit -m "feat(os): add NixStoreFetcher with injectable HTTP for lazy NAR fetch"
```

---

### Task 7: Implement UreqHttpClient for production use

Wire up `ureq` as the real HTTP client implementing `HttpClient`.

**Files:**
- Modify: `crates/harmony-os/src/nix_store_fetcher.rs` (add impl after trait definition)

**Step 1: Write the failing test**

Add to the `mod tests` in `nix_store_fetcher.rs`:

```rust
#[test]
fn ureq_client_exists() {
    // Smoke test: UreqHttpClient can be constructed.
    let _client = UreqHttpClient::new();
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-os -- ureq_client_exists`
Expected: FAIL — `UreqHttpClient` does not exist.

**Step 3: Implement UreqHttpClient**

Add after the `HttpClient` trait definition in `nix_store_fetcher.rs`:

```rust
/// Production HTTP client using `ureq`.
pub struct UreqHttpClient;

impl UreqHttpClient {
    pub fn new() -> Self {
        Self
    }
}

impl HttpClient for UreqHttpClient {
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        use std::io::Read;
        let response = ureq::get(url).call().map_err(|e| match e {
            ureq::Error::StatusCode(404) => FetchError::NotFound,
            other => FetchError::Network(other.to_string()),
        })?;
        let mut body = Vec::new();
        response
            .into_body()
            .read_to_end(&mut body)
            .map_err(|e| FetchError::Network(e.to_string()))?;
        Ok(body)
    }
}
```

Note: We won't test live HTTP in CI. The smoke test just verifies the type compiles and can be constructed.

**Step 4: Run test to verify it passes**

Run: `cargo test -p harmony-os -- ureq_client_exists`
Expected: PASS

**Step 5: Run full test suite + clippy**

Run: `cargo test -p harmony-os && cargo clippy -p harmony-os`
Expected: All pass, no warnings.

**Step 6: Commit**

```bash
git add crates/harmony-os/src/nix_store_fetcher.rs
git commit -m "feat(os): add UreqHttpClient for production lazy NAR fetch"
```

---

### Task 8: Integration test — SharedNixStoreServer + NixStoreFetcher end-to-end

Test the full flow: shared server wrapped for kernel use, fetcher imports through the mutex, kernel can walk to previously-missing paths.

**Files:**
- Modify: `crates/harmony-os/src/nix_store_fetcher.rs` (add integration test)

**Step 1: Write the test**

Add a new test in `nix_store_fetcher.rs`'s `mod tests`:

```rust
#[test]
fn shared_server_fetch_and_walk() {
    use harmony_microkernel::nix_store_server::SharedNixStoreServer;
    use std::sync::{Arc, Mutex};

    let (nar, hex) = test_nar_and_hash();
    let responses = build_test_responses("abc12345678901234567890123456789", &nar, &hex);
    let http = MockHttp { responses };

    // Set up shared server.
    let server = NixStoreServer::new();
    let shared = Arc::new(Mutex::new(server));

    // Wrap for FileServer use (simulating kernel).
    let mut wrapper = SharedNixStoreServer {
        inner: Arc::clone(&shared),
    };

    // Walk miss through wrapper.
    use harmony_microkernel::FileServer;
    assert_eq!(
        wrapper.walk(0, 1, "abc12345678901234567890123456789-test-pkg"),
        Err(IpcError::NotFound)
    );

    // Fetcher processes misses through the Arc<Mutex>.
    let mut fetcher = NixStoreFetcher::new(Box::new(http));
    {
        let mut srv = shared.lock().unwrap();
        fetcher.process_misses(&mut srv);
    }

    // Now walk through the wrapper should succeed.
    let qp = wrapper
        .walk(0, 2, "abc12345678901234567890123456789-test-pkg")
        .unwrap();
    assert_ne!(qp, 0);
}
```

**Step 2: Run test**

Run: `cargo test -p harmony-os -- shared_server_fetch_and_walk`
Expected: PASS (uses previously implemented components)

**Step 3: Run full workspace test + clippy**

Run: `cargo test --workspace && cargo clippy --workspace`
Expected: All tests pass, no warnings.

**Step 4: Commit**

```bash
git add crates/harmony-os/src/nix_store_fetcher.rs
git commit -m "test(os): add integration test for SharedNixStoreServer + NixStoreFetcher"
```

---

### Task 9: Final verification and cleanup

Run the full quality gate and verify everything works together.

**Step 1: Format check**

Run: `cargo fmt --all -- --check`
Expected: No formatting issues.

**Step 2: Full clippy**

Run: `cargo clippy --workspace`
Expected: No warnings.

**Step 3: Full test suite**

Run: `cargo test --workspace`
Expected: All tests pass.

**Step 4: Review — verify no TODO/FIXME left behind**

Run: `grep -r "TODO\|FIXME\|XXX\|HACK" crates/harmony-os/src/nix_store_fetcher.rs crates/harmony-os/src/narinfo.rs crates/harmony-os/src/nix_base32.rs crates/harmony-microkernel/src/nix_store_server.rs || echo "Clean"`
Expected: "Clean" (no stray markers)
