# Signed Narinfo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Ed25519 `Sig` field to narinfo so Harmony caches work as trusted Nix substituters.

**Architecture:** `BinaryCacheServer` gains an optional `(key_name, PrivateIdentity)` for signing. On each narinfo request, it computes the Nix fingerprint, signs with Ed25519, and appends the `Sig:` line. Signing is skipped when no key or no references.

**Tech Stack:** Rust, `harmony-identity` (Ed25519), `base64` crate, Nix narinfo/fingerprint format

---

## File Structure

| File | Change | Responsibility |
|------|--------|---------------|
| `crates/harmony-os/Cargo.toml` | Modify | Add `base64` dependency |
| `crates/harmony-os/src/narinfo.rs` | Modify | Add `compute_narinfo_fingerprint`, `sig` field on `NarInfo`, `sig` param on `serialize_narinfo` |
| `crates/harmony-os/src/nix_binary_cache.rs` | Modify | Add `signing` field, `new_with_signing` constructor, sign in `handle_request` |

---

### Task 1: Fingerprint computation + NarInfo sig parsing

**Files:**
- Modify: `crates/harmony-os/src/narinfo.rs`

- [ ] **Step 1: Write failing tests for fingerprint computation**

Add to `mod tests` in `narinfo.rs`:

```rust
#[test]
fn compute_fingerprint_with_refs() {
    let fp = compute_narinfo_fingerprint(
        "abc123-hello",
        "sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5vpj0850gk224669lcr3yq",
        12345,
        Some(&["dep456-glibc".to_string(), "ghi789-gcc".to_string()]),
    );
    assert_eq!(
        fp.unwrap(),
        "1;/nix/store/abc123-hello;sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5vpj0850gk224669lcr3yq;12345;dep456-glibc,ghi789-gcc"
    );
}

#[test]
fn compute_fingerprint_empty_refs() {
    let fp = compute_narinfo_fingerprint(
        "abc123-hello",
        "sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5vpj0850gk224669lcr3yq",
        12345,
        Some(&[]),
    );
    assert_eq!(
        fp.unwrap(),
        "1;/nix/store/abc123-hello;sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5vpj0850gk224669lcr3yq;12345;"
    );
}

#[test]
fn compute_fingerprint_none_refs_returns_none() {
    let fp = compute_narinfo_fingerprint(
        "abc123-hello",
        "sha256:abc",
        100,
        None,
    );
    assert!(fp.is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os compute_fingerprint`
Expected: FAIL — function doesn't exist

- [ ] **Step 3: Implement compute_narinfo_fingerprint**

Add this public function to `narinfo.rs` (above `serialize_narinfo`, inside `#[cfg(feature = "std")]` or not — it only uses `alloc` types, so keep it ungated):

```rust
/// Compute the Nix narinfo fingerprint string for signing.
///
/// Format: `1;/nix/store/<name>;<nar_hash>;<nar_size>;<comma-separated-refs>`
///
/// Returns `None` when `references` is `None` (fingerprint requires
/// references to be known).
pub fn compute_narinfo_fingerprint(
    store_path_name: &str,
    nar_hash: &str,
    nar_size: u64,
    references: Option<&[String]>,
) -> Option<String> {
    let refs = references?;
    let comma_refs = refs.join(",");
    Some(format!(
        "1;/nix/store/{store_path_name};{nar_hash};{nar_size};{comma_refs}"
    ))
}
```

- [ ] **Step 4: Run fingerprint tests**

Run: `cargo test -p harmony-os compute_fingerprint`
Expected: PASS

- [ ] **Step 5: Write failing tests for sig parsing**

Add to `mod tests` in `narinfo.rs`:

```rust
#[test]
fn parse_sig_field() {
    let input = "URL: nar/a.nar\nNarHash: sha256:abc\nNarSize: 10\nSig: cache.nixos.org-1:GrGV/abc123==\n";
    let info = NarInfo::parse(input).unwrap();
    assert_eq!(info.sig, Some("cache.nixos.org-1:GrGV/abc123==".to_string()));
}

#[test]
fn parse_missing_sig_is_none() {
    let input = "URL: nar/a.nar\nNarHash: sha256:abc\nNarSize: 10\n";
    let info = NarInfo::parse(input).unwrap();
    assert_eq!(info.sig, None);
}
```

- [ ] **Step 6: Add sig field to NarInfo and update parser**

Add to `NarInfo` struct:

```rust
    /// Ed25519 signature in `<keyname>:<base64sig>` format.
    pub sig: Option<String>,
```

In `parse`, add `let mut sig = None;` and in the loop (as an additional else-if after the references block):

```rust
} else if sig.is_none() {
    if let Some(val) = line.strip_prefix("Sig: ") {
        sig = Some(val.to_string());
    }
}
```

Note: the `references.is_none()` guard and the `sig.is_none()` guard need to be restructured since they're both `else if` arms. The cleanest approach: change the references block to not use `else if references.is_none()` — instead check `references.is_none()` inside the arm. Similarly for sig. The full loop body becomes:

```rust
for line in input.lines() {
    if let Some(val) = line.strip_prefix("URL: ") {
        url = Some(val.to_string());
    } else if let Some(val) = line.strip_prefix("Compression: ") {
        compression = Some(val.to_string());
    } else if let Some(val) = line.strip_prefix("NarHash: ") {
        nar_hash = Some(val.to_string());
    } else if let Some(val) = line.strip_prefix("NarSize: ") {
        nar_size = Some(
            val.parse::<u64>()
                .map_err(|_| NarInfoError::InvalidNarSize)?,
        );
    } else if let Some(val) = line.strip_prefix("References: ") {
        if references.is_none() {
            let refs: Vec<String> = val
                .split_whitespace()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            references = Some(refs);
        }
    } else if let Some(val) = line.strip_prefix("Sig: ") {
        if sig.is_none() {
            sig = Some(val.to_string());
        }
    }
}
```

Add `sig,` to the return struct.

- [ ] **Step 7: Run all narinfo tests**

Run: `cargo test -p harmony-os narinfo`
Expected: PASS

- [ ] **Step 8: Write failing test for serialize with sig**

Add to `mod serialize_tests`:

```rust
#[test]
fn serialize_with_sig() {
    let hash = sha2::Sha256::digest(b"sig test");
    let text = serialize_narinfo("abc123-hello", &hash.into(), 8, None, Some("mykey-1:AAAA=="));
    assert!(text.contains("Sig: mykey-1:AAAA==\n"));
}

#[test]
fn serialize_without_sig() {
    let hash = sha2::Sha256::digest(b"no sig");
    let text = serialize_narinfo("abc123-hello", &hash.into(), 6, None, None);
    assert!(!text.contains("Sig:"));
}
```

- [ ] **Step 9: Update serialize_narinfo to accept sig parameter**

Change signature:

```rust
pub fn serialize_narinfo(
    store_path_name: &str,
    nar_sha256: &[u8; 32],
    nar_size: u64,
    references: Option<&[String]>,
    sig: Option<&str>,
) -> String {
```

After the references block, add:

```rust
if let Some(s) = sig {
    text.push_str("Sig: ");
    text.push_str(s);
    text.push('\n');
}
```

- [ ] **Step 10: Fix all existing callers of serialize_narinfo**

In `nix_binary_cache.rs`, update the call in `handle_request` to pass `None` as the 5th arg:

```rust
let text = serialize_narinfo(
    &entry.name,
    &entry.nar_sha256,
    entry.nar_size,
    entry.references.as_deref(),
    None,
);
```

Also fix ALL existing serialize tests to pass `None` as the 5th arg.
This includes the four original tests (`serialize_minimal_narinfo`,
`serialize_round_trip`, `serialize_store_path_format`,
`serialize_rejects_newline_injection`) AND the three references tests
(`serialize_with_references`, `serialize_without_references`,
`serialize_with_empty_references`) — every call to `serialize_narinfo`
needs `None` appended.

- [ ] **Step 11: Run all tests and clippy**

Run: `cargo test -p harmony-os && cargo clippy --workspace -- -D warnings`
Expected: ALL PASS

- [ ] **Step 12: Commit**

```bash
git add crates/harmony-os/src/narinfo.rs crates/harmony-os/src/nix_binary_cache.rs
git commit -m "feat(narinfo): add fingerprint computation, sig field parsing and serialization

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Add base64 dependency

**Files:**
- Modify: `crates/harmony-os/Cargo.toml`

- [ ] **Step 1: Add base64 crate**

Add to `[dependencies]` in `crates/harmony-os/Cargo.toml`:

```toml
base64 = "0.22"
```

The `base64` crate is only needed at the `BinaryCacheServer` level (std), so it can be ungated (harmony-os already requires std for most functionality).

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p harmony-os`
Expected: compiles successfully

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-os/Cargo.toml
git commit -m "chore: add base64 dependency for narinfo signature encoding

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: BinaryCacheServer signing integration

**Files:**
- Modify: `crates/harmony-os/src/nix_binary_cache.rs`

- [ ] **Step 1: Write failing test for signed narinfo**

Add to `mod tests` in `nix_binary_cache.rs`:

```rust
#[test]
fn signed_narinfo_contains_sig_line() {
    use harmony_identity::PrivateIdentity;
    use rand::rngs::OsRng;

    let identity = PrivateIdentity::generate(&mut OsRng);
    let name = "abc12345678901234567890123456789-hello";
    let refs = Some(vec!["dep12345678901234567890123456789-glibc".to_string()]);

    let mut srv = build_server();
    srv.import_nar(name, build_test_nar(b"data"), refs).unwrap();

    // Reconstruct with signing key.
    // (We need to rebuild since build_server has no signing.)
    let mut nix = NixStoreServer::new();
    nix.import_nar(name, build_test_nar(b"data")).unwrap();
    let mut ref_map = std::collections::HashMap::new();
    ref_map.insert(
        name.to_string(),
        vec!["dep12345678901234567890123456789-glibc".to_string()],
    );
    let mut srv = BinaryCacheServer::new_with_signing(
        nix,
        ref_map,
        "test-key-1".to_string(),
        identity,
    );
    let resp = srv.handle_request("/abc12345678901234567890123456789.narinfo");
    match resp {
        CacheResponse::Narinfo(text) => {
            assert!(text.contains("Sig: test-key-1:"), "missing Sig line: {text}");
            // Verify the signature line is well-formed: keyname:base64
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
            assert!(!text.contains("Sig:"), "should not have Sig without signing key");
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
        std::collections::HashMap::new(),  // no refs
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os nix_binary_cache`
Expected: FAIL — `new_with_signing` doesn't exist

- [ ] **Step 3: Add signing field and constructor**

Add import at top of `nix_binary_cache.rs`:

```rust
use harmony_identity::PrivateIdentity;
```

Add `signing` field to `BinaryCacheServer`:

```rust
pub struct BinaryCacheServer {
    server: NixStoreServer,
    hash_index: HashMap<String, IndexEntry>,
    misses: BTreeSet<String>,
    signing: Option<(String, PrivateIdentity)>,
}
```

Add the `new_with_signing` constructor:

```rust
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
```

Update `new_with_refs` to initialize `signing: None`:

```rust
Self {
    server,
    hash_index,
    misses: BTreeSet::new(),
    signing: None,
}
```

- [ ] **Step 4: Update handle_request to sign narinfo**

Import at top:

```rust
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use crate::narinfo::{compute_narinfo_fingerprint, serialize_narinfo};
use crate::nix_base32::encode_nix_base32;
```

Update the narinfo response branch in `handle_request`:

```rust
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
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-os nix_binary_cache`
Expected: PASS

- [ ] **Step 6: Write signature verification test**

Add this integration test that verifies the actual Ed25519 signature:

```rust
#[test]
fn signature_verifies_against_public_key() {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use harmony_identity::PrivateIdentity;
    use rand::rngs::OsRng;
    use crate::narinfo::{NarInfo, compute_narinfo_fingerprint};
    use crate::nix_base32::encode_nix_base32;

    let identity = PrivateIdentity::generate(&mut OsRng);
    let public = identity.identity.clone();
    let name = "abc12345678901234567890123456789-verify";
    let refs = vec!["dep12345678901234567890123456789-glibc".to_string()];

    let mut nix = NixStoreServer::new();
    nix.import_nar(name, build_test_nar(b"verify data")).unwrap();
    let mut ref_map = std::collections::HashMap::new();
    ref_map.insert(name.to_string(), refs.clone());
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

    // Parse the narinfo to extract sig and hash.
    let parsed = NarInfo::parse(&text).unwrap();
    let sig_str = parsed.sig.expect("expected Sig field");
    let (_key_name, sig_b64) = sig_str.split_once(':').expect("sig format is key:base64");
    let sig_bytes: [u8; 64] = BASE64.decode(sig_b64).unwrap().try_into().unwrap();

    // Recompute fingerprint from parsed fields.
    let fingerprint = compute_narinfo_fingerprint(
        name,
        &parsed.nar_hash,
        parsed.nar_size,
        parsed.references.as_deref(),
    )
    .unwrap();

    // Verify.
    public
        .verify(fingerprint.as_bytes(), &sig_bytes)
        .expect("signature should verify");
}
```

- [ ] **Step 7: Run all workspace tests and clippy**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings`
Expected: ALL PASS

- [ ] **Step 8: Run nightly rustfmt**

Run: `cargo +nightly fmt --all`

- [ ] **Step 9: Commit**

```bash
git add crates/harmony-os/src/nix_binary_cache.rs
git commit -m "feat(binary-cache): sign narinfo with Ed25519 via optional PrivateIdentity

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
