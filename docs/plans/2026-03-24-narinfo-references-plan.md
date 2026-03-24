# Narinfo References Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `References` field to narinfo so Nix clients can resolve dependency closures.

**Architecture:** Thread references through all three intake paths (HTTP fetch, mesh, local publish) and persist via `.meta` sidecar files. Each layer gains an `Option<Vec<String>>` parameter — `None` means unknown, `Some(vec![])` means zero deps.

**Tech Stack:** Rust, `no_std`-compatible `NarInfo` parser, `std`-gated serializer, SHA-256/Nix-base32

---

## File Structure

| File | Change | Responsibility |
|------|--------|---------------|
| `crates/harmony-os/src/narinfo.rs` | Modify | Add `references` field to `NarInfo`, update parse + serialize |
| `crates/harmony-os/src/nix_binary_cache.rs` | Modify | Add `references` to `IndexEntry`, update `import_nar` + `handle_request` |
| `crates/harmony-os/src/persistent_nar_store.rs` | Modify | Write/read `.meta` sidecar, add `references` param |
| `crates/harmony-os/src/nar_publisher.rs` | Modify | Encode references in mesh announcement payload |
| `crates/harmony-os/src/mesh_nar_source.rs` | Modify | Parse extended payload, update `MeshNarFetch` trait |
| `crates/harmony-os/src/nix_store_fetcher.rs` | Modify | Propagate references from parsed narinfo through return types |

---

### Task 1: NarInfo parse + serialize with references

**Files:**
- Modify: `crates/harmony-os/src/narinfo.rs`

- [ ] **Step 1: Write failing tests for references parsing**

Add to `mod tests` in `narinfo.rs`:

```rust
#[test]
fn parse_references_field() {
    let input = "URL: nar/a.nar\nNarHash: sha256:abc\nNarSize: 10\nReferences: def456-glibc-2.38 ghi789-gcc-13.2\n";
    let info = NarInfo::parse(input).unwrap();
    assert_eq!(
        info.references,
        Some(vec!["def456-glibc-2.38".to_string(), "ghi789-gcc-13.2".to_string()])
    );
}

#[test]
fn parse_missing_references_is_none() {
    let input = "URL: nar/a.nar\nNarHash: sha256:abc\nNarSize: 10\n";
    let info = NarInfo::parse(input).unwrap();
    assert_eq!(info.references, None);
}

#[test]
fn parse_empty_references_is_some_empty() {
    let input = "URL: nar/a.nar\nNarHash: sha256:abc\nNarSize: 10\nReferences: \n";
    let info = NarInfo::parse(input).unwrap();
    assert_eq!(info.references, Some(vec![]));
}

#[test]
fn parse_references_no_space_after_colon_is_none() {
    let input = "URL: nar/a.nar\nNarHash: sha256:abc\nNarSize: 10\nReferences:packed\n";
    let info = NarInfo::parse(input).unwrap();
    assert_eq!(info.references, None);
}

#[test]
fn parse_references_from_sample_narinfo() {
    let info = NarInfo::parse(SAMPLE_NARINFO).unwrap();
    assert_eq!(
        info.references,
        Some(vec!["def456-glibc-2.38".to_string(), "ghi789-gcc-13.2".to_string()])
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os narinfo -- --nocapture`
Expected: FAIL — `NarInfo` has no `references` field

- [ ] **Step 3: Add references field to NarInfo and update parser**

In `narinfo.rs`, add `references` to the struct:

```rust
pub struct NarInfo {
    pub url: String,
    pub compression: String,
    pub nar_hash: String,
    pub nar_size: u64,
    /// Runtime dependency store path names.
    /// `None` = not provided, `Some(vec![])` = zero dependencies.
    pub references: Option<Vec<String>>,
}
```

In `parse`, add a `references` variable and match arm:

```rust
let mut references = None;
```

Inside the `for line` loop, add before the closing brace:

```rust
} else if let Some(val) = line.strip_prefix("References: ") {
    let refs: Vec<String> = val.split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    references = Some(refs);
}
```

In the return `Ok(NarInfo { ... })`, add:

```rust
references,
```

- [ ] **Step 4: Run tests to verify parsing passes**

Run: `cargo test -p harmony-os narinfo -- --nocapture`
Expected: PASS

- [ ] **Step 5: Write failing test for serialize with references**

Add to `mod serialize_tests` in `narinfo.rs`:

```rust
#[test]
fn serialize_with_references() {
    let hash = sha2::Sha256::digest(b"ref test");
    let refs = vec!["def456-glibc-2.39".to_string(), "ghi789-gcc-lib".to_string()];
    let text = serialize_narinfo("abc123-hello", &hash.into(), 8, Some(&refs));
    assert!(text.contains("References: def456-glibc-2.39 ghi789-gcc-lib\n"));

    // Round-trip: parse it back.
    let parsed = NarInfo::parse(&text).unwrap();
    assert_eq!(parsed.references, Some(refs));
}

#[test]
fn serialize_without_references() {
    let hash = sha2::Sha256::digest(b"no ref test");
    let text = serialize_narinfo("abc123-hello", &hash.into(), 11, None);
    assert!(!text.contains("References"));
}

#[test]
fn serialize_with_empty_references() {
    let hash = sha2::Sha256::digest(b"empty ref");
    let text = serialize_narinfo("abc123-hello", &hash.into(), 9, Some(&[]));
    assert!(text.contains("References: \n"));

    let parsed = NarInfo::parse(&text).unwrap();
    assert_eq!(parsed.references, Some(vec![]));
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cargo test -p harmony-os narinfo -- --nocapture`
Expected: FAIL — `serialize_narinfo` doesn't accept references param

- [ ] **Step 7: Update serialize_narinfo signature and implementation**

Change the signature to:

```rust
pub fn serialize_narinfo(
    store_path_name: &str,
    nar_sha256: &[u8; 32],
    nar_size: u64,
    references: Option<&[String]>,
) -> String {
```

After the existing `format!` block, before returning, append the References line if present:

```rust
let mut text = format!(
    "StorePath: /nix/store/{store_path_name}\n\
     URL: nar/{store_path_name}.nar\n\
     Compression: none\n\
     NarHash: sha256:{hash_b32}\n\
     NarSize: {nar_size}\n"
);
if let Some(refs) = references {
    text.push_str("References: ");
    text.push_str(&refs.join(" "));
    text.push('\n');
}
text
```

- [ ] **Step 8: Fix all existing callers of serialize_narinfo**

In `nix_binary_cache.rs` line 108, update the call:

```rust
let text = serialize_narinfo(&entry.name, &entry.nar_sha256, entry.nar_size, None);
```

(This is temporary — Task 3 will pass real references.)

- [ ] **Step 9: Fix existing serialize tests that pass wrong arg count**

Update existing tests in `serialize_tests` to pass `None` as the 4th arg:

```rust
// serialize_minimal_narinfo
let text = serialize_narinfo("abc123-hello", &hash.into(), 13, None);

// serialize_round_trip
let text = serialize_narinfo("xyz789-world", &hash.into(), nar_data.len() as u64, None);

// serialize_store_path_format
let text = serialize_narinfo("test123-pkg", &hash.into(), 4, None);

// serialize_rejects_newline_injection
serialize_narinfo("abc123-pkg\nURL: nar/fake.nar\njunk", &hash.into(), 4, None);
```

- [ ] **Step 10: Run all tests and clippy**

Run: `cargo test -p harmony-os narinfo && cargo clippy --workspace -- -D warnings`
Expected: ALL PASS, no clippy warnings

- [ ] **Step 11: Commit**

```bash
git add crates/harmony-os/src/narinfo.rs crates/harmony-os/src/nix_binary_cache.rs
git commit -m "feat(narinfo): add References field to parse and serialize"
```

---

### Task 2: PersistentNarStore .meta sidecar

**Files:**
- Modify: `crates/harmony-os/src/persistent_nar_store.rs`

- [ ] **Step 1: Write failing tests for .meta sidecar**

Add to `mod tests` in `persistent_nar_store.rs`:

```rust
#[test]
fn persist_with_references_writes_meta() {
    let tmp = TempDir::new().unwrap();
    let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();

    let refs = Some(vec!["dep123-glibc".to_string(), "dep456-gcc".to_string()]);
    store
        .persist_and_import(&mut server, "abc123-hello", build_test_nar(b"hello"), refs)
        .unwrap();

    // .meta file should exist with References line.
    let meta = std::fs::read_to_string(tmp.path().join("abc123-hello.meta")).unwrap();
    assert!(meta.contains("References: dep123-glibc dep456-gcc"));
}

#[test]
fn persist_without_references_no_meta() {
    let tmp = TempDir::new().unwrap();
    let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();

    store
        .persist_and_import(&mut server, "abc123-hello", build_test_nar(b"hello"), None)
        .unwrap();

    assert!(!tmp.path().join("abc123-hello.meta").exists());
}

#[test]
fn persist_empty_references_writes_meta() {
    let tmp = TempDir::new().unwrap();
    let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();

    store
        .persist_and_import(&mut server, "abc123-hello", build_test_nar(b"hello"), Some(vec![]))
        .unwrap();

    let meta = std::fs::read_to_string(tmp.path().join("abc123-hello.meta")).unwrap();
    assert!(meta.contains("References: \n") || meta.contains("References: "));
}

#[test]
fn reload_restores_references() {
    let tmp = TempDir::new().unwrap();
    let refs = Some(vec!["dep123-glibc".to_string()]);

    {
        let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
        store
            .persist_and_import(&mut server, "abc123-hello", build_test_nar(b"hello"), refs.clone())
            .unwrap();
    }

    // Reopen — references should be available.
    let (_store, _server, ref_map) = PersistentNarStore::open_with_refs(tmp.path()).unwrap();
    assert_eq!(ref_map.get("abc123-hello"), Some(&refs.unwrap()));
}

#[test]
fn reload_missing_meta_gives_none() {
    let tmp = TempDir::new().unwrap();

    {
        let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
        store
            .persist_and_import(&mut server, "abc123-hello", build_test_nar(b"hello"), None)
            .unwrap();
    }

    let (_store, _server, ref_map) = PersistentNarStore::open_with_refs(tmp.path()).unwrap();
    assert!(!ref_map.contains_key("abc123-hello"));
}

#[test]
fn reload_corrupted_meta_skipped() {
    let tmp = TempDir::new().unwrap();

    {
        let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
        store
            .persist_and_import(&mut server, "abc123-hello", build_test_nar(b"hello"), None)
            .unwrap();
    }

    // Write corrupted .meta.
    std::fs::write(tmp.path().join("abc123-hello.meta"), b"\xff\xfe invalid utf8").unwrap();

    // Reopen — NAR should still load, references None.
    let (_store, mut server, ref_map) = PersistentNarStore::open_with_refs(tmp.path()).unwrap();
    server.walk(0, 1, "abc123-hello").unwrap();
    assert!(!ref_map.contains_key("abc123-hello"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os persistent_nar_store -- --nocapture`
Expected: FAIL — `persist_and_import` doesn't accept references param

- [ ] **Step 3: Add references parameter to persist_and_import**

Update `persist_and_import` signature:

```rust
pub fn persist_and_import(
    &self,
    server: &mut NixStoreServer,
    name: &str,
    nar_bytes: Vec<u8>,
    references: Option<Vec<String>>,
) -> io::Result<()> {
```

After the `std::fs::write(&path, &nar_bytes)?;` block (around line 130), write the `.meta` sidecar:

```rust
// Write .meta sidecar if references are provided.
if let Some(ref refs) = references {
    let meta_path = self.dir.join(format!("{name}.meta"));
    let meta_content = format!("References: {}\n", refs.join(" "));
    std::fs::write(&meta_path, meta_content.as_bytes())?;
}
```

- [ ] **Step 4: Add open_with_refs method for reload with references**

Add a new method alongside `open`:

```rust
/// Open a persistent NAR store, returning references per store path.
///
/// Returns `(store, server, ref_map)` where `ref_map` maps store path
/// names to their reference lists (loaded from `.meta` sidecar files).
pub fn open_with_refs(
    dir: &Path,
) -> io::Result<(Self, NixStoreServer, std::collections::HashMap<String, Vec<String>>)> {
    std::fs::create_dir_all(dir)?;
    let mut server = NixStoreServer::new();
    let mut ref_map = std::collections::HashMap::new();

    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[persistent-nar-store] error reading dir entry: {e}, skipping");
                continue;
            }
        };
        let path = entry.path();

        if path.extension().map_or(true, |ext| ext != "nar") {
            continue;
        }
        if !path.is_file() {
            continue;
        }

        let name = match path.file_stem().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        let nar_bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "[persistent-nar-store] failed to read {}: {e}, skipping",
                    path.display()
                );
                continue;
            }
        };
        if let Err(e) = server.import_nar(&name, nar_bytes) {
            eprintln!(
                "[persistent-nar-store] skipping {}: {:?}",
                path.display(),
                e
            );
            continue;
        }

        // Try to read .meta sidecar.
        let meta_path = dir.join(format!("{name}.meta"));
        if let Ok(meta_text) = std::fs::read_to_string(&meta_path) {
            if let Some(refs) = parse_meta_references(&meta_text) {
                ref_map.insert(name, refs);
            }
        }
    }

    Ok((Self { dir: dir.to_path_buf() }, server, ref_map))
}
```

Add a helper function at module level:

```rust
/// Parse References from a .meta sidecar file.
fn parse_meta_references(text: &str) -> Option<Vec<String>> {
    for line in text.lines() {
        if let Some(val) = line.strip_prefix("References: ") {
            let refs: Vec<String> = val.split_whitespace()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            return Some(refs);
        }
    }
    None
}
```

- [ ] **Step 5: Fix existing callers of persist_and_import**

Update all existing test calls and any production callers to pass `None` as the 4th argument. Search the codebase for `persist_and_import` calls. The existing tests in `persistent_nar_store.rs` all need updating, e.g.:

```rust
store.persist_and_import(&mut server, "abc123-hello", nar, None).unwrap();
```

- [ ] **Step 6: Run all tests and clippy**

Run: `cargo test -p harmony-os persistent_nar_store && cargo clippy --workspace -- -D warnings`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/persistent_nar_store.rs
git commit -m "feat(nar-store): .meta sidecar for references persistence"
```

---

### Task 3: BinaryCacheServer references in IndexEntry

**Files:**
- Modify: `crates/harmony-os/src/nix_binary_cache.rs`

- [ ] **Step 1: Write failing test for narinfo with references**

Add to `mod tests` in `nix_binary_cache.rs`:

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os nix_binary_cache -- --nocapture`
Expected: FAIL — `import_nar` doesn't accept references param

- [ ] **Step 3: Add references to IndexEntry and update import_nar**

Add `references` to `IndexEntry`:

```rust
struct IndexEntry {
    name: Arc<str>,
    nar_sha256: [u8; 32],
    nar_size: u64,
    references: Option<Vec<String>>,
}
```

Update `import_nar` signature:

```rust
pub fn import_nar(
    &mut self,
    name: &str,
    nar_bytes: Vec<u8>,
    references: Option<Vec<String>>,
) -> Result<(), NarError> {
```

In the `IndexEntry` construction inside `import_nar`, add `references`:

```rust
IndexEntry {
    name: Arc::from(name),
    nar_sha256: sha256,
    nar_size,
    references,
},
```

- [ ] **Step 4: Update handle_request to pass references to serialize_narinfo**

In `handle_request`, update the narinfo generation (around line 108):

```rust
Some(entry) => {
    let text = serialize_narinfo(
        &entry.name,
        &entry.nar_sha256,
        entry.nar_size,
        entry.references.as_deref(),
    );
    CacheResponse::Narinfo(text)
}
```

- [ ] **Step 5: Update new() and add new_with_refs() constructor**

In the `new()` method's `IndexEntry` construction, add `references: None`:

```rust
IndexEntry {
    name: Arc::clone(name),
    nar_sha256: sha256,
    nar_size,
    references: None,
},
```

Add a `new_with_refs` constructor that populates references from a map
(returned by `PersistentNarStore::open_with_refs`):

```rust
/// Create a binary cache server, populating references from a pre-loaded map.
///
/// `ref_map` maps store path names to their reference lists (typically
/// loaded from `.meta` sidecar files by `PersistentNarStore::open_with_refs`).
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
            let references = ref_map.get(name.as_ref()).cloned();
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
    }
}
```

Add a test for `new_with_refs`:

```rust
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
```

- [ ] **Step 6: Fix all existing callers of import_nar**

Search for `.import_nar(` across the crate. All existing calls need a `None` (or appropriate references) appended. This includes tests in `nix_binary_cache.rs`, `nix_store_fetcher.rs`, and `persistent_nar_store.rs` that call `BinaryCacheServer::import_nar`.

The `build_server_with_nar` helper in `nix_binary_cache.rs` tests calls `BinaryCacheServer::new()` which goes through `NixStoreServer`, not `import_nar` directly — no change needed there.

- [ ] **Step 7: Run all tests and clippy**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-os/src/nix_binary_cache.rs
git commit -m "feat(binary-cache): thread references through IndexEntry and narinfo response"
```

---

### Task 4: Mesh announcement payload with references

**Files:**
- Modify: `crates/harmony-os/src/nar_publisher.rs`
- Modify: `crates/harmony-os/src/mesh_nar_source.rs`

- [ ] **Step 1: Write failing test for publish with references**

Add to `mod tests` in `nar_publisher.rs`:

```rust
#[test]
fn publish_with_references_encodes_in_payload() {
    let (announcer, log) = MockAnnouncer::new();
    let mut publisher = NarPublisher::new(announcer);

    let nar = build_test_nar(b"ref test");
    let store_path = "abc12345678901234567890123456789-ref-pkg";
    let refs = Some(vec!["dep123-glibc".to_string(), "dep456-gcc".to_string()]);
    publisher.publish(store_path, &nar, refs).unwrap();

    let announcements = log.borrow();
    let store_announcement = &announcements[0];
    let payload = String::from_utf8(store_announcement.1.clone()).unwrap();
    let lines: Vec<&str> = payload.lines().collect();
    assert!(lines.len() >= 3, "expected CID + 2 refs, got {lines:?}");
    // Line 0 = CID hex (64 chars).
    assert_eq!(lines[0].len(), 64);
    // Lines 1+ = reference names.
    assert_eq!(lines[1], "dep123-glibc");
    assert_eq!(lines[2], "dep456-gcc");
}

#[test]
fn publish_without_references_single_line_payload() {
    let (announcer, log) = MockAnnouncer::new();
    let mut publisher = NarPublisher::new(announcer);

    let nar = build_test_nar(b"no ref");
    let store_path = "abc12345678901234567890123456789-noref-pkg";
    publisher.publish(store_path, &nar, None).unwrap();

    let announcements = log.borrow();
    let payload = String::from_utf8(announcements[0].1.clone()).unwrap();
    assert!(!payload.contains('\n'), "no-ref payload should be single line");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os nar_publisher -- --nocapture`
Expected: FAIL — `publish` doesn't accept references param

- [ ] **Step 3: Update NarPublisher::publish to accept and encode references**

Update `publish` signature:

```rust
pub fn publish(
    &mut self,
    store_path_name: &str,
    nar_bytes: &[u8],
    references: Option<Vec<String>>,
) -> Result<ContentId, String> {
```

Update the announcement payload construction (around line 101-104):

```rust
let root_cid_hex = hex::encode(root_cid.to_bytes());
let store_key = format!("harmony/nix/store/{store_hash}");

// Payload: line 1 = CID hex, lines 2+ = reference store path names.
let mut payload = root_cid_hex.clone();
if let Some(refs) = &references {
    for r in refs {
        payload.push('\n');
        payload.push_str(r);
    }
}
self.announcer
    .announce(&store_key, payload.as_bytes())?;
```

- [ ] **Step 4: Fix all existing callers of publish**

Search for `.publish(` calls. All existing tests and production calls need a `None` appended as the 3rd arg.

- [ ] **Step 5: Run nar_publisher tests**

Run: `cargo test -p harmony-os nar_publisher -- --nocapture`
Expected: PASS

- [ ] **Step 6: Write failing test for MeshNarSource parsing extended payload**

Add to `mod tests` in `mesh_nar_source.rs`:

```rust
#[test]
fn fetch_with_references_from_extended_payload() {
    use crate::nar_publisher::{ContentAnnouncer, NarPublisher};

    struct NoopAnnouncer;
    impl ContentAnnouncer for NoopAnnouncer {
        fn announce(&self, _key: &str, _payload: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    let nar = build_test_nar(b"refs mesh test");
    let store_path = "abc12345678901234567890123456789-refs-test";
    let refs = Some(vec!["dep123-glibc".to_string()]);

    let mut publisher = NarPublisher::new(NoopAnnouncer);
    let root_cid = publisher.publish(store_path, &nar, refs.clone()).unwrap();

    // Build querier with extended payload (CID + refs).
    let mut querier = MockQuerier::new();
    let store_hash = &store_path[..32];
    let root_cid_hex = hex::encode(root_cid.to_bytes());
    let mut payload = root_cid_hex.clone();
    payload.push_str("\ndep123-glibc");
    querier.insert(
        &format!("harmony/nix/store/{store_hash}"),
        payload.into_bytes(),
    );

    // Insert root + all books.
    let root_fetch_key = content::fetch_key(&root_cid_hex);
    querier.insert(&root_fetch_key, publisher.get_book(&root_cid).unwrap().to_vec());
    let book_cids = dag::walk(&root_cid, publisher.book_store()).unwrap();
    for cid in &book_cids {
        let cid_hex = hex::encode(cid.to_bytes());
        let fetch_key = content::fetch_key(&cid_hex);
        querier.insert(&fetch_key, publisher.get_book(cid).unwrap().to_vec());
    }

    let source = MeshNarSource::new(querier);
    let result = source.try_fetch(store_path).unwrap();
    assert!(result.is_some());
    let (fetched_nar, fetched_refs) = result.unwrap();
    assert_eq!(fetched_nar, nar);
    assert_eq!(fetched_refs, refs);
}
```

- [ ] **Step 7: Update MeshNarFetch trait and MeshNarSource**

Update `MeshNarFetch` trait:

```rust
pub trait MeshNarFetch {
    fn fetch_nar(&self, store_path_name: &str) -> Option<(Vec<u8>, Option<Vec<String>>)>;
}
```

Update `MeshNarSource::try_fetch` return type:

```rust
pub fn try_fetch(
    &self,
    store_path_name: &str,
) -> Result<Option<(Vec<u8>, Option<Vec<String>>)>, String> {
```

In `try_fetch`, update the CID hex parsing (around lines 97-103) to handle the extended payload:

```rust
let root_cid_hex_bytes = match self.querier.query(&mapping_key)? {
    Some(bytes) => bytes,
    None => return Ok(None),
};

let payload_text = String::from_utf8(root_cid_hex_bytes)
    .map_err(|e| format!("payload is not valid UTF-8: {e}"))?;
let mut lines = payload_text.lines();
let root_cid_hex = lines.next()
    .ok_or_else(|| "empty store path payload".to_string())?;

// Remaining lines are reference store path names.
let references: Vec<String> = lines
    .filter(|l| !l.is_empty())
    .map(|l| l.to_string())
    .collect();
let references = if references.is_empty() && !payload_text.contains('\n') {
    None // Old-format single-line payload — references unknown.
} else {
    Some(references)
};

let root_cid_bytes: [u8; 32] = hex::decode(root_cid_hex)
    .map_err(|e| format!("failed to decode root CID hex: {e}"))?
    .try_into()
    .map_err(|v: Vec<u8>| format!("root CID is {} bytes, expected 32", v.len()))?;
```

And at the end of `try_fetch`, return the tuple:

```rust
Ok(Some((reassembled, references)))
```

Update the `MeshNarFetch` impl:

```rust
impl<Q: ContentQuerier> MeshNarFetch for MeshNarSource<Q> {
    fn fetch_nar(&self, store_path_name: &str) -> Option<(Vec<u8>, Option<Vec<String>>)> {
        match self.try_fetch(store_path_name) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("[mesh-nar] fetch failed for {store_path_name}: {e}");
                None
            }
        }
    }
}
```

- [ ] **Step 8: Fix all callers of MeshNarFetch::fetch_nar**

In `nix_store_fetcher.rs`, the `fetch_nar` call (around line 208) returns `Option<Vec<u8>>`. Update to destructure the tuple:

```rust
if let Some(ref mesh) = self.mesh {
    if let Some((mesh_nar, _mesh_refs)) = mesh.fetch_nar(&name_str) {
        nar_bytes = Some(mesh_nar);
        from_mesh = true;
    }
}
```

(The `_mesh_refs` will be used in Task 5.)

Also update `MockMesh` and `EmptyMesh` in `nix_store_fetcher.rs` tests:

```rust
impl MeshNarFetch for MockMesh {
    fn fetch_nar(&self, _: &str) -> Option<(Vec<u8>, Option<Vec<String>>)> {
        Some((self.nar.clone(), None))
    }
}

impl MeshNarFetch for EmptyMesh {
    fn fetch_nar(&self, _: &str) -> Option<(Vec<u8>, Option<Vec<String>>)> {
        None
    }
}
```

- [ ] **Step 9: Run all tests and clippy**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings`
Expected: ALL PASS

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-os/src/nar_publisher.rs crates/harmony-os/src/mesh_nar_source.rs crates/harmony-os/src/nix_store_fetcher.rs
git commit -m "feat(mesh): encode references in announcement payload, update MeshNarFetch trait"
```

---

### Task 5: NixStoreFetcher propagates references

**Files:**
- Modify: `crates/harmony-os/src/nix_store_fetcher.rs`

- [ ] **Step 1: Write failing test for references in fetch return**

Add to `mod tests` in `nix_store_fetcher.rs`:

```rust
#[test]
fn fetch_propagates_references() {
    let nar_bytes = build_test_nar(b"ref propagation test");
    let hash = Sha256::digest(&nar_bytes);
    let hash_b32 = encode_nix_base32(hash.as_slice());
    let compressed = compress_xz(&nar_bytes);

    let store_hash = "abc12345678901234567890123456789";
    let store_path_name = format!("{}-ref-prop", store_hash);
    let narinfo_text = format!(
        "StorePath: /nix/store/{}\nURL: nar/rp.nar.xz\nCompression: xz\nNarHash: sha256:{}\nNarSize: {}\nReferences: dep123-glibc dep456-gcc\n",
        store_path_name, hash_b32, nar_bytes.len()
    );

    let mut responses = HashMap::new();
    responses.insert(
        format!("https://cache.nixos.org/{}.narinfo", store_hash),
        Ok(narinfo_text.into_bytes()),
    );
    responses.insert(
        "https://cache.nixos.org/nar/rp.nar.xz".to_string(),
        Ok(compressed),
    );

    let mock = MockHttp { responses };
    let mut fetcher = NixStoreFetcher::new(Box::new(mock));
    let mut server = NixStoreServer::new();

    use harmony_microkernel::FileServer;
    let _ = server.walk(0, 1, &store_path_name);

    let imported = fetcher.process_misses(&mut server);
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].0, store_path_name);
    assert_eq!(
        imported[0].2,
        Some(vec!["dep123-glibc".to_string(), "dep456-gcc".to_string()])
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os nix_store_fetcher -- --nocapture`
Expected: FAIL — tuples have 2 elements, not 3

- [ ] **Step 3: Update fetch_nar to return references**

Change `fetch_nar` return type:

```rust
fn fetch_nar(&self, store_path_name: &str) -> Result<(Vec<u8>, Option<Vec<String>>), FetchError> {
```

After parsing narinfo (around line 307), capture references:

```rust
let narinfo =
    NarInfo::parse(&narinfo_text).map_err(|e| FetchError::NarInfo(format!("{:?}", e)))?;
let references = narinfo.references.clone();
```

At the end of `fetch_nar`, return the tuple:

```rust
Ok((nar_bytes, references))
```

- [ ] **Step 4: Update process_miss_list return type and threading**

Change the return type of `process_misses`, `process_misses_shared`, and `process_miss_list`:

```rust
pub fn process_misses(&mut self, server: &mut NixStoreServer) -> Vec<(String, Vec<u8>, Option<Vec<String>>)>
```

```rust
pub fn process_misses_shared(&mut self, server: &Arc<Mutex<NixStoreServer>>) -> Vec<(String, Vec<u8>, Option<Vec<String>>)>
```

```rust
fn process_miss_list<F>(&mut self, misses: Vec<Arc<str>>, mut import_fn: F) -> Vec<(String, Vec<u8>, Option<Vec<String>>)>
```

In `process_miss_list`, update the mesh path to capture references:

```rust
let mut nar_refs = None;
if let Some(ref mesh) = self.mesh {
    if let Some((mesh_nar, mesh_references)) = mesh.fetch_nar(&name_str) {
        nar_bytes = Some(mesh_nar);
        nar_refs = mesh_references;
        from_mesh = true;
    }
}
```

Update the HTTP fallback to capture references from `fetch_nar`:

```rust
match self.fetch_nar(&name_str) {
    Ok((http_nar, http_refs)) => {
        nar_bytes = Some(http_nar);
        nar_refs = http_refs;
    }
    ...
}
```

Update the return tuples from `(name, bytes)` to `(name, bytes, refs)`:

```rust
imported.push((name_str, http_nar, http_refs));
// and similarly for other push sites
imported.push((name_str, nar_bytes, nar_refs));
```

- [ ] **Step 5: Fix all existing tests that destructure the return tuples**

Update existing tests like `fetch_and_import_success`, `process_misses_returns_imported_pairs`, `mesh_miss_falls_back_to_http` to destructure 3-element tuples:

```rust
assert_eq!(imported[0].0, store_path_name);
// imported[0].1 = nar bytes
// imported[0].2 = references (Option<Vec<String>>)
```

- [ ] **Step 6: Run all tests and clippy**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings`
Expected: ALL PASS

- [ ] **Step 7: Run nightly rustfmt**

Run: `cargo +nightly fmt --all`

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-os/src/nix_store_fetcher.rs
git commit -m "feat(fetcher): propagate narinfo references through fetch return types"
```
