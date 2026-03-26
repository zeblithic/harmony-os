# Critical Server /state Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `/state` pseudo-files to ContentServer, NixStoreServer, and ConfigServer so their critical data survives hot-swap via CBOR serialization.

**Architecture:** Each server defines a private `*State` struct with serde derives, serializes transferable fields to CBOR on read, and restores from CBOR on write. Follows the EchoServer `/state` pattern established in harmony-os-lbz. Prerequisite: harmony core PR #127 (merged) adds serde feature to harmony-athenaeum.

**Tech Stack:** Rust, `no_std` + `alloc`, `serde` + `ciborium` (CBOR), `harmony-athenaeum` with `serde` feature.

**Spec:** `docs/superpowers/specs/2026-03-25-critical-server-state-design.md`

---

### Task 1: Enable harmony-athenaeum serde feature

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/harmony-microkernel/Cargo.toml`

**Context:**
- harmony core PR #127 added `features = ["serde"]` to `harmony-athenaeum` with conditional derives on `Book`, `PageAddr`, `BookType`.
- The workspace root pins `harmony-athenaeum` at `branch = "main"`.
- The microkernel's `kernel` feature enables `harmony-athenaeum/std`. We need to also enable `harmony-athenaeum/serde`.

- [ ] **Step 1: Update workspace dep**

In root `Cargo.toml`, the harmony-athenaeum line needs no change (it tracks `main` which now has the serde feature). But we need to run `cargo update -p harmony-athenaeum` to pick up the new commit.

- [ ] **Step 2: Enable serde feature in microkernel**

In `crates/harmony-microkernel/Cargo.toml`, update the `kernel` feature to also enable `harmony-athenaeum/serde`:

Change:
```toml
"dep:harmony-athenaeum", "harmony-athenaeum/std",
```
to:
```toml
"dep:harmony-athenaeum", "harmony-athenaeum/std", "harmony-athenaeum/serde",
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p harmony-microkernel`
Expected: compiles with `Book`, `PageAddr`, `BookType` now having serde derives.

- [ ] **Step 4: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/harmony-microkernel/Cargo.toml
git commit -m "build: enable harmony-athenaeum serde feature for /state serialization

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Add serde derives to NarEntry, NarArchive, StorePath

**Files:**
- Modify: `crates/harmony-microkernel/src/nar.rs`
- Modify: `crates/harmony-microkernel/src/nix_store_server.rs`

**Context:**
- `NarEntry` (nar.rs:56) is an enum with `Regular`, `Symlink`, `Directory` variants. Contains `Arc<str>` (serde handles as string) and `BTreeMap<Arc<str>, NarEntry>` (recursive).
- `NarArchive` (nar.rs:353) wraps `root: NarEntry`.
- `StorePath` (nix_store_server.rs:30) has `nar_blob: Vec<u8>` and `archive: NarArchive`.
- All need `Serialize`/`Deserialize` for the NixStoreServer /state.
- Add `use serde::{Serialize, Deserialize};` to files that don't already have it.

- [ ] **Step 1: Add derives to NarEntry and NarArchive**

In `nar.rs`:

Add import (if not present):
```rust
use serde::{Deserialize, Serialize};
```

Update `NarEntry`:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NarEntry {
```

Update `NarArchive`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarArchive {
```

- [ ] **Step 2: Add derives to StorePath**

In `nix_store_server.rs`:

Add import:
```rust
use serde::{Deserialize, Serialize};
```

Update `StorePath`:
```rust
#[derive(Serialize, Deserialize)]
struct StorePath {
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p harmony-microkernel`

- [ ] **Step 4: Run existing tests**

Run: `cargo test -p harmony-microkernel nar`
Expected: all existing NAR tests pass (derives don't change behavior).

- [ ] **Step 5: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/nar.rs crates/harmony-microkernel/src/nix_store_server.rs
git commit -m "feat(nar): add serde derives to NarEntry, NarArchive, StorePath

Enables CBOR serialization of NixStoreServer state for hot-swap.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: ContentServer /state

**Files:**
- Modify: `crates/harmony-microkernel/src/content_server.rs`

**Context:**
- ContentServer has QPath constants: ROOT=0, BOOKS_DIR=1, PAGES_DIR=2, INGEST=3. Add STATE=4.
- Uses `FidTracker<NodeKind>` with `NodeKind` enum (Root, BooksDir, PagesDir, Ingest, Book, Page).
- Walk (line 389) routes from root to named children.
- `pages: BTreeMap<u32, (PageAddr, Vec<u8>)>` and `books: BTreeMap<[u8; 32], Book>` are the transferable state.
- `serde` + `ciborium` already imported by the crate (used by node_config/signed_config).
- Follow the EchoServer pattern: add State to NodeKind, walk "state" → State, read serializes, write restores.

- [ ] **Step 1: Write failing tests**

Add to `content_server.rs` test module:

```rust
    #[test]
    fn state_round_trip() {
        let mut old = ContentServer::new();
        // Ingest a book
        let blob = alloc::vec![0x42u8; 8000];
        old.walk(0, 1, "ingest").unwrap();
        old.open(1, OpenMode::ReadWrite).unwrap();
        old.write(1, 0, &blob).unwrap();
        let resp = old.read(1, 0, 256).unwrap();
        let cid: [u8; 32] = resp[..32].try_into().unwrap();
        old.clunk(1).unwrap();

        // Read state
        old.walk(0, 2, "state").unwrap();
        old.open(2, OpenMode::Read).unwrap();
        let state_bytes = old.read(2, 0, 4 * 1024 * 1024).unwrap();
        old.clunk(2).unwrap();

        // Write state to new server
        let mut new = ContentServer::new();
        new.walk(0, 1, "state").unwrap();
        new.open(1, OpenMode::Write).unwrap();
        new.write(1, 0, &state_bytes).unwrap();
        new.clunk(1).unwrap();

        // Verify: get_book_bytes works on new server
        let restored = new.get_book_bytes(&cid).unwrap();
        assert_eq!(restored, blob);
    }

    #[test]
    fn state_walk_exists() {
        let mut server = ContentServer::new();
        let qpath = server.walk(0, 1, "state").unwrap();
        assert!(qpath > 0);
    }

    #[test]
    fn state_empty_server_round_trip() {
        let mut old = ContentServer::new();
        old.walk(0, 1, "state").unwrap();
        old.open(1, OpenMode::Read).unwrap();
        let state_bytes = old.read(1, 0, 65536).unwrap();
        old.clunk(1).unwrap();

        let mut new = ContentServer::new();
        new.walk(0, 1, "state").unwrap();
        new.open(1, OpenMode::Write).unwrap();
        new.write(1, 0, &state_bytes).unwrap();
        new.clunk(1).unwrap();

        assert_eq!(new.book_count(), 0);
        assert_eq!(new.page_count(), 0);
    }
```

- [ ] **Step 2: Implement**

Add `STATE` QPath constant (after INGEST):
```rust
const STATE: QPath = 4;
```

**IMPORTANT:** Verify that STATE=4 doesn't collide with BOOK_QPATH_BASE or PAGE_QPATH_BASE ranges. BOOK_QPATH_BASE is 0x1_0000_0000, PAGE_QPATH_BASE is 0x1000_0000. STATE=4 is well below both. Safe.

Add `State` to `NodeKind`:
```rust
enum NodeKind {
    Root,
    BooksDir,
    PagesDir,
    Ingest,
    State,   // NEW
    Book([u8; 32]),
    Page(PageAddr),
}
```

Add `ContentServerState` struct (private, with serde):
```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ContentServerState {
    pages: Vec<(u32, PageAddr, Vec<u8>)>,
    books: Vec<([u8; 32], Book)>,
}
```

Update `walk` (line 389) — add "state" case in the Root match:
```rust
"state" => (STATE, NodeKind::State),
```

Update `open` — State allows Read, Write, ReadWrite. The existing open logic rejects Write on Root/BooksDir/PagesDir and requires ReadWrite for Ingest. State should allow any mode. Add State to the leaf check (alongside Book/Page) for Read-only rejection, but actually State needs Write too. The simplest approach: add State to the Ingest-like path that allows ReadWrite, or better — don't add any restriction (State falls through to mark_open without rejection, like in EchoServer). Check how the open method is structured and follow the pattern.

Update `read` — add STATE case:
```rust
NodeKind::State => {
    let state = ContentServerState {
        pages: self.pages.iter().map(|(&k, (addr, data))| (k, *addr, data.clone())).collect(),
        books: self.books.iter().map(|(&k, v)| (k, v.clone())).collect(),
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&state, &mut buf).map_err(|_| IpcError::ResourceExhausted)?;
    Ok(slice_data(&buf, offset, count))
}
```

Update `write` — add STATE case:
```rust
NodeKind::State => {
    let state: ContentServerState = ciborium::from_reader(data)
        .map_err(|_| IpcError::InvalidArgument)?;
    self.pages = state.pages.into_iter().map(|(k, addr, data)| (k, (addr, data))).collect();
    self.books = state.books.into_iter().map(|(k, v)| (k, v)).collect();
    Ok(u32::try_from(data.len()).unwrap_or(u32::MAX))
}
```

Update `stat` — add STATE case:
```rust
NodeKind::State => Ok(FileStat {
    qpath: STATE,
    name: Arc::from("state"),
    size: 0, // dynamic content
    file_type: FileType::Regular,
}),
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-microkernel content_server`
Expected: all pass (existing + 3 new).

- [ ] **Step 4: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/content_server.rs
git commit -m "feat(content): add /state for hot-swap state transfer

CBOR serialization of books + pages BTreeMaps. Read serializes,
write restores. Round-trip tested with book ingest + verify.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: NixStoreServer /state

**Files:**
- Modify: `crates/harmony-microkernel/src/nix_store_server.rs`

**Context:**
- NixStoreServer uses `FidTracker<NixFidPayload>` with a complex walk that navigates into NAR trees.
- The root walk (line 439) checks if name matches a store path. We need to add a "state" case before the store-path lookup.
- BUT: NixStoreServer's walk from root goes directly to store paths (not named children like "state"). The walk checks `self.store_paths.contains_key(name)`. We need to intercept "state" before this check.
- `store_paths: BTreeMap<Arc<str>, StorePath>` is the transferable state.
- `misses` is an optimization cache — not transferred.

**IMPORTANT:** The implementer must read the NixStoreServer walk method carefully. It's structured differently from ContentServer/EchoServer — the root walk dynamically resolves store path names, not fixed file names. The "state" entry must be added as a special case before the dynamic lookup.

- [ ] **Step 1: Write failing tests**

Add to the nix_store_server.rs test module. The tests need to construct NARs — look for existing test helpers like `nar_regular_file()`.

```rust
    #[test]
    fn state_round_trip() {
        let mut old = NixStoreServer::new();
        let nar = nar_regular_file(b"hello nix", false);
        old.import_nar("abc123-hello", nar).unwrap();

        // Read state
        old.walk(0, 1, "state").unwrap();
        old.open(1, OpenMode::Read).unwrap();
        let state_bytes = old.read(1, 0, 4 * 1024 * 1024).unwrap();
        old.clunk(1).unwrap();

        // Write state to new server
        let mut new_srv = NixStoreServer::new();
        new_srv.walk(0, 1, "state").unwrap();
        new_srv.open(1, OpenMode::Write).unwrap();
        new_srv.write(1, 0, &state_bytes).unwrap();
        new_srv.clunk(1).unwrap();

        // Verify
        assert!(new_srv.has_store_path("abc123-hello"));
    }

    #[test]
    fn state_walk_exists() {
        let mut server = NixStoreServer::new();
        server.walk(0, 1, "state").unwrap();
    }

    #[test]
    fn state_misses_not_transferred() {
        let mut old = NixStoreServer::new();
        // Walk a non-existent path to generate a miss
        assert!(old.walk(0, 1, "nonexistent-path").is_err());
        let misses = old.drain_misses();
        assert!(!misses.is_empty());

        // Read + write state
        old.walk(0, 2, "state").unwrap();
        old.open(2, OpenMode::Read).unwrap();
        let state_bytes = old.read(2, 0, 4 * 1024 * 1024).unwrap();
        old.clunk(2).unwrap();

        let mut new_srv = NixStoreServer::new();
        new_srv.walk(0, 1, "state").unwrap();
        new_srv.open(1, OpenMode::Write).unwrap();
        new_srv.write(1, 0, &state_bytes).unwrap();
        new_srv.clunk(1).unwrap();

        // Misses should NOT be transferred
        assert!(new_srv.drain_misses().is_empty());
    }
```

- [ ] **Step 2: Implement**

Add `NixStoreServerState` struct and `STATE` QPath. Add `State` variant to `NixFidPayload`. Add "state" intercept in root walk, read/write/stat handlers.

The implementer should read the full walk, read, write, and stat methods to understand the NixFidPayload pattern and add State handling consistently.

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-microkernel nix_store_server`
Expected: all pass.

- [ ] **Step 4: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/nix_store_server.rs
git commit -m "feat(nix-store): add /state for hot-swap state transfer

CBOR serialization of store_paths BTreeMap. Misses cache excluded
(session optimization, not persistent state).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: ConfigServer /state

**Files:**
- Modify: `crates/harmony-microkernel/src/config_server.rs`

**Context:**
- ConfigServer has QPath constants ROOT=0 through NODE_CBOR=7. Add STATE=8.
- Uses `FidTracker<NodeKind>` with fixed file names in walk (active, pending, previous, stage, commit, rollback, node.cbor).
- All transferable types already have serde derives (NodeConfig, etc.).
- `cas: Arc<ContentServer>` is NOT included in state (infrastructure reference).

- [ ] **Step 1: Write failing tests**

Add to config_server.rs test module:

```rust
    #[test]
    fn state_round_trip() {
        let (cas, signed_cid, trusted) = setup();
        let mut old = ConfigServer::new(cas.clone(), trusted.clone());

        // Stage + commit a config
        stage_config(&mut old, &signed_cid).unwrap();
        commit(&mut old).unwrap();

        // Read state
        old.walk(0, 20, "state").unwrap();
        old.open(20, OpenMode::Read).unwrap();
        let state_bytes = old.read(20, 0, 4 * 1024 * 1024).unwrap();
        old.clunk(20).unwrap();

        // Write state to new server (same CAS Arc)
        let mut new_srv = ConfigServer::new(cas, trusted);
        new_srv.walk(0, 21, "state").unwrap();
        new_srv.open(21, OpenMode::Write).unwrap();
        new_srv.write(21, 0, &state_bytes).unwrap();
        new_srv.clunk(21).unwrap();

        // Verify: active CID matches
        let active = read_active(&mut new_srv);
        let expected = format_cid_hex(&signed_cid);
        assert_eq!(core::str::from_utf8(&active).unwrap(), &expected);
    }

    #[test]
    fn state_walk_exists() {
        let (cas, _signed_cid, trusted) = setup();
        let mut server = ConfigServer::new(cas, trusted);
        server.walk(0, 1, "state").unwrap();
    }
```

- [ ] **Step 2: Implement**

Add STATE=8 QPath, State to NodeKind, ConfigServerState struct, walk/read/write/stat handlers. Follow the existing pattern exactly.

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-microkernel config_server`
Expected: all pass.

- [ ] **Step 4: Run full workspace + clippy + nightly fmt**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/config_server.rs
git commit -m "feat(config): add /state for hot-swap state transfer

CBOR serialization of trusted_operators + active/pending/previous
config pointers. CAS Arc excluded (infrastructure wiring).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
