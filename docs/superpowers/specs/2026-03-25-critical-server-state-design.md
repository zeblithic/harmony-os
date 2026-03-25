# Hot-Swap /state: ContentServer + NixStoreServer + ConfigServer

## Goal

Implement `/state` pseudo-files for the three servers that lose critical data without state transfer during hot-swap: ContentServer (CAS books/pages), NixStoreServer (imported store paths), and ConfigServer (active/pending/previous config pointers).

## Prerequisite

harmony core PR #127 must merge first — it adds an optional `serde` feature to `harmony-athenaeum` with `Serialize`/`Deserialize` derives on `Book`, `PageAddr`, and `BookType`. After merge, update harmony-os's workspace `Cargo.toml` to enable the feature.

## Scope

**In scope:**
- Enable `harmony-athenaeum` serde feature in workspace deps
- Add serde derives to `NarEntry` in `nar.rs`
- Add serde derives to `StorePath` in `nix_store_server.rs`
- ContentServer `/state`: CBOR serialization of books + pages BTreeMaps
- NixStoreServer `/state`: CBOR serialization of store_paths BTreeMap
- ConfigServer `/state`: CBOR serialization of config pointers + trusted operators
- Unit tests for each server's state round-trip

**Out of scope:**
- Kernel-level hot_swap integration tests (already covered by EchoServer in harmony-os-lbz)
- Hardware/ephemeral servers (harmony-os-1um)
- State versioning (server-side concern — deferred)

## Architecture

### Serialization: CBOR everywhere

All three servers use `ciborium` (already a workspace dep) for CBOR serialization. Each server defines a private `*State` struct that captures its transferable fields:

- `ContentServerState` — flattened pages + books as `Vec<(K, V)>`
- `NixStoreServerState` — flattened store_paths as `Vec<(String, StorePath)>`
- `ConfigServerState` — direct copy of 6 Option fields + trusted_operators

### What's NOT transferred

| Server | Excluded | Reason |
|--------|----------|--------|
| ContentServer | `tracker`, `ingest_buffers` | Session state — new server starts fresh |
| NixStoreServer | `tracker`, `misses` | Session + optimization cache |
| ConfigServer | `cas`, `tracker` | Infrastructure ref (caller provides Arc), session |

### /state file pattern

Each server follows the same pattern established by EchoServer:

1. Add `STATE` QPath constant
2. Walk: `"state"` → `STATE`
3. Open: Read, Write, ReadWrite all allowed
4. Read: serialize transferable fields to CBOR, return bytes
5. Write: deserialize CBOR, replace transferable fields
6. Stat: regular file, size = 0 (dynamic content)

## ContentServer /state

### State struct

```rust
#[derive(Serialize, Deserialize)]
struct ContentServerState {
    /// Pages flattened from BTreeMap<u32, (PageAddr, Vec<u8>)>.
    pages: Vec<(u32, PageAddr, Vec<u8>)>,
    /// Books flattened from BTreeMap<[u8; 32], Book>.
    books: Vec<([u8; 32], Book)>,
}
```

Flattened to `Vec<(K, V)>` because CBOR map keys with complex types can be problematic. Reconstruction into `BTreeMap` on write is straightforward.

### Read

```rust
let state = ContentServerState {
    pages: self.pages.iter().map(|(&k, (addr, data))| (k, *addr, data.clone())).collect(),
    books: self.books.iter().map(|(&k, v)| (k, v.clone())).collect(),
};
// serialize to CBOR
```

### Write

```rust
let state: ContentServerState = ciborium::from_reader(&data[..])?;
self.pages = state.pages.into_iter().map(|(k, addr, data)| (k, (addr, data))).collect();
self.books = state.books.into_iter().map(|(k, v)| (k, v)).collect();
```

### Size consideration

ContentServer can hold up to BOOK_MAX_SIZE (1MB) per ingested book, with up to 4 concurrent ingests. Typical CAS usage is well under MAX_STATE_SIZE (4MB). Very large CAS instances should use persistent storage rather than in-memory state transfer.

## NixStoreServer /state

### Serde derives needed

In `nar.rs`, add to `NarEntry`:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NarEntry { ... }
```

In `nix_store_server.rs`, add to `StorePath` (or its constituent types):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorePath { ... }
```

Note: `NarEntry` contains `Arc<str>` (for symlink targets and directory entry keys). Serde handles `Arc<str>` as a string — serializes to string, deserializes back to `Arc<str>`. This works correctly with ciborium.

### State struct

```rust
#[derive(Serialize, Deserialize)]
struct NixStoreServerState {
    /// Store paths flattened from BTreeMap<Arc<str>, StorePath>.
    store_paths: Vec<(String, StorePath)>,
}
```

`Arc<str>` → `String` on serialization, `String` → `Arc::from(s.as_str())` on reconstruction.

### NarEntry offset validity

`NarEntry::Regular` has `contents_offset` and `contents_len` that reference positions in the original NAR blob. The NAR blob data lives in ContentServer's pages (via the CAS), not in NixStoreServer. Since ContentServer's state is also transferred (or persists via `Arc`), these offsets remain valid after hot-swap.

### Size consideration

A typical Nix store with 50 imported paths: ~50-200KB serialized. Well within MAX_STATE_SIZE.

## ConfigServer /state

### State struct

```rust
#[derive(Serialize, Deserialize)]
struct ConfigServerState {
    trusted_operators: Vec<[u8; 16]>,
    active_cid: Option<[u8; 32]>,
    active_config: Option<NodeConfig>,
    pending_cid: Option<[u8; 32]>,
    pending_config: Option<NodeConfig>,
    previous_cid: Option<[u8; 32]>,
    previous_config: Option<NodeConfig>,
}
```

All types already derive `Serialize`/`Deserialize` (from the NodeConfig bead). Direct field copy — no flattening needed.

### What about `cas: Arc<ContentServer>`?

Excluded from `/state`. The `Arc` is infrastructure wiring, not data. The caller constructs the new ConfigServer with the same `Arc<ContentServer>` before passing it to `hot_swap`. The `/state` write restores the config pointers; the CAS reference is already wired up.

### Size consideration

Tiny — 3 optional NodeConfigs (each <1KB) + a few CID hashes + operator list. Under 10KB total.

## File Map

| File | Change |
|------|--------|
| `Cargo.toml` (workspace root) | Enable `serde` feature on `harmony-athenaeum` workspace dep |
| `harmony-microkernel/src/nar.rs` | Add `Serialize`/`Deserialize` derives to `NarEntry` |
| `harmony-microkernel/src/nix_store_server.rs` | Add serde derives to `StorePath`, add STATE qpath + walk/read/write/stat |
| `harmony-microkernel/src/content_server.rs` | Add STATE qpath + walk/read/write/stat with `ContentServerState` |
| `harmony-microkernel/src/config_server.rs` | Add STATE qpath + walk/read/write/stat with `ConfigServerState` |

## Testing Strategy

### ContentServer tests (~3 tests)
- `state_read_returns_books_and_pages` — ingest a book, read `/state`, deserialize, verify CID present
- `state_write_restores_content` — serialize known state, write to fresh server, verify `get_book_bytes` works
- `state_round_trip` — ingest → read state → new server → write state → verify content matches

### NixStoreServer tests (~3 tests)
- `state_read_returns_store_paths` — import a NAR, read `/state`, deserialize, verify path present
- `state_write_restores_store_paths` — serialize known state, write to fresh server, verify `has_store_path`
- `state_round_trip` — import → read state → new server → write state → verify path accessible

### ConfigServer tests (~3 tests)
- `state_read_returns_config_pointers` — stage + commit, read `/state`, verify active CID in deserialized data
- `state_write_restores_config` — serialize known state, write to fresh server, read `active` file, verify CID
- `state_round_trip` — commit → read state → new server (with same CAS Arc) → write state → read node.cbor, verify

All tests are unit-level — no kernel involvement. Each test creates a server, manipulates it, reads/writes `/state`, and verifies. The kernel-level `hot_swap` + `/state` integration was proven end-to-end with EchoServer in harmony-os-lbz.

## Future Work

- **State versioning:** Each server can prepend a version byte to its CBOR. The write handler checks the version and rejects incompatible state. Not needed for v1 — all servers start at the same version.
- **Incremental transfer:** For very large ContentServers, consider streaming state in chunks rather than one read/write. Current MAX_STATE_SIZE (4MB) covers typical usage.
- **Persistent backing store:** ContentServer and NixStoreServer could back their BTreeMaps with persistent storage (disk/CAS) to avoid in-memory state transfer entirely. Orthogonal to `/state`.
