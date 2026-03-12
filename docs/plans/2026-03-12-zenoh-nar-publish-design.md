# Zenoh NAR Publish & Mesh Fetch — Design

**Goal:** After a NAR is fetched from cache.nixos.org and imported into NixStoreServer, publish it via Zenoh so any peer on the Harmony mesh can access the same /nix/store path without re-fetching from the old internet. Also wire up the receive side so nodes check the mesh before falling back to cache.nixos.org.

**Bead:** harmony-2jx

## Architecture

Two new components in Ring 3 (`harmony-os`), one per direction:

```
NixStoreFetcher (existing)
  │
  │ returns Vec<(name, nar_bytes)> on successful imports
  │
  ├──→ NarPublisher (new)
  │      chunks NAR via dag::ingest()
  │      stores blobs in ContentStore
  │      announces via ContentAnnouncer trait
  │      serves queries for blobs and store path → CID mappings
  │      └──→ Zenoh mesh (publish direction)
  │
  └──← MeshNarSource (new)
         queries mesh for store path's root CID
         walks DAG, fetches blobs via ContentQuerier trait
         reassembles NAR via dag::reassemble()
         └──← Zenoh mesh (receive direction)
```

**Fetch order for a cache miss:**
1. MeshNarSource queries the mesh for the store path
2. If found, returns NAR bytes (no cache.nixos.org needed)
3. If not found, NixStoreFetcher fetches from cache.nixos.org as before
4. After successful import, caller passes (name, nar_bytes) to NarPublisher
5. NarPublisher chunks, stores, announces — available to the mesh

## NarPublisher — Publish Direction

### Traits

```rust
pub trait ContentAnnouncer {
    fn announce(&self, key_expr: &str, payload: &[u8]) -> Result<(), String>;
    fn put_queryable(&self, key_expr: &str, data: &[u8]) -> Result<(), String>;
}
```

Production implementation wraps a Zenoh session. Tests use a mock that collects announcements.

### Struct

```rust
pub struct NarPublisher<A: ContentAnnouncer> {
    announcer: A,
    blob_store: MemoryBlobStore,
    content_store: ContentStore<MemoryBlobStore>,
    published_paths: HashMap<String, ContentId>,
}
```

### Publish Flow

1. Receive (name, nar_bytes) from caller
2. `dag::ingest(&nar_bytes, &config, &mut blob_store)` → root_cid
3. Store name → root_cid in published_paths
4. Announce store path mapping on `harmony/nix/store/{store_hash}` with root_cid as payload
5. For each blob in the DAG, announce on `harmony/announce/{cid_hex}`

### Serving Queries

- `harmony/content/{shard}/{cid_hex}` → look up blob in ContentStore, reply with data
- `harmony/nix/store/{store_hash}` → look up root CID in published_paths, reply

### Error Handling

Best-effort. If chunking or announcing fails, log a warning. The NAR is already imported locally.

## MeshNarSource — Receive Direction

### Traits

```rust
pub trait ContentQuerier {
    fn query(&self, key_expr: &str) -> Result<Option<Vec<u8>>, String>;
}

pub trait MeshNarFetch {
    fn fetch_nar(&self, store_path_name: &str) -> Option<Vec<u8>>;
}
```

`MeshNarSource<Q: ContentQuerier>` implements `MeshNarFetch`. The fetcher holds `Option<Box<dyn MeshNarFetch>>` — no generic parameter pollution.

### Query Flow

1. Extract store hash from store path name
2. Query `harmony/nix/store/{store_hash}` → get root CID (or None)
3. Walk the DAG to discover all blob CIDs
4. For each blob, query `harmony/content/{shard}/{cid_hex}`
5. Reassemble via `dag::reassemble()` → full NAR bytes

### Hash Verification

CID verification is sufficient. Every blob is content-verified by its ContentId on fetch, and the DAG structure guarantees integrity of the whole. No narinfo needed from the mesh path.

## Integration with NixStoreFetcher

### Changes

- Add `mesh: Option<Box<dyn MeshNarFetch>>` field
- `process_misses()` and `process_misses_shared()` return `Vec<(String, Vec<u8>)>` (successfully imported pairs)
- Before cache.nixos.org fetch, try `mesh.fetch_nar(store_path_name)` if available
- If mesh returns data, import directly (skip HTTP fetch)

### Caller Wiring

```rust
let fetcher = NixStoreFetcher::new(http, Some(mesh_source));
let publisher = NarPublisher::new(announcer);

// Main loop
let imported = fetcher.process_misses_shared(&server);
for (name, nar_bytes) in imported {
    publisher.publish(&name, nar_bytes);
}
```

## Zenoh Key Expressions

| Key Expression | Direction | Purpose |
|---|---|---|
| `harmony/nix/store/{store_hash}` | Queryable + Query | Store path → root CID mapping |
| `harmony/content/{shard}/{cid_hex}` | Queryable + Query | Blob data fetch (existing namespace) |
| `harmony/announce/{cid_hex}` | Put | Notify peers of new content (existing namespace) |

## Files

### New

| File | Contents |
|---|---|
| `crates/harmony-os/src/nar_publisher.rs` | NarPublisher, ContentAnnouncer trait |
| `crates/harmony-os/src/mesh_nar_source.rs` | MeshNarSource, ContentQuerier trait, MeshNarFetch impl |

### Modified

| File | Change |
|---|---|
| `crates/harmony-os/src/nix_store_fetcher.rs` | MeshNarFetch trait, optional mesh field, try-mesh-first, return Vec |
| `crates/harmony-os/src/lib.rs` | Add pub mod declarations |
| `crates/harmony-os/Cargo.toml` | Ensure harmony-content features if needed |

### Unchanged

Ring 2 (`harmony-microkernel/src/nix_store_server.rs`) — server stays sans-I/O, unaware of Zenoh.

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Publisher vs fetcher coupling | Separate NarPublisher | Single responsibility, independent testability |
| Communication from fetcher | Return Vec<(String, Vec<u8>)> | Simplest, zero coupling |
| Zenoh I/O pattern | Injectable traits | Consistent with HttpClient pattern, testable with mocks |
| Publishing failure | Best-effort | Import is primary; mesh is a bonus |
| Scope | Publish + receive | Enables end-to-end mesh testing |
| Store path → CID mapping | Zenoh queryable | Peers discover root CID without narinfo |
| Hash verification on mesh | CID verification sufficient | Every blob hash-verified by ContentId |
| Mesh in fetcher | Box<dyn MeshNarFetch>, optional | Clean opt-in, no generic pollution |
| Ring 2 changes | None | Sans-I/O boundary preserved |

## Non-Goals

- Persistent blob storage (MemoryBlobStore for now; RocksDB/mmap is future work)
- Bloom/Cuckoo filter broadcasting (separate bead)
- DAG-level multi-blob transfer coordination
- Retry logic for failed publishes
- Sidecar deployment configuration
