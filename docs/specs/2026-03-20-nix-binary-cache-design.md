# Nix Binary Cache Protocol Layer (harmony-os-q9d)

Sans-I/O binary cache server that speaks the Nix binary cache protocol
on top of the existing NixStoreServer, NarPublisher, and persistent
storage layer.

## Context

harmony-os already has the internal plumbing for NAR storage and mesh
distribution:

- `NixStoreServer` — 9P file server for `/nix/store`, stores parsed NARs
- `NarPublisher` — chunks NARs into content-addressed DAGs, announces on Zenoh
- `MeshNarSource` — fetches NARs from the mesh by reassembling DAGs
- `NixStoreFetcher` — orchestrates mesh-first, HTTP-fallback fetch
- `PersistentNarStore` — disk persistence for NARs across restarts
- `DiskBookStore` — disk persistence for DAG chunks

What's missing: a protocol adapter that lets Nix clients (`nix-daemon`)
query this infrastructure over the standard binary cache HTTP protocol.

## Design

### Architecture

```
Nix Client (nix-daemon)
  substituters = http://localhost:N
         │
         │  HTTP (future thin binding, not in this bead)
         ▼
BinaryCacheServer (sans-I/O)
  handle_request(path) → CacheResponse
  drain_misses() → background fetch list
         │
         │ reads from
         ▼
NixStoreServer + raw NAR blobs
```

`BinaryCacheServer` is a standalone struct, not a 9P `FileServer`. The
binary cache protocol is HTTP-shaped (stateless request → response),
not filesystem-shaped. A future bead adds the HTTP binding layer
(`tiny-http` or similar).

### Required Changes to NixStoreServer (harmony-microkernel)

Two small additions to `NixStoreServer`'s public API:

1. `pub fn get_nar_blob(&self, name: &str) -> Option<&[u8]>` — returns
   the raw NAR bytes for a store path. Needed by `BinaryCacheServer` to
   serve NAR data and compute narinfo hashes.

2. `pub fn store_path_names(&self) -> impl Iterator<Item = &Arc<str>>` —
   iterates over imported store path names. Needed to populate the hash
   index on construction.

Both are thin accessors over existing private fields — no structural
changes to the microkernel.

### New Files

| File | Purpose |
|------|---------|
| `crates/harmony-os/src/nix_binary_cache.rs` | `BinaryCacheServer`, `CacheResponse` enum, request routing, miss recording |
| Addition to `crates/harmony-os/src/narinfo.rs` | `serialize_narinfo()` free function for narinfo generation |
| Addition to `crates/harmony-os/src/nix_base32.rs` | `encode_nix_base32()` (extracted from test helper) |

No new dependencies.

### BinaryCacheServer API

```rust
pub struct BinaryCacheServer {
    server: NixStoreServer,
    hash_index: HashMap<String, Arc<str>>,  // 32-char hash → full name
    misses: BTreeSet<String>,               // 32-char hashes for background fetch
}

pub enum CacheResponse {
    Narinfo(String),       // text/x-nix-narinfo
    NarData(Vec<u8>),      // application/x-nix-nar
    CacheInfo(String),     // text/x-nix-cache-info
    NotFound,              // 404, miss recorded for narinfo requests
    BadRequest,            // 400, malformed request path
}
```

**Ownership:** `BinaryCacheServer` owns the `NixStoreServer`. Created
from `PersistentNarStore::open()` output — the caller passes the
`NixStoreServer` into `BinaryCacheServer::new()`.

**Integration with PersistentNarStore and NixStoreFetcher:**
`BinaryCacheServer` exposes `import_nar()` and `server_mut()` so the
persistence and fetch layers can interact with the underlying server:

```rust
impl BinaryCacheServer {
    pub fn new(server: NixStoreServer) -> Self;
    pub fn handle_request(&mut self, path: &str) -> CacheResponse;
    pub fn drain_misses(&mut self) -> Vec<String>;
    pub fn import_nar(&mut self, name: &str, nar_bytes: Vec<u8>) -> Result<(), NarError>;
    pub fn has_store_path(&self, name: &str) -> bool;
    pub fn server_mut(&mut self) -> &mut NixStoreServer;
}
```

`import_nar()` delegates to `server.import_nar()` and updates the
hash index. `server_mut()` provides escape-hatch access for callers
that need direct 9P interaction (e.g., `NixStoreFetcher`'s
`process_misses`).

**Hash index:** `HashMap<String, Arc<str>>` mapping the 32-char store
hash prefix to the full store path name. Populated on construction
via `server.store_path_names()`, updated on each `import_nar()`.
Provides O(1) narinfo lookups.

### Request Routing

`handle_request(path)` routes on path pattern:

| Pattern | Response |
|---------|----------|
| `/{32-char-hex}.narinfo` | Look up store path by hash → generate narinfo → `Narinfo(text)` |
| `/nar/{store-path-name}.nar` | Look up raw NAR blob → `NarData(bytes)` |
| `/nix-cache-info` | Static metadata → `CacheInfo(text)` |
| Anything else | `NotFound` |

Routing details:
- `.narinfo` paths must have exactly 32 hex characters before the suffix.
  Non-hex or wrong-length paths return `BadRequest`.
- `/nar/` paths for unknown store path names return `NotFound`.
- Unrecognized path patterns return `NotFound` (not `BadRequest`) to
  match standard Nix client expectations.

On `.narinfo` miss: the 32-char hash is recorded in the `misses` set
for background fetch processing.

### Narinfo Generation

Free function in `narinfo.rs` (avoids changing the existing `NarInfo`
parser struct):

```rust
pub fn serialize_narinfo(store_path_name: &str, nar_hash: &[u8], nar_size: u64) -> String;
```

Produces minimal unsigned narinfo (5 fields):

```
StorePath: /nix/store/{store-path-name}
URL: nar/{store-path-name}.nar
Compression: none
NarHash: sha256:{nix-base32-encoded-sha256}
NarSize: {byte-count}
```

Served uncompressed (`Compression: none`). The raw NAR bytes are
already in memory. Compression on serve is unnecessary for
localhost/LAN — the Nix client handles both formats transparently.

`BinaryCacheServer` computes the SHA-256 of the raw NAR blob (via
`sha2::Sha256`) on each narinfo request. Caching the hash is a
future optimization if profiling shows it matters.

Future beads add `References` (harmony-os-yte) and `Sig`
(harmony-os-sls) fields.

### nix-cache-info Response

```
StoreDir: /nix/store
WantMassQuery: 1
Priority: 30
```

`Priority: 30` gives the local mesh cache higher priority than
cache.nixos.org (priority 40). In Nix's substituter system, lower
numeric value = higher priority, so nix-daemon tries the local
cache first.

### nix_base32 Encoder

The encoder already exists as a test helper in `nix_store_fetcher.rs`.
Extract to the public `nix_base32` module:

```rust
pub fn encode_nix_base32(bytes: &[u8]) -> String;
```

Uses Nix's non-standard alphabet (`0123456789abcdfghijklmnpqrsvwxyz`)
with LSB-first bit ordering.

### Miss Recording and Background Fetch

On narinfo miss, `BinaryCacheServer` records the 32-char store hash
in its `misses` set. `drain_misses()` returns these hashes as
`Vec<String>`.

The background fetch loop needs a new adapter (not the existing
`NixStoreFetcher::process_misses` which expects full store path
names). The adapter:

1. Takes a hash from `drain_misses()`
2. Fetches `{upstream}/{hash}.narinfo` to discover the full store
   path name
3. Fetches the NAR via the existing `NixStoreFetcher::fetch_nar`
   logic
4. Calls `BinaryCacheServer::import_nar()` to import and index

This adapter is lightweight glue code in `nix_binary_cache.rs`. The
heavy lifting (HTTP fetch, mesh query, decompression, hash
verification) is already done by `NixStoreFetcher`.

### What This Bead Does NOT Include

- HTTP server binding (separate bead — adds `tiny-http` or similar)
- narinfo `References` field (harmony-os-yte)
- narinfo `Sig` field / signing (harmony-os-sls)
- Mesh publishing on behalf of the binary cache (NarPublisher already
  handles this; wiring is the HTTP binding bead's concern)
- XZ/zstd compression on serve

## Test Plan

### nix_base32 tests
- `encode_decode_round_trip` — encode random bytes, decode, verify match
- `encode_known_sha256` — encode SHA-256 of empty string, verify matches
  existing decode test vector (`0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73`)
- `encode_empty` — encode empty slice

### narinfo serialization tests
- `serialize_minimal_narinfo` — verify all 5 fields present with correct format
- `serialize_round_trip` — serialize, parse with existing `NarInfo::parse()`, verify fields match
- `serialize_store_path_format` — verify `/nix/store/` prefix in StorePath field

### BinaryCacheServer tests
- `handle_narinfo_request` — import NAR, request narinfo by hash, verify response text
- `handle_nar_data_request` — import NAR, request `/nar/{name}.nar`, verify bytes match
- `handle_cache_info` — assert exact field values: `StoreDir: /nix/store`, `WantMassQuery: 1`, `Priority: 30`
- `handle_not_found_records_miss` — missing hash → NotFound + hash in misses
- `drain_misses` — verify drain returns hashes, set empty after drain, duplicates deduplicated
- `handle_bad_request_malformed_hash` — wrong-length hash, non-hex chars → BadRequest
- `handle_not_found_unknown_nar` — `/nar/unknown.nar` → NotFound
- `hash_index_populated_on_import` — import NAR, narinfo lookup by hash works
- `import_after_miss` — miss recorded, drain, import, subsequent narinfo request succeeds (miss set empty)

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-ncv | Prerequisite (closed) — persistent storage |
| harmony-os-yte | Blocked by this — adds References field |
| harmony-os-sls | Blocked by yte — adds Sig field |
| harmony-os-ys8 | Related — CI cache uses same infrastructure |
