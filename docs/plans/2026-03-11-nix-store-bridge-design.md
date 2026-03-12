# /nix/store Bridge — Design

**Goal:** Serve Nix store paths as a 9P filesystem inside Harmony OS, backed
by NAR archives stored as Books in the content-addressed system.

**Scope:** Layers 1-3 only (NAR parser, NixStore FileServer, mount-point
wiring). Layers 4-5 (lazy fetch from cache.nixos.org, Zenoh mesh publishing)
are tracked as separate beads (harmony-wuf, harmony-2jx).

## Context

Nix store paths are content-addressed: each path is `<hash>-<name>` where
the hash covers the NAR (Nix ARchive) serialization of the directory tree.
This maps naturally to Harmony's Book model — one NAR = one Book, CID =
SHA-256 of the NAR bytes.

The microkernel already has all the routing infrastructure: `Namespace` does
longest-prefix matching, `Kernel.walk()` dispatches to the correct
`FileServer`, and `FidTracker` handles 9P fid lifecycle boilerplate. Adding
a new filesystem server is mostly domain logic.

### Why NAR-as-Book

Two approaches were considered:

1. **NAR-as-Book** (chosen): Store the entire NAR blob as a Book. Parse it
   on import to build an in-memory directory tree. Serve file reads by
   slicing into the original NAR blob at recorded offsets.

2. **Manifest-based**: Decompose each NAR into individual files, store each
   as its own Book, maintain a separate manifest mapping paths to CIDs.

NAR-as-Book wins because:
- One Book = one store path — simple 1:1 mapping
- NAR is the canonical Nix transport format (what cache.nixos.org serves)
- Trivial import: download NAR, hash it, store as Book, done
- Content verification is free: Book CID = NAR hash = store path hash
- No manifest format to invent or maintain

### Vision

Nix packages enter the Harmony mesh once (imported from cache.nixos.org or
built locally), then are available to all peers via Zenoh content routing.
Any node needing `/nix/store/<hash>-hello` resolves it through the content
system — local cache first, then mesh peers, then fallback to Web 2.0
caches. Once fetched, the NAR is stored as a Book and never needs to be
fetched again.

## Design

### Layer 1: NAR Parser (`nar.rs`)

New module in `harmony-microkernel`. Parses NAR byte streams into a
directory tree. Zero-copy for file contents — stores offsets into the
original NAR blob rather than copying data.

#### NAR Wire Format

```
nix-archive-1 (
  type <type>
  [executable ""]           # only for regular files
  contents <size> <bytes>   # regular file
  target <size> <bytes>     # symlink
  (entry (name <n>) (node <recurse>))...  # directory
)
```

Strings are length-prefixed (8-byte LE length + data + padding to 8-byte
boundary). Parentheses are literal `(` and `)` tokens (also length-prefixed
strings).

#### Data Model

```rust
pub enum NarEntry {
    Regular {
        executable: bool,
        contents_offset: usize,  // offset into NAR blob
        contents_len: usize,
    },
    Symlink {
        target: Arc<str>,
    },
    Directory {
        entries: BTreeMap<Arc<str>, NarEntry>,
    },
}

pub struct NarArchive {
    pub root: NarEntry,
}
```

#### API

```rust
impl NarArchive {
    /// Parse a NAR blob into a directory tree.
    /// Regular file entries store offsets into `data` rather than copies.
    pub fn parse(data: &[u8]) -> Result<Self, NarError> { ... }

    /// Look up an entry by path (e.g., "bin/hello").
    pub fn lookup(&self, path: &str) -> Option<&NarEntry> { ... }
}
```

#### Error Cases

```rust
pub enum NarError {
    TooShort,
    InvalidMagic,
    InvalidString,
    UnexpectedToken,
    InvalidType,
    OffsetOverflow,
}
```

### Layer 2: NixStore FileServer (`nix_store_server.rs`)

New `FileServer` implementation in `harmony-microkernel`. Serves the
parsed NAR trees as a 9P filesystem.

#### Data Model

```rust
pub struct NixStoreServer {
    /// store_path_name → (NAR blob, parsed archive)
    /// Key is the full `<hash>-<name>` string (e.g., "abc123-hello-2.10")
    store_paths: BTreeMap<Arc<str>, StorePath>,
    fids: FidTracker<NixFidPayload>,
}

struct StorePath {
    nar_blob: Vec<u8>,
    archive: NarArchive,
}
```

#### Fid Payload

```rust
#[derive(Clone)]
enum NixFidPayload {
    /// The /nix/store root directory
    Root,
    /// A store path root (e.g., /nix/store/<hash>-<name>)
    StorePathRoot { name: Arc<str> },
    /// An entry inside a store path
    Entry { store_name: Arc<str>, path: Arc<str> },
}
```

#### QPath Derivation

Stable QPath for each node, derived by hashing the full path:

- Root (`/nix/store`): QPath 0
- Store path dirs: hash of store path name
- Interior entries: hash of `store_name + "/" + relative_path`

#### Walk Semantics

1. From Root → walk to a store path name → `StorePathRoot`
2. From StorePathRoot → walk into NAR directory tree → `Entry`
3. From Entry → walk deeper via `NarArchive::lookup`
4. Walk to non-existent name → `IpcError::NotFound`

#### Read Semantics

- **Regular file**: slice `nar_blob[offset..offset+len]`, respect
  `offset`/`count` parameters
- **Directory**: return sorted entry listing (name + type per entry)
- **Symlink**: return target string

#### Stat Semantics

- **Regular file**: `FileType::Regular`, size = `contents_len`,
  name from path
- **Directory**: `FileType::Directory`, size = entry count
- **Symlink**: `FileType::Regular` (9P doesn't have a symlink type),
  size = target length

#### Import API

```rust
impl NixStoreServer {
    /// Import a NAR archive as a store path.
    /// `name` is the `<hash>-<name>` string.
    /// `nar_bytes` is the raw NAR blob.
    pub fn import_nar(&mut self, name: &str, nar_bytes: Vec<u8>)
        -> Result<(), NarError> { ... }
}
```

### Layer 3: Mount-Point Wiring

No new infrastructure. During kernel initialization, register the
NixStoreServer as a process and mount it:

```rust
let nix_pid = kernel.spawn("nix-store", Box::new(nix_store_server))?;
// Mount in each process namespace:
process.namespace.mount("/nix/store", nix_pid, 0)?;
```

The existing path flow handles everything:
1. `sys_openat("/nix/store/abc123-hello/bin/hello")`
2. `Kernel.walk()` → `Namespace.resolve("/nix/store/abc123-hello/bin/hello")`
3. Matches `/nix/store` mount → remainder = `abc123-hello/bin/hello`
4. Dispatches walk to NixStoreServer with path components
5. NixStoreServer walks: Root → `abc123-hello` → `bin` → `hello`

## Testing Strategy

### NAR Parser
- Parse minimal NAR (single regular file), verify entry and offsets
- Parse NAR with directory tree, verify recursive structure
- Parse NAR with symlinks, verify targets
- Parse NAR with executable flag, verify it's captured
- Reject truncated NAR, invalid magic, malformed strings
- Zero-copy verification: read file contents via offset into original blob

### NixStore FileServer
- Import NAR, walk to file, open, read, verify contents match
- Walk to non-existent store path → NotFound
- Walk into directory, stat entries, verify types
- Directory read returns sorted listing
- Symlink stat returns target
- Multiple store paths coexist without interference
- FidTracker lifecycle: walk, open, read, clunk, verify fid released

### Integration (with Kernel)
- Mount NixStoreServer at `/nix/store`, walk full path through Kernel
- Namespace resolution routes correctly alongside other mounts
- Multiple processes see the same store paths

## Architecture Notes

- **Memory model**: Each imported store path holds the full NAR blob in
  memory. For milestone A this is acceptable — store paths are typically
  10-100 KB (static binaries) to ~50 MB (large packages). Layer 4 will
  add lazy fetch, and a future LRU eviction layer can bound memory.

- **Read-only**: NixStoreServer is read-only. Write operations return
  `IpcError::ReadOnly`. Mutation happens only through `import_nar()`.

- **No symlink resolution**: The server returns symlink targets as data.
  Symlink resolution is the Linuxulator's responsibility (it already
  needs this for Linux compat). Not in scope for this layer.

- **Thread safety**: Like all current FileServers, NixStoreServer is
  single-threaded behind the kernel's process dispatch. No interior
  mutability needed.

## Non-Goals

- Lazy NAR fetch from cache.nixos.org (Layer 4 — bead harmony-wuf)
- Zenoh mesh publishing of imported NARs (Layer 5 — bead harmony-2jx)
- Dynamic linking support (separate bead)
- Nix daemon protocol / nix-build support (stretch goal in harmony-9ad)
- Symlink resolution within the server (Linuxulator responsibility)
