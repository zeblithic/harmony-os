# Lazy NAR Fetch from cache.nixos.org — Design

**Goal:** Automatically fetch missing Nix store paths from cache.nixos.org when
a client walks to a path that NixStoreServer doesn't have locally.

**Scope:** Layer 4 only. Adds miss recording to NixStoreServer (Ring 2) and a
new NixStoreFetcher module (Ring 3) that fetches, decompresses, verifies, and
imports NARs. Multiple substituters, async fetching, and Zenoh mesh publishing
are out of scope.

## Context

Layer 3 (the /nix/store bridge, PR #26) established NixStoreServer as a 9P
FileServer backed by NAR archives. Store paths must be imported via
`import_nar()` before they can be served. Layer 4 closes the gap: when a
client requests a store path that hasn't been imported yet, the system
automatically fetches it from the upstream Nix binary cache.

### Architecture Decision: Push Model

Two approaches were considered:

1. **Push model (chosen):** An external Ring 3 orchestrator polls NixStoreServer
   for miss events, fetches NARs over HTTP, and imports them. NixStoreServer
   stays purely sans-I/O.

2. **Callback model:** Inject a fetcher trait object into NixStoreServer so it
   can trigger fetches inline during walk. Rejected because it breaks the
   sans-I/O invariant of Ring 2 — the server would need to block on network
   I/O or manage async state.

Push model wins because:
- NixStoreServer stays sans-I/O (Ring 2, `no_std + alloc`)
- All network I/O is isolated in Ring 3 where `std` is available
- Matches the existing sans-I/O patterns (Node returning NodeAction, etc.)
- Simpler to test: Ring 2 tests need no HTTP mocking

## Design

### Ring 2 Changes: Miss Recording

Minimal additions to `NixStoreServer`:

```rust
pub struct NixStoreServer {
    store_paths: BTreeMap<Arc<str>, StorePath>,
    fids: FidTracker<NixFidPayload>,
    misses: Vec<Arc<str>>,  // NEW
}

impl NixStoreServer {
    /// Drain all recorded miss events.
    /// Called by the Ring 3 fetcher on its own schedule.
    pub fn drain_misses(&mut self) -> Vec<Arc<str>> {
        core::mem::take(&mut self.misses)
    }
}
```

**Walk change:** When a walk from `Root` fails to find a store path name in
`store_paths`, push the name onto `misses` before returning `NotFound`. This
is the only change to existing walk logic — one line.

**Deduplication:** The `misses` vec may contain duplicates if multiple clients
request the same missing path. The fetcher deduplicates on drain (cheaper than
maintaining a set in Ring 2 for every walk).

### Ring 3: NixStoreFetcher

New module in `harmony-os` crate: `nix_store_fetcher.rs`.

#### Data Model

```rust
pub struct NixStoreFetcher {
    poll_interval: Duration,
    cache_url: &'static str,  // "https://cache.nixos.org"
    failed: HashSet<String>,  // store paths that failed fetch (no retry)
}
```

#### Main Loop

Runs on a dedicated thread. Blocking, synchronous, single fetch at a time.

```rust
impl NixStoreFetcher {
    pub fn run(&mut self, server: &mut NixStoreServer) {
        loop {
            let misses = server.drain_misses();
            for name in misses {
                if self.failed.contains(name.as_ref()) {
                    continue;
                }
                match self.fetch_and_import(&name, server) {
                    Ok(()) => {}
                    Err(e) => {
                        log::warn!("fetch failed for {name}: {e}");
                        self.failed.insert(name.to_string());
                    }
                }
            }
            std::thread::sleep(self.poll_interval);
        }
    }
}
```

#### Fetch Pipeline (`fetch_and_import`)

1. **Extract store hash:** First 32 chars of the store path name (the hash
   portion of `<hash>-<name>`)

2. **Fetch NARInfo:** `GET https://cache.nixos.org/<store-hash>.narinfo`
   Parse response to extract `URL`, `NarHash`, `NarSize`

3. **Fetch NAR:** `GET https://cache.nixos.org/<nar-url>` (typically
   `nar/<hash>.nar.xz`)

4. **Decompress:** xz decompress the fetched bytes

5. **Verify:** SHA-256 hash the decompressed NAR, compare against `NarHash`
   from narinfo (Nix base32 encoding)

6. **Import:** `server.import_nar(&name, nar_bytes)`

#### NARInfo Parser

Simple line-based format, only 3 fields needed:

```
StorePath: /nix/store/<hash>-<name>
URL: nar/<hash>.nar.xz
Compression: xz
NarHash: sha256:<nix-base32-hash>
NarSize: 12345
References: <hash>-dep1 <hash>-dep2
```

A small parsing function, not a separate module. Extracts `URL`, `NarHash`,
and `NarSize`. Returns error on missing/malformed fields.

#### Error Handling

- 404 from cache.nixos.org: store path doesn't exist upstream, add to `failed`
- Network error: add to `failed`
- Hash mismatch: add to `failed`, log warning
- Decompression failure: add to `failed`, log warning
- NARInfo parse failure: add to `failed`, log warning

Failed store paths are never retried in the current session. A future
enhancement could add TTL-based retry, but YAGNI for now.

### Shared Access: Arc<Mutex<NixStoreServer>>

NixStoreServer is owned by the kernel's process table as a `FileServer`.
The fetcher thread also needs `&mut` access. Solution:

```rust
pub struct SharedNixStoreServer {
    inner: Arc<Mutex<NixStoreServer>>,
}

impl FileServer for SharedNixStoreServer {
    fn walk(&mut self, fid: u32, name: &str) -> Result<Stat, IpcError> {
        self.inner.lock().unwrap().walk(fid, name)
    }
    // ... delegate all FileServer methods
}
```

- Kernel holds a `SharedNixStoreServer` (implements `FileServer`)
- Fetcher thread holds `Arc<Mutex<NixStoreServer>>` directly
- Lock contention is minimal: fetcher holds lock only for `drain_misses()`
  (microseconds) and `import_nar()` (parse time). Network I/O happens
  outside the lock.
- Only NixStoreServer uses this pattern — other servers stay as `Box<dyn FileServer>`

### Wiring (kernel init)

```rust
let nix_server = NixStoreServer::new();
let shared = Arc::new(Mutex::new(nix_server));

// Register with kernel via wrapper
let wrapper = SharedNixStoreServer { inner: Arc::clone(&shared) };
let nix_pid = kernel.spawn("nix-store", Box::new(wrapper))?;
process.namespace.mount("/nix/store", nix_pid, 0)?;

// Start fetcher on dedicated thread
let fetcher_handle = Arc::clone(&shared);
std::thread::spawn(move || {
    let mut fetcher = NixStoreFetcher::new();
    loop {
        let misses = fetcher_handle.lock().unwrap().drain_misses();
        // ... fetch pipeline (lock released during network I/O)
        for name in &misses {
            match fetcher.fetch_nar(name) {
                Ok(nar_bytes) => {
                    fetcher_handle.lock().unwrap().import_nar(name, nar_bytes).ok();
                }
                Err(e) => { /* log, add to failed */ }
            }
        }
        std::thread::sleep(fetcher.poll_interval);
    }
});
```

## Dependencies (Ring 3 only)

| Crate | Purpose |
|-------|---------|
| `ureq` | Blocking HTTP client (small, no async runtime) |
| `xz2` | xz/lzma decompression |
| `sha2` | SHA-256 (may reuse via harmony-crypto) |
| `data-encoding` | Nix base32 decoding (non-standard alphabet) |

## Testing Strategy

### Ring 2 Tests (nix_store_server.rs)

- Walk to missing store path records name in misses
- `drain_misses()` returns accumulated misses and clears list
- `drain_misses()` on empty server returns empty vec
- Duplicate miss names are all recorded
- After `import_nar()` of a previously-missing path, walk succeeds

### Ring 3 Tests (nix_store_fetcher.rs)

- **NARInfo parser:** parse valid narinfo → correct URL/NarHash/NarSize.
  Reject missing fields, bad hash format
- **Nix base32 decoder:** round-trip encode/decode, reject invalid chars
- **Hash verification:** correct NAR passes, tampered NAR rejected
- **Decompression:** valid xz → correct bytes, corrupt xz → error
- **Integration (no network):** injectable HTTP layer (trait or closure).
  Inject miss, provide canned narinfo + nar.xz, verify store path appears

**No live network tests in CI.** Test data built from existing NAR test
helpers: construct NAR, xz-compress, compute SHA-256, build matching narinfo.

## Non-Goals

- Multiple substituters / Cachix / private caches (future enhancement)
- Async / concurrent fetches (YAGNI — single-threaded blocking is sufficient)
- Retry logic with backoff (failed paths stay failed for session lifetime)
- Zenoh mesh publishing of fetched NARs (Layer 5 — bead harmony-2jx)
- Prefetching / dependency resolution (fetch only what's requested)
