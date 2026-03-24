# Narinfo References Field — Design Spec

## Goal

Add `References` field to narinfo generation so Nix clients can compute
closure sizes and verify dependency completeness. References flow through
all three intake paths (HTTP fetch, mesh fetch, local publish) and persist
to disk via a `.meta` sidecar file.

## Background

The `BinaryCacheServer` (bead harmony-os-q9d) serves narinfo with five
fields: StorePath, URL, Compression, NarHash, NarSize. Without
`References`, clients can fetch individual store paths but cannot resolve
dependency closures — a requirement for `nix-store --realise` and
`nix copy`.

NARs themselves do not contain reference information. It originates from
the Nix derivation metadata and must enter the system via the intake path
that imports the NAR.

## Data Model

### NarInfo struct (`narinfo.rs`)

```rust
pub struct NarInfo {
    pub url: String,
    pub compression: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Option<Vec<String>>,
}
```

- `None` — references not provided (field omitted from serialized narinfo)
- `Some(vec![])` — zero runtime dependencies (empty `References:` line)
- `Some(vec!["abc123-glibc-2.39", ...])` — full store path names

### IndexEntry (`nix_binary_cache.rs`)

```rust
struct IndexEntry {
    name: Arc<str>,
    nar_sha256: [u8; 32],
    nar_size: u64,
    references: Option<Vec<String>>,
}
```

### Serialization

`serialize_narinfo` gains a `references: Option<&[String]>` parameter.
When `Some`, emits a `References:` line with space-separated store path
names. When `None`, omits the line entirely.

```
StorePath: /nix/store/abc123-hello-2.10
URL: nar/abc123-hello-2.10.nar
Compression: none
NarHash: sha256:1b8m03r63...
NarSize: 12345
References: def456-glibc-2.39 ghi789-gcc-lib-13.2
```

### Parsing

`NarInfo::parse` matches `References: ` (colon + single space, per Nix
convention). Missing `References` line → `None`. Empty value after the
prefix → `Some(vec![])`. Non-empty value split on whitespace →
`Some(vec![...])`. A malformed `References:` with no space after the
colon is treated as an unrecognized line (`None`).

## Persistence — `.meta` Sidecar

`PersistentNarStore` writes a `<name>.meta` file alongside each
`<name>.nar`. Format is key-value, one field per line, same syntax as
narinfo:

```
References: def456-glibc-2.39 ghi789-gcc-lib-13.2
```

Currently only `References`, but this file is the extension point for the
signing bead (harmony-os-sls) to add `Sig:` lines later.

### Write order

1. Write `<name>.nar` (crash here → NAR orphan, tolerated on reload)
2. Write `<name>.meta` (crash here → NAR loads without references)

### `.meta` content rules

- `None` references → do not write a `.meta` file
- `Some(vec![])` → write `.meta` with `References: \n` (empty value)
- `Some(vec![...])` → write `.meta` with `References: ref1 ref2\n`

On reload this preserves the semantic difference: missing `.meta` → `None`,
present `.meta` with empty References line → `Some(vec![])`.

### Reload behavior

- `.meta` present and valid → references restored (including empty `Some(vec![])`)
- `.meta` missing → references become `None` (NAR still loads)
- `.meta` corrupted → logged, skipped (NAR still loads without references)

## Intake Paths

### HTTP fetch (`NixStoreFetcher`)

Upstream `.narinfo` responses already include `References:`. After
`NarInfo::parse`, the references are captured. When the fetched NAR is
imported via `persist_and_import`, references are passed through.

No new HTTP requests needed — the data is already in the narinfo response.

`NixStoreFetcher::fetch_nar` currently returns `Result<Vec<u8>, FetchError>`,
discarding the parsed `NarInfo`. It must return references alongside NAR
bytes. Similarly, `process_misses` and `process_misses_shared` return
`Vec<(String, Vec<u8>)>` and must include references in the tuples so
callers can pass them to `persist_and_import`.

### Mesh fetch (`NarPublisher` / `MeshNarSource`)

`NarPublisher::publish` accepts `references: Option<Vec<String>>` and
extends the announcement payload on `harmony/nix/store/{hash}`:

```
<cid_hex>\n<ref1>\n<ref2>...
```

- Line 1: root CID hex (always present, backward compatible)
- Lines 2+: reference store path names (one per line)
- No references / `None`: payload is CID only (single line)

`MeshNarSource::try_fetch` parses this format: split payload on `\n`,
hex-decode line 1 as the root CID, collect remaining non-empty lines as
references. Returns references alongside the NAR bytes.

Reference names are Nix store path names — validated to contain no
newlines, carriage returns, NUL bytes, or spaces within individual names.

The `MeshNarFetch` trait must also change its return type to propagate
references: `fn fetch_nar(&self, name: &str) -> Option<(Vec<u8>, Option<Vec<String>>)>`.

Backward compatibility: old publishers that emit CID-only payloads
produce `None` references on fetch (single line, no `\n`). Old consumers
that read the entire payload as CID hex will fail on `\n` — but all
consumers in this codebase are updated together.

### Local publish (`BinaryCacheServer` / `PersistentNarStore`)

`BinaryCacheServer::import_nar` and `PersistentNarStore::persist_and_import`
gain a `references: Option<Vec<String>>` parameter. Callers without
references pass `None`.

## API Changes Summary

| Function | Change |
|----------|--------|
| `serialize_narinfo` | Add `references: Option<&[String]>` param |
| `NarInfo::parse` | Parse `References` field into `Option<Vec<String>>` |
| `BinaryCacheServer::import_nar` | Add `references: Option<Vec<String>>` param |
| `BinaryCacheServer::new` | Load references from IndexEntry during init |
| `PersistentNarStore::persist_and_import` | Add `references: Option<Vec<String>>` param, write `.meta` |
| `PersistentNarStore::reopen` | Read `.meta` files, pass references to import |
| `NarPublisher::publish` | Add `references: Option<Vec<String>>` param, extend payload |
| `MeshNarSource::try_fetch` | Parse first line as CID hex, remaining lines as references, return alongside NAR bytes |
| `MeshNarFetch::fetch_nar` (trait) | Return `Option<(Vec<u8>, Option<Vec<String>>)>` |
| `NixStoreFetcher::fetch_nar` | Return references from parsed narinfo alongside NAR bytes |
| `NixStoreFetcher::process_misses` | Include references in return tuples |
| `NixStoreFetcher::process_misses_shared` | Include references in return tuples |

## Testing

- **Narinfo round-trip**: serialize with references → parse → verify.
  Test `None` (no line emitted), `Some(vec![])` (empty line),
  multi-reference.
- **Parser backward compat**: parse narinfo without References → `None`.
  Parse with empty `References: ` → `Some(vec![])`.
  Parse `References:` (no space) → `None` (malformed).
- **`.meta` sidecar**: persist with references, reload, verify recovered.
  Test missing `.meta` (graceful `None`), corrupted `.meta` (NAR loads),
  and `Some(vec![])` round-trip (empty References line preserved).
- **Mesh payload format**: publish with references, parse payload, verify
  CID + references. Test single-line payload (no references, backward compat).
- **HTTP fetch round-trip**: mock upstream narinfo with References →
  `NixStoreFetcher` → `persist_and_import` → `BinaryCacheServer` serves
  narinfo with matching References line.
- **Mesh fetch round-trip**: `NarPublisher` with references → mock
  announcer → `MeshNarSource` → verify references returned alongside
  NAR bytes.
- **Integration**: import NAR with references, request `.narinfo`, verify
  `References:` line in response.

## Out of Scope

- `Sig` field (signing) — bead harmony-os-sls
- `Deriver` field — not needed for closure resolution
- HTTP server binding — separate bead
- Compression on serve — stays `none`
