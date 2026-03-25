# Signed Narinfo via Ed25519 — Design Spec

## Goal

Add `Sig` field to narinfo so Harmony binary caches can be used as
trusted substituters in Nix configs. Signatures use Ed25519 from
`harmony-identity`, signing the standard Nix fingerprint format.

## Background

Nix binary caches can optionally sign narinfo responses. Clients verify
signatures against `trusted-public-keys` in `nix.conf`. Without
signatures, a cache can only be used with `--no-check-sigs` or as an
untrusted substituter.

The signing key and fingerprint format are defined by Nix. Harmony
already has Ed25519 keypair support via `harmony-identity`.

## Nix Fingerprint Format

Signatures cover a fingerprint string:

```
1;<store_path>;<nar_hash>;<nar_size>;<comma-separated-references>
```

Example:
```
1;/nix/store/abc123-hello;sha256:1b8m03r63...;12345;dep456-glibc,ghi789-gcc
```

- Version prefix is always `1`
- References are comma-separated (not space-separated like the narinfo
  `References:` field)
- If references are unknown (`None`), the fingerprint cannot be computed
  and the `Sig:` line is omitted

## Nix Sig Field Format

```
Sig: <key_name>:<base64-signature>
```

- `key_name` is a caller-provided identifier (e.g., `"harmony-mesh-1"`)
- Signature is Ed25519 over the fingerprint bytes
- Base64 uses standard alphabet with `=` padding (e.g.,
  `cache.nixos.org-1:GrGV/Ls10Tzo...dhfTBQ==`)

## Data Model

### BinaryCacheServer

```rust
pub struct BinaryCacheServer {
    server: NixStoreServer,
    hash_index: HashMap<String, IndexEntry>,
    misses: BTreeSet<String>,
    signing: Option<(String, PrivateIdentity)>,  // (key_name, key)
}
```

### Constructors

- `new(server)` — no signing, no refs (backward compat)
- `new_with_refs(server, ref_map)` — no signing (backward compat)
- `new_with_signing(server, ref_map, key_name, identity)` — signing enabled

`new` and `new_with_refs` delegate to `new_with_signing` with `None`
signing. All three delegate to one implementation that accepts
`Option<(String, PrivateIdentity)>`.

### serialize_narinfo

Gains `sig: Option<&str>` as final parameter. When `Some`, appends:

```
Sig: <value>\n
```

The serializer is kept pure — it receives the pre-formatted sig string
and just appends it. Fingerprint computation and signing happen in the
caller (`BinaryCacheServer::handle_request`).

### NarInfo::parse

Updated to extract `Sig:` field into a new `sig: Option<String>` field
on `NarInfo`. Uses `strip_prefix("Sig: ")` matching. Takes first
occurrence only (consistent with `References:` parsing).

## Signing Flow

In `BinaryCacheServer::handle_request`, when `self.signing` is `Some`:

1. Look up `IndexEntry` (name, nar_sha256, nar_size, references)
2. If `references` is `None` → skip signing (fingerprint requires refs)
3. Compute fingerprint via `compute_narinfo_fingerprint()`
4. Sign: `identity.sign(fingerprint.as_bytes())` → `[u8; 64]`
5. Base64-encode signature (standard alphabet, no padding)
6. Format: `"{key_name}:{base64sig}"`
7. Pass to `serialize_narinfo` as `sig` parameter

## New Public Functions

### compute_narinfo_fingerprint

```rust
pub fn compute_narinfo_fingerprint(
    store_path_name: &str,
    nar_hash: &str,       // "sha256:<nix-base32>"
    nar_size: u64,
    references: Option<&[String]>,
) -> Option<String>
```

Returns `None` when `references` is `None`. The fingerprint string is:

```
1;/nix/store/{store_path_name};{nar_hash};{nar_size};{comma_refs}
```

Where `comma_refs` is references joined by `,`. An empty references list
(`Some(&[])`) produces a trailing `;` with no refs — this is correct per
the Nix spec.

## API Changes Summary

| Function | Change |
|----------|--------|
| `BinaryCacheServer` struct | Add `signing: Option<(String, PrivateIdentity)>` field |
| `BinaryCacheServer::new` | Delegates to shared impl with `None` signing |
| `BinaryCacheServer::new_with_refs` | Delegates to shared impl with `None` signing |
| `BinaryCacheServer::new_with_signing` | New constructor accepting key_name + identity |
| `serialize_narinfo` | Add `sig: Option<&str>` parameter |
| `NarInfo` struct | Add `sig: Option<String>` field |
| `NarInfo::parse` | Extract `Sig: ` field |
| `compute_narinfo_fingerprint` | New public function in `narinfo.rs` |

## Testing

- **Fingerprint format**: known-vector test with specific store path,
  hash, size, and references. Verify exact string match.
- **Fingerprint with empty refs**: `Some(&[])` produces `"1;/nix/store/name;hash;size;"`.
- **Fingerprint with None refs**: returns `None`.
- **Signature round-trip**: generate keypair, sign fingerprint, verify
  with public key.
- **Narinfo with Sig line**: serialize with sig → parse → verify `sig`
  field matches.
- **Narinfo without Sig**: serialize with `None` sig → parse → `sig` is
  `None`.
- **No signing key configured**: `handle_request` produces narinfo
  without `Sig:` (backward compat).
- **Signing key but no references**: `handle_request` produces narinfo
  without `Sig:` (can't compute fingerprint).
- **Integration**: configure `BinaryCacheServer` with signing key, import
  NAR with references, request narinfo, verify `Sig:` line verifies
  against the public key.

## Out of Scope

- UCAN delegation chains — separate bead
- Post-quantum signatures (ML-DSA-65) — Nix spec only supports Ed25519
- Key rotation / multiple signatures per narinfo
- Signature persistence in `.meta` sidecar — can be added later
- Signature verification on fetch (client-side) — separate concern
