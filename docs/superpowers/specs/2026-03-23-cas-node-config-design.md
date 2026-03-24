# Declarative Node Configuration via Content-Addressed Bundles

## Goal

Define and implement the `NodeConfig` bundle — a CBOR-serialized, content-addressed, cryptographically signed declarative configuration for Harmony OS nodes. This is the architectural keystone for "NixOS on harmony-os": every node's running state is determined by a single CID.

## Scope

**In scope (this deliverable):**
- `NodeConfig` schema (core subset: kernel, identity, network, services)
- CBOR deterministic serialization + CID computation
- `SignedConfig` envelope with ML-DSA-65 signature verification
- `ConfigServer` — 9P file server at `/env/config` for two-phase activation
- `ConfigApplicator` — Ring 3 logic to apply config changes + Zenoh subscription
- Mesh distribution via existing CAS + Zenoh content layer

**Out of scope:**
- Drivers, storage, compute, schedule fields (future NodeConfig extensions)
- Fleet orchestration (rolling updates, canary deployments, config groups)
- Generation-based config history
- NixOS module system bridge (separate design)

## Architecture

### Ring Placement

Types and validation in Ring 2 (harmony-microkernel). Application logic in Ring 3 (harmony-os).

Ring 2 understands the NodeConfig schema so it can:
- Parse and validate CBOR structure
- Verify ML-DSA-65 signatures (reject unsigned configs)
- Check that all referenced CIDs exist in the CAS

Ring 3 consumes validated configs and:
- Applies them to the running system (start/stop services, reconfigure network)
- Subscribes to Zenoh config announcements from operators
- Handles two-phase activation user flow (stage → commit)

### Data Flow

```
Operator builds NodeConfig
    → CBOR serialize (deterministic)
    → Sign with PQ identity → SignedConfig
    → Ingest into ContentServer → CID
    → Publish CID on harmony/config/{target_node_address}

Target node receives CID announcement
    → Write CID to /env/config/stage
    → ConfigServer fetches SignedConfig from CAS
    → Verify signature + validate schema + check CID references
    → Operator writes "1" to /env/config/commit
    → ConfigServer: pending → active, old active → previous
    → Ring 3 ConfigApplicator reads new active, applies changes
```

## Schema

### NodeConfig (CBOR-serialized)

```rust
/// A node's declarative configuration — content-addressed via CBOR + SHA-256.
pub struct NodeConfig {
    /// Schema version for forward compatibility (starts at 1).
    pub version: u32,
    /// CID of the kernel binary (ELF/PE image in CAS).
    pub kernel: [u8; 32],
    /// CID of the node's encrypted PqIdentity bundle.
    pub identity: [u8; 32],
    /// Inline network config (small enough to not need its own CID).
    pub network: NetworkConfig,
    /// CIDs of service binaries/configs to launch at boot.
    pub services: Vec<ServiceEntry>,
}

pub struct NetworkConfig {
    /// Mesh seed peers (address hashes to bootstrap from).
    pub mesh_seeds: Vec<[u8; 16]>,
    /// UDP port for mesh traffic.
    pub port: u16,
}

pub struct ServiceEntry {
    /// Human-readable service name (e.g., "content-server").
    pub name: String,
    /// CID of the service binary in CAS.
    pub binary: [u8; 32],
    /// Optional CID of service-specific config blob.
    pub config: Option<[u8; 32]>,
}
```

### SignedConfig (Signature Envelope)

```rust
/// Signed wrapper around a serialized NodeConfig.
pub struct SignedConfig {
    /// CBOR-encoded NodeConfig bytes (deterministic).
    pub config_bytes: Vec<u8>,
    /// ML-DSA-65 signature over config_bytes by the operator identity.
    pub signature: Vec<u8>,
    /// Operator's PQ address hash (verifier looks up public key).
    pub signer: [u8; 16],
}
```

The `SignedConfig` is what gets stored as a book in the CAS. Its CID is the SHA-256 of the entire CBOR-serialized `SignedConfig`. The inner `config_bytes` contains the deterministic CBOR encoding of `NodeConfig`, whose own hash serves as a stable content identifier for the logical config (independent of who signed it).

## Serialization

**Format:** CBOR (RFC 8949) via the `ciborium` crate.

**Determinism:** Structs have fixed field order, so CBOR encoding is deterministic without explicit map key sorting. Same `NodeConfig` always produces the same bytes, which always produces the same CID.

**CID computation:** `SHA-256(cbor_bytes)` — consistent with the rest of the Harmony CAS (`harmony-athenaeum` uses `sha256_hash`).

**Size:** NodeConfig is metadata (CID references, a few strings, small vecs). Well under 1KB for typical configs. Stored as a single-page book in the CAS.

## ConfigServer (Ring 2, 9P)

A new `FileServer` implementation mounted at `/env/config` in the microkernel namespace.

### Virtual Filesystem

```
/env/config/
├── active       — read: CID hex of current config (empty if unconfigured)
├── pending      — read: CID hex of staged config (empty if none)
├── previous     — read: CID hex of last-known-good config (empty if none)
├── stage        — write: CID hex to stage a new config
├── commit       — write: "1" to activate staged config
├── rollback     — write: "1" to revert to previous config
└── node.cbor    — read: active NodeConfig as raw CBOR bytes
```

### Stage Validation

When a CID is written to `/env/config/stage`, the ConfigServer:

1. Fetches the `SignedConfig` book from `ContentServer` by CID
2. Deserializes the outer `SignedConfig` from CBOR
3. Verifies the ML-DSA-65 signature over `config_bytes` using the signer's PQ public key (looked up from key hierarchy)
4. Deserializes the inner `config_bytes` as `NodeConfig`
5. Validates schema version is supported
6. Checks all referenced CIDs exist in the CAS (kernel, identity, each service binary and config)
7. On success: stores as `pending` state. On failure: returns `IpcError::PermissionDenied` (bad signature) or `IpcError::InvalidArgument` (malformed/missing refs)

### Commit / Rollback

**Commit** (write "1" to `/env/config/commit`):
- Requires: `pending` is set
- Action: `active` → `previous`, `pending` → `active`, clear `pending`
- Returns: success or `IpcError::InvalidArgument` if no pending config

**Rollback** (write "1" to `/env/config/rollback`):
- Requires: `previous` is set
- Action: swap `active` ↔ `previous`
- Returns: success or `IpcError::InvalidArgument` if no previous config

### Interaction with ContentServer

ConfigServer holds a reference (shared `Arc` or direct 9P client) to the ContentServer for CID lookups. It does not duplicate book storage — it only caches the three CID pointers (active/pending/previous) and the deserialized active `NodeConfig`.

## ConfigApplicator (Ring 3)

Ring 3 logic that watches for config changes and applies them.

### Responsibilities

1. **Zenoh subscription:** Subscribes to `harmony/config/{self_address}` for incoming config CID announcements from operators
2. **Auto-stage:** When a config CID arrives via Zenoh, writes it to `/env/config/stage` (validation happens in Ring 2)
3. **Apply on commit:** After a successful commit, reads the new active `NodeConfig` and:
   - Compares against previous config to compute a diff
   - Starts new services, stops removed services
   - Reconfigures network if `NetworkConfig` changed
   - Logs all changes
4. **Announce:** After successful activation, publishes the new active CID on `harmony/config/{self_address}` so the mesh knows this node's current state

### Config Diff

A lightweight diff between two `NodeConfig` values:

```rust
pub struct ConfigDiff {
    pub kernel_changed: bool,
    pub identity_changed: bool,
    pub network_changed: bool,
    pub services_added: Vec<String>,
    pub services_removed: Vec<String>,
    pub services_updated: Vec<String>,
}
```

Kernel and identity changes are logged but not auto-applied (require reboot). Service and network changes are applied live.

## Mesh Distribution

### Zenoh Key Expression

`harmony/config/{node_address_hex}` — 32-character hex encoding of the 16-byte node address.

Operators publish a config CID to a specific node's key. Nodes subscribe to their own key. Fleet monitoring can subscribe to `harmony/config/**` to observe all config changes.

### Fetch Path

Config books are fetched through the existing content layer — same as NARs or any other content. No new transport or protocol needed.

### Operator Push Flow

1. Build `NodeConfig` struct
2. Serialize to deterministic CBOR
3. Sign with operator's PQ identity → `SignedConfig`
4. Serialize `SignedConfig` to CBOR, ingest into local CAS → CID
5. Publish CID on `harmony/config/{target_node_address}`
6. Target node auto-stages, operator (or automation) commits

## File Map

| File | Ring | Purpose |
|------|------|---------|
| `harmony-microkernel/src/node_config.rs` | 2 | `NodeConfig`, `NetworkConfig`, `ServiceEntry` types + CBOR serialization + CID computation |
| `harmony-microkernel/src/signed_config.rs` | 2 | `SignedConfig` type + ML-DSA-65 signature verification |
| `harmony-microkernel/src/config_server.rs` | 2 | `ConfigServer` 9P file server at `/env/config` |
| `harmony-os/src/config_applicator.rs` | 3 | Config watcher, Zenoh subscription, diff + apply logic |
| `harmony-microkernel/Cargo.toml` | 2 | Add `ciborium` dependency |

## Testing Strategy

- **Unit tests** in `node_config.rs`: CBOR round-trip (serialize → deserialize → assert equality), determinism (serialize twice → same bytes), CID stability (known input → known CID)
- **Unit tests** in `signed_config.rs`: valid signature passes, tampered bytes rejected, wrong signer rejected
- **Unit tests** in `config_server.rs`: full 9P lifecycle — stage → validate → commit → read active; rollback; stage with bad signature → error; stage with missing CID refs → error
- **Unit tests** in `config_applicator.rs`: diff computation (added/removed/changed services), network change detection
- **Integration test**: end-to-end flow — build config → sign → ingest → stage → commit → read back → verify CID matches

## Future Work (Explicitly Deferred)

- **Extended schema fields:** drivers, storage, compute, schedule (add to NodeConfig when those subsystems exist)
- **Generation history:** numbered generations with rollback-to-N (currently only rollback-to-previous)
- **Fleet orchestration:** rolling updates, canary percentages, config groups
- **NixOS module bridge:** `configuration.nix` → `NodeConfig` translation
- **Config pinning:** prevent auto-staging from mesh (manual-only mode)
