// SPDX-License-Identifier: GPL-2.0-or-later
//! NodeConfig — declarative configuration for a Harmony OS node.
//!
//! A `NodeConfig` describes the complete desired state of a node: which
//! kernel binary to run, which identity to use, how to connect to the mesh,
//! and which services to start. It serializes to CBOR for storage in the
//! content-addressed store and its CID (SHA-256 of the CBOR bytes) serves
//! as an immutable handle — changing any field produces a new CID.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use harmony_athenaeum::sha256_hash;
use serde::{Deserialize, Serialize};

/// Current schema version. Bump when making breaking changes to the
/// serialized format so that readers can reject incompatible configs.
pub const SCHEMA_VERSION: u32 = 1;

// ── Error type ───────────────────────────────────────────────────────

/// Errors that can arise when working with `NodeConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The bytes supplied to `from_cbor` could not be deserialized.
    DeserializeFailed(String),
}

// ── Config types ─────────────────────────────────────────────────────

/// Network connectivity parameters for a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Bootstrap peers to attempt on first boot, as 128-bit mesh addresses.
    pub mesh_seeds: Vec<[u8; 16]>,
    /// UDP/TCP port the node listens on.
    pub port: u16,
}

/// A single service entry in the node's service manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEntry {
    /// Human-readable service name (e.g. `"harmony-dns"`).
    pub name: String,
    /// CID of the service binary in the content store.
    pub binary: [u8; 32],
    /// Optional CID of a service-specific config blob.
    pub config: Option<[u8; 32]>,
}

/// Declarative description of the desired state of a Harmony OS node.
///
/// All fields are content-addressed: `kernel`, `identity`, and each
/// service's `binary`/`config` are SHA-256 CIDs into the local store.
/// The config itself gets a CID via [`NodeConfig::cid`], enabling
/// atomic transitions between named configurations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Schema version — must equal [`SCHEMA_VERSION`] for this reader.
    pub version: u32,
    /// CID of the kernel binary to boot.
    pub kernel: [u8; 32],
    /// CID of the node's identity blob.
    pub identity: [u8; 32],
    /// Network connectivity parameters.
    pub network: NetworkConfig,
    /// Ordered list of services to start.
    pub services: Vec<ServiceEntry>,
}

// ── NodeConfig impl ──────────────────────────────────────────────────

impl NodeConfig {
    /// Serialize this config to CBOR bytes.
    ///
    /// CBOR encoding is deterministic for a given config value: the same
    /// struct fields in the same order always produce the same bytes.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .expect("CBOR serialization of NodeConfig is infallible");
        buf
    }

    /// Deserialize a `NodeConfig` from CBOR bytes.
    ///
    /// Returns [`ConfigError::DeserializeFailed`] if the bytes are not
    /// valid CBOR or do not match the `NodeConfig` schema.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ConfigError> {
        ciborium::from_reader(bytes)
            .map_err(|e| ConfigError::DeserializeFailed(alloc::format!("{e}")))
    }

    /// Compute the content identifier (CID) for this config.
    ///
    /// The CID is the SHA-256 hash of the CBOR serialization. Two configs
    /// are identical if and only if their CIDs match.
    pub fn cid(&self) -> [u8; 32] {
        sha256_hash(&self.to_cbor())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> NodeConfig {
        NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [1u8; 32],
            identity: [2u8; 32],
            network: NetworkConfig {
                mesh_seeds: alloc::vec![[0xAB; 16], [0xCD; 16]],
                port: 7777,
            },
            services: alloc::vec![ServiceEntry {
                name: String::from("harmony-dns"),
                binary: [3u8; 32],
                config: Some([4u8; 32]),
            }],
        }
    }

    #[test]
    fn cbor_round_trip() {
        let original = sample_config();
        let bytes = original.to_cbor();
        let decoded = NodeConfig::from_cbor(&bytes).expect("round-trip must succeed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn cbor_deterministic() {
        let config = sample_config();
        let first = config.to_cbor();
        let second = config.to_cbor();
        assert_eq!(first, second, "CBOR encoding must be deterministic");
    }

    #[test]
    fn cid_stable() {
        let config = sample_config();
        let cid1 = config.cid();
        let cid2 = config.cid();
        assert_eq!(cid1, cid2, "CID must be stable across calls");
        assert_eq!(
            cid1,
            sha256_hash(&config.to_cbor()),
            "CID must equal sha256_hash(to_cbor())"
        );
    }

    #[test]
    fn cid_changes_with_content() {
        let config_a = sample_config();
        let mut config_b = sample_config();
        config_b.network.port = 8888;
        assert_ne!(
            config_a.cid(),
            config_b.cid(),
            "different content must produce different CID"
        );
    }

    #[test]
    fn from_cbor_rejects_garbage() {
        let garbage = [0xFF, 0xFF, 0xFF];
        assert!(
            NodeConfig::from_cbor(&garbage).is_err(),
            "garbage bytes must produce an error"
        );
    }

    #[test]
    fn empty_services_round_trips() {
        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [0u8; 32],
            identity: [0u8; 32],
            network: NetworkConfig {
                mesh_seeds: alloc::vec![],
                port: 0,
            },
            services: alloc::vec![],
        };
        let decoded = NodeConfig::from_cbor(&config.to_cbor()).expect("round-trip must succeed");
        assert_eq!(config, decoded);
    }

    #[test]
    fn service_without_config_round_trips() {
        let config = NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [5u8; 32],
            identity: [6u8; 32],
            network: NetworkConfig {
                mesh_seeds: alloc::vec![],
                port: 1234,
            },
            services: alloc::vec![ServiceEntry {
                name: String::from("bare-service"),
                binary: [7u8; 32],
                config: None,
            }],
        };
        let decoded = NodeConfig::from_cbor(&config.to_cbor()).expect("round-trip must succeed");
        assert_eq!(config, decoded);
    }
}
