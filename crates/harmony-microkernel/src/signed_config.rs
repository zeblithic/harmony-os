// SPDX-License-Identifier: GPL-2.0-or-later

//! SignedConfig — an authenticated envelope wrapping a [`NodeConfig`].
//!
//! A `SignedConfig` bundles a CBOR-encoded [`NodeConfig`] with an ML-DSA-65
//! signature from the operator identity that authorized it. Verification
//! checks three things in order:
//!
//! 1. The embedded public key deserializes correctly.
//! 2. The public key's derived address hash matches the declared `signer` field.
//! 3. The `signer` address is in the caller-supplied `trusted_operators` list.
//! 4. The ML-DSA-65 signature over `config_bytes` is valid.
//!
//! CIDs are SHA-256 of the CBOR-encoded `SignedConfig` itself, providing
//! a content-addressed handle to the whole authenticated envelope.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use harmony_athenaeum::sha256_hash;
use harmony_identity::PqIdentity;
use serde::{Deserialize, Serialize};

// ── Error type ───────────────────────────────────────────────────────

/// Errors that can arise when verifying a `SignedConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedConfigError {
    /// The CBOR bytes could not be deserialized into a `SignedConfig`.
    DeserializeFailed(String),
    /// The `signer_pubkey` bytes could not be parsed as a `PqIdentity`.
    InvalidPublicKey(String),
    /// The address hash derived from `signer_pubkey` does not match `signer`.
    AddressMismatch,
    /// The `signer` address is not in the caller-supplied trusted operator list.
    UntrustedSigner,
    /// The ML-DSA-65 signature is not valid for `config_bytes`.
    SignatureInvalid(String),
}

// ── SignedConfig ──────────────────────────────────────────────────────

/// An authenticated envelope wrapping a CBOR-encoded [`NodeConfig`].
///
/// The `config_bytes` field holds the raw CBOR of the `NodeConfig`; the
/// `signature` is an ML-DSA-65 signature over those bytes, produced by the
/// operator whose full public key is in `signer_pubkey`. The `signer` field
/// caches the 16-byte address hash so callers can check the trusted-operator
/// list without deserializing the full public key first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    /// CBOR-encoded [`crate::node_config::NodeConfig`].
    pub config_bytes: Vec<u8>,
    /// ML-DSA-65 signature over `config_bytes`.
    pub signature: Vec<u8>,
    /// Operator PQ address hash (16 bytes) — cached from `signer_pubkey`.
    pub signer: [u8; 16],
    /// Operator full PQ public key (3136 bytes: 1184 ML-KEM + 1952 ML-DSA).
    pub signer_pubkey: Vec<u8>,
}

impl SignedConfig {
    /// Verify the signed config against a list of trusted operator addresses.
    ///
    /// Returns the deserialized [`PqIdentity`] of the signer on success so
    /// the caller can use the key for further operations without re-parsing.
    ///
    /// # Errors
    ///
    /// Returns [`SignedConfigError`] if any of the four checks fail:
    /// public key parse, address consistency, trust check, or signature.
    pub fn verify(&self, trusted_operators: &[[u8; 16]]) -> Result<PqIdentity, SignedConfigError> {
        // 1. Parse the operator public key.
        let identity = PqIdentity::from_public_bytes(&self.signer_pubkey)
            .map_err(|e| SignedConfigError::InvalidPublicKey(alloc::format!("{e:?}")))?;

        // 2. Ensure the key's derived address matches the declared signer field.
        if identity.address_hash != self.signer {
            return Err(SignedConfigError::AddressMismatch);
        }

        // 3. Ensure the signer is in the trusted-operator allow-list.
        if !trusted_operators.contains(&self.signer) {
            return Err(SignedConfigError::UntrustedSigner);
        }

        // 4. Verify the ML-DSA-65 signature over config_bytes.
        identity
            .verify(&self.config_bytes, &self.signature)
            .map_err(|e| SignedConfigError::SignatureInvalid(alloc::format!("{e:?}")))?;

        Ok(identity)
    }

    /// Serialize this `SignedConfig` to CBOR bytes.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .expect("CBOR serialization of SignedConfig is infallible");
        buf
    }

    /// Deserialize a `SignedConfig` from CBOR bytes.
    ///
    /// Returns [`SignedConfigError::DeserializeFailed`] if the bytes are not
    /// valid CBOR or do not match the `SignedConfig` schema.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, SignedConfigError> {
        ciborium::from_reader(bytes)
            .map_err(|e| SignedConfigError::DeserializeFailed(alloc::format!("{e}")))
    }

    /// Compute the content identifier (CID) for this envelope.
    ///
    /// The CID is the SHA-256 hash of the CBOR serialization of this
    /// `SignedConfig`. Two envelopes are identical if and only if their
    /// CIDs match.
    pub fn cid(&self) -> [u8; 32] {
        sha256_hash(&self.to_cbor())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_config::{NetworkConfig, NodeConfig, SCHEMA_VERSION};
    use harmony_identity::PqPrivateIdentity;
    use rand::rngs::OsRng;

    fn sample_config() -> NodeConfig {
        NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [1u8; 32],
            identity: [2u8; 32],
            network: NetworkConfig {
                mesh_seeds: alloc::vec![[0xAB; 16]],
                port: 7777,
            },
            services: alloc::vec![],
        }
    }

    fn sign_config(config: &NodeConfig, signer: &PqPrivateIdentity) -> SignedConfig {
        let config_bytes = config.to_cbor();
        let signature = signer.sign(&config_bytes).expect("signing should succeed");
        let pub_id = signer.public_identity();
        SignedConfig {
            config_bytes,
            signature,
            signer: pub_id.address_hash,
            signer_pubkey: pub_id.to_public_bytes(),
        }
    }

    #[test]
    fn valid_signature_accepted() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let signed = sign_config(&config, &signer);
        let trusted = [signer.public_identity().address_hash];
        assert!(signed.verify(&trusted).is_ok());
    }

    #[test]
    fn tampered_bytes_rejected() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let mut signed = sign_config(&config, &signer);

        // Flip a byte in config_bytes to invalidate the signature.
        signed.config_bytes[0] ^= 0xFF;

        let trusted = [signer.public_identity().address_hash];
        assert!(matches!(
            signed.verify(&trusted),
            Err(SignedConfigError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn wrong_signer_address_rejected() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let mut signed = sign_config(&config, &signer);

        // Set signer to an address that doesn't match the pubkey.
        signed.signer = [0xFF; 16];

        let trusted = [[0xFF; 16]];
        assert!(matches!(
            signed.verify(&trusted),
            Err(SignedConfigError::AddressMismatch)
        ));
    }

    #[test]
    fn untrusted_signer_rejected() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let signed = sign_config(&config, &signer);

        // Empty trusted list — signer is not trusted.
        assert!(matches!(
            signed.verify(&[]),
            Err(SignedConfigError::UntrustedSigner)
        ));
    }

    #[test]
    fn invalid_pubkey_bytes_rejected() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let mut signed = sign_config(&config, &signer);

        // Replace pubkey with garbage bytes.
        signed.signer_pubkey = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];

        let trusted = [signer.public_identity().address_hash];
        assert!(matches!(
            signed.verify(&trusted),
            Err(SignedConfigError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn cbor_round_trip() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let signed = sign_config(&config, &signer);

        let cbor = signed.to_cbor();
        let restored = SignedConfig::from_cbor(&cbor).expect("CBOR round-trip must succeed");

        assert_eq!(restored.config_bytes, signed.config_bytes);
        assert_eq!(restored.signature, signed.signature);
        assert_eq!(restored.signer, signed.signer);
        assert_eq!(restored.signer_pubkey, signed.signer_pubkey);
    }

    #[test]
    fn cid_is_sha256_of_cbor() {
        let signer = PqPrivateIdentity::generate(&mut OsRng);
        let config = sample_config();
        let signed = sign_config(&config, &signer);

        let expected = sha256_hash(&signed.to_cbor());
        assert_eq!(signed.cid(), expected);
    }
}
