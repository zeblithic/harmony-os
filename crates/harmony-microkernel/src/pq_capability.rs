// SPDX-License-Identifier: GPL-2.0-or-later

//! Post-quantum UCAN capability verification for the microkernel.
//!
//! Mirrors the classical `verify_token()` + resolver/store infrastructure from
//! `harmony-identity` but for ML-DSA-65 signed `PqUcanToken`s.

use alloc::collections::BTreeMap;
use harmony_identity::{PqIdentity, PqUcanToken, RevocationSet, UcanError};

/// Resolves PQ identities by their 16-byte address hash.
pub trait PqIdentityResolver {
    /// Look up a post-quantum identity by its address hash.
    fn resolve(&self, address_hash: &[u8; 16]) -> Option<&PqIdentity>;
}

/// Resolves PQ UCAN tokens by their 32-byte BLAKE3 content hash.
pub trait PqProofResolver {
    /// Look up a PQ UCAN token by its content hash.
    fn resolve(&self, proof_hash: &[u8; 32]) -> Option<&PqUcanToken>;
}

/// In-memory store of `PqIdentity` values keyed by address hash.
#[derive(Debug, Default)]
pub struct PqMemoryIdentityStore {
    identities: BTreeMap<[u8; 16], PqIdentity>,
}

impl PqMemoryIdentityStore {
    /// Create a new empty identity store.
    pub fn new() -> Self {
        Self {
            identities: BTreeMap::new(),
        }
    }

    /// Insert a PQ identity, keyed by its address hash.
    pub fn insert(&mut self, identity: PqIdentity) {
        self.identities.insert(identity.address_hash, identity);
    }
}

impl PqIdentityResolver for PqMemoryIdentityStore {
    fn resolve(&self, address_hash: &[u8; 16]) -> Option<&PqIdentity> {
        self.identities.get(address_hash)
    }
}

/// In-memory store of `PqUcanToken` values keyed by BLAKE3 content hash.
#[derive(Debug, Default)]
pub struct PqMemoryProofStore {
    tokens: BTreeMap<[u8; 32], PqUcanToken>,
}

impl PqMemoryProofStore {
    /// Create a new empty proof store.
    pub fn new() -> Self {
        Self {
            tokens: BTreeMap::new(),
        }
    }

    /// Insert a PQ UCAN token, keyed by its content hash.
    pub fn insert(&mut self, token: PqUcanToken) {
        let hash = token.content_hash();
        self.tokens.insert(hash, token);
    }
}

impl PqProofResolver for PqMemoryProofStore {
    fn resolve(&self, proof_hash: &[u8; 32]) -> Option<&PqUcanToken> {
        self.tokens.get(proof_hash)
    }
}

/// Verify a post-quantum UCAN token and its delegation chain.
///
/// Fully sans-I/O: the caller provides current time, proof resolution,
/// identity lookup, and revocation state.
pub fn verify_pq_token(
    token: &PqUcanToken,
    now: u64,
    proofs: &impl PqProofResolver,
    identities: &impl PqIdentityResolver,
    revocations: &impl RevocationSet,
    max_depth: usize,
) -> Result<(), UcanError> {
    verify_pq_token_recursive(
        token,
        now,
        proofs,
        identities,
        revocations,
        max_depth,
        0,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_pq_token_recursive(
    token: &PqUcanToken,
    now: u64,
    proofs: &impl PqProofResolver,
    identities: &impl PqIdentityResolver,
    revocations: &impl RevocationSet,
    max_depth: usize,
    current_depth: usize,
    expected_hash: Option<&[u8; 32]>,
) -> Result<(), UcanError> {
    if token.not_before > now {
        return Err(UcanError::NotYetValid);
    }
    if token.expires_at != 0 && now > token.expires_at {
        return Err(UcanError::Expired);
    }

    let token_hash = token.content_hash();

    if let Some(expected) = expected_hash {
        if token_hash != *expected {
            return Err(UcanError::ChainBroken);
        }
    }

    if revocations.is_revoked(&token_hash) {
        return Err(UcanError::Revoked);
    }

    let issuer = identities
        .resolve(&token.issuer)
        .ok_or(UcanError::IssuerNotFound)?;
    token.verify_signature(&issuer.verifying_key)?;

    if let Some(parent_hash) = &token.proof {
        if current_depth >= max_depth {
            return Err(UcanError::ChainTooDeep {
                depth: current_depth,
                limit: max_depth,
            });
        }

        let parent = proofs
            .resolve(parent_hash)
            .ok_or(UcanError::ProofNotFound)?;

        if parent.audience != token.issuer {
            return Err(UcanError::ChainBroken);
        }

        if parent.capability != token.capability {
            return Err(UcanError::CapabilityMismatch);
        }

        if token.not_before < parent.not_before {
            return Err(UcanError::AttenuationViolation);
        }
        if parent.expires_at != 0 && (token.expires_at == 0 || token.expires_at > parent.expires_at)
        {
            return Err(UcanError::AttenuationViolation);
        }

        verify_pq_token_recursive(
            parent,
            now,
            proofs,
            identities,
            revocations,
            max_depth,
            current_depth + 1,
            Some(parent_hash),
        )?;
    }

    Ok(())
}
