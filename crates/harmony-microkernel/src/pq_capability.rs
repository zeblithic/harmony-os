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

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_identity::{CapabilityType, MemoryRevocationSet, PqPrivateIdentity};
    use harmony_unikernel::KernelEntropy;

    fn test_rng() -> KernelEntropy<impl FnMut(&mut [u8])> {
        let mut seed = 42u64;
        KernelEntropy::new(move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
        })
    }

    fn issue(
        rng: &mut impl rand_core::CryptoRngCore,
        issuer: &PqPrivateIdentity,
        audience: &[u8; 16],
        cap: CapabilityType,
        resource: &[u8],
        not_before: u64,
        expires_at: u64,
    ) -> PqUcanToken {
        issuer
            .issue_pq_root_token(rng, audience, cap, resource, not_before, expires_at)
            .unwrap()
    }

    fn setup_stores(issuer: &PqPrivateIdentity) -> (PqMemoryIdentityStore, PqMemoryProofStore) {
        let mut ids = PqMemoryIdentityStore::new();
        ids.insert(issuer.public_identity().clone());
        (ids, PqMemoryProofStore::new())
    }

    #[test]
    fn valid_root_token_passes() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let token = issue(
            &mut rng,
            &issuer,
            &[0xAA; 16],
            CapabilityType::Endpoint,
            b"pid:1",
            0,
            0,
        );
        let (ids, proofs) = setup_stores(&issuer);
        let revocations = MemoryRevocationSet::new();
        assert!(verify_pq_token(&token, 100, &proofs, &ids, &revocations, 5).is_ok());
    }

    #[test]
    fn expired_token_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let token = issue(
            &mut rng,
            &issuer,
            &[0xAA; 16],
            CapabilityType::Endpoint,
            b"x",
            0,
            50,
        );
        let (ids, proofs) = setup_stores(&issuer);
        let revocations = MemoryRevocationSet::new();
        assert!(matches!(
            verify_pq_token(&token, 100, &proofs, &ids, &revocations, 5),
            Err(UcanError::Expired)
        ));
    }

    #[test]
    fn not_yet_valid_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let token = issue(
            &mut rng,
            &issuer,
            &[0xAA; 16],
            CapabilityType::Endpoint,
            b"x",
            200,
            0,
        );
        let (ids, proofs) = setup_stores(&issuer);
        let revocations = MemoryRevocationSet::new();
        assert!(matches!(
            verify_pq_token(&token, 100, &proofs, &ids, &revocations, 5),
            Err(UcanError::NotYetValid)
        ));
    }

    #[test]
    fn issuer_not_found_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let token = issue(
            &mut rng,
            &issuer,
            &[0xAA; 16],
            CapabilityType::Endpoint,
            b"x",
            0,
            0,
        );
        // Empty identity store — issuer is unknown.
        let ids = PqMemoryIdentityStore::new();
        let proofs = PqMemoryProofStore::new();
        let revocations = MemoryRevocationSet::new();
        assert!(matches!(
            verify_pq_token(&token, 100, &proofs, &ids, &revocations, 5),
            Err(UcanError::IssuerNotFound)
        ));
    }

    #[test]
    fn wrong_signer_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let wrong = PqPrivateIdentity::generate(&mut rng);
        // Token signed by `issuer`, but store only has `wrong`'s identity
        // registered under issuer's address hash — signature won't match.
        let token = issue(
            &mut rng,
            &issuer,
            &[0xAA; 16],
            CapabilityType::Endpoint,
            b"x",
            0,
            0,
        );
        let mut ids = PqMemoryIdentityStore::new();
        ids.insert(wrong.public_identity().clone());
        let proofs = PqMemoryProofStore::new();
        let revocations = MemoryRevocationSet::new();
        // Issuer address hash won't be found (wrong identity has different hash).
        assert!(verify_pq_token(&token, 100, &proofs, &ids, &revocations, 5).is_err());
    }

    #[test]
    fn revoked_token_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let token = issue(
            &mut rng,
            &issuer,
            &[0xAA; 16],
            CapabilityType::Endpoint,
            b"x",
            0,
            0,
        );
        let (ids, proofs) = setup_stores(&issuer);
        let mut revocations = MemoryRevocationSet::new();
        revocations.insert(token.content_hash());
        assert!(matches!(
            verify_pq_token(&token, 100, &proofs, &ids, &revocations, 5),
            Err(UcanError::Revoked)
        ));
    }

    #[test]
    fn chain_too_deep_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let delegate = PqPrivateIdentity::generate(&mut rng);
        let delegate_addr = delegate.public_identity().address_hash;

        let parent = issue(
            &mut rng,
            &issuer,
            &delegate_addr,
            CapabilityType::Endpoint,
            b"pid:1",
            0,
            0,
        );

        let mut child = PqUcanToken {
            issuer: delegate.public_identity().address_hash,
            audience: [0xBB; 16],
            capability: CapabilityType::Endpoint,
            resource: b"pid:1".to_vec(),
            not_before: 0,
            expires_at: 0,
            nonce: [0u8; 16],
            proof: Some(parent.content_hash()),
            signature: alloc::vec![],
        };
        let signable = child.signable_bytes();
        child.signature = delegate.sign(&signable).unwrap();

        let mut ids = PqMemoryIdentityStore::new();
        ids.insert(issuer.public_identity().clone());
        ids.insert(delegate.public_identity().clone());
        let mut proofs = PqMemoryProofStore::new();
        proofs.insert(parent);
        let revocations = MemoryRevocationSet::new();

        // max_depth=0 means root only — no delegation allowed.
        assert!(matches!(
            verify_pq_token(&child, 100, &proofs, &ids, &revocations, 0),
            Err(UcanError::ChainTooDeep { depth: 0, limit: 0 })
        ));
    }

    #[test]
    fn chain_broken_audience_mismatch_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let delegate = PqPrivateIdentity::generate(&mut rng);

        // Parent is issued to [0xFF; 16], not to delegate's address.
        let parent = issue(
            &mut rng,
            &issuer,
            &[0xFF; 16],
            CapabilityType::Endpoint,
            b"pid:1",
            0,
            0,
        );

        let mut child = PqUcanToken {
            issuer: delegate.public_identity().address_hash,
            audience: [0xBB; 16],
            capability: CapabilityType::Endpoint,
            resource: b"pid:1".to_vec(),
            not_before: 0,
            expires_at: 0,
            nonce: [0u8; 16],
            proof: Some(parent.content_hash()),
            signature: alloc::vec![],
        };
        let signable = child.signable_bytes();
        child.signature = delegate.sign(&signable).unwrap();

        let mut ids = PqMemoryIdentityStore::new();
        ids.insert(issuer.public_identity().clone());
        ids.insert(delegate.public_identity().clone());
        let mut proofs = PqMemoryProofStore::new();
        proofs.insert(parent);
        let revocations = MemoryRevocationSet::new();

        assert!(matches!(
            verify_pq_token(&child, 100, &proofs, &ids, &revocations, 5),
            Err(UcanError::ChainBroken)
        ));
    }

    #[test]
    fn capability_mismatch_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let delegate = PqPrivateIdentity::generate(&mut rng);
        let delegate_addr = delegate.public_identity().address_hash;

        // Parent grants Memory, child claims Endpoint.
        let parent = issue(
            &mut rng,
            &issuer,
            &delegate_addr,
            CapabilityType::Memory,
            b"x",
            0,
            0,
        );

        let mut child = PqUcanToken {
            issuer: delegate_addr,
            audience: [0xBB; 16],
            capability: CapabilityType::Endpoint,
            resource: b"x".to_vec(),
            not_before: 0,
            expires_at: 0,
            nonce: [0u8; 16],
            proof: Some(parent.content_hash()),
            signature: alloc::vec![],
        };
        let signable = child.signable_bytes();
        child.signature = delegate.sign(&signable).unwrap();

        let mut ids = PqMemoryIdentityStore::new();
        ids.insert(issuer.public_identity().clone());
        ids.insert(delegate.public_identity().clone());
        let mut proofs = PqMemoryProofStore::new();
        proofs.insert(parent);
        let revocations = MemoryRevocationSet::new();

        assert!(matches!(
            verify_pq_token(&child, 100, &proofs, &ids, &revocations, 5),
            Err(UcanError::CapabilityMismatch)
        ));
    }

    #[test]
    fn attenuation_violation_loosened_not_before_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let delegate = PqPrivateIdentity::generate(&mut rng);
        let delegate_addr = delegate.public_identity().address_hash;

        // Parent: not_before=100.
        let parent = issue(
            &mut rng,
            &issuer,
            &delegate_addr,
            CapabilityType::Endpoint,
            b"x",
            100,
            0,
        );

        // Child: not_before=50 (earlier than parent — loosens the constraint).
        let mut child = PqUcanToken {
            issuer: delegate_addr,
            audience: [0xBB; 16],
            capability: CapabilityType::Endpoint,
            resource: b"x".to_vec(),
            not_before: 50,
            expires_at: 0,
            nonce: [0u8; 16],
            proof: Some(parent.content_hash()),
            signature: alloc::vec![],
        };
        let signable = child.signable_bytes();
        child.signature = delegate.sign(&signable).unwrap();

        let mut ids = PqMemoryIdentityStore::new();
        ids.insert(issuer.public_identity().clone());
        ids.insert(delegate.public_identity().clone());
        let mut proofs = PqMemoryProofStore::new();
        proofs.insert(parent);
        let revocations = MemoryRevocationSet::new();

        assert!(matches!(
            verify_pq_token(&child, 200, &proofs, &ids, &revocations, 5),
            Err(UcanError::AttenuationViolation)
        ));
    }

    #[test]
    fn attenuation_violation_loosened_expiry_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let delegate = PqPrivateIdentity::generate(&mut rng);
        let delegate_addr = delegate.public_identity().address_hash;

        // Parent: expires_at=500.
        let parent = issue(
            &mut rng,
            &issuer,
            &delegate_addr,
            CapabilityType::Endpoint,
            b"x",
            0,
            500,
        );

        // Child: expires_at=1000 (later than parent — loosens the constraint).
        let mut child = PqUcanToken {
            issuer: delegate_addr,
            audience: [0xBB; 16],
            capability: CapabilityType::Endpoint,
            resource: b"x".to_vec(),
            not_before: 0,
            expires_at: 1000,
            nonce: [0u8; 16],
            proof: Some(parent.content_hash()),
            signature: alloc::vec![],
        };
        let signable = child.signable_bytes();
        child.signature = delegate.sign(&signable).unwrap();

        let mut ids = PqMemoryIdentityStore::new();
        ids.insert(issuer.public_identity().clone());
        ids.insert(delegate.public_identity().clone());
        let mut proofs = PqMemoryProofStore::new();
        proofs.insert(parent);
        let revocations = MemoryRevocationSet::new();

        assert!(matches!(
            verify_pq_token(&child, 100, &proofs, &ids, &revocations, 5),
            Err(UcanError::AttenuationViolation)
        ));
    }

    #[test]
    fn proof_not_found_rejected() {
        let mut rng = test_rng();
        let issuer = PqPrivateIdentity::generate(&mut rng);
        let delegate = PqPrivateIdentity::generate(&mut rng);

        // Child references a proof hash that doesn't exist in the store.
        let mut child = PqUcanToken {
            issuer: delegate.public_identity().address_hash,
            audience: [0xBB; 16],
            capability: CapabilityType::Endpoint,
            resource: b"x".to_vec(),
            not_before: 0,
            expires_at: 0,
            nonce: [0u8; 16],
            proof: Some([0xDE; 32]),
            signature: alloc::vec![],
        };
        let signable = child.signable_bytes();
        child.signature = delegate.sign(&signable).unwrap();

        let mut ids = PqMemoryIdentityStore::new();
        ids.insert(issuer.public_identity().clone());
        ids.insert(delegate.public_identity().clone());
        let proofs = PqMemoryProofStore::new(); // empty
        let revocations = MemoryRevocationSet::new();

        assert!(matches!(
            verify_pq_token(&child, 100, &proofs, &ids, &revocations, 5),
            Err(UcanError::ProofNotFound)
        ));
    }

    #[test]
    fn valid_delegation_chain_passes() {
        let mut rng = test_rng();
        let root = PqPrivateIdentity::generate(&mut rng);
        let delegate = PqPrivateIdentity::generate(&mut rng);
        let delegate_addr = delegate.public_identity().address_hash;

        let parent = issue(
            &mut rng,
            &root,
            &delegate_addr,
            CapabilityType::Endpoint,
            b"pid:1",
            0,
            0,
        );

        let mut child = PqUcanToken {
            issuer: delegate_addr,
            audience: [0xBB; 16],
            capability: CapabilityType::Endpoint,
            resource: b"pid:1".to_vec(),
            not_before: 0,
            expires_at: 0,
            nonce: [0u8; 16],
            proof: Some(parent.content_hash()),
            signature: alloc::vec![],
        };
        let signable = child.signable_bytes();
        child.signature = delegate.sign(&signable).unwrap();

        let mut ids = PqMemoryIdentityStore::new();
        ids.insert(root.public_identity().clone());
        ids.insert(delegate.public_identity().clone());
        let mut proofs = PqMemoryProofStore::new();
        proofs.insert(parent);
        let revocations = MemoryRevocationSet::new();

        assert!(verify_pq_token(&child, 100, &proofs, &ids, &revocations, 5).is_ok());
    }
}
