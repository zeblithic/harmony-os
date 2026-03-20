// SPDX-License-Identifier: GPL-2.0-or-later

//! Post-quantum key hierarchy — mutual attestation, session bindings,
//! and bound capability verification for the microkernel.
//!
//! Implements the four-tier key hierarchy:
//! - **Owner** — accountability root, claims hardware, delegates to users
//! - **Hardware** — platform identity, mutually attested with owner
//! - **Session** — ephemeral per-boot, signs session bindings
//! - **User** — long-lived, authority delegated from owner
//!
//! The owner and hardware tiers use mutual attestation (`OwnerClaim` +
//! `HardwareAcceptance`). User authority is activated per-session via
//! `SessionBinding`, tying a UCAN token to a specific session key and
//! hardware identity.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use harmony_crypto::hash::blake3_hash;
use harmony_identity::{IdentityError, PqIdentity, PqUcanToken};

/// ML-DSA-65 signature length (FIPS 204).
const SIG_LENGTH: usize = 3309;

// ── Error types ──────────────────────────────────────────────────────

/// Errors produced by attestation verification.
#[derive(Debug)]
pub enum AttestationError {
    /// The owner claim's `owner_address` does not match the supplied public key.
    OwnerAddressMismatch,
    /// The owner claim's `hardware_address` does not match the supplied public key.
    HardwareAddressMismatch,
    /// The hardware acceptance's `owner_address` does not match the owner public key.
    AcceptanceOwnerMismatch,
    /// The hardware acceptance's `hardware_address` does not match the hardware public key.
    AcceptanceHardwareMismatch,
    /// The `owner_claim_hash` in the acceptance does not match the computed hash.
    ClaimHashMismatch,
    /// An ML-DSA-65 signature failed verification.
    SignatureInvalid(IdentityError),
    /// The hardware acceptance timestamp predates the owner claim.
    TemporalIncoherence,
}

/// Errors produced by session binding verification.
#[derive(Debug)]
pub enum BindingError {
    /// The binding's `session_address` does not match the session public key.
    SessionAddressMismatch,
    /// The binding's `hardware_address` does not match the expected value.
    HardwareAddressMismatch,
    /// The binding's `user_token_hash` does not match the expected token hash.
    TokenHashMismatch,
    /// The binding's nonce has already been used in this session.
    NonceReplay,
    /// An ML-DSA-65 signature failed verification.
    SignatureInvalid(IdentityError),
}

// ── Attestation types ────────────────────────────────────────────────

/// An owner's claim over a hardware identity.
///
/// Signed by the owner's ML-DSA-65 key. The `signature` field covers
/// all other fields in big-endian wire order via `signable_bytes()`.
#[derive(Clone)]
pub struct OwnerClaim {
    /// Owner's PQ address hash.
    pub owner_address: [u8; 16],
    /// Hardware identity's PQ address hash.
    pub hardware_address: [u8; 16],
    /// When the claim was made (Unix timestamp, seconds).
    pub claimed_at: u64,
    /// Owner index (0 = primary). Reserved for future multi-owner extension.
    pub owner_index: u32,
    /// Random nonce for uniqueness — ensures each `OwnerClaim` produces a
    /// distinct signed byte sequence even when the same owner/hardware pair
    /// re-attests. Not tracked at verification time; replay protection is
    /// provided by the `HardwareAcceptance::owner_claim_hash` binding.
    pub nonce: [u8; 16],
    /// ML-DSA-65 signature by the owner over the signable fields.
    pub signature: [u8; SIG_LENGTH],
}

/// Hardware's acceptance of an owner claim.
///
/// Signed by the hardware's ML-DSA-65 key. Binds to a specific
/// `OwnerClaim` via `owner_claim_hash`.
#[derive(Clone)]
pub struct HardwareAcceptance {
    /// Hardware identity's PQ address hash.
    pub hardware_address: [u8; 16],
    /// Owner's PQ address hash.
    pub owner_address: [u8; 16],
    /// When the acceptance was recorded (Unix timestamp, seconds).
    pub accepted_at: u64,
    /// BLAKE3 hash of the corresponding `OwnerClaim` (binds to specific claim).
    pub owner_claim_hash: [u8; 32],
    /// ML-DSA-65 signature by the hardware over the signable fields.
    pub signature: [u8; SIG_LENGTH],
}

/// A paired owner claim and hardware acceptance — mutual attestation.
#[derive(Clone)]
pub struct AttestationPair {
    /// The owner's claim over this hardware.
    pub owner_claim: OwnerClaim,
    /// The hardware's acceptance of the owner.
    pub hardware_acceptance: HardwareAcceptance,
}

/// A session binding that activates user authority for one boot cycle.
///
/// Signed by the session key (ephemeral, generated at boot). Ties a
/// specific UCAN token to this session and hardware identity.
#[derive(Clone)]
pub struct SessionBinding {
    /// This boot's session key address hash.
    pub session_address: [u8; 16],
    /// User being activated.
    pub user_address: [u8; 16],
    /// BLAKE3 hash of the user's UCAN from Chain 2.
    pub user_token_hash: [u8; 32],
    /// Hardware this session runs on (ties binding to specific node).
    pub hardware_address: [u8; 16],
    /// When the binding was created (Unix timestamp, seconds).
    pub bound_at: u64,
    /// Random nonce for intra-session replay protection.
    pub nonce: [u8; 16],
    /// ML-DSA-65 signature by the session key.
    pub signature: [u8; SIG_LENGTH],
}

/// A user-submitted capability: a UCAN token paired with a session binding.
#[derive(Clone)]
pub struct BoundCapability {
    /// Owner -> User UCAN (Chain 2).
    pub token: PqUcanToken,
    /// Session activation (Chain 3).
    pub binding: SessionBinding,
}

// ── Signable bytes ───────────────────────────────────────────────────

impl OwnerClaim {
    /// Return the signable portion of the claim (all fields except `signature`).
    ///
    /// Wire format: `[16B owner_address][16B hardware_address][8B claimed_at][4B owner_index][16B nonce]`
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + 16 + 8 + 4 + 16);
        buf.extend_from_slice(&self.owner_address);
        buf.extend_from_slice(&self.hardware_address);
        buf.extend_from_slice(&self.claimed_at.to_be_bytes());
        buf.extend_from_slice(&self.owner_index.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf
    }

    /// Compute the BLAKE3 content hash of this claim (signable bytes + signature).
    ///
    /// This is the value stored in `HardwareAcceptance::owner_claim_hash` to
    /// bind the acceptance to a specific claim.
    pub fn content_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(60 + SIG_LENGTH);
        buf.extend_from_slice(&self.signable_bytes());
        buf.extend_from_slice(&self.signature);
        blake3_hash(&buf)
    }
}

impl HardwareAcceptance {
    /// Return the signable portion of the acceptance (all fields except `signature`).
    ///
    /// Wire format: `[16B hardware_address][16B owner_address][8B accepted_at][32B owner_claim_hash]`
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + 16 + 8 + 32);
        buf.extend_from_slice(&self.hardware_address);
        buf.extend_from_slice(&self.owner_address);
        buf.extend_from_slice(&self.accepted_at.to_be_bytes());
        buf.extend_from_slice(&self.owner_claim_hash);
        buf
    }
}

impl SessionBinding {
    /// Return the signable portion of the binding (all fields except `signature`).
    ///
    /// Wire format: `[16B session_address][16B user_address][32B user_token_hash][16B hardware_address][8B bound_at][16B nonce]`
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + 16 + 32 + 16 + 8 + 16);
        buf.extend_from_slice(&self.session_address);
        buf.extend_from_slice(&self.user_address);
        buf.extend_from_slice(&self.user_token_hash);
        buf.extend_from_slice(&self.hardware_address);
        buf.extend_from_slice(&self.bound_at.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf
    }
}

// ── Verification functions ───────────────────────────────────────────

/// Verify a mutual attestation pair.
///
/// Checks both directions: the owner's claim over the hardware and
/// the hardware's acceptance of the owner. Both signatures must be
/// valid, and the acceptance must reference the exact claim via
/// its BLAKE3 content hash.
pub fn verify_attestation(
    pair: &AttestationPair,
    owner_pubkey: &PqIdentity,
    hardware_pubkey: &PqIdentity,
) -> Result<(), AttestationError> {
    let claim = &pair.owner_claim;
    let acceptance = &pair.hardware_acceptance;

    // 1. Owner claim addresses match the supplied public keys.
    if claim.owner_address != owner_pubkey.address_hash {
        return Err(AttestationError::OwnerAddressMismatch);
    }
    if claim.hardware_address != hardware_pubkey.address_hash {
        return Err(AttestationError::HardwareAddressMismatch);
    }

    // 2. Owner's signature over the claim.
    owner_pubkey
        .verify(&claim.signable_bytes(), &claim.signature)
        .map_err(AttestationError::SignatureInvalid)?;

    // 3. Acceptance's claim hash matches the actual claim.
    if acceptance.owner_claim_hash != claim.content_hash() {
        return Err(AttestationError::ClaimHashMismatch);
    }

    // 4. Acceptance addresses match the supplied public keys.
    if acceptance.hardware_address != hardware_pubkey.address_hash {
        return Err(AttestationError::AcceptanceHardwareMismatch);
    }
    if acceptance.owner_address != owner_pubkey.address_hash {
        return Err(AttestationError::AcceptanceOwnerMismatch);
    }

    // 5. Hardware's signature over the acceptance.
    hardware_pubkey
        .verify(&acceptance.signable_bytes(), &acceptance.signature)
        .map_err(AttestationError::SignatureInvalid)?;

    // 6. Temporal coherence: acceptance cannot predate its claim.
    if acceptance.accepted_at < claim.claimed_at {
        return Err(AttestationError::TemporalIncoherence);
    }

    Ok(())
}

/// Verify a session binding against the current session key.
///
/// This is NOT a UCAN token — it has its own verification path.
/// The session public key is available directly from the kernel's
/// `session_identity` field (no identity store lookup needed).
pub fn verify_session_binding(
    binding: &SessionBinding,
    session_pubkey: &PqIdentity,
    hardware_address: &[u8; 16],
    token_hash: &[u8; 32],
    used_nonces: &BTreeSet<[u8; 16]>,
) -> Result<(), BindingError> {
    // 1. Session address matches the session public key.
    if binding.session_address != session_pubkey.address_hash {
        return Err(BindingError::SessionAddressMismatch);
    }

    // 2. Hardware address matches this node.
    if binding.hardware_address != *hardware_address {
        return Err(BindingError::HardwareAddressMismatch);
    }

    // 3. Token hash matches the presented UCAN.
    if binding.user_token_hash != *token_hash {
        return Err(BindingError::TokenHashMismatch);
    }

    // 4. Nonce has not been used in this session.
    if used_nonces.contains(&binding.nonce) {
        return Err(BindingError::NonceReplay);
    }

    // 5. Session key's signature over the binding.
    session_pubkey
        .verify(&binding.signable_bytes(), &binding.signature)
        .map_err(BindingError::SignatureInvalid)?;

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_identity::{CapabilityType, MemoryRevocationSet, PqPrivateIdentity};
    use harmony_unikernel::KernelEntropy;

    use crate::pq_capability::{verify_pq_token, PqMemoryIdentityStore, PqMemoryProofStore};

    fn test_rng() -> KernelEntropy<impl FnMut(&mut [u8])> {
        let mut seed = 42u64;
        KernelEntropy::new(move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
        })
    }

    /// Helper: sign `signable_bytes` with a private identity and copy into a
    /// fixed-size `[u8; 3309]` signature array.
    fn sign_fixed(identity: &PqPrivateIdentity, message: &[u8]) -> [u8; SIG_LENGTH] {
        let sig_vec = identity.sign(message).unwrap();
        let mut sig = [0u8; SIG_LENGTH];
        sig.copy_from_slice(&sig_vec);
        sig
    }

    /// Helper: create an `OwnerClaim` signed by the owner.
    fn make_owner_claim(
        owner: &PqPrivateIdentity,
        hardware_addr: &[u8; 16],
        nonce: [u8; 16],
    ) -> OwnerClaim {
        let mut claim = OwnerClaim {
            owner_address: owner.public_identity().address_hash,
            hardware_address: *hardware_addr,
            claimed_at: 1000,
            owner_index: 0,
            nonce,
            signature: [0u8; SIG_LENGTH],
        };
        claim.signature = sign_fixed(owner, &claim.signable_bytes());
        claim
    }

    /// Helper: create a `HardwareAcceptance` signed by the hardware identity,
    /// referencing a specific `OwnerClaim`.
    fn make_hardware_acceptance(
        hardware: &PqPrivateIdentity,
        owner_addr: &[u8; 16],
        claim: &OwnerClaim,
    ) -> HardwareAcceptance {
        let mut acceptance = HardwareAcceptance {
            hardware_address: hardware.public_identity().address_hash,
            owner_address: *owner_addr,
            accepted_at: 1001,
            owner_claim_hash: claim.content_hash(),
            signature: [0u8; SIG_LENGTH],
        };
        acceptance.signature = sign_fixed(hardware, &acceptance.signable_bytes());
        acceptance
    }

    /// Helper: create a valid `AttestationPair`.
    fn make_attestation(
        owner: &PqPrivateIdentity,
        hardware: &PqPrivateIdentity,
    ) -> AttestationPair {
        let hw_addr = hardware.public_identity().address_hash;
        let owner_addr = owner.public_identity().address_hash;
        let claim = make_owner_claim(owner, &hw_addr, [0xAA; 16]);
        let acceptance = make_hardware_acceptance(hardware, &owner_addr, &claim);
        AttestationPair {
            owner_claim: claim,
            hardware_acceptance: acceptance,
        }
    }

    /// Helper: create a `SessionBinding` signed by the session key.
    fn make_session_binding(
        session: &PqPrivateIdentity,
        user_addr: &[u8; 16],
        token_hash: &[u8; 32],
        hardware_addr: &[u8; 16],
        nonce: [u8; 16],
    ) -> SessionBinding {
        let mut binding = SessionBinding {
            session_address: session.public_identity().address_hash,
            user_address: *user_addr,
            user_token_hash: *token_hash,
            hardware_address: *hardware_addr,
            bound_at: 2000,
            nonce,
            signature: [0u8; SIG_LENGTH],
        };
        binding.signature = sign_fixed(session, &binding.signable_bytes());
        binding
    }

    // ── Attestation tests ────────────────────────────────────────────

    #[test]
    fn valid_attestation_passes() {
        let mut rng = test_rng();
        let owner = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);

        let pair = make_attestation(&owner, &hardware);
        let result = verify_attestation(&pair, owner.public_identity(), hardware.public_identity());
        assert!(result.is_ok());
    }

    #[test]
    fn attestation_wrong_owner_signer_rejected() {
        let mut rng = test_rng();
        let owner = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);
        let wrong_owner = PqPrivateIdentity::generate(&mut rng);

        // Claim is signed by `owner` but we verify against `wrong_owner`.
        let pair = make_attestation(&owner, &hardware);
        let result = verify_attestation(
            &pair,
            wrong_owner.public_identity(),
            hardware.public_identity(),
        );
        assert!(matches!(
            result,
            Err(AttestationError::OwnerAddressMismatch)
        ));
    }

    #[test]
    fn attestation_wrong_hardware_signer_rejected() {
        let mut rng = test_rng();
        let owner = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);
        let wrong_hardware = PqPrivateIdentity::generate(&mut rng);

        // Build a claim that references the REAL hardware address,
        // and an acceptance signed by wrong_hardware but with the
        // real hardware's address in the claim.
        let pair = make_attestation(&owner, &hardware);

        // Verify with wrong hardware pubkey — address won't match the claim.
        let result = verify_attestation(
            &pair,
            owner.public_identity(),
            wrong_hardware.public_identity(),
        );
        assert!(matches!(
            result,
            Err(AttestationError::HardwareAddressMismatch)
        ));
    }

    #[test]
    fn attestation_mismatched_addresses_rejected() {
        let mut rng = test_rng();
        let owner = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);
        let other_hardware = PqPrivateIdentity::generate(&mut rng);

        // Owner claims one hardware, but acceptance is from a different hardware.
        let claim = make_owner_claim(
            &owner,
            &other_hardware.public_identity().address_hash,
            [0xBB; 16],
        );
        let acceptance =
            make_hardware_acceptance(&hardware, &owner.public_identity().address_hash, &claim);
        let pair = AttestationPair {
            owner_claim: claim,
            hardware_acceptance: acceptance,
        };

        // The claim says hardware_address = other_hardware, but we pass hardware's pubkey.
        let result = verify_attestation(&pair, owner.public_identity(), hardware.public_identity());
        assert!(matches!(
            result,
            Err(AttestationError::HardwareAddressMismatch)
        ));
    }

    #[test]
    fn attestation_tampered_claim_hash_rejected() {
        let mut rng = test_rng();
        let owner = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);

        let mut pair = make_attestation(&owner, &hardware);

        // Tamper with the claim hash in the acceptance.
        pair.hardware_acceptance.owner_claim_hash[0] ^= 0xFF;
        // Re-sign the acceptance with the tampered hash.
        pair.hardware_acceptance.signature =
            sign_fixed(&hardware, &pair.hardware_acceptance.signable_bytes());

        let result = verify_attestation(&pair, owner.public_identity(), hardware.public_identity());
        assert!(matches!(result, Err(AttestationError::ClaimHashMismatch)));
    }

    #[test]
    fn session_binding_nonce_replay_rejected() {
        let mut rng = test_rng();
        let session = PqPrivateIdentity::generate(&mut rng);
        let user = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);

        let hw_addr = hardware.public_identity().address_hash;
        let user_addr = user.public_identity().address_hash;

        // Issue a UCAN from user -> some audience (just need a token hash).
        let token = user
            .issue_pq_root_token(
                &mut rng,
                &[0xCC; 16],
                CapabilityType::Endpoint,
                b"pid:1",
                0,
                0,
            )
            .unwrap();
        let token_hash = token.content_hash();

        let shared_nonce = [0x42; 16];

        let binding1 =
            make_session_binding(&session, &user_addr, &token_hash, &hw_addr, shared_nonce);
        let binding2 =
            make_session_binding(&session, &user_addr, &token_hash, &hw_addr, shared_nonce);

        let mut used_nonces = BTreeSet::new();

        // First binding passes.
        let result = verify_session_binding(
            &binding1,
            session.public_identity(),
            &hw_addr,
            &token_hash,
            &used_nonces,
        );
        assert!(result.is_ok());

        // Record the nonce.
        used_nonces.insert(binding1.nonce);

        // Second binding with the same nonce is rejected.
        let result = verify_session_binding(
            &binding2,
            session.public_identity(),
            &hw_addr,
            &token_hash,
            &used_nonces,
        );
        assert!(matches!(result, Err(BindingError::NonceReplay)));
    }

    // ── Session binding tests ────────────────────────────────────────

    #[test]
    fn valid_session_binding_passes() {
        let mut rng = test_rng();
        let session = PqPrivateIdentity::generate(&mut rng);
        let user = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);

        let hw_addr = hardware.public_identity().address_hash;
        let user_addr = user.public_identity().address_hash;
        let token_hash = [0xDD; 32];

        let binding = make_session_binding(&session, &user_addr, &token_hash, &hw_addr, [0x01; 16]);

        let used_nonces = BTreeSet::new();
        let result = verify_session_binding(
            &binding,
            session.public_identity(),
            &hw_addr,
            &token_hash,
            &used_nonces,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn session_binding_wrong_session_key_rejected() {
        let mut rng = test_rng();
        let session = PqPrivateIdentity::generate(&mut rng);
        let wrong_session = PqPrivateIdentity::generate(&mut rng);
        let user = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);

        let hw_addr = hardware.public_identity().address_hash;
        let user_addr = user.public_identity().address_hash;
        let token_hash = [0xDD; 32];

        // Binding signed by `session`, but verified against `wrong_session`.
        let binding = make_session_binding(&session, &user_addr, &token_hash, &hw_addr, [0x02; 16]);

        let used_nonces = BTreeSet::new();
        let result = verify_session_binding(
            &binding,
            wrong_session.public_identity(),
            &hw_addr,
            &token_hash,
            &used_nonces,
        );
        assert!(matches!(result, Err(BindingError::SessionAddressMismatch)));
    }

    #[test]
    fn session_binding_wrong_hardware_rejected() {
        let mut rng = test_rng();
        let session = PqPrivateIdentity::generate(&mut rng);
        let user = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);

        let hw_addr = hardware.public_identity().address_hash;
        let user_addr = user.public_identity().address_hash;
        let token_hash = [0xDD; 32];

        let binding = make_session_binding(&session, &user_addr, &token_hash, &hw_addr, [0x03; 16]);

        let wrong_hw_addr = [0xFF; 16];
        let used_nonces = BTreeSet::new();
        let result = verify_session_binding(
            &binding,
            session.public_identity(),
            &wrong_hw_addr,
            &token_hash,
            &used_nonces,
        );
        assert!(matches!(result, Err(BindingError::HardwareAddressMismatch)));
    }

    #[test]
    fn session_binding_wrong_token_hash_rejected() {
        let mut rng = test_rng();
        let session = PqPrivateIdentity::generate(&mut rng);
        let user = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);

        let hw_addr = hardware.public_identity().address_hash;
        let user_addr = user.public_identity().address_hash;
        let token_hash = [0xDD; 32];

        let binding = make_session_binding(&session, &user_addr, &token_hash, &hw_addr, [0x04; 16]);

        let wrong_hash = [0xEE; 32];
        let used_nonces = BTreeSet::new();
        let result = verify_session_binding(
            &binding,
            session.public_identity(),
            &hw_addr,
            &wrong_hash,
            &used_nonces,
        );
        assert!(matches!(result, Err(BindingError::TokenHashMismatch)));
    }

    #[test]
    fn session_binding_replayed_nonce_rejected() {
        let mut rng = test_rng();
        let session = PqPrivateIdentity::generate(&mut rng);
        let user = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);

        let hw_addr = hardware.public_identity().address_hash;
        let user_addr = user.public_identity().address_hash;
        let token_hash = [0xDD; 32];
        let nonce = [0x05; 16];

        let binding = make_session_binding(&session, &user_addr, &token_hash, &hw_addr, nonce);

        let mut used_nonces = BTreeSet::new();
        used_nonces.insert(nonce);

        let result = verify_session_binding(
            &binding,
            session.public_identity(),
            &hw_addr,
            &token_hash,
            &used_nonces,
        );
        assert!(matches!(result, Err(BindingError::NonceReplay)));
    }

    // ── Bound capability full chain test ─────────────────────────────

    #[test]
    fn bound_capability_full_chain_passes() {
        let mut rng = test_rng();
        let owner = PqPrivateIdentity::generate(&mut rng);
        let hardware = PqPrivateIdentity::generate(&mut rng);
        let session = PqPrivateIdentity::generate(&mut rng);
        let user = PqPrivateIdentity::generate(&mut rng);

        let hw_addr = hardware.public_identity().address_hash;
        let user_addr = user.public_identity().address_hash;

        // Chain 1: mutual attestation.
        let attestation = make_attestation(&owner, &hardware);
        assert!(verify_attestation(
            &attestation,
            owner.public_identity(),
            hardware.public_identity(),
        )
        .is_ok());

        // Chain 2: owner delegates to user via UCAN.
        let user_token = owner
            .issue_pq_root_token(
                &mut rng,
                &user_addr,
                CapabilityType::Endpoint,
                b"pid:1",
                0,
                0,
            )
            .unwrap();

        // Verify the UCAN chain.
        let mut id_store = PqMemoryIdentityStore::new();
        id_store.insert(owner.public_identity().clone());
        id_store.insert(user.public_identity().clone());
        let proof_store = PqMemoryProofStore::new();
        let revocations = MemoryRevocationSet::new();

        assert!(
            verify_pq_token(&user_token, 100, &proof_store, &id_store, &revocations, 5,).is_ok()
        );

        // Chain 3: session binding.
        let token_hash = user_token.content_hash();
        let binding = make_session_binding(&session, &user_addr, &token_hash, &hw_addr, [0x10; 16]);

        let used_nonces = BTreeSet::new();
        assert!(verify_session_binding(
            &binding,
            session.public_identity(),
            &hw_addr,
            &token_hash,
            &used_nonces,
        )
        .is_ok());

        // All three chains verified — construct the BoundCapability.
        let _bound = BoundCapability {
            token: user_token,
            binding,
        };
    }
}
