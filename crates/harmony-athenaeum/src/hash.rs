// SPDX-License-Identifier: GPL-2.0-or-later
//! Hash functions for address derivation.

use sha2::{Digest, Sha224, Sha256};

use crate::addr::Algorithm;

/// Compute full SHA-256 hash (32 bytes).
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute full SHA-224 hash (28 bytes).
pub fn sha224_hash(data: &[u8]) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Extract 21 bits from the most significant end of a digest.
fn extract_bits_msb(digest: &[u8]) -> u32 {
    // Take first 3 bytes (24 bits), shift right by 3 to get 21 bits
    let b0 = digest[0] as u32;
    let b1 = digest[1] as u32;
    let b2 = digest[2] as u32;
    ((b0 << 16) | (b1 << 8) | b2) >> 3
}

/// Extract 21 bits from the least significant end of a digest.
fn extract_bits_lsb(digest: &[u8]) -> u32 {
    let len = digest.len();
    let b0 = digest[len - 3] as u32;
    let b1 = digest[len - 2] as u32;
    let b2 = digest[len - 1] as u32;
    ((b0 << 16) | (b1 << 8) | b2) >> 3
}

/// Derive 21 hash address bits from chunk data using the specified algorithm.
pub(crate) fn derive_hash_bits(data: &[u8], algorithm: Algorithm) -> u32 {
    match algorithm {
        Algorithm::Sha256Msb => extract_bits_msb(&sha256_hash(data)),
        Algorithm::Sha256Lsb => extract_bits_lsb(&sha256_hash(data)),
        Algorithm::Sha224Msb => extract_bits_msb(&sha224_hash(data)),
        Algorithm::Sha224Lsb => extract_bits_lsb(&sha224_hash(data)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Algorithm;

    #[test]
    fn sha256_msb_deterministic() {
        let bits1 = derive_hash_bits(b"hello", Algorithm::Sha256Msb);
        let bits2 = derive_hash_bits(b"hello", Algorithm::Sha256Msb);
        assert_eq!(bits1, bits2);
    }

    #[test]
    fn sha256_msb_vs_lsb_differ() {
        let msb = derive_hash_bits(b"test data", Algorithm::Sha256Msb);
        let lsb = derive_hash_bits(b"test data", Algorithm::Sha256Lsb);
        assert_ne!(msb, lsb);
    }

    #[test]
    fn sha224_msb_vs_sha256_msb_differ() {
        let sha256 = derive_hash_bits(b"test data", Algorithm::Sha256Msb);
        let sha224 = derive_hash_bits(b"test data", Algorithm::Sha224Msb);
        assert_ne!(sha256, sha224);
    }

    #[test]
    fn hash_bits_fit_in_21_bits() {
        for algo in [
            Algorithm::Sha256Msb,
            Algorithm::Sha256Lsb,
            Algorithm::Sha224Msb,
            Algorithm::Sha224Lsb,
        ] {
            let bits = derive_hash_bits(b"anything", algo);
            assert!(bits <= 0x1FFFFF, "hash bits {:#x} exceed 21-bit max", bits);
        }
    }

    #[test]
    fn different_data_different_bits() {
        let a = derive_hash_bits(b"alice", Algorithm::Sha256Msb);
        let b = derive_hash_bits(b"bob", Algorithm::Sha256Msb);
        assert_ne!(a, b);
    }

    #[test]
    fn full_hash_sha256_known_vector() {
        // SHA-256("abc") = ba7816bf...
        let hash = sha256_hash(b"abc");
        assert_eq!(hash[0], 0xba);
        assert_eq!(hash[1], 0x78);
    }

    #[test]
    fn full_hash_sha224_known_vector() {
        // SHA-224("abc") = 23097d22...
        let hash = sha224_hash(b"abc");
        assert_eq!(hash[0], 0x23);
        assert_eq!(hash[1], 0x09);
    }

    #[test]
    fn all_four_algorithms_produce_values() {
        let data = b"test chunk data for athenaeum";
        let results: Vec<u32> = [
            Algorithm::Sha256Msb,
            Algorithm::Sha256Lsb,
            Algorithm::Sha224Msb,
            Algorithm::Sha224Lsb,
        ]
        .iter()
        .map(|a| derive_hash_bits(data, *a))
        .collect();
        // All should produce non-zero values for this input
        for r in &results {
            assert!(*r > 0);
        }
    }
}
