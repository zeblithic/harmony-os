// SPDX-License-Identifier: GPL-2.0-or-later
//! ChunkAddr — 32-bit content-addressed chunk identifier.

/// Hash algorithm selector for address derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Algorithm {
    Sha256Msb = 0,
    Sha256Lsb = 1,
    Sha224Msb = 2,
    Sha224Lsb = 3,
}

/// Chunk nesting depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Depth {
    Blob = 0,
    Bundle1 = 1,
    Bundle2 = 2,
    Bundle3 = 3,
}

/// A 32-bit content-addressed chunk identifier.
///
/// ## 32-bit Layout
///
/// ```text
/// bits 31-11: hash_bits (21 bits)
/// bits 10-9:  algorithm (2 bits)
/// bits 8-7:   depth (2 bits)
/// bits 6-4:   size_exponent (3 bits)
/// bits 3-0:   checksum (4 bits)
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkAddr(pub(crate) u32);

impl ChunkAddr {
    /// Construct a `ChunkAddr` from its component fields.
    /// The checksum is computed automatically. The `_checksum` parameter is ignored (pass 0).
    pub fn new(
        hash_bits: u32,
        algorithm: Algorithm,
        depth: Depth,
        size_exponent: u8,
        _checksum: u8,
    ) -> Self {
        let algo = algorithm as u32;
        let d = depth as u32;
        let se = size_exponent as u32;
        let bits28 = (hash_bits << 7) | (algo << 5) | (d << 3) | se;
        let checksum = Self::compute_checksum(bits28);
        ChunkAddr((bits28 << 4) | checksum as u32)
    }

    /// Extract the 21-bit hash address.
    pub fn hash_bits(&self) -> u32 {
        (self.0 >> 11) & 0x1F_FFFF
    }

    /// Extract the algorithm selector.
    pub fn algorithm(&self) -> Algorithm {
        let raw = ((self.0 >> 9) & 0x3) as u8;
        match raw {
            0 => Algorithm::Sha256Msb,
            1 => Algorithm::Sha256Lsb,
            2 => Algorithm::Sha224Msb,
            3 => Algorithm::Sha224Lsb,
            _ => unreachable!(),
        }
    }

    /// Extract the depth field.
    pub fn depth(&self) -> Depth {
        let raw = ((self.0 >> 7) & 0x3) as u8;
        match raw {
            0 => Depth::Blob,
            1 => Depth::Bundle1,
            2 => Depth::Bundle2,
            3 => Depth::Bundle3,
            _ => unreachable!(),
        }
    }

    /// Extract the 3-bit size exponent.
    pub fn size_exponent(&self) -> u8 {
        ((self.0 >> 4) & 0x7) as u8
    }

    /// Chunk size in bytes: `4096 >> size_exponent`.
    pub fn size_bytes(&self) -> usize {
        4096 >> self.size_exponent()
    }

    /// Extract the 4-bit checksum.
    pub fn checksum(&self) -> u8 {
        (self.0 & 0xF) as u8
    }

    /// Verify the checksum matches the other 28 bits.
    pub fn verify_checksum(&self) -> bool {
        let bits28 = self.0 >> 4;
        let expected = Self::compute_checksum(bits28);
        self.checksum() == expected
    }

    /// Compute 4-bit XOR-fold checksum of 28 bits.
    fn compute_checksum(bits28: u32) -> u8 {
        let mut c = 0u8;
        for i in 0..7 {
            c ^= ((bits28 >> (i * 4)) & 0xF) as u8;
        }
        c & 0xF
    }
}

impl core::fmt::Debug for ChunkAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ChunkAddr({:#010x} hash={} algo={:?} depth={:?} size={}B)",
            self.0,
            self.hash_bits(),
            self.algorithm(),
            self.depth(),
            self.size_bytes()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_fields() {
        let addr = ChunkAddr::new(0x1FFFFF, Algorithm::Sha256Msb, Depth::Blob, 0, 0);
        assert_eq!(addr.hash_bits(), 0x1FFFFF);
        assert_eq!(addr.algorithm(), Algorithm::Sha256Msb);
        assert_eq!(addr.depth(), Depth::Blob);
        assert_eq!(addr.size_exponent(), 0);
        assert_eq!(addr.size_bytes(), 4096);
        assert!(addr.verify_checksum());
    }

    #[test]
    fn algorithm_variants() {
        for algo in [
            Algorithm::Sha256Msb,
            Algorithm::Sha256Lsb,
            Algorithm::Sha224Msb,
            Algorithm::Sha224Lsb,
        ] {
            let addr = ChunkAddr::new(42, algo, Depth::Blob, 0, 0);
            assert_eq!(addr.algorithm(), algo);
            assert!(addr.verify_checksum());
        }
    }

    #[test]
    fn depth_variants() {
        for (depth, expected) in [
            (Depth::Blob, 0u8),
            (Depth::Bundle1, 1),
            (Depth::Bundle2, 2),
            (Depth::Bundle3, 3),
        ] {
            let addr = ChunkAddr::new(0, Algorithm::Sha256Msb, depth, 0, 0);
            assert_eq!(addr.depth() as u8, expected);
        }
    }

    #[test]
    fn size_exponent_all_values() {
        let expected_sizes = [4096, 2048, 1024, 512, 256, 128, 64, 32];
        for (exp, &expected) in expected_sizes.iter().enumerate() {
            let addr = ChunkAddr::new(0, Algorithm::Sha256Msb, Depth::Blob, exp as u8, 0);
            assert_eq!(addr.size_bytes(), expected);
        }
    }

    #[test]
    fn checksum_detects_single_bit_flip() {
        let addr = ChunkAddr::new(12345, Algorithm::Sha224Lsb, Depth::Bundle1, 3, 0);
        assert!(addr.verify_checksum());
        let corrupted = ChunkAddr(addr.0 ^ (1 << 20));
        assert!(!corrupted.verify_checksum());
    }

    #[test]
    fn checksum_all_zeros() {
        let addr = ChunkAddr::new(0, Algorithm::Sha256Msb, Depth::Blob, 0, 0);
        assert_eq!(addr.checksum(), 0);
        assert!(addr.verify_checksum());
    }

    #[test]
    fn max_hash_bits_value() {
        let addr = ChunkAddr::new(0x1FFFFF, Algorithm::Sha224Lsb, Depth::Bundle3, 7, 0);
        assert_eq!(addr.hash_bits(), 0x1FFFFF);
        assert_eq!(addr.size_bytes(), 32);
        assert!(addr.verify_checksum());
    }

    #[test]
    fn from_raw_u32_round_trip() {
        let addr = ChunkAddr::new(100, Algorithm::Sha256Lsb, Depth::Blob, 2, 0);
        let raw = addr.0;
        let restored = ChunkAddr(raw);
        assert_eq!(restored.hash_bits(), 100);
        assert_eq!(restored.algorithm(), Algorithm::Sha256Lsb);
        assert_eq!(restored.size_bytes(), 1024);
    }

    #[test]
    fn debug_format() {
        let addr = ChunkAddr::new(42, Algorithm::Sha256Msb, Depth::Blob, 0, 0);
        let debug = alloc::format!("{:?}", addr);
        assert!(debug.contains("ChunkAddr("));
        assert!(debug.contains("hash=42"));
    }
}
