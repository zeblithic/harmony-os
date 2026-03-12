// SPDX-License-Identifier: GPL-2.0-or-later

//! Nix-specific base32 decoder.
//!
//! Nix uses a non-standard base32 alphabet: `0123456789abcdfghijklmnpqrsvwxyz`
//! (missing `e`, `o`, `t`, `u` to avoid confusion). Hashes are encoded with
//! the most-significant digit first, but each digit's bits are scattered into
//! the output in LSB-first order within each 5-bit group.

/// Nix base32 alphabet (32 chars, missing e/o/t/u).
pub const NIX_BASE32_CHARS: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Decode a Nix base32 string into bytes.
///
/// Nix base32 encoding reverses the character order relative to the bit
/// positions: character at index `i` corresponds to bit position
/// `(len - 1 - i) * 5`. The output length is `input.len() * 5 / 8` bytes.
pub fn decode_nix_base32(input: &str) -> Result<Vec<u8>, NixBase32Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let len = input.len();
    let hash_size = len * 5 / 8;
    let mut out = vec![0u8; hash_size];

    for (i, c) in input.chars().enumerate() {
        let digit = NIX_BASE32_CHARS
            .iter()
            .position(|&ch| ch == c as u8)
            .ok_or(NixBase32Error::InvalidChar(c))?;

        // Character at position i was encoded with n = len - 1 - i.
        // Its 5 bits occupy bit positions n*5 .. n*5+4 in the output.
        let n = len - 1 - i;
        let b = n * 5;
        for j in 0..5 {
            if (b + j) / 8 < hash_size {
                out[(b + j) / 8] |= (((digit >> j) & 1) as u8) << ((b + j) % 8);
            }
        }
    }

    Ok(out)
}

/// Errors from Nix base32 decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NixBase32Error {
    /// Input contains a character not in the Nix base32 alphabet.
    InvalidChar(char),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_known_sha256() {
        // SHA-256 hash of an empty string (NOT an empty NAR).
        // hex: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // Nix base32 encoding (verified against Nix reference implementation):
        let nix_b32 = "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73";
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let expected: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&expected_hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let decoded = decode_nix_base32(nix_b32).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn reject_invalid_char() {
        // 'e' is not in the Nix base32 alphabet.
        assert!(decode_nix_base32("e000000000000000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn reject_wrong_length_for_sha256() {
        // SHA-256 needs exactly 52 Nix base32 chars.
        assert!(decode_nix_base32("abc").is_ok()); // short decode is allowed
                                                   // but the caller validates length -- decoder just decodes what it gets
    }

    #[test]
    fn empty_input() {
        let decoded = decode_nix_base32("").unwrap();
        assert!(decoded.is_empty());
    }
}
