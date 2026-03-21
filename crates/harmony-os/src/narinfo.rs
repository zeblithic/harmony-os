// SPDX-License-Identifier: GPL-2.0-or-later

//! NARInfo parser — extracts URL, NarHash, and NarSize from `.narinfo` files.
//!
//! NARInfo is a simple line-based format served by Nix binary caches.
//! We only need three fields for Layer 4 (lazy fetch).

use alloc::string::{String, ToString};

/// Parsed NARInfo — the three fields needed for lazy fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarInfo {
    /// Relative URL to the NAR file (e.g. `nar/1234abcd.nar.xz`).
    pub url: String,
    /// Compression type (e.g. `"xz"`, `"bzip2"`, `"none"`).
    pub compression: String,
    /// Hash of the decompressed NAR (e.g. `sha256:<nix-base32>`).
    pub nar_hash: String,
    /// Size of the decompressed NAR in bytes.
    pub nar_size: u64,
}

/// Errors from parsing NARInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarInfoError {
    /// A required field was not found.
    MissingField(&'static str),
    /// NarSize was not a valid integer.
    InvalidNarSize,
}

impl NarInfo {
    /// Parse a NARInfo response body.
    pub fn parse(input: &str) -> Result<Self, NarInfoError> {
        let mut url = None;
        let mut compression = None;
        let mut nar_hash = None;
        let mut nar_size = None;

        for line in input.lines() {
            if let Some(val) = line.strip_prefix("URL: ") {
                url = Some(val.to_string());
            } else if let Some(val) = line.strip_prefix("Compression: ") {
                compression = Some(val.to_string());
            } else if let Some(val) = line.strip_prefix("NarHash: ") {
                nar_hash = Some(val.to_string());
            } else if let Some(val) = line.strip_prefix("NarSize: ") {
                nar_size = Some(
                    val.parse::<u64>()
                        .map_err(|_| NarInfoError::InvalidNarSize)?,
                );
            }
        }

        Ok(NarInfo {
            url: url.ok_or(NarInfoError::MissingField("URL"))?,
            compression: compression.unwrap_or_else(|| "bzip2".to_string()),
            nar_hash: nar_hash.ok_or(NarInfoError::MissingField("NarHash"))?,
            nar_size: nar_size.ok_or(NarInfoError::MissingField("NarSize"))?,
        })
    }
}

/// Generate a minimal unsigned narinfo string.
///
/// Produces 5 fields: StorePath, URL, Compression, NarHash, NarSize.
/// The NAR is served uncompressed (`Compression: none`).
///
/// `nar_sha256` must be the raw 32-byte SHA-256 digest of the NAR blob.
#[cfg(feature = "std")]
pub fn serialize_narinfo(store_path_name: &str, nar_sha256: &[u8], nar_size: u64) -> String {
    use crate::nix_base32::encode_nix_base32;

    let hash_b32 = encode_nix_base32(nar_sha256);
    format!(
        "StorePath: /nix/store/{store_path_name}\n\
         URL: nar/{store_path_name}.nar\n\
         Compression: none\n\
         NarHash: sha256:{hash_b32}\n\
         NarSize: {nar_size}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_NARINFO: &str = "\
StorePath: /nix/store/abc123-hello-2.10
URL: nar/1234abcd.nar.xz
Compression: xz
FileHash: sha256:aaaa
FileSize: 5678
NarHash: sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5vpj0850gk224669lcr3yq
NarSize: 12345
References: def456-glibc-2.38 ghi789-gcc-13.2
Deriver: jkl012-hello-2.10.drv
Sig: cache.nixos.org-1:abcdef1234567890\n";

    #[test]
    fn parse_valid_narinfo() {
        let info = NarInfo::parse(SAMPLE_NARINFO).unwrap();
        assert_eq!(info.url, "nar/1234abcd.nar.xz");
        assert_eq!(info.compression, "xz");
        assert_eq!(
            info.nar_hash,
            "sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5vpj0850gk224669lcr3yq"
        );
        assert_eq!(info.nar_size, 12345);
    }

    #[test]
    fn reject_missing_url() {
        let input = "NarHash: sha256:abc\nNarSize: 100\n";
        assert_eq!(
            NarInfo::parse(input),
            Err(NarInfoError::MissingField("URL"))
        );
    }

    #[test]
    fn reject_missing_nar_hash() {
        let input = "URL: nar/foo.nar.xz\nNarSize: 100\n";
        assert_eq!(
            NarInfo::parse(input),
            Err(NarInfoError::MissingField("NarHash"))
        );
    }

    #[test]
    fn reject_missing_nar_size() {
        let input = "URL: nar/foo.nar.xz\nNarHash: sha256:abc\n";
        assert_eq!(
            NarInfo::parse(input),
            Err(NarInfoError::MissingField("NarSize"))
        );
    }

    #[test]
    fn reject_invalid_nar_size() {
        let input = "URL: nar/foo.nar.xz\nNarHash: sha256:abc\nNarSize: notanumber\n";
        assert_eq!(NarInfo::parse(input), Err(NarInfoError::InvalidNarSize));
    }

    #[test]
    fn fields_can_appear_in_any_order() {
        let input = "NarSize: 42\nNarHash: sha256:xyz\nURL: nar/bar.nar.xz\n";
        let info = NarInfo::parse(input).unwrap();
        assert_eq!(info.url, "nar/bar.nar.xz");
        assert_eq!(info.nar_hash, "sha256:xyz");
        assert_eq!(info.nar_size, 42);
        assert_eq!(info.compression, "bzip2"); // Nix spec default when absent
    }

    #[test]
    fn explicit_compression_field() {
        let input = "URL: nar/a.nar.zst\nCompression: zstd\nNarHash: sha256:abc\nNarSize: 10\n";
        let info = NarInfo::parse(input).unwrap();
        assert_eq!(info.compression, "zstd");
    }

    #[cfg(feature = "std")]
    mod serialize_tests {
        use super::super::*;
        use sha2::Digest;

        #[test]
        fn serialize_minimal_narinfo() {
            let hash = sha2::Sha256::digest(b"test nar data");
            let text = serialize_narinfo("abc123-hello", hash.as_slice(), 13);

            assert!(text.contains("StorePath: /nix/store/abc123-hello\n"));
            assert!(text.contains("URL: nar/abc123-hello.nar\n"));
            assert!(text.contains("Compression: none\n"));
            assert!(text.contains("NarHash: sha256:"));
            assert!(text.contains("NarSize: 13\n"));
        }

        #[test]
        fn serialize_round_trip() {
            let nar_data = b"some nar content for round trip";
            let hash = sha2::Sha256::digest(nar_data);
            let text = serialize_narinfo("xyz789-world", hash.as_slice(), nar_data.len() as u64);

            // Parse it back with the existing parser.
            let parsed = NarInfo::parse(&text).unwrap();
            assert_eq!(parsed.url, "nar/xyz789-world.nar");
            assert_eq!(parsed.compression, "none");
            assert_eq!(parsed.nar_size, nar_data.len() as u64);
            assert!(parsed.nar_hash.starts_with("sha256:"));
        }

        #[test]
        fn serialize_store_path_format() {
            let hash = sha2::Sha256::digest(b"data");
            let text = serialize_narinfo("test123-pkg", hash.as_slice(), 4);
            let store_line = text.lines().find(|l| l.starts_with("StorePath:")).unwrap();
            assert_eq!(store_line, "StorePath: /nix/store/test123-pkg");
        }
    }
}
