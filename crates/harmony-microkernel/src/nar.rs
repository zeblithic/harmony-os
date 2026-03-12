// SPDX-License-Identifier: GPL-2.0-or-later

//! NAR (Nix ARchive) parser — zero-copy, `no_std`-compatible.
//!
//! Parses NAR byte streams into a directory tree. File contents are
//! referenced by offset into the original NAR blob rather than copied,
//! enabling zero-copy reads when serving files via 9P.
//!
//! This is Layer 1 of the /nix/store bridge (see design doc:
//! `docs/plans/2026-03-11-nix-store-bridge-design.md`).

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

// ── Error type ──────────────────────────────────────────────────────

/// Errors that can occur when parsing a NAR archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarError {
    /// The input buffer is too short to read the expected data.
    TooShort,
    /// The archive does not start with `nix-archive-1`.
    InvalidMagic,
    /// A length-prefixed string is malformed (e.g. non-zero padding).
    InvalidString,
    /// A token was not the expected value.
    UnexpectedToken,
    /// The `type` field contained an unrecognized value.
    InvalidType,
    /// An arithmetic overflow occurred when computing offsets.
    OffsetOverflow,
    /// A directory contains two entries with the same name.
    DuplicateEntry,
    /// Directory entries are not in lexicographic order (NAR spec requirement).
    OutOfOrder,
    /// The archive has trailing bytes after the root node.
    TrailingData,
    /// Directory nesting exceeds the maximum allowed depth.
    NestingTooDeep,
}

/// Maximum directory nesting depth. Prevents stack overflow from crafted
/// archives with deeply nested directories. 256 levels is generous for
/// real Nix store paths (typical depth is < 20).
const MAX_NESTING_DEPTH: usize = 256;

// ── Entry types ─────────────────────────────────────────────────────

/// A single entry in a parsed NAR archive.
///
/// File contents use zero-copy: `contents_offset` and `contents_len`
/// point into the original NAR blob rather than holding a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarEntry {
    /// A regular file.
    Regular {
        /// Whether the file has the executable flag set.
        executable: bool,
        /// Byte offset of the file contents within the NAR blob.
        contents_offset: usize,
        /// Length of the file contents in bytes.
        contents_len: usize,
    },
    /// A symbolic link.
    Symlink {
        /// The symlink target path.
        target: Arc<str>,
    },
    /// A directory containing named entries.
    Directory {
        /// Child entries, sorted by name.
        entries: BTreeMap<Arc<str>, NarEntry>,
    },
}

// ── String parser helpers ───────────────────────────────────────────

/// Read a NAR length-prefixed string at `pos`.
///
/// NAR strings are encoded as:
/// - 8-byte little-endian length
/// - `length` bytes of data
/// - 0-padding to the next 8-byte boundary
///
/// Returns `(data_slice, new_position)`.
fn read_string(data: &[u8], pos: usize) -> Result<(&[u8], usize), NarError> {
    // Need at least 8 bytes for the length field.
    if pos.checked_add(8).ok_or(NarError::OffsetOverflow)? > data.len() {
        return Err(NarError::TooShort);
    }

    let len_bytes: [u8; 8] = data[pos..pos + 8]
        .try_into()
        .map_err(|_| NarError::TooShort)?;
    let len: usize = u64::from_le_bytes(len_bytes)
        .try_into()
        .map_err(|_| NarError::OffsetOverflow)?;

    // Padding: round up to next 8-byte boundary.
    let padded_len = len.checked_add(7).ok_or(NarError::OffsetOverflow)? & !7;

    let data_start = pos.checked_add(8).ok_or(NarError::OffsetOverflow)?;
    let data_end = data_start
        .checked_add(len)
        .ok_or(NarError::OffsetOverflow)?;
    let total_end = data_start
        .checked_add(padded_len)
        .ok_or(NarError::OffsetOverflow)?;

    if data_end > data.len() || total_end > data.len() {
        return Err(NarError::TooShort);
    }

    // Validate that all padding bytes are zero.
    for &b in &data[data_end..total_end] {
        if b != 0 {
            return Err(NarError::InvalidString);
        }
    }

    let string_data = &data[data_start..data_end];
    Ok((string_data, total_end))
}

/// Read a NAR string at `pos` and verify it matches `expected`.
///
/// Returns the new position after the string.
fn expect_string(data: &[u8], pos: usize, expected: &[u8]) -> Result<usize, NarError> {
    let (found, new_pos) = read_string(data, pos)?;
    if found != expected {
        return Err(NarError::UnexpectedToken);
    }
    Ok(new_pos)
}

// ── Node parsers ────────────────────────────────────────────────────

/// Parse a NAR node at `pos`.
///
/// Expects: `( type <type-string> ... )`
/// Dispatches to the appropriate type-specific parser.
///
/// Returns `(entry, new_position)`.
pub fn parse_node(data: &[u8], pos: usize) -> Result<(NarEntry, usize), NarError> {
    parse_node_depth(data, pos, 0)
}

/// Internal depth-tracking version of [`parse_node`].
fn parse_node_depth(data: &[u8], pos: usize, depth: usize) -> Result<(NarEntry, usize), NarError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(NarError::NestingTooDeep);
    }

    let pos = expect_string(data, pos, b"(")?;
    let pos = expect_string(data, pos, b"type")?;

    let (type_str, pos) = read_string(data, pos)?;

    match type_str {
        b"regular" => parse_regular(data, pos),
        b"symlink" => parse_symlink(data, pos),
        b"directory" => parse_directory(data, pos, depth),
        _ => Err(NarError::InvalidType),
    }
}

/// Parse a regular file node.
///
/// At entry, `pos` points just after the `type regular` tokens.
/// NAR grammar: `"regular" ["executable" ""] ["contents" <data>] ")"`.
/// The `contents` field is optional — Nix omits it for empty files.
fn parse_regular(data: &[u8], pos: usize) -> Result<(NarEntry, usize), NarError> {
    // Peek at the next token to see if it's "executable", "contents", or ")".
    let (token, next_pos) = read_string(data, pos)?;

    let (executable, pos) = if token == b"executable" {
        // Read the empty marker string.
        let pos = expect_string(data, next_pos, b"")?;
        (true, pos)
    } else {
        (false, pos)
    };

    // Peek again — "contents" or ")" (empty file).
    let (token, next_pos) = read_string(data, pos)?;

    if token == b")" {
        // Empty regular file — no contents field.
        let entry = NarEntry::Regular {
            executable,
            contents_offset: 0,
            contents_len: 0,
        };
        return Ok((entry, next_pos));
    }

    if token != b"contents" {
        return Err(NarError::UnexpectedToken);
    }
    let pos = next_pos;

    // Read the contents length (8-byte LE).
    if pos.checked_add(8).ok_or(NarError::OffsetOverflow)? > data.len() {
        return Err(NarError::TooShort);
    }
    let len_bytes: [u8; 8] = data[pos..pos + 8]
        .try_into()
        .map_err(|_| NarError::TooShort)?;
    let contents_len: usize = u64::from_le_bytes(len_bytes)
        .try_into()
        .map_err(|_| NarError::OffsetOverflow)?;
    let padded_len = contents_len
        .checked_add(7)
        .ok_or(NarError::OffsetOverflow)?
        & !7;

    let contents_offset = pos.checked_add(8).ok_or(NarError::OffsetOverflow)?;
    let contents_end = contents_offset
        .checked_add(contents_len)
        .ok_or(NarError::OffsetOverflow)?;
    let padded_end = contents_offset
        .checked_add(padded_len)
        .ok_or(NarError::OffsetOverflow)?;

    if contents_end > data.len() || padded_end > data.len() {
        return Err(NarError::TooShort);
    }

    // Validate that content padding bytes are zero (same policy as read_string).
    for &b in &data[contents_end..padded_end] {
        if b != 0 {
            return Err(NarError::InvalidString);
        }
    }

    let pos = padded_end;

    // Expect closing ")".
    let pos = expect_string(data, pos, b")")?;

    let entry = NarEntry::Regular {
        executable,
        contents_offset,
        contents_len,
    };
    Ok((entry, pos))
}

/// Parse a symlink node.
///
/// At entry, `pos` points just after the `type symlink` tokens.
/// Expects `target <path>`, then `)`.
fn parse_symlink(data: &[u8], pos: usize) -> Result<(NarEntry, usize), NarError> {
    let pos = expect_string(data, pos, b"target")?;

    let (target_bytes, pos) = read_string(data, pos)?;

    // Convert target to a string. NAR targets should be valid UTF-8 paths.
    let target_str = core::str::from_utf8(target_bytes).map_err(|_| NarError::InvalidString)?;

    let pos = expect_string(data, pos, b")")?;

    let entry = NarEntry::Symlink {
        target: Arc::from(target_str),
    };
    Ok((entry, pos))
}

/// Parse a directory node.
///
/// At entry, `pos` points just after the `type directory` tokens.
/// Expects zero or more `entry ( name <n> node <recurse> )` sequences,
/// then `)`.
fn parse_directory(data: &[u8], pos: usize, depth: usize) -> Result<(NarEntry, usize), NarError> {
    let mut entries = BTreeMap::new();
    let mut last_name: Option<Arc<str>> = None;
    let mut pos = pos;

    loop {
        // Peek at the next token.
        let (token, next_pos) = read_string(data, pos)?;

        if token == b")" {
            // End of directory.
            let entry = NarEntry::Directory { entries };
            return Ok((entry, next_pos));
        }

        if token != b"entry" {
            return Err(NarError::UnexpectedToken);
        }
        pos = next_pos;

        // Expect "(" to start the entry.
        pos = expect_string(data, pos, b"(")?;

        // Expect "name".
        pos = expect_string(data, pos, b"name")?;

        // Read the entry name.
        let (name_bytes, new_pos) = read_string(data, pos)?;
        pos = new_pos;
        let name_str = core::str::from_utf8(name_bytes).map_err(|_| NarError::InvalidString)?;
        // NAR spec: entry names must not be empty, contain '/' or '\0', or be "." / "..".
        // Also reject '\n' and '\r' — listings use '\n' as separator, so these would
        // create ambiguous output that clients misparse.
        if name_str.is_empty()
            || name_str.contains('/')
            || name_str.contains('\0')
            || name_str.contains('\n')
            || name_str.contains('\r')
            || name_str == "."
            || name_str == ".."
        {
            return Err(NarError::InvalidString);
        }
        let name: Arc<str> = Arc::from(name_str);

        // NAR spec requires entries in strictly ascending lexicographic order.
        if let Some(ref prev) = last_name {
            if *name == **prev {
                return Err(NarError::DuplicateEntry);
            }
            if *name < **prev {
                return Err(NarError::OutOfOrder);
            }
        }
        last_name = Some(Arc::clone(&name));

        // Expect "node".
        pos = expect_string(data, pos, b"node")?;

        // Recurse into the node (depth + 1 for nesting limit).
        let (child_entry, new_pos) = parse_node_depth(data, pos, depth + 1)?;
        pos = new_pos;

        // Expect ")" to close the entry.
        pos = expect_string(data, pos, b")")?;

        entries.insert(name, child_entry);
    }
}

// ── Top-level API ───────────────────────────────────────────────────

/// A parsed NAR archive.
///
/// Holds the recursive directory tree. File contents are referenced by
/// offset into the original NAR blob (zero-copy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarArchive {
    /// The root entry of the archive.
    pub root: NarEntry,
}

impl NarArchive {
    /// Parse a NAR blob into a directory tree.
    ///
    /// Validates the `nix-archive-1` magic header, then parses the
    /// root node. File contents are stored as offsets, not copies.
    pub fn parse(data: &[u8]) -> Result<Self, NarError> {
        if data.is_empty() {
            return Err(NarError::InvalidMagic);
        }

        // Read and verify magic.
        let (magic, pos) = read_string(data, 0)?;
        if magic != b"nix-archive-1" {
            return Err(NarError::InvalidMagic);
        }

        // Parse the root node.
        let (root, end_pos) = parse_node(data, pos)?;

        if end_pos != data.len() {
            return Err(NarError::TrailingData);
        }

        Ok(NarArchive { root })
    }

    /// Look up an entry by path (e.g., `"bin/hello"`).
    ///
    /// An empty string returns the root entry. Path components are
    /// split on `/`. Returns `None` if any component is not found or
    /// if a non-directory is encountered mid-path.
    pub fn lookup(&self, path: &str) -> Option<&NarEntry> {
        if path.is_empty() {
            return Some(&self.root);
        }

        let mut current = &self.root;
        for component in path.split('/') {
            // Empty components (from double-slashes or leading/trailing slashes)
            // are intentionally skipped. Paths produced by `walk` always use a
            // single `/` separator, so this case should not arise in practice.
            if component.is_empty() {
                continue;
            }
            match current {
                NarEntry::Directory { entries } => {
                    current = entries.get(component)?;
                }
                _ => return None,
            }
        }
        Some(current)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;

    // ── Test helpers ────────────────────────────────────────────────

    /// Encode a byte slice as a NAR length-prefixed string.
    ///
    /// Format: 8-byte LE length + data + 0-padding to 8-byte boundary.
    pub(crate) fn nar_string(s: &[u8]) -> Vec<u8> {
        let len = s.len() as u64;
        let padded_len = (s.len() + 7) & !7;
        let mut buf = Vec::with_capacity(8 + padded_len);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s);
        // Pad with zeros to 8-byte boundary.
        let padding = padded_len - s.len();
        for _ in 0..padding {
            buf.push(0);
        }
        buf
    }

    /// Build a complete NAR archive for a regular file.
    ///
    /// Format: `nix-archive-1 ( type regular [executable ""] contents <data> )`
    pub(crate) fn nar_regular_file(contents: &[u8], executable: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&nar_string(b"nix-archive-1"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"regular"));
        if executable {
            buf.extend_from_slice(&nar_string(b"executable"));
            buf.extend_from_slice(&nar_string(b""));
        }
        buf.extend_from_slice(&nar_string(b"contents"));
        buf.extend_from_slice(&nar_string(contents));
        buf.extend_from_slice(&nar_string(b")"));
        buf
    }

    /// Build a complete NAR archive for a symlink.
    ///
    /// Format: `nix-archive-1 ( type symlink target <path> )`
    pub(crate) fn nar_symlink(target: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&nar_string(b"nix-archive-1"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"symlink"));
        buf.extend_from_slice(&nar_string(b"target"));
        buf.extend_from_slice(&nar_string(target.as_bytes()));
        buf.extend_from_slice(&nar_string(b")"));
        buf
    }

    /// Build a complete NAR archive for a directory with two entries:
    /// - `bin/hello` (executable regular file, contents: `"#!/bin/sh\necho hello\n"`)
    /// - `README` (non-executable regular file, contents: `"Hello, world!\n"`)
    ///
    /// Format:
    /// ```text
    /// nix-archive-1 (
    ///   type directory
    ///   entry ( name README node ( type regular contents "Hello, world!\n" ) )
    ///   entry ( name bin node ( type directory
    ///     entry ( name hello node ( type regular executable "" contents "#!/bin/sh\necho hello\n" ) )
    ///   ) )
    /// )
    /// ```
    pub(crate) fn nar_directory_with_files() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&nar_string(b"nix-archive-1"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"directory"));

        // entry: README (regular, non-executable)
        buf.extend_from_slice(&nar_string(b"entry"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"name"));
        buf.extend_from_slice(&nar_string(b"README"));
        buf.extend_from_slice(&nar_string(b"node"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"regular"));
        buf.extend_from_slice(&nar_string(b"contents"));
        buf.extend_from_slice(&nar_string(b"Hello, world!\n"));
        buf.extend_from_slice(&nar_string(b")"));
        buf.extend_from_slice(&nar_string(b")"));

        // entry: bin (directory containing hello)
        buf.extend_from_slice(&nar_string(b"entry"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"name"));
        buf.extend_from_slice(&nar_string(b"bin"));
        buf.extend_from_slice(&nar_string(b"node"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"directory"));

        // entry: bin/hello (executable)
        buf.extend_from_slice(&nar_string(b"entry"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"name"));
        buf.extend_from_slice(&nar_string(b"hello"));
        buf.extend_from_slice(&nar_string(b"node"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"regular"));
        buf.extend_from_slice(&nar_string(b"executable"));
        buf.extend_from_slice(&nar_string(b""));
        buf.extend_from_slice(&nar_string(b"contents"));
        buf.extend_from_slice(&nar_string(b"#!/bin/sh\necho hello\n"));
        buf.extend_from_slice(&nar_string(b")"));
        buf.extend_from_slice(&nar_string(b")"));

        // Close bin directory
        buf.extend_from_slice(&nar_string(b")"));
        buf.extend_from_slice(&nar_string(b")"));

        // Close root directory
        buf.extend_from_slice(&nar_string(b")"));

        buf
    }

    // ── String parser tests ─────────────────────────────────────────

    #[test]
    fn read_string_basic() {
        let data = nar_string(b"hello");
        let (s, pos) = read_string(&data, 0).unwrap();
        assert_eq!(s, b"hello");
        // "hello" is 5 bytes, padded to 8 → total = 8 + 8 = 16.
        assert_eq!(pos, 16);
    }

    #[test]
    fn read_string_exact_alignment() {
        // "type" is 4 bytes, padded to 8 → total = 8 + 8 = 16.
        let data = nar_string(b"type");
        let (s, pos) = read_string(&data, 0).unwrap();
        assert_eq!(s, b"type");
        assert_eq!(pos, 16);
    }

    #[test]
    fn read_string_8_byte_aligned() {
        // "contents" is exactly 8 bytes, no padding needed → total = 8 + 8 = 16.
        let data = nar_string(b"contents");
        let (s, pos) = read_string(&data, 0).unwrap();
        assert_eq!(s, b"contents");
        assert_eq!(pos, 16);
    }

    #[test]
    fn read_string_truncated() {
        // Only 4 bytes — not enough for the 8-byte length field.
        let data = [0u8; 4];
        assert_eq!(read_string(&data, 0), Err(NarError::TooShort));
    }

    #[test]
    fn read_string_length_exceeds_data() {
        // Length field says 100 but only 10 bytes of data follow.
        let mut data = Vec::new();
        data.extend_from_slice(&100u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 10]);
        assert_eq!(read_string(&data, 0), Err(NarError::TooShort));
    }

    #[test]
    fn read_string_nonzero_padding() {
        // "hello" is 5 bytes → 3 padding bytes to reach 8-byte boundary.
        // Build manually with non-zero padding.
        let mut data = Vec::new();
        data.extend_from_slice(&5u64.to_le_bytes()); // length = 5
        data.extend_from_slice(b"hello"); // 5 bytes of content
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // 3 non-zero padding bytes
        assert_eq!(read_string(&data, 0), Err(NarError::InvalidString));
    }

    #[test]
    fn expect_string_matches() {
        let data = nar_string(b"(");
        let pos = expect_string(&data, 0, b"(").unwrap();
        assert_eq!(pos, 16); // "(" is 1 byte, padded to 8 → total = 16.
    }

    #[test]
    fn expect_string_mismatch() {
        let data = nar_string(b"(");
        assert_eq!(
            expect_string(&data, 0, b")"),
            Err(NarError::UnexpectedToken)
        );
    }

    // ── Entry parser tests ──────────────────────────────────────────

    #[test]
    fn parse_regular_file() {
        let contents = b"Hello, world!\n";
        let nar = nar_regular_file(contents, false);

        let archive = NarArchive::parse(&nar).unwrap();
        match &archive.root {
            NarEntry::Regular {
                executable,
                contents_offset,
                contents_len,
            } => {
                assert!(!executable);
                assert_eq!(*contents_len, contents.len());
                // Verify we can read the contents back from the NAR blob.
                assert_eq!(
                    &nar[*contents_offset..*contents_offset + *contents_len],
                    contents
                );
            }
            other => panic!("Expected Regular, got {:?}", other),
        }
    }

    #[test]
    fn parse_executable_file() {
        let contents = b"#!/bin/sh\necho hello\n";
        let nar = nar_regular_file(contents, true);

        let archive = NarArchive::parse(&nar).unwrap();
        match &archive.root {
            NarEntry::Regular {
                executable,
                contents_offset,
                contents_len,
            } => {
                assert!(executable);
                assert_eq!(*contents_len, contents.len());
                assert_eq!(
                    &nar[*contents_offset..*contents_offset + *contents_len],
                    contents
                );
            }
            other => panic!("Expected Regular, got {:?}", other),
        }
    }

    #[test]
    fn parse_symlink_entry() {
        let nar = nar_symlink("/nix/store/abc123-bash/bin/bash");

        let archive = NarArchive::parse(&nar).unwrap();
        match &archive.root {
            NarEntry::Symlink { target } => {
                assert_eq!(&**target, "/nix/store/abc123-bash/bin/bash");
            }
            other => panic!("Expected Symlink, got {:?}", other),
        }
    }

    #[test]
    fn parse_directory_with_files() {
        let nar = nar_directory_with_files();
        let archive = NarArchive::parse(&nar).unwrap();

        // Root should be a directory.
        match &archive.root {
            NarEntry::Directory { entries } => {
                assert_eq!(entries.len(), 2);
                assert!(entries.contains_key("README"));
                assert!(entries.contains_key("bin"));

                // Check README.
                match entries.get("README").unwrap() {
                    NarEntry::Regular {
                        executable,
                        contents_offset,
                        contents_len,
                    } => {
                        assert!(!executable);
                        assert_eq!(
                            &nar[*contents_offset..*contents_offset + *contents_len],
                            b"Hello, world!\n"
                        );
                    }
                    other => panic!("Expected Regular README, got {:?}", other),
                }

                // Check bin directory.
                match entries.get("bin").unwrap() {
                    NarEntry::Directory {
                        entries: bin_entries,
                    } => {
                        assert_eq!(bin_entries.len(), 1);
                        match bin_entries.get("hello").unwrap() {
                            NarEntry::Regular {
                                executable,
                                contents_offset,
                                contents_len,
                            } => {
                                assert!(executable);
                                assert_eq!(
                                    &nar[*contents_offset..*contents_offset + *contents_len],
                                    b"#!/bin/sh\necho hello\n"
                                );
                            }
                            other => panic!("Expected Regular hello, got {:?}", other),
                        }
                    }
                    other => panic!("Expected Directory bin, got {:?}", other),
                }
            }
            other => panic!("Expected Directory, got {:?}", other),
        }
    }

    // ── NarArchive tests ────────────────────────────────────────────

    #[test]
    fn archive_parse_regular() {
        let nar = nar_regular_file(b"test data", false);
        let archive = NarArchive::parse(&nar).unwrap();
        assert!(matches!(archive.root, NarEntry::Regular { .. }));
    }

    #[test]
    fn archive_parse_invalid_magic() {
        let mut nar = Vec::new();
        nar.extend_from_slice(&nar_string(b"not-a-nar"));
        nar.extend_from_slice(&nar_string(b"("));
        nar.extend_from_slice(&nar_string(b"type"));
        nar.extend_from_slice(&nar_string(b"regular"));
        nar.extend_from_slice(&nar_string(b"contents"));
        nar.extend_from_slice(&nar_string(b"data"));
        nar.extend_from_slice(&nar_string(b")"));

        assert_eq!(NarArchive::parse(&nar), Err(NarError::InvalidMagic));
    }

    #[test]
    fn archive_parse_empty() {
        assert_eq!(NarArchive::parse(&[]), Err(NarError::InvalidMagic));
    }

    #[test]
    fn archive_lookup_nested() {
        let nar = nar_directory_with_files();
        let archive = NarArchive::parse(&nar).unwrap();

        // Empty path → root.
        let root = archive.lookup("").unwrap();
        assert!(matches!(root, NarEntry::Directory { .. }));

        // README at top level.
        let readme = archive.lookup("README").unwrap();
        match readme {
            NarEntry::Regular { contents_len, .. } => {
                assert_eq!(*contents_len, b"Hello, world!\n".len());
            }
            other => panic!("Expected Regular README, got {:?}", other),
        }

        // Nested: bin/hello.
        let hello = archive.lookup("bin/hello").unwrap();
        match hello {
            NarEntry::Regular { executable, .. } => {
                assert!(executable);
            }
            other => panic!("Expected Regular hello, got {:?}", other),
        }

        // Walk through a file (not a directory).
        assert!(archive.lookup("README/foo").is_none());

        // Nonexistent path.
        assert!(archive.lookup("nonexistent").is_none());
        assert!(archive.lookup("bin/nonexistent").is_none());
    }

    #[test]
    fn archive_rejects_trailing_data() {
        let mut nar = nar_regular_file(b"data", false);
        nar.extend_from_slice(&[0xDE, 0xAD]); // trailing garbage
        assert_eq!(NarArchive::parse(&nar), Err(NarError::TrailingData));
    }

    #[test]
    fn archive_rejects_duplicate_directory_entry() {
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"directory"));
        // First entry named "a"
        buf.extend(nar_string(b"entry"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"name"));
        buf.extend(nar_string(b"a"));
        buf.extend(nar_string(b"node"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b"contents"));
        buf.extend(nar_string(b"first"));
        buf.extend(nar_string(b")"));
        buf.extend(nar_string(b")"));
        // Duplicate entry named "a"
        buf.extend(nar_string(b"entry"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"name"));
        buf.extend(nar_string(b"a"));
        buf.extend(nar_string(b"node"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b"contents"));
        buf.extend(nar_string(b"second"));
        buf.extend(nar_string(b")"));
        buf.extend(nar_string(b")"));
        buf.extend(nar_string(b")"));
        assert_eq!(NarArchive::parse(&buf), Err(NarError::DuplicateEntry));
    }

    #[test]
    fn archive_rejects_out_of_order_entries() {
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"directory"));
        // First entry named "b" (should come second lexicographically)
        buf.extend(nar_string(b"entry"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"name"));
        buf.extend(nar_string(b"b"));
        buf.extend(nar_string(b"node"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b"contents"));
        buf.extend(nar_string(b"first"));
        buf.extend(nar_string(b")"));
        buf.extend(nar_string(b")"));
        // Second entry named "a" (wrong order)
        buf.extend(nar_string(b"entry"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"name"));
        buf.extend(nar_string(b"a"));
        buf.extend(nar_string(b"node"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b"contents"));
        buf.extend(nar_string(b"second"));
        buf.extend(nar_string(b")"));
        buf.extend(nar_string(b")"));
        buf.extend(nar_string(b")"));
        assert_eq!(NarArchive::parse(&buf), Err(NarError::OutOfOrder));
    }

    #[test]
    fn regular_file_rejects_nonzero_content_padding() {
        // Build a regular file with contents "hi" (2 bytes → 6 padding bytes).
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b"contents"));
        // Manually encode contents with non-zero padding.
        let content = b"hi";
        buf.extend_from_slice(&(content.len() as u64).to_le_bytes());
        buf.extend_from_slice(content);
        // 6 padding bytes, but make one non-zero.
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0xFF]);
        buf.extend(nar_string(b")"));
        assert_eq!(NarArchive::parse(&buf), Err(NarError::InvalidString));
    }

    /// Helper: build a directory NAR with a single entry of the given name.
    fn nar_dir_with_name(name: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"directory"));
        buf.extend(nar_string(b"entry"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"name"));
        buf.extend(nar_string(name));
        buf.extend(nar_string(b"node"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b"contents"));
        buf.extend(nar_string(b"x"));
        buf.extend(nar_string(b")"));
        buf.extend(nar_string(b")"));
        buf.extend(nar_string(b")"));
        buf
    }

    #[test]
    fn rejects_entry_name_with_slash() {
        assert_eq!(
            NarArchive::parse(&nar_dir_with_name(b"a/b")),
            Err(NarError::InvalidString)
        );
    }

    #[test]
    fn rejects_entry_name_dot() {
        assert_eq!(
            NarArchive::parse(&nar_dir_with_name(b".")),
            Err(NarError::InvalidString)
        );
    }

    #[test]
    fn rejects_entry_name_dotdot() {
        assert_eq!(
            NarArchive::parse(&nar_dir_with_name(b"..")),
            Err(NarError::InvalidString)
        );
    }

    #[test]
    fn rejects_empty_entry_name() {
        assert_eq!(
            NarArchive::parse(&nar_dir_with_name(b"")),
            Err(NarError::InvalidString)
        );
    }

    #[test]
    fn rejects_entry_name_with_newline() {
        assert_eq!(
            NarArchive::parse(&nar_dir_with_name(b"foo\nbar")),
            Err(NarError::InvalidString)
        );
    }

    #[test]
    fn rejects_entry_name_with_carriage_return() {
        assert_eq!(
            NarArchive::parse(&nar_dir_with_name(b"foo\rbar")),
            Err(NarError::InvalidString)
        );
    }

    #[test]
    fn empty_regular_file_without_contents() {
        // NAR spec: contents field is optional for empty files.
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        // No "contents" — just close immediately.
        buf.extend(nar_string(b")"));
        let archive = NarArchive::parse(&buf).unwrap();
        assert_eq!(
            archive.root,
            NarEntry::Regular {
                executable: false,
                contents_offset: 0,
                contents_len: 0,
            }
        );
    }

    #[test]
    fn empty_executable_file_without_contents() {
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b"executable"));
        buf.extend(nar_string(b""));
        // No "contents" — just close.
        buf.extend(nar_string(b")"));
        let archive = NarArchive::parse(&buf).unwrap();
        assert_eq!(
            archive.root,
            NarEntry::Regular {
                executable: true,
                contents_offset: 0,
                contents_len: 0,
            }
        );
    }

    #[test]
    fn rejects_deeply_nested_directories() {
        // Build a NAR with MAX_NESTING_DEPTH + 2 levels of nesting.
        let depth = MAX_NESTING_DEPTH + 2;
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        for i in 0..depth {
            buf.extend(nar_string(b"("));
            buf.extend(nar_string(b"type"));
            buf.extend(nar_string(b"directory"));
            buf.extend(nar_string(b"entry"));
            buf.extend(nar_string(b"("));
            buf.extend(nar_string(b"name"));
            // Use a unique, ascending name at each level.
            let name = alloc::format!("d{i}");
            buf.extend(nar_string(name.as_bytes()));
            buf.extend(nar_string(b"node"));
        }
        // Innermost node: a regular file.
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b")"));
        // Close all the entry/directory pairs.
        for _ in 0..depth {
            buf.extend(nar_string(b")"));
            buf.extend(nar_string(b")"));
        }
        assert_eq!(NarArchive::parse(&buf), Err(NarError::NestingTooDeep));
    }
}
