# /nix/store Bridge Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Serve Nix store paths as a read-only 9P filesystem via a NAR parser and NixStore FileServer, mounted at `/nix/store` in the process namespace.

**Architecture:** Layer 1 (NAR parser) produces a zero-copy directory tree from NAR bytes. Layer 2 (NixStore FileServer) implements the `FileServer` trait over parsed NARs using `FidTracker`. Layer 3 (mount wiring) registers the server in the kernel and mounts it at `/nix/store`. Read the design doc at `docs/plans/2026-03-11-nix-store-bridge-design.md` for full context.

**Tech Stack:** Rust, `no_std` compatible (`alloc` only), `harmony-microkernel` crate. Pattern reference: `library_server.rs` (simplest read-only FileServer), `content_server.rs` (complex FileServer with multiple node types).

---

## Reference Files

Before starting any task, read these files to understand patterns:

- **FileServer trait:** `crates/harmony-microkernel/src/lib.rs` — trait definition, `Fid`, `QPath`, `IpcError`, `FileType`, `FileStat`, `OpenMode`
- **FidTracker:** `crates/harmony-microkernel/src/fid_tracker.rs` — `FidTracker<T>`, `FidEntry<T>`, `begin_open`, `mark_open`, `insert`, `clunk`, `clone_fid`
- **LibraryServer:** `crates/harmony-microkernel/src/library_server.rs` — simplest read-only FileServer, follow this pattern for read/write/open/clunk/stat
- **Kernel spawn:** `crates/harmony-microkernel/src/kernel.rs` — `spawn_process()` signature (name, server, mounts, vm_config)
- **Namespace:** `crates/harmony-microkernel/src/namespace.rs` — `mount()` and `resolve()` for path routing
- **Crate registration:** `crates/harmony-microkernel/src/lib.rs` — module declarations and feature gates

---

## Task 1: NAR String Parser Helpers

The NAR format uses length-prefixed, 8-byte-aligned strings for all tokens. Build the low-level parsers first.

**Files:**
- Create: `crates/harmony-microkernel/src/nar.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add module declaration)

**Step 1: Write failing tests for string parsing**

Add to `nar.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! NAR (Nix ARchive) parser — zero-copy directory tree from NAR bytes.
//!
//! NAR is Nix's deterministic archive format. Strings are 8-byte LE
//! length-prefixed, padded to 8-byte boundaries. The parser produces
//! a tree of `NarEntry` nodes; regular file entries store offsets into
//! the original NAR blob for zero-copy reads.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

/// Errors from NAR parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarError {
    TooShort,
    InvalidMagic,
    InvalidString,
    UnexpectedToken,
    InvalidType,
    OffsetOverflow,
}

/// Read a NAR length-prefixed string at `pos`. Returns (string_bytes, new_pos).
/// NAR strings: 8-byte LE length, then data, then 0-padding to 8-byte boundary.
fn read_string(data: &[u8], pos: usize) -> Result<(&[u8], usize), NarError> {
    if pos + 8 > data.len() {
        return Err(NarError::TooShort);
    }
    let len = u64::from_le_bytes(
        data[pos..pos + 8].try_into().map_err(|_| NarError::TooShort)?
    ) as usize;
    let start = pos + 8;
    let end = start + len;
    if end > data.len() {
        return Err(NarError::TooShort);
    }
    // Padding to 8-byte boundary
    let padded = (end + 7) & !7;
    let next = padded.min(data.len());
    Ok((&data[start..end], next))
}

/// Read a NAR string and verify it matches `expected`.
fn expect_string(data: &[u8], pos: usize, expected: &[u8]) -> Result<usize, NarError> {
    let (s, next) = read_string(data, pos)?;
    if s != expected {
        return Err(NarError::UnexpectedToken);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NAR string encoding helper for tests: 8-byte LE length + data + padding
    fn nar_string(s: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(s.len() as u64).to_le_bytes());
        out.extend_from_slice(s);
        // Pad to 8-byte boundary
        let pad = (8 - (s.len() % 8)) % 8;
        out.extend(core::iter::repeat(0u8).take(pad));
        out
    }

    #[test]
    fn read_string_basic() {
        let data = nar_string(b"hello");
        let (s, next) = read_string(&data, 0).unwrap();
        assert_eq!(s, b"hello");
        assert_eq!(next, data.len());
    }

    #[test]
    fn read_string_exact_alignment() {
        // "type" is 4 bytes, padded to 8
        let data = nar_string(b"type");
        let (s, next) = read_string(&data, 0).unwrap();
        assert_eq!(s, b"type");
        assert_eq!(next, 16); // 8 (len) + 4 (data) + 4 (pad) = 16
    }

    #[test]
    fn read_string_8_byte_aligned() {
        // "contents" is 8 bytes, no padding needed
        let data = nar_string(b"contents");
        let (s, next) = read_string(&data, 0).unwrap();
        assert_eq!(s, b"contents");
        assert_eq!(next, 16); // 8 (len) + 8 (data) = 16
    }

    #[test]
    fn read_string_truncated() {
        assert_eq!(read_string(&[0; 4], 0), Err(NarError::TooShort));
    }

    #[test]
    fn read_string_length_exceeds_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&100u64.to_le_bytes()); // length = 100
        data.extend_from_slice(&[0; 10]); // only 10 bytes of data
        assert_eq!(read_string(&data, 0), Err(NarError::TooShort));
    }

    #[test]
    fn expect_string_matches() {
        let data = nar_string(b"(");
        let next = expect_string(&data, 0, b"(").unwrap();
        assert_eq!(next, data.len());
    }

    #[test]
    fn expect_string_mismatch() {
        let data = nar_string(b"(");
        assert_eq!(expect_string(&data, 0, b")"), Err(NarError::UnexpectedToken));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel nar::tests -- --nocapture`
Expected: FAIL — module `nar` not declared in `lib.rs`

**Step 3: Register the module**

In `crates/harmony-microkernel/src/lib.rs`, add after the `pub mod namespace;` line:

```rust
pub mod nar;
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel nar::tests`
Expected: all 6 tests PASS

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/nar.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(nar): add NAR string parser helpers with tests"
```

---

## Task 2: NAR Entry Types and Regular File Parsing

Parse `type regular` entries with zero-copy content offsets.

**Files:**
- Modify: `crates/harmony-microkernel/src/nar.rs`

**Step 1: Write failing tests for regular file parsing**

Add to `nar.rs` above the `tests` module:

```rust
/// A parsed NAR filesystem entry.
#[derive(Debug, Clone)]
pub enum NarEntry {
    /// Regular file. Offsets point into the original NAR blob.
    Regular {
        executable: bool,
        contents_offset: usize,
        contents_len: usize,
    },
    /// Symbolic link.
    Symlink {
        target: Arc<str>,
    },
    /// Directory with named children.
    Directory {
        entries: BTreeMap<Arc<str>, NarEntry>,
    },
}

/// A parsed NAR archive.
#[derive(Debug, Clone)]
pub struct NarArchive {
    pub root: NarEntry,
}

/// Parse a single NAR node starting at `pos`.
/// Returns (entry, new_pos).
fn parse_node(data: &[u8], pos: usize) -> Result<(NarEntry, usize), NarError> {
    // expect "("
    let pos = expect_string(data, pos, b"(")?;
    // expect "type"
    let pos = expect_string(data, pos, b"type")?;
    // read type string
    let (type_str, pos) = read_string(data, pos)?;

    match type_str {
        b"regular" => parse_regular(data, pos),
        b"symlink" => parse_symlink(data, pos),
        b"directory" => parse_directory(data, pos),
        _ => Err(NarError::InvalidType),
    }
}

/// Parse a regular file node. `pos` is right after the "regular" type string.
fn parse_regular(data: &[u8], mut pos: usize) -> Result<(NarEntry, usize), NarError> {
    let mut executable = false;

    // Peek at next token — could be "executable", "contents", or ")"
    let (next_tok, after_tok) = read_string(data, pos)?;

    if next_tok == b"executable" {
        executable = true;
        // Read the empty executable marker string
        let (_marker, after_marker) = read_string(data, after_tok)?;
        pos = after_marker;
    } else {
        // Don't consume — let contents/close handle it
    }

    // Now expect "contents" or ")" (empty file)
    let (tok, after_tok2) = if next_tok == b"executable" {
        read_string(data, pos)?
    } else {
        (next_tok, after_tok)
    };

    if tok == b")" {
        // Empty regular file
        return Ok((
            NarEntry::Regular {
                executable,
                contents_offset: 0,
                contents_len: 0,
            },
            after_tok2,
        ));
    }

    if tok != b"contents" {
        return Err(NarError::UnexpectedToken);
    }

    // Read content length, but record offset instead of copying data
    if after_tok2 + 8 > data.len() {
        return Err(NarError::TooShort);
    }
    let content_len = u64::from_le_bytes(
        data[after_tok2..after_tok2 + 8]
            .try_into()
            .map_err(|_| NarError::TooShort)?,
    ) as usize;
    let contents_offset = after_tok2 + 8;
    let content_end = contents_offset
        .checked_add(content_len)
        .ok_or(NarError::OffsetOverflow)?;
    if content_end > data.len() {
        return Err(NarError::TooShort);
    }

    // Skip past content + padding
    let padded = (content_end + 7) & !7;
    let pos = padded.min(data.len());

    // expect closing ")"
    let pos = expect_string(data, pos, b")")?;

    Ok((
        NarEntry::Regular {
            executable,
            contents_offset,
            contents_len: content_len,
        },
        pos,
    ))
}
```

Add these tests:

```rust
    // Helper: build a minimal NAR for a single regular file
    fn nar_regular_file(contents: &[u8], executable: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        if executable {
            buf.extend(nar_string(b"executable"));
            buf.extend(nar_string(b""));
        }
        buf.extend(nar_string(b"contents"));
        buf.extend(nar_string(contents));
        buf.extend(nar_string(b")"));
        buf
    }

    #[test]
    fn parse_regular_file() {
        let nar = nar_regular_file(b"hello world", false);
        // Skip past "nix-archive-1" to the node
        let (_, pos) = read_string(&nar, 0).unwrap(); // skip magic
        let (entry, _) = parse_node(&nar, pos).unwrap();
        match entry {
            NarEntry::Regular { executable, contents_offset, contents_len } => {
                assert!(!executable);
                assert_eq!(contents_len, 11);
                assert_eq!(&nar[contents_offset..contents_offset + contents_len], b"hello world");
            }
            _ => panic!("expected Regular"),
        }
    }

    #[test]
    fn parse_executable_file() {
        let nar = nar_regular_file(b"#!/bin/sh", true);
        let (_, pos) = read_string(&nar, 0).unwrap();
        let (entry, _) = parse_node(&nar, pos).unwrap();
        match entry {
            NarEntry::Regular { executable, contents_offset, contents_len } => {
                assert!(executable);
                assert_eq!(contents_len, 9);
                assert_eq!(&nar[contents_offset..contents_offset + contents_len], b"#!/bin/sh");
            }
            _ => panic!("expected Regular"),
        }
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel nar::tests::parse_regular`
Expected: FAIL — `parse_node` etc. not yet returning correct results (compilation errors until all pieces are in place, or test assertions fail)

**Step 3: Verify both tests pass**

Run: `cargo test -p harmony-microkernel nar::tests`
Expected: all 8 tests PASS (6 prior + 2 new)

**Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/nar.rs
git commit -m "feat(nar): parse regular file entries with zero-copy offsets"
```

---

## Task 3: NAR Symlink and Directory Parsing

Parse `type symlink` and `type directory` entries, completing the recursive parser.

**Files:**
- Modify: `crates/harmony-microkernel/src/nar.rs`

**Step 1: Write failing tests**

Add the parser functions and tests:

```rust
/// Parse a symlink node. `pos` is right after the "symlink" type string.
fn parse_symlink(data: &[u8], pos: usize) -> Result<(NarEntry, usize), NarError> {
    // expect "target"
    let pos = expect_string(data, pos, b"target")?;
    // read target string
    let (target_bytes, pos) = read_string(data, pos)?;
    let target = core::str::from_utf8(target_bytes)
        .map_err(|_| NarError::InvalidString)?;
    // expect ")"
    let pos = expect_string(data, pos, b")")?;
    Ok((NarEntry::Symlink { target: Arc::from(target) }, pos))
}

/// Parse a directory node. `pos` is right after the "directory" type string.
fn parse_directory(data: &[u8], mut pos: usize) -> Result<(NarEntry, usize), NarError> {
    let mut entries = BTreeMap::new();

    loop {
        // Peek: "entry" or ")"
        let (tok, after_tok) = read_string(data, pos)?;
        if tok == b")" {
            return Ok((NarEntry::Directory { entries }, after_tok));
        }
        if tok != b"entry" {
            return Err(NarError::UnexpectedToken);
        }
        pos = after_tok;

        // expect "("
        pos = expect_string(data, pos, b"(")?;
        // expect "name"
        pos = expect_string(data, pos, b"name")?;
        // read name
        let (name_bytes, after_name) = read_string(data, pos)?;
        let name = core::str::from_utf8(name_bytes)
            .map_err(|_| NarError::InvalidString)?;
        pos = after_name;

        // expect "node"
        pos = expect_string(data, pos, b"node")?;

        // Recurse
        let (child, after_child) = parse_node(data, pos)?;
        pos = after_child;

        // expect ")" closing the entry
        pos = expect_string(data, pos, b")")?;

        entries.insert(Arc::from(name), child);
    }
}
```

Add these tests:

```rust
    fn nar_symlink(target: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"symlink"));
        buf.extend(nar_string(b"target"));
        buf.extend(nar_string(target.as_bytes()));
        buf.extend(nar_string(b")"));
        buf
    }

    #[test]
    fn parse_symlink_entry() {
        let nar = nar_symlink("../lib/libfoo.so");
        let (_, pos) = read_string(&nar, 0).unwrap();
        let (entry, _) = parse_node(&nar, pos).unwrap();
        match entry {
            NarEntry::Symlink { target } => {
                assert_eq!(&*target, "../lib/libfoo.so");
            }
            _ => panic!("expected Symlink"),
        }
    }

    // Build a NAR directory with two files: bin/hello (executable) and README
    fn nar_directory_with_files() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(nar_string(b"nix-archive-1"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"directory"));

        // entry: "README" (regular)
        buf.extend(nar_string(b"entry"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"name"));
        buf.extend(nar_string(b"README"));
        buf.extend(nar_string(b"node"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b"contents"));
        buf.extend(nar_string(b"Read me!"));
        buf.extend(nar_string(b")"));  // close node
        buf.extend(nar_string(b")"));  // close entry

        // entry: "bin" (directory with "hello" executable)
        buf.extend(nar_string(b"entry"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"name"));
        buf.extend(nar_string(b"bin"));
        buf.extend(nar_string(b"node"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"directory"));
        // nested entry: "hello"
        buf.extend(nar_string(b"entry"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"name"));
        buf.extend(nar_string(b"hello"));
        buf.extend(nar_string(b"node"));
        buf.extend(nar_string(b"("));
        buf.extend(nar_string(b"type"));
        buf.extend(nar_string(b"regular"));
        buf.extend(nar_string(b"executable"));
        buf.extend(nar_string(b""));
        buf.extend(nar_string(b"contents"));
        buf.extend(nar_string(b"\x7fELF"));
        buf.extend(nar_string(b")"));  // close hello node
        buf.extend(nar_string(b")"));  // close hello entry
        buf.extend(nar_string(b")"));  // close bin node
        buf.extend(nar_string(b")"));  // close bin entry

        buf.extend(nar_string(b")"));  // close root directory
        buf
    }

    #[test]
    fn parse_directory_with_files() {
        let nar = nar_directory_with_files();
        let (_, pos) = read_string(&nar, 0).unwrap();
        let (entry, _) = parse_node(&nar, pos).unwrap();
        match &entry {
            NarEntry::Directory { entries } => {
                assert_eq!(entries.len(), 2);
                assert!(entries.contains_key("README"));
                assert!(entries.contains_key("bin"));

                // Verify README
                match &entries["README"] {
                    NarEntry::Regular { executable, contents_len, contents_offset } => {
                        assert!(!executable);
                        assert_eq!(*contents_len, 8);
                        assert_eq!(&nar[*contents_offset..*contents_offset + *contents_len], b"Read me!");
                    }
                    _ => panic!("expected Regular for README"),
                }

                // Verify bin/hello
                match &entries["bin"] {
                    NarEntry::Directory { entries: bin_entries } => {
                        assert_eq!(bin_entries.len(), 1);
                        match &bin_entries["hello"] {
                            NarEntry::Regular { executable, contents_len, contents_offset } => {
                                assert!(executable);
                                assert_eq!(*contents_len, 4);
                                assert_eq!(&nar[*contents_offset..*contents_offset + *contents_len], b"\x7fELF");
                            }
                            _ => panic!("expected Regular for hello"),
                        }
                    }
                    _ => panic!("expected Directory for bin"),
                }
            }
            _ => panic!("expected Directory"),
        }
    }
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel nar::tests`
Expected: all 10 tests PASS

**Step 3: Commit**

```bash
git add crates/harmony-microkernel/src/nar.rs
git commit -m "feat(nar): parse symlink and directory entries with recursive descent"
```

---

## Task 4: NarArchive::parse and NarArchive::lookup

Wire up the top-level parse function and path-based lookup.

**Files:**
- Modify: `crates/harmony-microkernel/src/nar.rs`

**Step 1: Write failing tests**

Add to `nar.rs` (above tests module):

```rust
impl NarArchive {
    /// Parse a NAR blob into a directory tree.
    pub fn parse(data: &[u8]) -> Result<Self, NarError> {
        let pos = expect_string(data, 0, b"nix-archive-1")
            .map_err(|_| NarError::InvalidMagic)?;
        let (root, _) = parse_node(data, pos)?;
        Ok(NarArchive { root })
    }

    /// Look up an entry by slash-separated path (e.g., "bin/hello").
    /// Empty path returns the root entry.
    pub fn lookup(&self, path: &str) -> Option<&NarEntry> {
        if path.is_empty() {
            return Some(&self.root);
        }
        let mut current = &self.root;
        for component in path.split('/') {
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
```

Add tests:

```rust
    #[test]
    fn archive_parse_regular() {
        let nar = nar_regular_file(b"test data", false);
        let archive = NarArchive::parse(&nar).unwrap();
        match &archive.root {
            NarEntry::Regular { contents_len, .. } => assert_eq!(*contents_len, 9),
            _ => panic!("expected Regular root"),
        }
    }

    #[test]
    fn archive_parse_invalid_magic() {
        let data = nar_string(b"not-a-nar");
        assert_eq!(NarArchive::parse(&data), Err(NarError::InvalidMagic));
    }

    #[test]
    fn archive_parse_empty() {
        assert_eq!(NarArchive::parse(&[]), Err(NarError::InvalidMagic));
    }

    #[test]
    fn archive_lookup_nested() {
        let nar = nar_directory_with_files();
        let archive = NarArchive::parse(&nar).unwrap();

        // Root
        assert!(matches!(archive.lookup(""), Some(NarEntry::Directory { .. })));

        // Direct child
        assert!(matches!(archive.lookup("README"), Some(NarEntry::Regular { .. })));

        // Nested child
        let hello = archive.lookup("bin/hello");
        assert!(matches!(hello, Some(NarEntry::Regular { executable: true, .. })));

        // Nonexistent
        assert!(archive.lookup("nonexistent").is_none());
        assert!(archive.lookup("bin/nonexistent").is_none());

        // Walk through a file (not a directory)
        assert!(archive.lookup("README/foo").is_none());
    }
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel nar::tests`
Expected: all 15 tests PASS

**Step 3: Commit**

```bash
git add crates/harmony-microkernel/src/nar.rs
git commit -m "feat(nar): add NarArchive::parse and lookup with path traversal"
```

---

## Task 5: NixStore FileServer — Skeleton and Import

Create the NixStore server with `import_nar`, walk to store path roots, and stat.

**Files:**
- Create: `crates/harmony-microkernel/src/nix_store_server.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add module declaration)

**Step 1: Write failing tests**

Create `nix_store_server.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! NixStoreServer — read-only 9P file server for `/nix/store`.
//!
//! Serves Nix store paths backed by parsed NAR archives. Each store
//! path is imported as a NAR blob, parsed into a `NarArchive`, and
//! served as a directory tree through the `FileServer` trait.
//!
//! Pattern reference: `library_server.rs` (simplest read-only server).

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fid_tracker::FidTracker;
use crate::nar::{NarArchive, NarEntry, NarError};
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

/// An imported store path: NAR blob + parsed tree.
struct StorePath {
    nar_blob: Vec<u8>,
    archive: NarArchive,
}

/// What a fid points at in the NixStore namespace.
#[derive(Clone)]
enum NixFidPayload {
    /// The /nix/store root directory.
    Root,
    /// A store path root (e.g., /nix/store/<hash>-<name>).
    StorePathRoot { name: Arc<str> },
    /// An entry inside a store path (relative path within the NAR).
    Entry { store_name: Arc<str>, path: Arc<str> },
}

/// Read-only 9P file server serving Nix store paths from NAR archives.
pub struct NixStoreServer {
    store_paths: BTreeMap<Arc<str>, StorePath>,
    tracker: FidTracker<NixFidPayload>,
}

impl NixStoreServer {
    /// Create a new, empty NixStoreServer.
    pub fn new() -> Self {
        Self {
            store_paths: BTreeMap::new(),
            tracker: FidTracker::new(0, NixFidPayload::Root),
        }
    }

    /// Import a NAR archive as a store path.
    ///
    /// `name` is the `<hash>-<name>` string (e.g., "abc123-hello-2.10").
    /// `nar_bytes` is the raw NAR blob.
    pub fn import_nar(&mut self, name: &str, nar_bytes: Vec<u8>) -> Result<(), NarError> {
        let archive = NarArchive::parse(&nar_bytes)?;
        self.store_paths.insert(
            Arc::from(name),
            StorePath {
                nar_blob: nar_bytes,
                archive,
            },
        );
        Ok(())
    }

    /// FNV-1a hash for stable QPath derivation.
    fn qpath_for(s: &str) -> QPath {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in s.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h | 1 // ensure non-zero
    }

    /// Resolve a NixFidPayload to the corresponding NarEntry (if any).
    fn resolve_entry<'a>(&'a self, payload: &NixFidPayload) -> Option<&'a NarEntry> {
        match payload {
            NixFidPayload::Root => None,
            NixFidPayload::StorePathRoot { name } => {
                let sp = self.store_paths.get(name)?;
                Some(&sp.archive.root)
            }
            NixFidPayload::Entry { store_name, path } => {
                let sp = self.store_paths.get(store_name)?;
                sp.archive.lookup(path)
            }
        }
    }

    /// Resolve a NixFidPayload to the store path's NAR blob (if any).
    fn resolve_blob<'a>(&'a self, payload: &NixFidPayload) -> Option<&'a [u8]> {
        let name = match payload {
            NixFidPayload::Root => return None,
            NixFidPayload::StorePathRoot { name } => name,
            NixFidPayload::Entry { store_name, .. } => store_name,
        };
        self.store_paths.get(name).map(|sp| sp.nar_blob.as_slice())
    }
}

impl FileServer for NixStoreServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        let payload = entry.payload.clone();

        let new_payload = match &payload {
            NixFidPayload::Root => {
                // Walking from root: name must be a store path
                if !self.store_paths.contains_key(name) {
                    return Err(IpcError::NotFound);
                }
                NixFidPayload::StorePathRoot { name: Arc::from(name) }
            }
            NixFidPayload::StorePathRoot { name: store_name } => {
                // Walking into a store path — check the NAR root is a directory
                let sp = self.store_paths.get(store_name).ok_or(IpcError::NotFound)?;
                match sp.archive.lookup(name) {
                    Some(_) => NixFidPayload::Entry {
                        store_name: Arc::clone(store_name),
                        path: Arc::from(name),
                    },
                    None => return Err(IpcError::NotFound),
                }
            }
            NixFidPayload::Entry { store_name, path } => {
                // Walking deeper — current must be a directory
                let sp = self.store_paths.get(store_name).ok_or(IpcError::NotFound)?;
                let current = sp.archive.lookup(path).ok_or(IpcError::NotFound)?;
                match current {
                    NarEntry::Directory { entries } => {
                        if !entries.contains_key(name) {
                            return Err(IpcError::NotFound);
                        }
                        let child_path = if path.is_empty() {
                            Arc::from(name)
                        } else {
                            Arc::from(alloc::format!("{}/{}", path, name))
                        };
                        NixFidPayload::Entry {
                            store_name: Arc::clone(store_name),
                            path: child_path,
                        }
                    }
                    _ => return Err(IpcError::NotDirectory),
                }
            }
        };

        let qpath = match &new_payload {
            NixFidPayload::Root => 0,
            NixFidPayload::StorePathRoot { name } => Self::qpath_for(name),
            NixFidPayload::Entry { store_name, path } => {
                Self::qpath_for(&alloc::format!("{}/{}", store_name, path))
            }
        };

        self.tracker.insert(new_fid, qpath, new_payload)?;
        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        if mode != OpenMode::Read {
            return Err(IpcError::ReadOnly);
        }
        entry.mark_open(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }

        let payload = entry.payload.clone();

        match &payload {
            NixFidPayload::Root => {
                // Reading root directory: list store path names
                let listing: Vec<u8> = self
                    .store_paths
                    .keys()
                    .map(|k| alloc::format!("{}\n", k))
                    .collect::<alloc::string::String>()
                    .into_bytes();
                let off = offset as usize;
                if off >= listing.len() {
                    return Ok(Vec::new());
                }
                let end = (off + count as usize).min(listing.len());
                Ok(listing[off..end].to_vec())
            }
            _ => {
                let nar_entry = self.resolve_entry(&payload).ok_or(IpcError::NotFound)?;
                let blob = self.resolve_blob(&payload).ok_or(IpcError::NotFound)?;

                match nar_entry {
                    NarEntry::Regular { contents_offset, contents_len, .. } => {
                        let off = offset as usize;
                        if off >= *contents_len {
                            return Ok(Vec::new());
                        }
                        let end = (off + count as usize).min(*contents_len);
                        let start = contents_offset + off;
                        Ok(blob[start..contents_offset + end].to_vec())
                    }
                    NarEntry::Directory { entries } => {
                        // List directory entries
                        let listing: Vec<u8> = entries
                            .keys()
                            .map(|k| alloc::format!("{}\n", k))
                            .collect::<alloc::string::String>()
                            .into_bytes();
                        let off = offset as usize;
                        if off >= listing.len() {
                            return Ok(Vec::new());
                        }
                        let end = (off + count as usize).min(listing.len());
                        Ok(listing[off..end].to_vec())
                    }
                    NarEntry::Symlink { target } => {
                        let data = target.as_bytes();
                        let off = offset as usize;
                        if off >= data.len() {
                            return Ok(Vec::new());
                        }
                        let end = (off + count as usize).min(data.len());
                        Ok(data[off..end].to_vec())
                    }
                }
            }
        }
    }

    fn write(&mut self, _fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
        Err(IpcError::ReadOnly)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Ok(());
        }
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        let payload = entry.payload.clone();
        let qpath = entry.qpath;

        match &payload {
            NixFidPayload::Root => Ok(FileStat {
                qpath: 0,
                name: Arc::from("store"),
                size: self.store_paths.len() as u64,
                file_type: FileType::Directory,
            }),
            NixFidPayload::StorePathRoot { name } => {
                let nar_entry = self.resolve_entry(&payload).ok_or(IpcError::NotFound)?;
                let file_type = match nar_entry {
                    NarEntry::Directory { .. } => FileType::Directory,
                    NarEntry::Regular { .. } => FileType::Regular,
                    NarEntry::Symlink { .. } => FileType::Regular,
                };
                Ok(FileStat {
                    qpath,
                    name: Arc::clone(name),
                    size: 0,
                    file_type,
                })
            }
            NixFidPayload::Entry { store_name, path } => {
                let nar_entry = self.resolve_entry(&payload).ok_or(IpcError::NotFound)?;
                // Extract final path component for name
                let name = path
                    .rsplit('/')
                    .next()
                    .unwrap_or(path);
                let (file_type, size) = match nar_entry {
                    NarEntry::Directory { entries } => (FileType::Directory, entries.len() as u64),
                    NarEntry::Regular { contents_len, .. } => {
                        (FileType::Regular, *contents_len as u64)
                    }
                    NarEntry::Symlink { target } => (FileType::Regular, target.len() as u64),
                };
                Ok(FileStat {
                    qpath,
                    name: Arc::from(name),
                    size,
                    file_type,
                })
            }
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nar::tests as nar_tests;

    // We can't call nar_tests helpers directly (they're private).
    // Rebuild a test NAR inline.

    /// NAR string encoding helper.
    fn ns(s: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(s.len() as u64).to_le_bytes());
        out.extend_from_slice(s);
        let pad = (8 - (s.len() % 8)) % 8;
        out.extend(core::iter::repeat(0u8).take(pad));
        out
    }

    /// Build a NAR for a store path with: bin/hello (executable) and README.
    fn test_nar() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(ns(b"nix-archive-1"));
        buf.extend(ns(b"("));
        buf.extend(ns(b"type"));
        buf.extend(ns(b"directory"));

        // entry: README
        buf.extend(ns(b"entry"));
        buf.extend(ns(b"("));
        buf.extend(ns(b"name"));
        buf.extend(ns(b"README"));
        buf.extend(ns(b"node"));
        buf.extend(ns(b"("));
        buf.extend(ns(b"type"));
        buf.extend(ns(b"regular"));
        buf.extend(ns(b"contents"));
        buf.extend(ns(b"Read me!"));
        buf.extend(ns(b")"));
        buf.extend(ns(b")"));

        // entry: bin (directory)
        buf.extend(ns(b"entry"));
        buf.extend(ns(b"("));
        buf.extend(ns(b"name"));
        buf.extend(ns(b"bin"));
        buf.extend(ns(b"node"));
        buf.extend(ns(b"("));
        buf.extend(ns(b"type"));
        buf.extend(ns(b"directory"));
        buf.extend(ns(b"entry"));
        buf.extend(ns(b"("));
        buf.extend(ns(b"name"));
        buf.extend(ns(b"hello"));
        buf.extend(ns(b"node"));
        buf.extend(ns(b"("));
        buf.extend(ns(b"type"));
        buf.extend(ns(b"regular"));
        buf.extend(ns(b"executable"));
        buf.extend(ns(b""));
        buf.extend(ns(b"contents"));
        buf.extend(ns(b"\x7fELF"));
        buf.extend(ns(b")"));
        buf.extend(ns(b")"));
        buf.extend(ns(b")"));
        buf.extend(ns(b")"));

        buf.extend(ns(b")"));
        buf
    }

    fn test_server() -> NixStoreServer {
        let mut srv = NixStoreServer::new();
        srv.import_nar("abc123-hello-2.10", test_nar()).unwrap();
        srv
    }

    #[test]
    fn stat_root() {
        let mut srv = test_server();
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "store");
        assert_eq!(st.file_type, FileType::Directory);
        assert_eq!(st.size, 1); // one store path
    }

    #[test]
    fn walk_to_store_path() {
        let mut srv = test_server();
        let qpath = srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        assert_ne!(qpath, 0);
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "abc123-hello-2.10");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn walk_nonexistent_store_path() {
        let mut srv = test_server();
        assert_eq!(srv.walk(0, 1, "nonexistent"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_into_nar_tree() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        srv.walk(1, 2, "bin").unwrap();
        srv.walk(2, 3, "hello").unwrap();

        let st = srv.stat(3).unwrap();
        assert_eq!(&*st.name, "hello");
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.size, 4); // "\x7fELF"
    }

    #[test]
    fn read_file_contents() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        srv.walk(1, 2, "README").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 1024).unwrap();
        assert_eq!(data, b"Read me!");
    }

    #[test]
    fn read_with_offset() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        srv.walk(1, 2, "README").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 5, 100).unwrap();
        assert_eq!(data, b"me!");
    }

    #[test]
    fn read_past_eof() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        srv.walk(1, 2, "README").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 999, 100).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn write_rejected() {
        let mut srv = test_server();
        assert_eq!(srv.write(0, 0, &[0xDE]), Err(IpcError::ReadOnly));
    }

    #[test]
    fn read_without_open() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        srv.walk(1, 2, "README").unwrap();
        assert_eq!(srv.read(2, 0, 100), Err(IpcError::NotOpen));
    }

    #[test]
    fn open_write_mode_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        assert_eq!(srv.open(1, OpenMode::Write), Err(IpcError::ReadOnly));
    }

    #[test]
    fn clunk_releases_fid() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        srv.clunk(1).unwrap();
        assert_eq!(srv.stat(1), Err(IpcError::InvalidFid));
    }

    #[test]
    fn clunk_root_is_no_op() {
        let mut srv = test_server();
        srv.clunk(0).unwrap();
        // Root should still work
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
    }

    #[test]
    fn clone_fid_works() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_ne!(qpath, 0);
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "abc123-hello-2.10");
    }

    #[test]
    fn walk_through_file_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        srv.walk(1, 2, "README").unwrap();
        // README is a file, not a directory
        assert_eq!(srv.walk(2, 3, "foo"), Err(IpcError::NotDirectory));
    }

    #[test]
    fn read_directory_listing() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 4096).unwrap();
        let listing = core::str::from_utf8(&data).unwrap();
        // BTreeMap is sorted, so "README" < "bin"
        assert!(listing.contains("README\n"));
        assert!(listing.contains("bin\n"));
    }

    #[test]
    fn multiple_store_paths() {
        let mut srv = NixStoreServer::new();
        srv.import_nar("abc123-hello-2.10", test_nar()).unwrap();

        // Import a second store path (single file NAR)
        let mut nar2 = Vec::new();
        nar2.extend(ns(b"nix-archive-1"));
        nar2.extend(ns(b"("));
        nar2.extend(ns(b"type"));
        nar2.extend(ns(b"regular"));
        nar2.extend(ns(b"contents"));
        nar2.extend(ns(b"goodbye"));
        nar2.extend(ns(b")"));
        srv.import_nar("def456-bye-1.0", nar2).unwrap();

        // Both accessible
        srv.walk(0, 1, "abc123-hello-2.10").unwrap();
        srv.walk(0, 2, "def456-bye-1.0").unwrap();

        let st = srv.stat(0).unwrap();
        assert_eq!(st.size, 2); // two store paths
    }
}
```

**Step 2: Register the module**

In `crates/harmony-microkernel/src/lib.rs`, add with the `kernel` feature gate (like `content_server` and `library_server`):

```rust
#[cfg(feature = "kernel")]
pub mod nix_store_server;
```

**Step 3: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel nix_store_server::tests`
Expected: all 16 tests PASS

**Step 4: Run clippy**

Run: `cargo clippy -p harmony-microkernel`
Expected: zero warnings

**Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/nix_store_server.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(nix): add NixStoreServer — 9P file server for /nix/store backed by NAR archives"
```

---

## Task 6: NAR Parser — Make test helpers public for reuse

The NAR test helpers (`nar_string`, `nar_regular_file`, `nar_directory_with_files`, etc.) are duplicated in `nix_store_server.rs`. Make the NAR test builder usable from other test modules.

**Files:**
- Modify: `crates/harmony-microkernel/src/nar.rs` (make `nar_string` and builder helpers `pub(crate)` under `#[cfg(test)]`)

**Step 1: Mark helpers as `pub(crate)` in the tests module**

In `nar.rs`, change the test helpers visibility:

```rust
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Make the NAR builder helpers pub(crate) so nix_store_server tests can use them
    pub(crate) fn nar_string(s: &[u8]) -> Vec<u8> { ... }
    pub(crate) fn nar_regular_file(contents: &[u8], executable: bool) -> Vec<u8> { ... }
    pub(crate) fn nar_directory_with_files() -> Vec<u8> { ... }
    pub(crate) fn nar_symlink(target: &str) -> Vec<u8> { ... }
    // ... existing tests unchanged
}
```

Then update `nix_store_server.rs` tests to use these shared helpers instead of the duplicated `ns()` function.

**Step 2: Run all tests**

Run: `cargo test -p harmony-microkernel`
Expected: all tests pass

**Step 3: Commit**

```bash
git add crates/harmony-microkernel/src/nar.rs crates/harmony-microkernel/src/nix_store_server.rs
git commit -m "refactor(nar): share test NAR builders between nar and nix_store_server tests"
```

---

## Task 7: Integration Test — Kernel Mount and Walk

Verify that NixStoreServer works when mounted at `/nix/store` in the kernel's namespace routing.

**Files:**
- Modify: `crates/harmony-microkernel/src/nix_store_server.rs` (add integration test at bottom)

**Step 1: Write the integration test**

This test should:
1. Create a `Kernel` with a NixStoreServer process
2. Spawn a client process with `/nix/store` mounted to the NixStore process
3. Walk `/nix/store/abc123-hello-2.10/bin/hello` through the kernel
4. Open and read, verify contents

Check how existing kernel integration tests work first:

```rust
    #[cfg(test)]
    mod kernel_integration {
        // This test requires the "kernel" feature and kernel test infrastructure.
        // Follow the pattern from content_server.rs or kernel.rs integration tests.
        // The core assertion:
        //   1. kernel.spawn_process("nix-store", Box::new(nix_store_server), &[], None)
        //   2. kernel.spawn_process("client", ..., &[("/nix/store", nix_pid, 0)], None)
        //   3. kernel.walk(client_pid, 0, 1, "abc123-hello-2.10") → OK
        //   4. kernel.walk(client_pid, 1, 2, "bin") → OK
        //   5. kernel.walk(client_pid, 2, 3, "hello") → OK
        //   6. kernel.open(client_pid, 3, Read) → OK
        //   7. kernel.read(client_pid, 3, 0, 1024) → b"\x7fELF"
    }
```

Read `kernel.rs` to find the exact kernel test helpers and method signatures, then write the integration test matching those patterns.

**Step 2: Run the integration test**

Run: `cargo test -p harmony-microkernel nix_store_server::tests::kernel_integration`
Expected: PASS

**Step 3: Commit**

```bash
git add crates/harmony-microkernel/src/nix_store_server.rs
git commit -m "test(nix): add kernel integration test for /nix/store mount and walk"
```

---

## Task 8: Final Quality Gates

**Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: all tests pass

**Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: zero warnings

**Step 3: Run fmt check**

Run: `cargo fmt --all -- --check`
Expected: no formatting issues (fix if any)

**Step 4: Commit any fixes**

If clippy or fmt produced fixes:
```bash
git add -A
git commit -m "style: apply clippy and fmt fixes"
```
