// SPDX-License-Identifier: GPL-2.0-or-later

//! # Harmony Microkernel (Ring 2)
//!
//! Adds three capabilities to the unikernel foundation:
//! - **Process isolation** — cooperative, trait-object-based (hardware paging is future work)
//! - **9P-inspired IPC** — every process implements `FileServer`
//! - **Capability enforcement** — UCAN tokens gate all cross-process IPC

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "kernel")]
pub mod config_server;
#[cfg(feature = "kernel")]
pub mod content_server;
pub mod echo;
#[doc(hidden)] // pub for bench access only — not a stable API
pub mod fid_tracker;
pub mod genet_server;
pub mod gpio_server;
pub mod guest_loader;
pub mod hv_manager;
pub mod hv_server;
#[cfg(feature = "kernel")]
pub mod kernel;
#[cfg(feature = "kernel")]
pub mod library_server;
pub mod namespace;
pub mod nar;
pub mod net_device;
#[cfg(feature = "kernel")]
pub mod nix_store_server;
#[cfg(feature = "kernel")]
pub mod node_config;
pub mod sd_server;
pub mod serial_server;
pub mod uart_server;
pub mod virtio_net_server;
pub mod vm;

#[cfg(feature = "kernel")]
pub mod integrity;
#[cfg(feature = "kernel")]
pub mod key_hierarchy;
#[cfg(feature = "kernel")]
pub mod pq_capability;
#[cfg(feature = "kernel")]
pub mod signed_config;

use alloc::sync::Arc;
use alloc::vec::Vec;

// ── Fundamental identifiers ──────────────────────────────────────────

/// File identifier — a per-session handle to an open or walked file.
pub type Fid = u32;

/// Unique file identity — like an inode number. Stable across opens.
pub type QPath = u64;

// ── Enums ────────────────────────────────────────────────────────────

/// How a file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
}

/// What kind of entry a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    CharDev,
}

/// Errors returned by IPC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    NotFound,
    PermissionDenied,
    NotOpen,
    InvalidFid,
    NotDirectory,
    IsDirectory,
    ReadOnly,
    ResourceExhausted,
    /// The operation conflicts with existing state (e.g. cross-book page
    /// address collision — different content at the same 21-bit address).
    Conflict,
    NotSupported,
    InvalidArgument,
    /// The per-session nonce table is full — no more user-capability
    /// bindings can be accepted until the next reboot.
    NonceLimitExceeded,
    /// The target service is being hot-swapped — retry after a short delay.
    NotReady,
}

// ── File metadata ────────────────────────────────────────────────────

/// Metadata about a file (like 9P's stat).
#[derive(Debug, Clone, PartialEq)]
pub struct FileStat {
    pub qpath: QPath,
    pub name: Arc<str>,
    pub size: u64,
    pub file_type: FileType,
}

// ── FileServer trait ─────────────────────────────────────────────────

/// The heart of Ring 2: every process implements this trait.
///
/// Mirrors 9P2000 semantics (walk, open, read, write, clunk, stat)
/// but uses Rust types instead of wire-format bytes.
pub trait FileServer {
    /// Walk from `fid` to a child named `name`, assigning `new_fid`.
    /// Returns the new file's QPath.
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError>;

    /// Open `fid` with the given mode.
    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError>;

    /// Read up to `count` bytes at `offset` from an open fid.
    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError>;

    /// Write `data` at `offset` to an open fid. Returns bytes written.
    fn write(&mut self, fid: Fid, offset: u64, data: &[u8]) -> Result<u32, IpcError>;

    /// Release a fid (like 9P's clunk).
    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError>;

    /// Stat a fid — returns name, size, type.
    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError>;

    /// Clone a fid — create `new_fid` as a closed duplicate of `fid`.
    /// Equivalent to a 9P walk with zero path components.
    ///
    /// **Must be overridden** by any `FileServer` that will be mounted
    /// as a namespace root; the default returns `NotSupported` to
    /// distinguish "operation unsupported" from `InvalidFid`.
    fn clone_fid(&mut self, _fid: Fid, _new_fid: Fid) -> Result<QPath, IpcError> {
        Err(IpcError::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that FileServer is object-safe (can be used as Box<dyn FileServer>).
    struct NullServer;

    impl FileServer for NullServer {
        fn walk(&mut self, _: Fid, _: Fid, _: &str) -> Result<QPath, IpcError> {
            Err(IpcError::NotFound)
        }
        fn open(&mut self, _: Fid, _: OpenMode) -> Result<(), IpcError> {
            Err(IpcError::InvalidFid)
        }
        fn read(&mut self, _: Fid, _: u64, _: u32) -> Result<Vec<u8>, IpcError> {
            Err(IpcError::InvalidFid)
        }
        fn write(&mut self, _: Fid, _: u64, _: &[u8]) -> Result<u32, IpcError> {
            Err(IpcError::InvalidFid)
        }
        fn clunk(&mut self, _: Fid) -> Result<(), IpcError> {
            Err(IpcError::InvalidFid)
        }
        fn stat(&mut self, _: Fid) -> Result<FileStat, IpcError> {
            Err(IpcError::InvalidFid)
        }
    }

    #[test]
    fn file_server_is_object_safe() {
        let mut server: Box<dyn FileServer> = Box::new(NullServer);
        assert!(server.stat(0).is_err());
    }
}
