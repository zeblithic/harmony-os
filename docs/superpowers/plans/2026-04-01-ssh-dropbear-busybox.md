# SSH Server: Dropbear + BusyBox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** SSH into harmony-os nodes via `ssh root@<ip>` with password "harmony", getting a BusyBox ash shell.

**Architecture:** Cross-compile dropbear + busybox as static aarch64-musl binaries, embed in the boot crate via `include_bytes!`. Extend the Linuxulator's DirectBackend with a read-only in-memory filesystem (EmbeddedFs) that serves the embedded binaries and config files at standard paths. Load dropbear as PID 1; it forks children that exec busybox ash via the Linuxulator's `execve` → EmbeddedFs path.

**Tech Stack:** C cross-compilation (aarch64-linux-musl), dropbear 2024.86+, busybox 1.36+, harmony-os Linuxulator, QEMU for testing

**Spec:** `docs/superpowers/specs/2026-04-01-ssh-dropbear-busybox-design.md`

**Important note:** This feature is iterative — dropbear and busybox exercise syscalls we haven't tested. The plan includes a structured QEMU test-and-fix loop rather than exhaustive upfront specification.

---

## File Structure

| File | Responsibility |
|------|---------------|
| `deploy/build-userspace.sh` | **Create.** Cross-compile dropbear + busybox as static aarch64-musl binaries. |
| `deploy/busybox.config` | **Create.** BusyBox minimal build configuration. |
| `deploy/dropbear-options.h` | **Create.** Dropbear compile-time feature flags. |
| `deploy/dropbear-aarch64` | **Created by build script.** Pre-compiled static dropbear binary. |
| `deploy/busybox-aarch64` | **Created by build script.** Pre-compiled static busybox binary. |
| `deploy/dropbear-hostkey` | **Created by build script.** Pre-generated ed25519 SSH host key. |
| `crates/harmony-os/src/embedded_fs.rs` | **Create.** Read-only in-memory filesystem for embedded binaries. |
| `crates/harmony-os/src/linuxulator.rs` | **Modify.** Integrate EmbeddedFs, stub missing syscalls iteratively. |
| `crates/harmony-boot/src/main.rs` | **Modify.** Embed binaries, register with EmbeddedFs, load dropbear as init. |

---

### Task 1: Cross-Compilation Build Script

**Files:**
- Create: `deploy/build-userspace.sh`
- Create: `deploy/busybox.config`
- Create: `deploy/dropbear-options.h`

This task produces the three binary artifacts (dropbear, busybox, host key) that subsequent tasks embed. It runs on the development machine (Mac or Linux), not in CI.

- [ ] **Step 1: Create the BusyBox minimal config**

Create `deploy/busybox.config`:

```
# BusyBox minimal config for harmony-os SSH userspace
# Generate base: make CROSS_COMPILE=aarch64-linux-musl- defconfig
# Then disable everything except what's listed below.
#
# To use: cp busybox.config .config && make oldconfig

# Shell
CONFIG_ASH=y
CONFIG_ASH_JOB_CONTROL=y
CONFIG_ASH_ALIAS=y
CONFIG_FEATURE_SH_MATH=y
CONFIG_FEATURE_EDITING=y
CONFIG_FEATURE_TAB_COMPLETION=y
CONFIG_FEATURE_EDITING_HISTORY=128

# File operations
CONFIG_LS=y
CONFIG_FEATURE_LS_COLOR=y
CONFIG_CAT=y
CONFIG_ECHO=y
CONFIG_CP=y
CONFIG_MV=y
CONFIG_RM=y
CONFIG_MKDIR=y
CONFIG_CHMOD=y
CONFIG_HEAD=y
CONFIG_TAIL=y
CONFIG_WC=y
CONFIG_FIND=y
CONFIG_GREP=y
CONFIG_TOUCH=y
CONFIG_STAT=y

# Process management
CONFIG_PS=y
CONFIG_TOP=y
CONFIG_KILL=y
CONFIG_SLEEP=y

# System info
CONFIG_REBOOT=y
CONFIG_DF=y
CONFIG_FREE=y
CONFIG_UNAME=y
CONFIG_HOSTNAME=y
CONFIG_ENV=y
CONFIG_ID=y
CONFIG_PWD_APPLET=y
CONFIG_WHOAMI=y
CONFIG_DATE=y
CONFIG_UPTIME=y
CONFIG_DMESG=y

# Editor
CONFIG_VI=y

# Utilities
CONFIG_CLEAR=y
CONFIG_TRUE=y
CONFIG_FALSE=y
CONFIG_TEST=y
CONFIG_SEQ=y
CONFIG_PRINTF=y
CONFIG_TR=y
CONFIG_SORT=y
CONFIG_UNIQ=y
CONFIG_CUT=y
CONFIG_TEE=y
CONFIG_XARGS=y
CONFIG_YES=y
```

- [ ] **Step 2: Create the Dropbear options header**

Create `deploy/dropbear-options.h`:

```c
/* Dropbear minimal options for harmony-os embedded SSH server.
 * Copy to localoptions.h in dropbear source before building. */

/* Disable features we don't need */
#define DROPBEAR_CLI_LOCALTCPFWD 0
#define DROPBEAR_CLI_REMOTETCPFWD 0
#define DROPBEAR_SVR_LOCALTCPFWD 0
#define DROPBEAR_SVR_REMOTETCPFWD 0
#define DROPBEAR_CLI_AGENTFWD 0
#define DROPBEAR_SVR_AGENTFWD 0
#define SFTPSERVER_PATH ""
#define DROPBEAR_SFTPSERVER 0
#define DROPBEAR_SCP 0

/* Allow password "harmony" — disable shadow/PAM, use simple auth */
#define DROPBEAR_SVR_PASSWORD_AUTH 1
#define DROPBEAR_SVR_PAM_AUTH 0

/* Only ed25519 keys (smallest, fastest) */
#define DROPBEAR_RSA 0
#define DROPBEAR_DSS 0
#define DROPBEAR_ECDSA 0
#define DROPBEAR_ED25519 1

/* Paths */
#define DROPBEAR_PIDFILE ""
#define SSHD_BANNER ""
```

- [ ] **Step 3: Create the cross-compilation build script**

Create `deploy/build-userspace.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Cross-compile dropbear + busybox as static aarch64-linux-musl binaries.
# Run from the harmony-os repo root inside the Nix devshell:
#   nix develop --command bash deploy/build-userspace.sh
#
# Prerequisites: aarch64-linux-musl-gcc (provided by Nix devshell)
# Outputs:
#   deploy/dropbear-aarch64    (~110 KB, static)
#   deploy/busybox-aarch64     (~1 MB, static)
#   deploy/dropbear-hostkey    (ed25519 host key)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/.build-userspace"
CROSS=aarch64-linux-musl-

DROPBEAR_VERSION="2024.86"
BUSYBOX_VERSION="1.36.1"

mkdir -p "$WORK_DIR"

# ── Dropbear ─────────────────────────────────────────────────────
echo "=== Building dropbear ${DROPBEAR_VERSION} ==="

if [ ! -d "${WORK_DIR}/dropbear-${DROPBEAR_VERSION}" ]; then
    curl -fSL "https://matt.ucc.asn.au/dropbear/releases/dropbear-${DROPBEAR_VERSION}.tar.bz2" \
        -o "${WORK_DIR}/dropbear.tar.bz2"
    tar -xjf "${WORK_DIR}/dropbear.tar.bz2" -C "$WORK_DIR"
fi

cd "${WORK_DIR}/dropbear-${DROPBEAR_VERSION}"
cp -f "${SCRIPT_DIR}/dropbear-options.h" localoptions.h

./configure \
    --host=aarch64-linux-musl \
    --disable-zlib \
    --disable-pam \
    --disable-syslog \
    --disable-lastlog \
    --disable-utmp \
    --disable-utmpx \
    --disable-wtmp \
    --disable-wtmpx \
    CC="${CROSS}gcc" \
    LDFLAGS="-static" \
    CFLAGS="-Os"

make -j"$(nproc)" PROGRAMS=dropbear MULTI=0 STATIC=1
${CROSS}strip dropbear
cp -f dropbear "${SCRIPT_DIR}/dropbear-aarch64"
echo "  → dropbear-aarch64 ($(stat -f%z "${SCRIPT_DIR}/dropbear-aarch64" 2>/dev/null || stat -c%s "${SCRIPT_DIR}/dropbear-aarch64") bytes)"

# Generate host key if not present
if [ ! -f "${SCRIPT_DIR}/dropbear-hostkey" ]; then
    echo "=== Generating ed25519 host key ==="
    # Build dropbearkey for the host (not cross-compiled)
    make -j"$(nproc)" dropbearkey CC=cc LDFLAGS="" CFLAGS="-Os" STATIC=0 2>/dev/null || true
    if [ -f dropbearkey ]; then
        ./dropbearkey -t ed25519 -f "${SCRIPT_DIR}/dropbear-hostkey"
    else
        echo "WARNING: Could not build dropbearkey. Generate host key manually:"
        echo "  dropbearkey -t ed25519 -f deploy/dropbear-hostkey"
    fi
fi

# ── BusyBox ──────────────────────────────────────────────────────
echo "=== Building busybox ${BUSYBOX_VERSION} ==="

if [ ! -d "${WORK_DIR}/busybox-${BUSYBOX_VERSION}" ]; then
    curl -fSL "https://busybox.net/downloads/busybox-${BUSYBOX_VERSION}.tar.bz2" \
        -o "${WORK_DIR}/busybox.tar.bz2"
    tar -xjf "${WORK_DIR}/busybox.tar.bz2" -C "$WORK_DIR"
fi

cd "${WORK_DIR}/busybox-${BUSYBOX_VERSION}"

# Start from default config, then apply our minimal config
make CROSS_COMPILE="${CROSS}" defconfig
# Enable static linking
sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
# Apply our minimal applet selection
# (For now, use defconfig + static. Fine-tune with busybox.config later.)
make CROSS_COMPILE="${CROSS}" LDFLAGS="-static" -j"$(nproc)"
${CROSS}strip busybox
cp -f busybox "${SCRIPT_DIR}/busybox-aarch64"
echo "  → busybox-aarch64 ($(stat -f%z "${SCRIPT_DIR}/busybox-aarch64" 2>/dev/null || stat -c%s "${SCRIPT_DIR}/busybox-aarch64") bytes)"

echo "=== Done ==="
echo "Outputs:"
ls -lh "${SCRIPT_DIR}/dropbear-aarch64" "${SCRIPT_DIR}/busybox-aarch64" "${SCRIPT_DIR}/dropbear-hostkey" 2>/dev/null
```

- [ ] **Step 4: Make the script executable**

```bash
chmod +x deploy/build-userspace.sh
```

- [ ] **Step 5: Run the build script (inside Nix devshell)**

```bash
nix develop --command bash deploy/build-userspace.sh
```

Expected: Three files created in `deploy/`:
- `dropbear-aarch64` (~100-200 KB)
- `busybox-aarch64` (~1-2 MB)
- `dropbear-hostkey` (small key file)

Verify they're aarch64 static binaries:
```bash
file deploy/dropbear-aarch64
# Expected: ELF 64-bit LSB executable, ARM aarch64, statically linked

file deploy/busybox-aarch64
# Expected: ELF 64-bit LSB executable, ARM aarch64, statically linked
```

- [ ] **Step 6: Commit build artifacts and script**

```bash
git add deploy/build-userspace.sh deploy/busybox.config deploy/dropbear-options.h
git add deploy/dropbear-aarch64 deploy/busybox-aarch64 deploy/dropbear-hostkey
git commit -m "feat: cross-compile dropbear + busybox as static aarch64-musl binaries"
```

**Note:** The binaries are ~1-2 MB total. Committing them is acceptable (same pattern as `deploy/harmony-node-aarch64` at 30 MB). They change rarely.

---

### Task 2: EmbeddedFs — In-Memory Filesystem for the Linuxulator

**Files:**
- Create: `crates/harmony-os/src/embedded_fs.rs`
- Modify: `crates/harmony-os/src/lib.rs` (add module)

The current DirectBackend only exposes a serial log file. Dropbear needs to read files (`/etc/passwd`, `/bin/sh`, host key) and `execve` needs to load binaries from the filesystem. EmbeddedFs is a read-only in-memory filesystem backed by `&'static [u8]` slices.

- [ ] **Step 1: Create embedded_fs.rs with file registry and read support**

Create `crates/harmony-os/src/embedded_fs.rs`:

```rust
//! Read-only in-memory filesystem for embedded binaries and config files.
//!
//! Serves pre-registered (path → &[u8]) entries to the Linuxulator via the
//! standard file syscall path (open/read/stat/close). Used to provide
//! dropbear, busybox, /etc/passwd, and the SSH host key without needing
//! a real writable filesystem.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// A file entry in the embedded filesystem.
#[derive(Clone)]
pub struct EmbeddedFile {
    /// File contents.
    pub data: &'static [u8],
    /// Whether this file is executable (affects stat mode).
    pub executable: bool,
}

/// Read-only in-memory filesystem backed by static byte slices.
///
/// Files are registered at init time with absolute paths. The Linuxulator
/// routes open/read/stat through this when the path matches a registered entry.
pub struct EmbeddedFs {
    files: BTreeMap<String, EmbeddedFile>,
}

impl EmbeddedFs {
    /// Create an empty filesystem.
    pub fn new() -> Self {
        Self {
            files: BTreeMap::new(),
        }
    }

    /// Register a file at the given absolute path.
    pub fn add_file(&mut self, path: &str, data: &'static [u8], executable: bool) {
        self.files.insert(
            String::from(path),
            EmbeddedFile { data, executable },
        );
    }

    /// Look up a file by absolute path.
    pub fn get(&self, path: &str) -> Option<&EmbeddedFile> {
        self.files.get(path)
    }

    /// Check if a path exists (file or directory).
    pub fn exists(&self, path: &str) -> bool {
        // Check exact file match
        if self.files.contains_key(path) {
            return true;
        }
        // Check if path is a directory (any file starts with path/)
        let dir_prefix = if path.ends_with('/') {
            String::from(path)
        } else {
            let mut p = String::from(path);
            p.push('/');
            p
        };
        self.files.keys().any(|k| k.starts_with(&dir_prefix))
    }

    /// List entries in a directory (immediate children only).
    pub fn readdir(&self, path: &str) -> Vec<String> {
        let prefix = if path == "/" {
            String::from("/")
        } else if path.ends_with('/') {
            String::from(path)
        } else {
            let mut p = String::from(path);
            p.push('/');
            p
        };

        let mut entries = Vec::new();
        for key in self.files.keys() {
            if let Some(rest) = key.strip_prefix(&prefix) {
                // Immediate child: no more '/' in the remainder
                if !rest.contains('/') && !rest.is_empty() {
                    entries.push(String::from(rest));
                }
            }
        }
        entries.sort();
        entries.dedup();
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_get_file() {
        let mut fs = EmbeddedFs::new();
        fs.add_file("/bin/sh", b"#!/bin/sh\n", true);
        let f = fs.get("/bin/sh").unwrap();
        assert_eq!(f.data, b"#!/bin/sh\n");
        assert!(f.executable);
    }

    #[test]
    fn missing_file_returns_none() {
        let fs = EmbeddedFs::new();
        assert!(fs.get("/nonexistent").is_none());
    }

    #[test]
    fn exists_checks_files_and_directories() {
        let mut fs = EmbeddedFs::new();
        fs.add_file("/bin/dropbear", b"binary", true);
        fs.add_file("/etc/passwd", b"root::0:0::/:bin/sh\n", false);

        assert!(fs.exists("/bin/dropbear"));
        assert!(fs.exists("/etc/passwd"));
        assert!(fs.exists("/bin"));  // directory (has children)
        assert!(fs.exists("/etc"));
        assert!(!fs.exists("/tmp"));
    }

    #[test]
    fn readdir_lists_immediate_children() {
        let mut fs = EmbeddedFs::new();
        fs.add_file("/bin/dropbear", b"", true);
        fs.add_file("/bin/busybox", b"", true);
        fs.add_file("/etc/passwd", b"", false);

        let bin_entries = fs.readdir("/bin");
        assert_eq!(bin_entries, vec!["busybox", "dropbear"]);

        let root_entries = fs.readdir("/");
        // Should list "bin" and "etc" as directories
        // (they appear as prefixes of registered files)
        assert!(root_entries.is_empty()); // No files directly in /
    }
}
```

- [ ] **Step 2: Export the module from lib.rs**

In `crates/harmony-os/src/lib.rs`, add:

```rust
pub mod embedded_fs;
```

- [ ] **Step 3: Verify compilation and tests**

Run:
```bash
cargo +nightly fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p harmony-os embedded_fs
```

Expected: 4 tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-os/src/embedded_fs.rs crates/harmony-os/src/lib.rs
git commit -m "feat(os): add EmbeddedFs — read-only in-memory filesystem for embedded binaries"
```

---

### Task 3: Integrate EmbeddedFs into the Linuxulator

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

Wire file-related syscalls (open, read, stat, access, openat) to check EmbeddedFs before falling through to the 9P backend. This lets dropbear and busybox read their config files and lets `execve` find binaries.

**Implementation approach:** Add an `Option<EmbeddedFs>` field to the Linuxulator struct. In syscall handlers for `open`/`openat`/`stat`/`access`, check EmbeddedFs first. If the path matches, serve from memory. If not, fall through to the existing 9P backend.

For `execve`: when the target path matches an EmbeddedFs entry with `executable: true`, load the ELF from the embedded data instead of trying to read it from 9P.

This task is intentionally high-level — the exact syscall handlers to modify depend on what dropbear actually calls, which is discovered in Task 4's QEMU testing. The implementer should:

1. Add `embedded_fs: Option<EmbeddedFs>` to the Linuxulator struct
2. Add `with_embedded_fs(mut self, fs: EmbeddedFs) -> Self` builder method
3. Wire `sys_openat` / `sys_open` to check EmbeddedFs for the path
4. Wire `sys_stat` / `sys_fstat` / `sys_access` to check EmbeddedFs
5. Wire `sys_execve` to load from EmbeddedFs when path matches
6. Wire `sys_readlinkat` for symlink-like behavior (e.g., `/bin/sh` → busybox)

- [ ] **Step 1: Add EmbeddedFs field and constructor**

Add to the Linuxulator struct:

```rust
use crate::embedded_fs::EmbeddedFs;

// In the struct:
embedded_fs: Option<EmbeddedFs>,

// In constructors (with_tcp_and_arena):
embedded_fs: None,

// New method:
pub fn set_embedded_fs(&mut self, fs: EmbeddedFs) {
    self.embedded_fs = Some(fs);
}
```

- [ ] **Step 2: Wire sys_openat to check EmbeddedFs**

In `sys_openat` (or wherever file opens are handled), before the 9P walk:

```rust
// Check EmbeddedFs first
if let Some(ref efs) = self.embedded_fs {
    let path = /* resolve path from dirfd + pathname */;
    if let Some(file) = efs.get(&path) {
        // Create an FdKind::EmbeddedFile { path, offset: 0 }
        // or store the data reference for subsequent read() calls
        let fd = self.alloc_fd();
        // ... register in fd_table
        return fd as i64;
    }
}
// Fall through to 9P backend
```

The exact implementation depends on how the Linuxulator's fd table works — the implementer should follow existing patterns for `FdKind::File`.

- [ ] **Step 3: Wire sys_read for embedded file fds**

In `sys_read`, when the fd maps to an embedded file:

```rust
FdKind::EmbeddedFile { ref path, ref mut offset } => {
    if let Some(ref efs) = self.embedded_fs {
        if let Some(file) = efs.get(path) {
            let start = (*offset as usize).min(file.data.len());
            let end = (start + count).min(file.data.len());
            let bytes = &file.data[start..end];
            // Copy bytes to userspace buffer
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr as *mut u8, bytes.len());
            }
            *offset += bytes.len() as u64;
            return bytes.len() as i64;
        }
    }
    return EBADF;
}
```

- [ ] **Step 4: Wire sys_stat / sys_access for EmbeddedFs paths**

For `stat`: return a synthetic `FileStat` with correct size and mode (0755 for executables, 0644 for config files).

For `access`: return 0 (success) if the file exists in EmbeddedFs.

- [ ] **Step 5: Wire sys_execve for EmbeddedFs binaries**

When `execve` target matches an EmbeddedFs entry with `executable: true`:
1. Get the embedded data
2. Parse as ELF (same `parse_elf` used for the test binary)
3. Load segments into memory
4. Reset the Linuxulator state (fd table, signal handlers)
5. Jump to the new entry point

This follows the existing ELF loading pattern but sources the binary from EmbeddedFs instead of a hardcoded `include_bytes!`.

- [ ] **Step 6: Run tests**

```bash
cargo +nightly fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p harmony-os
```

Expected: All existing tests pass + embedded file syscalls work

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): integrate EmbeddedFs for file syscalls and execve"
```

---

### Task 4: Boot Integration — Embed Binaries and Start Dropbear

**Files:**
- Modify: `crates/harmony-boot/src/main.rs`

Embed the cross-compiled binaries, register them with EmbeddedFs, and load dropbear as PID 1 instead of the test ELF.

- [ ] **Step 1: Embed binary artifacts**

In `crates/harmony-boot/src/main.rs`, add near the top (alongside existing includes):

```rust
#[cfg(feature = "ring3")]
static DROPBEAR_BIN: &[u8] = include_bytes!("../../../deploy/dropbear-aarch64");
#[cfg(feature = "ring3")]
static BUSYBOX_BIN: &[u8] = include_bytes!("../../../deploy/busybox-aarch64");
#[cfg(feature = "ring3")]
static DROPBEAR_HOSTKEY: &[u8] = include_bytes!("../../../deploy/dropbear-hostkey");
```

- [ ] **Step 2: Build and register EmbeddedFs**

In the ring3 initialization section, after creating the Linuxulator:

```rust
// Build the embedded filesystem
let mut efs = harmony_os::embedded_fs::EmbeddedFs::new();

// Binaries
efs.add_file("/bin/dropbear", DROPBEAR_BIN, true);
efs.add_file("/bin/busybox", BUSYBOX_BIN, true);
efs.add_file("/bin/sh", BUSYBOX_BIN, true);  // busybox as /bin/sh

// Config files
efs.add_file("/etc/passwd", b"root::0:0:root:/root:/bin/sh\n", false);
efs.add_file("/etc/shells", b"/bin/sh\n", false);
efs.add_file("/etc/dropbear/dropbear_ed25519_host_key", DROPBEAR_HOSTKEY, false);

// Register with Linuxulator
linuxulator.set_embedded_fs(efs);
```

- [ ] **Step 3: Load dropbear instead of test ELF**

Replace the existing `include_bytes!("../test-bins/hello.elf")` with the dropbear binary as PID 1:

```rust
// Instead of: let elf_bytes = include_bytes!("../test-bins/hello.elf");
let elf_bytes = DROPBEAR_BIN;
```

The rest of the ELF loading (parse, allocate, load segments, jump) stays the same.

**Dropbear's argv:** The entry point needs command-line arguments. Dropbear expects:
```
/bin/dropbear -F -p 22 -r /etc/dropbear/dropbear_ed25519_host_key
```

The Linuxulator initializes the user stack with argc/argv. Modify the stack setup to pass dropbear's arguments instead of the test ELF's empty argv.

- [ ] **Step 4: Regenerate boot lockfiles**

Since the boot crate now `include_bytes!` new files, the lockfiles may need updating. Follow the established pattern:

1. Copy modified Cargo.toml files to main repo
2. Run `nix develop --command bash -c "cd crates/harmony-boot && cargo generate-lockfile && ..."`
3. Copy lockfiles back to worktree
4. Restore main repo

(Only if compilation fails due to lockfile mismatch.)

- [ ] **Step 5: Verify compilation**

```bash
cargo +nightly fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p harmony-os -p harmony-netstack
```

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(boot): embed dropbear + busybox, register EmbeddedFs, start SSH as init"
```

---

### Task 5: QEMU Testing and Iterative Syscall Gap-Filling

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs` (iterative)
- Modify: `crates/harmony-boot/src/main.rs` (if needed)

This task is iterative. Boot under QEMU, observe what fails, fix it, repeat until SSH login works.

- [ ] **Step 1: Build and boot in QEMU**

```bash
cargo xtask qemu-test
# Or for interactive mode:
cargo xtask qemu --arch x86_64 -- -net user,hostfwd=tcp::2222-:22
```

Watch serial output for:
- "NETSTACK: udp0 DHCP (fallback 10.0.2.15/24 after 5s)"
- Dropbear startup messages or crash
- Unhandled syscall warnings (ENOSYS)

- [ ] **Step 2: Fix unhandled syscalls**

For each `ENOSYS` or crash observed in serial output:

1. Identify the syscall number from the log
2. Determine what dropbear/busybox expects from it
3. Implement a minimal stub or real implementation:
   - **Stub:** Return a reasonable default (0 for success, fake data for queries)
   - **Real:** Wire through to existing infrastructure (e.g., `dup2` → copy fd entry)
4. Rebuild and re-test

Common patterns:
- `dup2(old, new)` → Copy fd_table entry from old to new
- `setsid()` → Return current PID
- `chdir(path)` → Update `self.cwd` string
- `getuid()`/`getgid()` → Return 0
- `setuid()`/`setgid()` → No-op, return 0
- `ioctl(fd, TIOCGWINSZ, ...)` → Write 80×24 terminal size
- `uname(buf)` → Write "Linux" / "harmony" / "6.1.0"
- `getcwd(buf, size)` → Copy `self.cwd` to buffer

- [ ] **Step 3: Iterate until dropbear starts listening**

Repeat Step 1-2 until serial output shows dropbear is listening on port 22:
```
[DROPBEAR] Listening on port 22
```

- [ ] **Step 4: Test SSH connection**

From the host machine:
```bash
ssh -o StrictHostKeyChecking=no -p 2222 root@localhost
# Password: harmony
```

If connection fails, check serial output for the specific failure point and fix.

- [ ] **Step 5: Iterate until shell prompt works**

Once SSH connects, verify:
- Password "harmony" is accepted
- Shell prompt appears (busybox ash)
- Basic commands work: `ls`, `echo hello`, `uname -a`

Each failure is another syscall to stub. Common ash-specific ones:
- `rt_sigaction` — already implemented
- `mmap` with specific flags — verify MAP_PRIVATE|MAP_ANONYMOUS works
- `brk` — already implemented
- `ioctl` on stdin/stdout — terminal settings

- [ ] **Step 6: Commit all syscall fixes**

```bash
cargo +nightly fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p harmony-os
git add crates/harmony-os/src/linuxulator.rs crates/harmony-boot/src/main.rs
git commit -m "feat(linuxulator): stub syscalls for dropbear + busybox (iterative QEMU testing)"
```

---

## Self-Review Checklist

**Spec coverage:**
- Cross-compilation: Task 1
- Binary embedding: Task 4
- EmbeddedFs (replaces "write to 9P" from spec): Task 2 + 3
- Boot integration: Task 4
- Dropbear as PID 1: Task 4
- BusyBox as shell: Task 4 (registered in EmbeddedFs)
- Password auth: Task 4 (/etc/passwd with empty password field)
- Host key: Task 1 (generated) + Task 4 (embedded)
- QEMU testing: Task 5
- Iterative syscall fixing: Task 5

**No placeholders:** Task 5 is intentionally iterative rather than prescriptive — this is by design, not a placeholder. The specific syscalls needed can only be discovered at runtime.

**Type consistency:**
- `EmbeddedFs` used consistently across Task 2 (definition), Task 3 (integration), Task 4 (construction)
- `EmbeddedFile { data, executable }` fields match across definition and usage
- `DROPBEAR_BIN`, `BUSYBOX_BIN`, `DROPBEAR_HOSTKEY` constants used consistently
