# SSH Server: Dropbear + BusyBox for Remote Access

**Beads:** harmony-os-l5r (SSH server), harmony-os-3t6 (static shell/busybox)
**Date:** 2026-04-01
**Status:** Draft

## Problem

harmony-os nodes (RPi5 fleet) have TCP networking and DHCP but no way to
log in remotely. Every management task requires physical HDMI + keyboard
access. SSH is the standard solution for headless Linux system management.

## Solution

Cross-compile dropbear (lightweight SSH server) and BusyBox (shell + coreutils)
as static aarch64-linux-musl binaries. Embed both in the boot crate. At boot,
write them to the 9P filesystem and exec dropbear as PID 1. Users SSH in with
password "harmony" and get a BusyBox ash shell.

## Architecture

### Cross-Compilation

Two static binaries, cross-compiled with the musl toolchain already available
in the Nix devshell (`pkgsCross.aarch64-multiplatform-musl`):

**Dropbear** (~110KB static):
- Minimal config: server only, no SCP, no forwarding, no SFTP
- Password authentication only (hardcoded "harmony")
- Ed25519 host key embedded at build time
- Compiled with: `CC=aarch64-linux-musl-gcc`, `LDFLAGS=-static`
- Key build flags: `PROGRAMS=dropbear`, `MULTI=0`
- Disable features: `#define DROPBEAR_CLI_LOCALTCPFWD 0`, etc.

**BusyBox** (~1MB static):
- Minimal config covering interactive management needs:
  - Shell: `ash`
  - File ops: `ls`, `cat`, `echo`, `cp`, `mv`, `rm`, `mkdir`, `chmod`, `head`,
    `tail`, `wc`, `find`, `grep`
  - Process: `ps`, `top`, `kill`, `sleep`
  - System: `reboot`, `df`, `free`, `uname`, `hostname`, `env`, `id`, `pwd`,
    `whoami`, `date`
  - Editor: `vi`
- No networking utilities (curl, wget, nc) — the mesh handles file distribution
- Compiled with: `CROSS_COMPILE=aarch64-linux-musl-`, `LDFLAGS=-static`

**Build script:** `deploy/build-userspace.sh` orchestrates the cross-compilation.
Downloads dropbear + busybox source, applies minimal configs, cross-compiles,
strips, and places binaries at `deploy/dropbear-aarch64` and `deploy/busybox-aarch64`.

### Embedding in the Kernel

Both binaries and the host key are embedded in the boot crate:

```rust
static DROPBEAR: &[u8] = include_bytes!("../../../deploy/dropbear-aarch64");
static BUSYBOX: &[u8] = include_bytes!("../../../deploy/busybox-aarch64");
static HOST_KEY: &[u8] = include_bytes!("../../../deploy/dropbear-hostkey");
```

The `deploy/` directory is already used for pre-built binaries (e.g.,
`deploy/harmony-node-aarch64` in the NixOS flake). This follows the same
pattern.

### Boot Sequence (ring3 path)

After the existing DHCP + TCP initialization:

1. **Write binaries to 9P filesystem:**
   - `/bin/dropbear` ← DROPBEAR bytes, mode 0755
   - `/bin/busybox` ← BUSYBOX bytes, mode 0755
   - `/bin/sh` ← symlink to `/bin/busybox` (or copy if symlinks unsupported)

2. **Write config files:**
   - `/etc/passwd` — `root:x:0:0:root:/root:/bin/sh` (password checked by
     dropbear via its own mechanism, not /etc/shadow)
   - `/etc/shells` — `/bin/sh`
   - `/etc/dropbear/dropbear_ed25519_host_key` ← HOST_KEY bytes

3. **Exec dropbear as PID 1:**
   - Command: `/bin/dropbear -F -p 22 -r /etc/dropbear/dropbear_ed25519_host_key`
   - `-F` = foreground (stay as PID 1, don't daemonize)
   - `-p 22` = listen on TCP port 22
   - `-r` = host key path

4. **On SSH connection:**
   - Dropbear calls `accept()` on its TCP listening socket
   - Forks a child process (`fork` + `execve`)
   - Child execs `/bin/sh` (BusyBox ash)
   - Parent continues listening for more connections

### Dropbear Password Authentication

Dropbear checks passwords via `crypt()` comparison against `/etc/passwd` or
`/etc/shadow`. For v1, the simplest approach:

- `/etc/passwd` contains `root::0:0:root:/root:/bin/sh` (empty password field)
- Dropbear is compiled with `DROPBEAR_ALLOW_BLANK_PASSWORD` or a custom auth
  callback that accepts "harmony"
- Alternative: embed a pre-computed crypt hash for "harmony" in `/etc/passwd`

The exact mechanism depends on which is simpler to get working with the
Linuxulator's syscall support. The iterative testing approach will determine
the path of least resistance.

### Linuxulator Syscall Requirements

Dropbear and BusyBox need syscalls beyond what the test ELF exercises. Rather
than predicting every syscall upfront, the implementation uses an iterative
approach:

1. Boot under QEMU with dropbear embedded
2. Watch serial log for `ENOSYS` / unhandled syscall warnings
3. Stub or implement the missing syscall
4. Rebuild and re-test
5. Repeat until SSH login works

**Expected gaps** (based on dropbear/busybox behavior):

| Syscall | Purpose | Implementation |
|---------|---------|---------------|
| `fork`/`clone` | Per-session child | Already partially implemented |
| `execve` | Exec shell | Already implemented |
| `dup2` | Redirect stdio to socket | Stub: copy fd entry |
| `setsid` | New session leader | Stub: return PID |
| `chdir` | Change to home dir | Stub: update cwd string |
| `getuid`/`getgid` | User identity | Return 0 (root) |
| `setuid`/`setgid` | Drop privileges | No-op (already root) |
| `access`/`stat` on files | Check file existence | Route through 9P |
| `pipe` | Parent-child IPC | Already implemented |
| `wait4`/`waitpid` | Reap children | Already implemented |
| `fcntl` | Set FD_CLOEXEC | Partially implemented |
| `ioctl` TIOCGWINSZ | Terminal window size | Stub: return 80x24 |
| `getpid`/`getppid` | Process identity | Already implemented |
| `uname` | System identification | Stub: return "Harmony" |
| `mmap`/`mprotect` | Memory management | Already implemented |
| `openat` | Open files | Route through 9P |
| `getcwd` | Current directory | Return cwd string |
| `sigaction`/`rt_sigaction` | Signal handling | Already implemented |

Most of these are already stubbed or implemented. The iterative approach
catches anything unexpected.

### Network Path

```
SSH client (host machine)
    ↓ TCP SYN to port 22
QEMU virtio-net / RPi5 GENET
    ↓ Ethernet frame
smoltcp (NetStack)
    ↓ TCP socket in SocketSet
TcpProvider → Linuxulator accept()
    ↓ fd for accepted connection
dropbear → fork() → dup2(fd, 0/1/2) → execve("/bin/sh")
    ↓
BusyBox ash ← reads stdin (from TCP socket)
             → writes stdout (to TCP socket)
```

### Host Key

A single ed25519 host key is generated at build time and embedded in all
nodes. This means all nodes have the same SSH fingerprint — acceptable for
a proof-of-concept where the nodes are on a trusted LAN.

Generate with: `dropbearkey -t ed25519 -f deploy/dropbear-hostkey`

**Follow-up:** Per-node host keys derived from the node's Harmony identity
(each node already has a unique PqPrivateIdentity).

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `deploy/build-userspace.sh` | Cross-compile script for dropbear + busybox |
| `deploy/dropbear-aarch64` | Pre-compiled static dropbear binary |
| `deploy/busybox-aarch64` | Pre-compiled static busybox binary |
| `deploy/dropbear-hostkey` | Pre-generated ed25519 SSH host key |
| `deploy/busybox.config` | BusyBox minimal build configuration |
| `deploy/dropbear-options.h` | Dropbear compile-time feature config |

### Modified Files

| File | Change |
|------|--------|
| `crates/harmony-boot/src/main.rs` | Embed binaries, write to 9P, exec dropbear as init |
| `crates/harmony-os/src/linuxulator.rs` | Stub missing syscalls (iterative) |

## Testing

**QEMU-based, not unit-testable.** The test flow:

1. Cross-compile dropbear + busybox via `deploy/build-userspace.sh`
2. Build kernel: `cargo xtask build` (includes embedded binaries)
3. Boot in QEMU with port forwarding: `-net user,hostfwd=tcp::2222-:22`
4. Watch serial log for dropbear startup ("Listening on port 22")
5. `ssh root@localhost -p 2222` with password "harmony"
6. Verify: interactive ash prompt, basic commands work

**CI:** The QEMU boot test can verify dropbear starts (check serial output)
without interactive SSH. Full SSH testing is manual.

**Iterative syscall verification:** Each QEMU boot run exercises the syscall
path. Failed syscalls appear in serial log → fix → rebuild → re-test.

## What is NOT in Scope

- **SCP/SFTP** — use CAS for file distribution
- **Port forwarding** — not needed for management
- **Public key authentication** — follow-up bead harmony-os-g7v
- **Per-node host keys** — all nodes share one key for v1
- **Init system / process supervision** — dropbear IS PID 1
- **Multiple users** — root only
- **Terminal emulation (PTY)** — if dropbear needs /dev/ptmx, we stub it.
  BusyBox ash can work with raw stdin/stdout from the socket fd.
- **Exhaustive busybox applet testing** — fix what we hit, don't test everything
- **Security hardening** — proof-of-concept, trusted LAN only

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Dropbear can't bind port 22 | Serial log error, PID 1 exits (kernel idle) |
| Fork fails (memory) | Dropbear logs error, connection rejected |
| Unhandled syscall | Returns ENOSYS, serial log warning (iterative fix target) |
| Bad password | Dropbear rejects, SSH client shows "Permission denied" |
| Network unreachable (no DHCP, no fallback) | Dropbear binds but no connections arrive |
| Shell command not found | BusyBox returns "applet not found" |
