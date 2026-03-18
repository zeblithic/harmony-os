# QEMU Test Harness — Design

**Date:** 2026-03-18
**Status:** Proposed
**Bead:** harmony-os-5yz

## Problem

harmony-os builds bootable kernels for x86_64 and aarch64, but there's no automated way to verify they actually boot. The only testing is `cargo test --workspace` which validates logic on the host — it never runs the kernel in a VM. A regression that breaks boot (wrong linker flags, broken serial init, panic in early boot) would go undetected until someone manually launches QEMU.

## Solution

A `cargo xtask qemu-test` command that builds each kernel, boots it in QEMU, captures serial output, and verifies boot milestones are reached. Pass/fail exit code for CI.

## Scope

**In scope:**
- `cargo xtask qemu-test` with `--target` and `--timeout` flags
- x86_64 and aarch64 boot verification via serial milestone matching
- Panic detection (immediate fail)
- Human-readable progress output
- CI-friendly exit codes (0 = pass, 1 = fail)
- aarch64 UEFI firmware (OVMF) and ESP image creation for QEMU virt

**Out of scope:**
- Benchmark/timing collection (separate bead: harmony-os-87o)
- Interactive QEMU mode / foreground serial
- Semihosting exit codes (serial matching is sufficient)
- Network testing or virtio-net assertions
- RPi5-specific testing (QEMU `virt` machine only for aarch64)
- Guest input / scripted test sequences

## Design

### Command Interface

```
cargo xtask qemu-test                        # test both architectures
cargo xtask qemu-test --target x86_64        # test x86_64 only
cargo xtask qemu-test --target aarch64       # test aarch64 only
cargo xtask qemu-test --timeout 10           # override default 30s
```

Exit codes:
- `0` — all milestones reached on all requested targets
- `1` — one or more targets failed (timeout, panic, or missing milestone)

### Output Format

```
[x86_64]  BUILDING... ok (2.1s)
[x86_64]  BOOTING...
[x86_64]  ✓ [BOOT] Harmony unikernel ...
[x86_64]  ✓ [ENTROPY] RDRAND ...
[x86_64]  ✓ [IDENTITY] ...
[x86_64]  ✓ [READY] entering event loop
[x86_64]  PASS (0.8s)

[aarch64] BUILDING... ok (3.4s)
[aarch64] BOOTING...
[aarch64] ✓ [PL011] Serial initialized ...
[aarch64] ✓ [RNDR] ...
[aarch64] ✓ [Identity] ...
[aarch64] ✓ [Runtime] ...
[aarch64] PASS (1.2s)
```

Each `✓` line shows the milestone substring followed by `...` to indicate the full serial line may contain more text. On failure, the last 20 lines of serial output are printed for diagnosis.

### Milestone Definitions

Each architecture has an ordered list of milestones — substrings that must appear in serial output in order. The harness checks them off as they appear. All must be reached before timeout for PASS.

**x86_64 milestones:**
1. `[BOOT] Harmony unikernel` — kernel entry (full line includes version)
2. `[ENTROPY] RDRAND` — RNG available (full line: `[ENTROPY] RDRAND available`)
3. `[IDENTITY]` — identity generated
4. `[READY] entering event loop` — boot complete

**aarch64 milestones:**
1. `[PL011] Serial initialized` — serial up after ExitBootServices
2. `[RNDR]` — hardware RNG available
3. `[Identity]` — identity generated
4. `[Runtime]` — unikernel runtime entered idle loop (full line: `[Runtime] Entering idle loop ...`)

Milestones are substring matches — `[Identity]` matches regardless of whether the kernel prints Ed25519 or ML-DSA details. This keeps the harness decoupled from crypto implementation changes.

**Panic detection:** The x86_64 panic handler prints `[PANIC]`, but the aarch64 panic handler prints `!!! PANIC:`. The harness checks for BOTH patterns — if any line contains `[PANIC]` or `!!! PANIC`, the harness immediately declares FAIL.

Milestones are hardcoded in the xtask source, not config files. They are tightly coupled to the boot code and should change alongside it.

### Build and QEMU Configuration

**x86_64:**

The x86_64 kernel uses the `bootloader` crate to create a BIOS disk image. The existing xtask already has this build pipeline. For the harness, the `qemu-test` feature must be enabled so the kernel calls `qemu_debug_exit` after reaching the event loop (providing a clean QEMU exit).

```bash
# Build (with qemu-test feature for clean exit)
cd crates/harmony-boot
cargo build --target x86_64-unknown-none --release --features qemu-test

# Create BIOS disk image (via bootloader crate, already in xtask)
# Output: target/harmony-boot-bios.img

# QEMU
qemu-system-x86_64 \
  -drive format=raw,file=target/harmony-boot-bios.img \
  -serial stdio \
  -display none \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -cpu qemu64,+rdrand \
  -no-reboot
```

Exit code mapping: guest writes `0x10` → host sees `(0x10 << 1) | 1 = 33` = success. The harness treats exit code 33 as clean termination (in addition to serial milestone matching).

**aarch64:**

The aarch64 kernel is a UEFI application (`.efi` PE file). QEMU's `-bios` flag expects raw firmware, not a UEFI application. The correct boot path requires:
1. UEFI firmware (OVMF/EDK2 for aarch64) loaded as the BIOS
2. A FAT32 ESP image with the kernel at `EFI/BOOT/BOOTAA64.EFI`

The `OVMF.fd` aarch64 firmware is provided by the `pkgs.OVMF.fd` package in the Nix flake (to be added). The ESP image is created by the harness at build time using `mtools` (already in the flake).

```bash
# Build kernel
cd crates/harmony-boot-aarch64
cargo build --target aarch64-unknown-uefi --release

# Create ESP image (FAT32, ~4MB)
dd if=/dev/zero of=target/harmony-aarch64-esp.img bs=1M count=4
mformat -i target/harmony-aarch64-esp.img ::
mmd -i target/harmony-aarch64-esp.img ::/EFI
mmd -i target/harmony-aarch64-esp.img ::/EFI/BOOT
mcopy -i target/harmony-aarch64-esp.img \
  target/aarch64-unknown-uefi/release/harmony-boot-aarch64.efi \
  ::/EFI/BOOT/BOOTAA64.EFI

# QEMU
qemu-system-aarch64 \
  -machine virt \
  -cpu max \
  -m 256M \
  -bios /path/to/QEMU_EFI.fd \
  -drive format=raw,file=target/harmony-aarch64-esp.img \
  -serial stdio \
  -display none \
  -no-reboot
```

Notes:
- `-cpu max` enables FEAT_RNG (RNDR instruction) needed by the kernel
- `-display none` suppresses the graphics window
- `-no-reboot` makes QEMU exit on triple-fault instead of rebooting
- `-serial stdio` routes PL011 to the harness's stdout pipe
- The OVMF firmware path comes from the Nix store; the harness resolves it via the `OVMF_FD` environment variable set in the flake's shellHook

### UEFI Firmware Discovery

QEMU 10.2.1 (provided by the Nix flake) ships `edk2-aarch64-code.fd` at `$QEMU_PREFIX/share/qemu/edk2-aarch64-code.fd`. The harness locates this automatically by resolving the path relative to the `qemu-system-aarch64` binary. No separate OVMF package or flake changes needed.

Override: set `OVMF_FD=/path/to/firmware.fd` to use a custom firmware.

### Harness Architecture

The runner uses a background reader thread for reliable timeout handling. A blocking `BufRead::lines()` loop cannot implement wall-clock timeouts because it blocks indefinitely waiting for a newline if the guest hangs mid-line.

Architecture:
1. Spawn QEMU with stdout piped (`std::process::Command`)
2. Spawn a reader thread that reads lines from stdout and sends them over a `mpsc::channel`
3. Main thread receives lines from the channel with `recv_timeout(remaining)`
4. For each line:
   - Contains `[PANIC]` or `!!! PANIC` → kill QEMU, drain buffered output, return FAIL
   - Matches next expected milestone → advance, print `✓`
   - All milestones matched → kill QEMU, return PASS
5. Channel timeout → kill QEMU, drain any remaining buffered lines, return FAIL with last 20 lines

The reader thread naturally exits when QEMU terminates (pipe closes → `lines()` returns `None`). A ring buffer of the last 20 lines is maintained for diagnostic output on failure.

### Files

| File | Action | Purpose |
|------|--------|---------|
| `xtask/src/qemu_test.rs` | Create | Subcommand entry — arg parsing, per-target dispatch, result reporting |
| `xtask/src/qemu_runner.rs` | Create | QEMU process management — spawn, serial capture, milestone matching, timeout |
| `xtask/src/main.rs` | Modify | Add `qemu-test` to subcommand dispatch |

## Verification

1. `cargo xtask qemu-test` — both targets pass
2. `cargo xtask qemu-test --target x86_64` — x86_64 only, passes
3. `cargo xtask qemu-test --target aarch64` — aarch64 only, passes
4. `cargo xtask qemu-test --timeout 1` — fails with timeout (kernel can't boot in 1s)
5. Manually introduce a panic in boot code → harness detects `[PANIC]` (x86_64) or `!!! PANIC` (aarch64) and fails immediately
