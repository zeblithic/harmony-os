# Nix Flake Dev Shell — Design

**Date:** 2026-03-18
**Status:** Proposed
**Bead:** harmony-os-58a

## Problem

harmony-os requires a complex build environment: Rust stable with 3 cross-compilation targets, QEMU for simulation, mtools for SD card imaging, and various system libraries. Currently this is all manually installed — anyone cloning the repo must figure out the toolchain setup on their own, and there's no guarantee of reproducibility across machines.

## Solution

A `flake.nix` that provides a single `nix develop` entry point. One command gives you everything needed to build, test, cross-compile, and simulate harmony-os. Integrated with direnv for automatic shell activation.

## Scope

**In scope:**
- Dev shell with full Rust toolchain, cross targets, and system tools
- Direnv integration for automatic activation

**Out of scope:**
- `nix build` derivations (harmony-os is built by cargo, not Nix)
- `nix run` apps (QEMU runners are a separate bead: harmony-os-5yz)
- NixOS modules or system configuration
- CI/GitHub Actions integration (separate bead: harmony-os-z94)
- Beads (`bd`) packaging

## Design

### Flake Inputs

| Input | Purpose |
|-------|---------|
| `nixpkgs` | System packages (QEMU, mtools, openssl, etc.) |
| `fenix` | Pinned Rust toolchain with cross targets |
| `flake-utils` | `eachSystem` helper for multi-platform support |

### Target Systems

`x86_64-darwin`, `aarch64-darwin`, `x86_64-linux`

### Rust Toolchain (via fenix)

Stable channel (pinned via `flake.lock`), constructed via `fenix.packages.${system}.stable.withComponents` to explicitly include:
- `cargo`, `rustc`, `clippy`, `rustfmt`
- `rust-analyzer` (must be explicitly listed — not in the default profile)
- `rust-src` (required for `build-std` on bare-metal/no_std targets: `aarch64-unknown-uefi`, `x86_64-unknown-none`)

Additional compilation targets added via `fenix.packages.${system}.targets`:
- `aarch64-unknown-uefi` — RPi5 and QEMU aarch64 kernel
- `x86_64-unknown-none` — QEMU x86_64 kernel
- `aarch64-unknown-linux-musl` — test ELF fixtures, musl binaries

Nightly is not included by default. If a specific use case requires it, it can be added later as a separate shell or overlay.

### System Packages

| Package | Purpose |
|---------|---------|
| `qemu` | `qemu-system-aarch64` and `qemu-system-x86_64` for simulation |
| `mtools` | FAT32 image creation (`mformat`, `mcopy`, `mmd`) |
| `curl` | Firmware download in `build-rpi5-image.sh` |
| `unzip` | Firmware extraction |
| `pkg-config` | Native dependency discovery |
| `openssl.dev` | Headers + pkg-config for ureq/rustls (split output — `openssl.dev` provides both headers and `.pc` files) |
| `git` | Cargo git dependencies |

**macOS-only (conditional via `lib.optionals stdenv.isDarwin`):**
| Package | Purpose |
|---------|---------|
| `libiconv` | String encoding (required by several Rust crates on macOS) |
| `darwin.apple_sdk.frameworks.Security` | TLS/crypto framework used by rustls |
| `darwin.apple_sdk.frameworks.SystemConfiguration` | Network configuration (used by ureq) |

### Cross-Compilation: aarch64 musl

No external GCC cross-compiler is needed. The existing per-crate config at `crates/harmony-test-elf/.cargo/config.toml` uses `rust-lld` as the linker:

```toml
[target.aarch64-unknown-linux-musl]
linker = "rust-lld"
rustflags = ["-C", "linker-flavor=ld.lld", "-C", "link-self-contained=no", "-C", "link-arg=--image-base=0x4A000000"]
```

`rust-lld` ships with the Rust toolchain from fenix — no additional Nix packages required. This approach was deliberately chosen to avoid the complexity of cross-linker name mismatches across platforms.

No root-level `.cargo/config.toml` is created. The per-crate config handles cross-compilation for the only crate that needs it.

### Direnv Integration

`.envrc` contains:
```
use flake
```

`.direnv/` is added to `.gitignore` (direnv cache directory).

With `nix-direnv` installed, the dev shell is cached and activates near-instantly on `cd`. Without `nix-direnv`, plain `direnv` still works but evaluates more frequently.

### Platform Considerations

**macOS (x86_64-darwin, aarch64-darwin):**
- Darwin-specific frameworks and `libiconv` are conditionally included (see System Packages above).
- `rust-lld` from the fenix toolchain handles musl cross-linking without needing a macOS-hosted GCC cross-compiler.

**Linux (x86_64-linux):**
- Straightforward — all packages available directly from nixpkgs.

### IFD and Pure Evaluation

fenix pins toolchains via a manifest fetch, which triggers Import From Derivation (IFD). This is allowed by default in `nix develop` but will cause `nix flake check` to fail unless run with `--impure`. This is expected behavior and documented in fenix's upstream.

### Files Created/Modified

| File | Action | Purpose |
|------|--------|---------|
| `flake.nix` | Create | Flake definition |
| `flake.lock` | Auto-generated | Pinned input versions |
| `.envrc` | Create | Direnv activation |
| `.gitignore` | Modify | Add `.direnv/` |

## Verification

After implementation, verify:
1. `nix develop` enters a shell with `rustc`, `cargo`, `clippy`, `rust-analyzer`, `qemu-system-aarch64` all available
2. `cargo test --workspace` — all workspace tests pass
3. `cargo clippy --workspace` — clean
4. Cross-compile excluded crate: `cd crates/harmony-test-elf && cargo build --target aarch64-unknown-linux-musl --release`
5. `qemu-system-aarch64 --version` available
6. `mformat --version` available
7. Direnv: `cd` out and back into the repo activates the shell automatically
