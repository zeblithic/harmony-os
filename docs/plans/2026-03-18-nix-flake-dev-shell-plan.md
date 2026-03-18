# Nix Flake Dev Shell Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a `flake.nix` that provides a reproducible dev shell for building, testing, cross-compiling, and simulating harmony-os.

**Architecture:** Single flake with one dev shell output. Fenix provides the Rust toolchain (stable + cross targets), nixpkgs provides system packages (QEMU, mtools, openssl). Direnv auto-activates the shell.

**Tech Stack:** Nix flakes, fenix (Rust toolchain), flake-utils, direnv

**Spec:** `docs/plans/2026-03-18-nix-flake-dev-shell-design.md`

---

### Task 0: Prerequisite — Install Nix (if not already installed)

All subsequent tasks require Nix with flakes enabled.

- [ ] **Step 1: Install Nix**

Run:
```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

This installs Nix in multi-user (daemon) mode on macOS. Requires `sudo`. Follow the prompts to completion, then open a new terminal.

- [ ] **Step 2: Enable flakes**

For a daemon (multi-user) install, edit the system-level config:
```bash
echo 'experimental-features = nix-command flakes' | sudo tee -a /etc/nix/nix.conf
sudo launchctl kickstart -k system/org.nixos.nix-daemon
```

Alternatively, pass `--extra-experimental-features "nix-command flakes"` to each `nix` invocation, but the config approach is simpler for daily use.

- [ ] **Step 3: Verify**

Run: `nix --version`

Expected: Prints a version like `nix (Nix) 2.x.x`.

---

### Task 1: Create `flake.nix`

**Files:**
- Create: `flake.nix`

- [ ] **Step 1: Write `flake.nix`**

```nix
{
  description = "Harmony OS — mesh-native operating system dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, fenix, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-darwin" "aarch64-darwin" "x86_64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Stable Rust toolchain with cross-compilation targets.
        # Uses fenix.combine to merge the host toolchain with target rust-std libs.
        rustToolchain = fenix.packages.${system}.combine [
          (fenix.packages.${system}.stable.withComponents [
            "cargo"
            "clippy"
            "rustc"
            "rustfmt"
            "rust-src"  # needed for build-std on no_std targets
          ])
          fenix.packages.${system}.targets.aarch64-unknown-uefi.stable.rust-std
          fenix.packages.${system}.targets.x86_64-unknown-none.stable.rust-std
          fenix.packages.${system}.targets.aarch64-unknown-linux-musl.stable.rust-std
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            rustToolchain
            # rust-analyzer as a standalone fenix derivation (always nightly,
            # always available — more reliable than including it in withComponents
            # where it may be silently dropped if the stable manifest omits it).
            fenix.packages.${system}.rust-analyzer
            pkgs.pkg-config
          ];

          buildInputs = [
            # Simulation & imaging
            pkgs.qemu
            pkgs.mtools  # note: may fail to build on some Darwin nixpkgs pins;
                         # fallback: `brew install mtools` and remove from here
            pkgs.curl
            pkgs.unzip

            # Build dependencies
            pkgs.openssl.dev
            pkgs.git
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          # Ensure pkg-config can find openssl
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
        };
      }
    );
}
```

- [ ] **Step 2: Generate `flake.lock`**

Run: `cd /Users/zeblith/work/zeblithic/harmony-os && nix flake lock`

Expected: `flake.lock` is created with pinned versions of nixpkgs, fenix, and flake-utils.

- [ ] **Step 3: Test the dev shell**

Run: `nix develop`

Expected: Enters a shell. Verify tools are present:
```bash
rustc --version          # Should show stable 1.92.x
cargo --version
clippy-driver --version
rustfmt --version
rust-analyzer --version
qemu-system-aarch64 --version
qemu-system-x86_64 --version
mformat --version
pkg-config --version
```

- [ ] **Step 4: Verify Rust targets are available**

Run (inside `nix develop`):
```bash
rustup target list --installed 2>/dev/null || rustc --print target-list | grep -E "aarch64-unknown-uefi|x86_64-unknown-none|aarch64-unknown-linux-musl"
```

Expected: All three targets appear. Note: with fenix, targets are baked into the combined toolchain — `rustup` may not be present, but `rustc --print sysroot` should show the targets under `lib/rustlib/`.

Alternatively verify by checking the sysroot:
```bash
ls "$(rustc --print sysroot)/lib/rustlib/" | grep -E "aarch64-unknown-uefi|x86_64-unknown-none|aarch64-unknown-linux-musl"
```

- [ ] **Step 5: Run workspace tests**

Run (inside `nix develop`):
```bash
cargo test --workspace
```

Expected: All workspace tests pass.

- [ ] **Step 6: Run clippy**

Run (inside `nix develop`):
```bash
cargo clippy --workspace
```

Expected: Clean, no warnings.

- [ ] **Step 7: Verify cross-compilation**

Run (inside `nix develop`):
```bash
cd crates/harmony-test-elf && cargo build --target aarch64-unknown-linux-musl --release
```

Expected: Builds successfully using `rust-lld` (configured in `crates/harmony-test-elf/.cargo/config.toml`).

- [ ] **Step 8: Commit**

```bash
git add flake.nix flake.lock
git commit -m "feat: add flake.nix dev shell with Rust toolchain, QEMU, and cross targets"
```

---

### Task 2: Add direnv integration

**Files:**
- Create: `.envrc`
- Modify: `.gitignore`

- [ ] **Step 1: Create `.envrc`**

```
use flake
```

- [ ] **Step 2: Add `.direnv/` to `.gitignore`**

Append to the existing `.gitignore`:
```
# Direnv cache
.direnv/
```

- [ ] **Step 3: Allow direnv for this directory**

Run: `direnv allow`

Expected: The dev shell activates automatically. If direnv is not installed, this step is skipped — the `.envrc` is still useful for anyone who does have it.

- [ ] **Step 4: Verify auto-activation**

Run:
```bash
cd /tmp && cd /Users/zeblith/work/zeblithic/harmony-os
```

Expected: direnv loads the flake shell automatically (shows `direnv: loading .envrc` and `direnv: export +PKG_CONFIG_PATH ...`).

- [ ] **Step 5: Commit**

```bash
git add .envrc .gitignore
git commit -m "feat: add direnv integration for automatic dev shell activation"
```

---

### Task 3: Smoke test — full build pipeline

This task verifies that the complete development workflow works end-to-end inside the Nix dev shell. No files to create — purely verification.

- [ ] **Step 1: Enter dev shell fresh**

Run: `nix develop` (or rely on direnv if set up)

- [ ] **Step 2: Run full workspace tests**

Run: `cargo test --workspace`

Expected: All tests pass.

- [ ] **Step 3: Run clippy**

Run: `cargo clippy --workspace`

Expected: Clean.

- [ ] **Step 4: Cross-compile test ELF**

Run:
```bash
cd crates/harmony-test-elf
cargo build --target aarch64-unknown-linux-musl --release
cd ../..
```

Expected: Builds successfully.

- [ ] **Step 5: Verify RPi5 image build script dependencies**

Run:
```bash
which mformat && which mcopy && which mmd && which curl && which unzip
```

Expected: All five tools found on PATH. (Don't run the full `build-rpi5-image.sh` — it downloads firmware and creates a 64MB image, which is expensive. Just verify the tools are available.)

- [ ] **Step 6: Verify QEMU is available for both architectures**

Run:
```bash
qemu-system-aarch64 --version
qemu-system-x86_64 --version
```

Expected: Both print version info.
