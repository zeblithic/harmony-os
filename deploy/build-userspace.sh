#!/usr/bin/env bash
set -euo pipefail

# Cross-compile static dropbear + busybox for aarch64-linux-musl via Nix.
#
# Run from the harmony-os repo root:
#   bash deploy/build-userspace.sh
#
# Prerequisites: Nix with flakes enabled
#
# Outputs:
#   deploy/dropbear-aarch64    (static ELF, ~737 KB)
#   deploy/busybox-aarch64     (static ELF, ~1.6 MB)
#
# Versions (from nixpkgs unstable):
#   dropbear 2025.89
#   busybox  1.37.0
#
# The binaries are built via Nix's pkgsStatic overlay which forces
# -static in LDFLAGS. This avoids manual cross-compilation issues
# with libtommath/libtomcrypt that occur when invoking make directly.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NIX="nix --extra-experimental-features nix-command\ flakes"

echo "=== Building static dropbear (aarch64-linux-musl) ==="
DROPBEAR_PATH=$($NIX build --impure --expr '
  let pkgs = import (builtins.getFlake "nixpkgs") {
    system = builtins.currentSystem;
    crossSystem = { config = "aarch64-unknown-linux-musl"; useLLVM = false; };
  };
  in pkgs.pkgsStatic.dropbear
' --no-link --print-out-paths)
cp -f "$DROPBEAR_PATH/bin/dropbear" "$SCRIPT_DIR/dropbear-aarch64"
echo "  → dropbear-aarch64 ($(wc -c < "$SCRIPT_DIR/dropbear-aarch64" | tr -d ' ') bytes)"

echo "=== Building static busybox (aarch64-linux-musl) ==="
BUSYBOX_PATH=$($NIX build --impure --expr '
  let pkgs = import (builtins.getFlake "nixpkgs") {
    system = builtins.currentSystem;
    crossSystem = { config = "aarch64-unknown-linux-musl"; useLLVM = false; };
  };
  in pkgs.pkgsStatic.busybox
' --no-link --print-out-paths)
cp -f "$BUSYBOX_PATH/bin/busybox" "$SCRIPT_DIR/busybox-aarch64"
echo "  → busybox-aarch64 ($(wc -c < "$SCRIPT_DIR/busybox-aarch64" | tr -d ' ') bytes)"

echo "=== Verifying ==="
file "$SCRIPT_DIR/dropbear-aarch64"
file "$SCRIPT_DIR/busybox-aarch64"

echo ""
echo "NOTE: No host key generated. For QEMU testing, use dropbear -R"
echo "(generates a temporary key on first connection). For production,"
echo "provision unique keys on first boot."
echo ""
echo "=== Done ==="
