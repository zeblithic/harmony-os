#!/usr/bin/env bash
set -euo pipefail

# Cross-compile static dropbear + busybox for Linux via Nix.
#
# Run from the harmony-os repo root:
#   bash deploy/build-userspace.sh [--arch ARCH]
#
# ARCH can be: aarch64 (default), x86_64, or all (builds both)
#
# Prerequisites: Nix with flakes enabled
#
# Outputs:
#   deploy/dropbear-{arch}    (static ELF, ~700-800 KB)
#   deploy/busybox-{arch}     (static ELF, ~1.6 MB)
#
# Versions (from nixpkgs unstable):
#   dropbear 2025.89
#   busybox  1.37.0
#
# The binaries are built via Nix's pkgsStatic overlay which forces
# -static in LDFLAGS. This avoids manual cross-compilation issues
# with libtommath/libtomcrypt that occur when invoking make directly.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NIX=(nix --extra-experimental-features "nix-command flakes")

# Parse --arch flag
ARCH="aarch64"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

build_for_arch() {
    local arch="$1"
    local musl_triple

    case "$arch" in
        aarch64) musl_triple="aarch64-unknown-linux-musl" ;;
        x86_64)  musl_triple="x86_64-unknown-linux-musl" ;;
        *)       echo "Unsupported arch: $arch" >&2; exit 1 ;;
    esac

    echo "=== Building static dropbear ($musl_triple) ==="
    local dropbear_path
    dropbear_path=$("${NIX[@]}" build --impure --expr "
      let pkgs = import (builtins.getFlake \"nixpkgs\") {
        system = builtins.currentSystem;
        crossSystem = { config = \"$musl_triple\"; useLLVM = false; };
      };
      in pkgs.pkgsStatic.dropbear
    " --no-link --print-out-paths)
    cp -f "$dropbear_path/bin/dropbear" "$SCRIPT_DIR/dropbear-$arch"
    echo "  → dropbear-$arch ($(wc -c < "$SCRIPT_DIR/dropbear-$arch" | tr -d ' ') bytes)"

    echo "=== Building static busybox ($musl_triple) ==="
    local busybox_path
    busybox_path=$("${NIX[@]}" build --impure --expr "
      let pkgs = import (builtins.getFlake \"nixpkgs\") {
        system = builtins.currentSystem;
        crossSystem = { config = \"$musl_triple\"; useLLVM = false; };
      };
      in pkgs.pkgsStatic.busybox
    " --no-link --print-out-paths)
    cp -f "$busybox_path/bin/busybox" "$SCRIPT_DIR/busybox-$arch"
    echo "  → busybox-$arch ($(wc -c < "$SCRIPT_DIR/busybox-$arch" | tr -d ' ') bytes)"

    echo "=== Verifying ($arch) ==="
    file "$SCRIPT_DIR/dropbear-$arch"
    file "$SCRIPT_DIR/busybox-$arch"
}

if [[ "$ARCH" == "all" ]]; then
    build_for_arch aarch64
    build_for_arch x86_64
else
    build_for_arch "$ARCH"
fi

echo ""
echo "NOTE: No host key generated. For QEMU testing, use dropbear -R"
echo "(generates a temporary key on first connection). For production,"
echo "provision unique keys on first boot."
echo ""
echo "=== Done ==="
