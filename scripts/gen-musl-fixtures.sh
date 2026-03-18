#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Generate aarch64 musl test fixtures for the dynamic ELF loader tests.
#
# Requires: aarch64-unknown-linux-musl C cross-compiler on PATH
# (provided by `nix develop` via the muslCross package).
#
# Output:
#   crates/harmony-os/tests/fixtures/hello              — dynamically-linked hello world
#   crates/harmony-os/tests/fixtures/ld-musl-aarch64.so.1 — musl dynamic linker
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$ROOT_DIR/crates/harmony-os/tests/fixtures"

# Detect the musl cross-compiler binary name.
# Nix provides it as aarch64-unknown-linux-musl-cc; other systems may
# use aarch64-linux-musl-gcc.
if command -v aarch64-unknown-linux-musl-cc &>/dev/null; then
    CC=aarch64-unknown-linux-musl-cc
elif command -v aarch64-linux-musl-gcc &>/dev/null; then
    CC=aarch64-linux-musl-gcc
else
    echo "Error: No aarch64 musl cross-compiler found on PATH." >&2
    echo "Run this inside 'nix develop' or install a musl cross-compiler." >&2
    exit 1
fi

echo "=== Generating aarch64 musl test fixtures ==="
echo "  Cross-compiler: $CC ($(command -v "$CC"))"

mkdir -p "$FIXTURES_DIR"

# ── Step 1: Compile a minimal dynamically-linked hello world ──
HELLO_SRC=$(mktemp /tmp/hello-XXXXXX.c)
trap 'rm -f "$HELLO_SRC"' EXIT

cat > "$HELLO_SRC" <<'CSRC'
#include <stdio.h>
int main(void) {
    printf("Hello from Harmony!\n");
    return 0;
}
CSRC

echo "  Compiling hello..."
$CC -o "$FIXTURES_DIR/hello" "$HELLO_SRC"
echo "  hello: $(wc -c < "$FIXTURES_DIR/hello") bytes"

# ── Step 2: Copy the musl dynamic linker ──
echo "  Locating ld-musl-aarch64.so.1..."
LD_MUSL=$($CC -print-file-name=ld-musl-aarch64.so.1)

if [ ! -f "$LD_MUSL" ] || [ "$LD_MUSL" = "ld-musl-aarch64.so.1" ]; then
    echo "Error: Could not locate ld-musl-aarch64.so.1 via $CC -print-file-name" >&2
    exit 1
fi

cp -f "$LD_MUSL" "$FIXTURES_DIR/ld-musl-aarch64.so.1"
echo "  ld-musl-aarch64.so.1: $(wc -c < "$FIXTURES_DIR/ld-musl-aarch64.so.1") bytes"

# ── Verify ──
echo ""
echo "=== Fixtures generated ==="
echo "  $FIXTURES_DIR/hello"
echo "  $FIXTURES_DIR/ld-musl-aarch64.so.1"

# Quick sanity: check it's actually an aarch64 ELF
if command -v file &>/dev/null; then
    echo ""
    file "$FIXTURES_DIR/hello"
    file "$FIXTURES_DIR/ld-musl-aarch64.so.1"
fi
