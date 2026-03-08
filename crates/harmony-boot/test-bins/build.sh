#!/bin/sh
# Build the test ELF binary. Requires x86_64 GNU binutils.
# On macOS: brew install x86_64-elf-binutils
# On Linux: apt install binutils
set -e

cd "$(dirname "$0")"

# Try platform-specific assembler names
AS="${AS:-}"
LD="${LD:-}"

if [ -z "$AS" ] || [ -z "$LD" ]; then
    if command -v x86_64-linux-gnu-as >/dev/null 2>&1; then
        AS="${AS:-x86_64-linux-gnu-as}"
        LD="${LD:-x86_64-linux-gnu-ld}"
    elif command -v x86_64-elf-as >/dev/null 2>&1; then
        AS="${AS:-x86_64-elf-as}"
        LD="${LD:-x86_64-elf-ld}"
    elif command -v as >/dev/null 2>&1 && [ "$(uname)" != "Darwin" ]; then
        AS="${AS:-as}"
        LD="${LD:-ld}"
    else
        echo "No x86_64 assembler found. Install x86_64-elf-binutils." >&2
        exit 1
    fi
fi

$AS -o hello.o hello.S
$LD -o hello.elf -nostdlib --static hello.o
rm -f hello.o
echo "Built hello.elf ($(wc -c < hello.elf | tr -d ' ') bytes)"
