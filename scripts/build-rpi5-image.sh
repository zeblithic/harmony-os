#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build a bootable RPi5 SD card image for Harmony OS.
#
# Output: target/harmony-rpi5.img (64 MB FAT32)
#
# RPi5 boot sequence:
#   SPI flash EEPROM → config.txt → RPI_EFI.fd (UEFI) → EFI/BOOT/BOOTAA64.EFI
#
# Unlike RPi4, the RPi5 bootloader firmware lives in SPI flash EEPROM
# on the board — no start4.elf or fixup4.dat needed on the SD card.
# The SD card only needs config.txt, UEFI firmware, and the kernel.
#
# UEFI firmware: worproject/rpi5-uefi (archived Feb 2025).
# For current D0 (rev 1.1) boards, use NumberOneGit/rpi5-uefi fork.
#
# Requirements: mtools, curl, unzip, cargo, aarch64-unknown-linux-musl target
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="$ROOT_DIR/target"
FIRMWARE_DIR="$TARGET_DIR/rpi5-firmware"
IMG="$TARGET_DIR/harmony-rpi5.img"
IMG_SIZE_MB=64

# ── Firmware URLs ──
# worproject/rpi5-uefi v0.3 — archived but releases still downloadable.
# For D0 boards, build from NumberOneGit/rpi5-uefi instead.
EDK2_RELEASE="https://github.com/worproject/rpi5-uefi/releases/download/v0.3/RPi5_UEFI_Release_v0.3.zip"

echo "=== Building Harmony RPi5 SD card image ==="

# ── Step 1: Build test ELF ──
echo "[1/4] Cross-compiling test ELF..."
(cd "$ROOT_DIR/crates/harmony-test-elf" && \
    cargo build --target aarch64-unknown-linux-musl --release)
TEST_ELF="$ROOT_DIR/crates/harmony-test-elf/target/aarch64-unknown-linux-musl/release/harmony-test-elf"
echo "  Test ELF: $(wc -c < "$TEST_ELF") bytes"

# ── Step 2: Build kernel with rpi5 feature ──
echo "[2/4] Building Harmony kernel (aarch64-uefi, rpi5)..."
(cd "$ROOT_DIR/crates/harmony-boot-aarch64" && \
    cargo build --target aarch64-unknown-uefi --release \
    --features rpi5 --no-default-features)
KERNEL="$ROOT_DIR/crates/harmony-boot-aarch64/target/aarch64-unknown-uefi/release/harmony-boot-aarch64.efi"
echo "  Kernel: $(wc -c < "$KERNEL") bytes"

# ── Step 3: Download/cache UEFI firmware ──
echo "[3/4] Preparing firmware..."
mkdir -p "$FIRMWARE_DIR"

if [ ! -f "$FIRMWARE_DIR/RPI_EFI.fd" ]; then
    echo "  Downloading RPi5 EDK2 UEFI firmware (worproject v0.3)..."
    curl -fSL "$EDK2_RELEASE" -o "$FIRMWARE_DIR/edk2.zip.tmp"
    mv -f "$FIRMWARE_DIR/edk2.zip.tmp" "$FIRMWARE_DIR/edk2.zip"
    unzip -o -j "$FIRMWARE_DIR/edk2.zip" "RPI_EFI.fd" -d "$FIRMWARE_DIR/"
    rm -f "$FIRMWARE_DIR/edk2.zip"
else
    echo "  Cached: RPI_EFI.fd"
fi

# ── Step 4: Create FAT32 image ──
echo "[4/4] Creating FAT32 image..."
rm -f "$IMG"
dd if=/dev/zero of="$IMG" bs=1M count=$IMG_SIZE_MB status=none
mformat -F -i "$IMG" ::

# Copy UEFI firmware (loaded by SPI bootloader via config.txt armstub=)
mcopy -i "$IMG" "$FIRMWARE_DIR/RPI_EFI.fd" ::

# Create config.txt for RPi5
# - arm_64bit=1: boot in AArch64 mode
# - enable_uart=1: enable debug UART (BCM2712 native at 0x107d001000)
# - uart_2ndstage=1: UART output during second-stage boot
# - armstub=RPI_EFI.fd: load UEFI firmware as the ARM stub
# - pciex4_reset=0: don't reset PCIe controller (preserves RP1 UART init
#   if needed, though we use the BCM2712 debug UART instead)
# - disable_commandline_tags=1: don't pass cmdline to the stub
# - disable_overscan=1: no overscan compensation
CONFIG=$(mktemp)
trap 'rm -f "$CONFIG"' EXIT
cat > "$CONFIG" <<'CONFIGEOF'
arm_64bit=1
enable_uart=1
uart_2ndstage=1
armstub=RPI_EFI.fd
pciex4_reset=0
disable_commandline_tags=1
disable_overscan=1
CONFIGEOF
mcopy -i "$IMG" "$CONFIG" ::config.txt
rm -f "$CONFIG"

# Create EFI/BOOT/ directory and copy kernel as the default boot target
mmd -i "$IMG" ::EFI
mmd -i "$IMG" ::EFI/BOOT
mcopy -i "$IMG" "$KERNEL" ::EFI/BOOT/BOOTAA64.EFI

echo ""
echo "=== Image built successfully ==="
echo "  Output: $IMG (${IMG_SIZE_MB} MB)"
echo "  Write to SD card: dd if=$IMG of=/dev/sdX bs=4M status=progress"
echo ""
echo "  Serial output: BCM2712 debug UART (3-pin JST connector)"
echo "  Baud rate: 115200 8N1"
