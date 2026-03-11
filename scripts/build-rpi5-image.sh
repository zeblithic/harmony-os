#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build a bootable RPi5 SD card image for Harmony OS.
#
# Output: target/harmony-rpi5.img (256 MB FAT32)
#
# Requirements: mtools, curl, sha256sum, cargo, aarch64-unknown-linux-musl target
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="$ROOT_DIR/target"
FIRMWARE_DIR="$TARGET_DIR/rpi5-firmware"
IMG="$TARGET_DIR/harmony-rpi5.img"
IMG_SIZE_MB=256

# ── Firmware URLs ──
FIRMWARE_REPO="https://github.com/raspberrypi/firmware/raw/master/boot"
EDK2_RELEASE="https://github.com/pftf/RPi4/releases/download/v1.38/RPi4_UEFI_Firmware_v1.38.zip"

echo "=== Building Harmony RPi5 SD card image ==="

# ── Step 1: Build test ELF ──
echo "[1/4] Cross-compiling test ELF..."
(cd "$ROOT_DIR/crates/harmony-test-elf" && \
    cargo build --target aarch64-unknown-linux-musl --release)
TEST_ELF="$TARGET_DIR/aarch64-unknown-linux-musl/release/harmony-test-elf"
echo "  Test ELF: $(wc -c < "$TEST_ELF") bytes"

# ── Step 2: Build kernel with rpi5 feature ──
echo "[2/4] Building Harmony kernel (aarch64-uefi, rpi5)..."
(cd "$ROOT_DIR/crates/harmony-boot-aarch64" && \
    cargo build --target aarch64-unknown-uefi --release \
    --features rpi5 --no-default-features)
KERNEL="$TARGET_DIR/aarch64-unknown-uefi/release/harmony-boot-aarch64.efi"
echo "  Kernel: $(wc -c < "$KERNEL") bytes"

# ── Step 3: Download/cache firmware ──
echo "[3/4] Preparing firmware..."
mkdir -p "$FIRMWARE_DIR"

download_if_missing() {
    local url="$1" dest="$2"
    if [ ! -f "$dest" ]; then
        echo "  Downloading $(basename "$dest")..."
        curl -fSL "$url" -o "$dest"
    else
        echo "  Cached: $(basename "$dest")"
    fi
}

download_if_missing "$FIRMWARE_REPO/start4.elf" "$FIRMWARE_DIR/start4.elf"
download_if_missing "$FIRMWARE_REPO/fixup4.dat" "$FIRMWARE_DIR/fixup4.dat"
download_if_missing "$FIRMWARE_REPO/bcm2712-rpi-5-b.dtb" "$FIRMWARE_DIR/bcm2712-rpi-5-b.dtb"

if [ ! -f "$FIRMWARE_DIR/RPI_EFI.fd" ]; then
    echo "  Downloading EDK2 UEFI firmware..."
    curl -fSL "$EDK2_RELEASE" -o "$FIRMWARE_DIR/edk2.zip"
    unzip -o -j "$FIRMWARE_DIR/edk2.zip" "RPI_EFI.fd" -d "$FIRMWARE_DIR/"
    rm -f "$FIRMWARE_DIR/edk2.zip"
else
    echo "  Cached: RPI_EFI.fd"
fi

# ── Step 4: Create FAT32 image ──
echo "[4/4] Creating FAT32 image..."
rm -f "$IMG"
# Create empty image
dd if=/dev/zero of="$IMG" bs=1M count=$IMG_SIZE_MB status=none
# Format as FAT32
mformat -F -i "$IMG" ::

# Copy firmware files
mcopy -i "$IMG" "$FIRMWARE_DIR/start4.elf" ::
mcopy -i "$IMG" "$FIRMWARE_DIR/fixup4.dat" ::
mcopy -i "$IMG" "$FIRMWARE_DIR/bcm2712-rpi-5-b.dtb" ::
mcopy -i "$IMG" "$FIRMWARE_DIR/RPI_EFI.fd" ::

# Create config.txt
CONFIG=$(mktemp)
cat > "$CONFIG" <<'CONFIGEOF'
arm_64bit=1
enable_uart=1
uart_2ndstage=1
armstub=RPI_EFI.fd
disable_commandline_tags=1
disable_overscan=1
CONFIGEOF
mcopy -i "$IMG" "$CONFIG" ::config.txt
rm -f "$CONFIG"

# Create EFI/BOOT/ directory and copy kernel
mmd -i "$IMG" ::EFI
mmd -i "$IMG" ::EFI/BOOT
mcopy -i "$IMG" "$KERNEL" ::EFI/BOOT/BOOTAA64.EFI

echo ""
echo "=== Image built successfully ==="
echo "  Output: $IMG (${IMG_SIZE_MB} MB)"
echo "  Write to SD card: dd if=$IMG of=/dev/sdX bs=4M status=progress"
