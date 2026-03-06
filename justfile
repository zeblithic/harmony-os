# Harmony OS build recipes

default:
    @just --list

# Build kernel ELF (stable Rust, no QEMU exit)
build-kernel:
    cd crates/harmony-boot && cargo build --target x86_64-unknown-none --release

# Build bootable BIOS disk image (bootloader crate requires nightly + rust-src)
# xtask build-image handles the kernel build internally
build:
    cargo +nightly run --manifest-path xtask/Cargo.toml -- build-image

# Build kernel with qemu-test feature (enables isa-debug-exit after boot)
build-test:
    cd crates/harmony-boot && cargo build --target x86_64-unknown-none --release --features qemu-test

# Build test disk image (with qemu-test feature)
# xtask build-image-test handles the kernel build internally
build-image-test:
    cargo +nightly run --manifest-path xtask/Cargo.toml -- build-image-test

# Run in QEMU interactively with VirtIO-net (multicast LAN)
run: build
    qemu-system-x86_64 \
        -drive format=raw,file=target/harmony-boot-bios.img \
        -serial stdio \
        -display none \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -cpu qemu64,+rdrand \
        -device virtio-net-pci,netdev=n0 \
        -netdev socket,id=n0,mcast=230.0.0.1:1234

# Run a second peer on the same virtual LAN
run-peer: build
    qemu-system-x86_64 \
        -drive format=raw,file=target/harmony-boot-bios.img \
        -serial stdio \
        -display none \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -cpu qemu64,+rdrand \
        -device virtio-net-pci,netdev=n0 \
        -netdev socket,id=n0,mcast=230.0.0.1:1234

# Host-native unit tests (workspace crates only, no bare-metal)
test:
    cargo test --workspace

# QEMU boot test — builds with qemu-test feature, verifies [IDENTITY] line + exit code
test-qemu: build-image-test
    #!/usr/bin/env bash
    set -uo pipefail
    echo "Booting QEMU and checking for [IDENTITY] line..."
    LOG=$(mktemp)
    trap "rm -f $LOG" EXIT
    timeout 10 qemu-system-x86_64 \
        -drive format=raw,file=target/harmony-boot-bios.img \
        -serial stdio \
        -display none \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -cpu qemu64,+rdrand \
        -device virtio-net-pci,netdev=n0 \
        -netdev socket,id=n0,mcast=230.0.0.1:1234 \
        2>/dev/null | tee "$LOG"
    EXIT=${PIPESTATUS[0]}
    cat "$LOG" >&2
    if ! grep -q '\[IDENTITY\]' "$LOG"; then
        echo "QEMU boot test: FAILED (no [IDENTITY] line)"
        exit 1
    fi
    # isa-debug-exit: guest writes 0x10, host sees (0x10 << 1) | 1 = 33
    if [ "$EXIT" -eq 33 ]; then
        echo "QEMU boot test: PASSED"
        exit 0
    fi
    echo "QEMU boot test: FAILED (QEMU exit $EXIT, expected 33)"
    exit 1

# Lint workspace crates
clippy:
    cargo clippy --workspace
    cd crates/harmony-boot && cargo clippy --target x86_64-unknown-none

# Format check
fmt-check:
    cargo fmt --all -- --check

# Full quality gate (host-side only, no QEMU)
check: test clippy fmt-check
    @echo "All host checks passed."
