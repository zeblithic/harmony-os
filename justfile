# Harmony OS build recipes

default:
    @just --list

# Build kernel ELF (stable Rust, no QEMU exit)
build-kernel:
    cd crates/harmony-boot && cargo build --target x86_64-unknown-none --release

# Build bootable BIOS disk image (bootloader crate requires nightly + rust-src)
build: build-kernel
    cargo +nightly run --manifest-path xtask/Cargo.toml -- build-image

# Build kernel with qemu-test feature (enables isa-debug-exit after boot)
build-test:
    cd crates/harmony-boot && cargo build --target x86_64-unknown-none --release --features qemu-test

# Build test disk image (with qemu-test feature)
build-image-test: build-test
    cargo +nightly run --manifest-path xtask/Cargo.toml -- build-image-test

# Run in QEMU interactively (no auto-exit — stays in event loop)
run: build
    qemu-system-x86_64 \
        -drive format=raw,file=target/harmony-boot-bios.img \
        -serial stdio \
        -display none \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -cpu qemu64,+rdrand

# Host-native unit tests (workspace crates only, no bare-metal)
test:
    cargo test --workspace

# QEMU boot test — builds with qemu-test feature, verifies [IDENTITY] line
test-qemu: build-image-test
    @echo "Booting QEMU and checking for [IDENTITY] line..."
    timeout 10 qemu-system-x86_64 \
        -drive format=raw,file=target/harmony-boot-bios.img \
        -serial stdio \
        -display none \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -cpu qemu64,+rdrand \
        2>/dev/null | tee /dev/stderr | grep -q '\[IDENTITY\]' \
        && echo "QEMU boot test: PASSED" \
        || (echo "QEMU boot test: FAILED" && exit 1)

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
