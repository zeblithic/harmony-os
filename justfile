# Harmony OS build recipes

default:
    @just --list

# Build kernel ELF (stable Rust, no nightly required)
build-kernel:
    cd crates/harmony-boot && cargo build --target x86_64-unknown-none --release

# Build bootable BIOS disk image via xtask (requires nightly for bootloader crate)
build: build-kernel
    cargo run --manifest-path xtask/Cargo.toml -- build-image

# Run in QEMU (serial on terminal)
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

# QEMU boot test — verifies kernel prints [IDENTITY] line within 10 seconds
test-qemu: build
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
