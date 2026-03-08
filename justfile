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

# Run a second peer on the same virtual LAN.
# Intentionally identical to `run` — QEMU auto-assigns distinct MAC
# addresses per instance, so each peer gets a unique identity.
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

# Two-node mesh test — verifies peer discovery and heartbeat exchange over virtual LAN
test-mesh: build
    #!/usr/bin/env bash
    set -euo pipefail
    MCAST_PORT=$(( ( RANDOM % 10000 ) + 20000 ))
    echo "Two-node mesh test: launching peers (mcast port $MCAST_PORT)..."
    LOG_A=$(mktemp)
    LOG_B=$(mktemp)
    PID_A=""
    PID_B=""
    cleanup() {
        [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
        [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
        [ -n "$PID_A" ] && wait "$PID_A" 2>/dev/null || true
        [ -n "$PID_B" ] && wait "$PID_B" 2>/dev/null || true
        rm -f "$LOG_A" "$LOG_B"
    }
    trap cleanup EXIT

    qemu-system-x86_64 \
        -drive format=raw,file=target/harmony-boot-bios.img,snapshot=on \
        -serial file:"$LOG_A" \
        -display none \
        -cpu qemu64,+rdrand \
        -device virtio-net-pci,netdev=n0 \
        -netdev socket,id=n0,mcast=230.0.0.1:$MCAST_PORT &
    PID_A=$!

    qemu-system-x86_64 \
        -drive format=raw,file=target/harmony-boot-bios.img,snapshot=on \
        -serial file:"$LOG_B" \
        -display none \
        -cpu qemu64,+rdrand \
        -device virtio-net-pci,netdev=n0 \
        -netdev socket,id=n0,mcast=230.0.0.1:$MCAST_PORT &
    PID_B=$!

    for i in $(seq 1 30); do
        sleep 1
        # Bail early if either node has exited (e.g., kernel panic).
        if ! kill -0 "$PID_A" 2>/dev/null || ! kill -0 "$PID_B" 2>/dev/null; then
            echo "  [${i}s] One or both nodes exited unexpectedly"
            break
        fi
        A_PEER=$(grep -c '\[PEER+\]' "$LOG_A" 2>/dev/null || echo 0)
        B_PEER=$(grep -c '\[PEER+\]' "$LOG_B" 2>/dev/null || echo 0)
        A_HBT=$(grep -c '\[HBT\]' "$LOG_A" 2>/dev/null || echo 0)
        B_HBT=$(grep -c '\[HBT\]' "$LOG_B" 2>/dev/null || echo 0)
        echo "  [${i}s] A: ${A_PEER} peers, ${A_HBT} heartbeats | B: ${B_PEER} peers, ${B_HBT} heartbeats"
        if [ "$A_PEER" -gt 0 ] && [ "$B_PEER" -gt 0 ] \
           && [ "$A_HBT" -gt 0 ] && [ "$B_HBT" -gt 0 ]; then
            echo ""
            echo "=== Node A log ==="
            cat "$LOG_A"
            echo ""
            echo "=== Node B log ==="
            cat "$LOG_B"
            echo ""
            echo "Two-node mesh test: PASSED"
            exit 0
        fi
    done

    echo ""
    echo "=== Node A log ==="
    cat "$LOG_A"
    echo ""
    echo "=== Node B log ==="
    cat "$LOG_B"
    echo ""
    echo "Two-node mesh test: FAILED (timeout after 30s)"
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
