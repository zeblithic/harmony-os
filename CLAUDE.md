# CLAUDE.md — Harmony OS

## What This Is

Harmony OS is a mesh-native operating system built on the Harmony protocol stack. It uses a concentric ring architecture where each ring adds capabilities for a different deployment tier.

## Architecture

```
Ring 0: harmony-core (no_std) — crypto, identity, packets, CIDs, state machines
        ↑ Lives in zeblithic/harmony (Apache-2.0 OR MIT) — NOT in this repo
Ring 1: harmony-unikernel   — Ring 0 + bare-metal driver + event loop = bootable single-purpose node
Ring 2: harmony-microkernel  — Ring 1 + 9P IPC, capability enforcement, process isolation
Ring 3: harmony-os           — Ring 2 + Linuxulator, DDE, declarative config, hot-swap
```

Rings 1-3 live in this repo. Ring 0 is consumed as a git dependency under its MIT license arm.

## Licensing

**This repo: GPL-2.0-or-later.** Chosen for Linux ecosystem compatibility.

**Dependency direction is one-way:**
- harmony-os depends on harmony (core) — GPL absorbs MIT, clean
- harmony (core) NEVER depends on harmony-os — keeps core permissively licensed

## Build & Test

```bash
cargo test --workspace           # All tests
cargo clippy --workspace         # Lint
cargo fmt --all -- --check       # Format check
cargo test -p harmony-unikernel  # Single crate
```

MSRV: Rust 1.75+. Edition 2021.

## Design Reference

The full architectural vision is documented in the harmony core repo:
`zeblithic/harmony/docs/plans/2026-03-04-mesh-os-design.md`

Key design decisions:
- **9P as native IPC** (Ring 2) — every kernel object is a file in a 9P namespace
- **Capability-based security** — no ambient authority, UCAN delegation chains
- **Sans-I/O core** — Ring 0 has zero runtime assumptions, works at every tier
- **Linuxulator** (Ring 3) — Linux syscall translation to 9P for binary compatibility

## Related Repos

| Repo | Role |
|------|------|
| `zeblithic/harmony` | Ring 0 protocol core (Apache-2.0 OR MIT) |
| `zeblithic/harmony-client` | Tauri desktop app |
| `zeblithic/harmony-os` | This repo — Rings 1-3 |
