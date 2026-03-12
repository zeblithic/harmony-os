# Linuxulator musl Binary Support — Design

**Goal:** Make the Linuxulator capable of booting a real musl-linked static
binary by wiring up the boot stack layout, PT_TLS parsing, and AT_RANDOM
entropy — all infrastructure that largely exists but isn't connected to the
boot path.

**Scope:** Gaps 1, 2, and 4 from the NixOS feasibility analysis.
Gap 3 (`/nix/store` ContentServer bridge) is deferred.

## Context

The Linuxulator already implements 33 syscalls and can run the hand-written
`harmony-test-elf` (no_std, no libc). A Nix-built musl static binary needs
four syscalls at startup — `set_tid_address`, `ioctl(TIOCGWINSZ)`, `writev`,
`exit_group` — all already implemented. The real gaps are in ELF loading
infrastructure, not syscalls.

### Gap 1: Boot Stack Layout

musl's `_start` (aarch64 `crt_arch.h`) reads SP to find argc, argv, envp,
and the auxiliary vector. The current boot path sets PC to `entry_point`
without constructing a stack. `build_initial_stack()` in `elf_loader.rs`
already implements the full Linux stack layout with 1100+ lines of test
coverage — it just isn't called from the boot path.

### Gap 2: PT_TLS Parsing

musl's `__init_tls` walks the program header table (via AT_PHDR) to find the
PT_TLS segment, which describes the thread-local storage template (`.tdata` +
`.tbss`). `errno` lives in TLS. The ELF parser in `elf.rs` currently handles
only PT_LOAD and PT_INTERP, silently skipping PT_TLS.

musl reads the phdrs itself — we don't need to interpret PT_TLS at load time.
We just need the parser to recognize it (for our own bookkeeping) and ensure
the program headers are mapped in memory at the address AT_PHDR advertises.
The first PT_LOAD segment typically starts at file offset 0 and includes the
ELF header + phdrs, so they're already mapped.

### Gap 4: AT_RANDOM Entropy

musl's `__init_libc` reads 16 bytes from the address in AT_RANDOM to
initialize `__stack_chk_guard` (stack canary) and `__sysinfo` (vDSO).
`build_initial_stack()` already handles AT_RANDOM substitution — it writes
the 16 random bytes to the stack top and patches the auxv entry. The caller
just needs to provide real entropy bytes instead of zeros.

## Design

### ELF Parser Changes (`elf.rs`)

Add `PT_TLS` constant (7) and parse it alongside PT_LOAD/PT_INTERP:

```rust
pub struct TlsInfo {
    pub vaddr: u64,   // template data address
    pub filesz: u64,  // initialized data size (.tdata)
    pub memsz: u64,   // total TLS size (.tdata + .tbss)
    pub align: u64,   // alignment requirement
}
```

Add `pub tls: Option<TlsInfo>` to `ParsedElf`. The parser populates it when
a PT_TLS segment is encountered.

### Boot Path Integration

The orchestrating code (Linuxulator or boot harness) must:

1. Parse ELF bytes via `parse_elf()`
2. Load segments via `InterpreterLoader::load()` (already works)
3. Allocate a stack region (e.g., 8 pages = 32 KiB)
4. Generate 16 random bytes from `KernelEntropy`
5. Call `build_initial_stack()` with argv, envp, auxv from `LoadResult`, and
   the random bytes
6. Set SP to the returned value, PC to `entry_point`

Steps 2 and 5 use existing, tested functions. Step 4 uses existing entropy
infrastructure.

### AT_RANDOM Entropy

In tests: deterministic bytes (e.g., `[0x42; 16]`).
In production: `KernelEntropy` backed by hardware CSPRNG (aarch64 RNDR).

### Testing Strategy

- **Unit tests in `elf.rs`:** Parse ELF with PT_TLS, verify `TlsInfo` fields
- **Unit tests in `elf_loader.rs`:** `build_initial_stack()` already
  extensively tested; add test verifying AT_PHDR points to mapped phdrs that
  include a PT_TLS entry
- **Integration test:** Build in-memory ELF with PT_LOAD + PT_TLS, load via
  `InterpreterLoader`, call `build_initial_stack()`, verify full stack layout
  (argc at SP, argv, envp, auxv with AT_RANDOM pointing to real bytes)
- **Deferred:** QEMU boot test with real musl binary (needs cross-compilation
  fixture)

## Architecture Notes

- **aarch64 TLS:** Uses `msr tpidr_el0` directly (no syscall needed). musl
  calls `__set_thread_area` which on aarch64 is an inline `msr`. No
  Linuxulator involvement required.
- **Program header mapping:** AT_PHDR points to `exe_base + load_bias +
  phdr_offset`. The first PT_LOAD segment (offset 0) maps the ELF header and
  phdr table, so musl can walk them in-process.
- **No new syscalls needed:** All four musl startup syscalls are already
  implemented.

## Non-Goals

- Dynamic linking / `ld-musl` interpreter support (PT_INTERP already parsed
  but no musl shared libs available yet)
- `/nix/store` filesystem bridge (deferred to separate bead)
- x86_64 TLS (`arch_prctl` already implemented but not tested with musl)
