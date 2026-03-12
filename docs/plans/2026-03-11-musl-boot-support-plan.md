# musl Boot Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the Linuxulator capable of booting a real musl-linked static binary by wiring up PT_TLS parsing, boot stack layout, and AT_RANDOM entropy.

**Architecture:** Three tightly-coupled changes compose into a working boot path: (1) teach the ELF parser to recognize PT_TLS segments so musl can find its TLS template, (2) wire `build_initial_stack()` into an end-to-end ELF boot function that constructs the Linux-standard stack layout, (3) plumb real entropy into the AT_RANDOM auxv entry. All building blocks exist — this plan connects them.

**Tech Stack:** Rust (no_std compatible), ELF64 format, Linux ABI (aarch64/x86_64)

**Design doc:** `docs/plans/2026-03-11-musl-boot-support-design.md`

---

### Task 1: PT_TLS Parsing in ELF Parser

**Files:**
- Modify: `crates/harmony-os/src/elf.rs:25-26` (add PT_TLS constant)
- Modify: `crates/harmony-os/src/elf.rs:86-110` (add TlsInfo to ParsedElf)
- Modify: `crates/harmony-os/src/elf.rs:222-275` (add PT_TLS match arm)
- Test: `crates/harmony-os/src/elf.rs` (tests module at line 302+)

**Context:** The ELF parser currently handles PT_LOAD (1) and PT_INTERP (3), discarding everything else via `_ => {}`. musl's `__init_tls` walks the program header table to find PT_TLS (7) for thread-local storage setup. We need the parser to extract this metadata. musl reads the phdrs itself via AT_PHDR, but we store the info in `ParsedElf` for our own bookkeeping (future bare-metal TLS setup).

**Step 1: Write the failing test**

Add to `crates/harmony-os/src/elf.rs` in the `tests` module, after the existing test helper `build_test_elf_with_interp`:

```rust
/// Build a test ELF with a PT_TLS segment in addition to PT_LOAD.
fn build_test_elf_with_tls(
    code: &[u8],
    tls_data: &[u8],
    tls_memsz: u64,
    tls_align: u64,
) -> Vec<u8> {
    let phdr_size = 56;
    let phnum = 2; // PT_LOAD + PT_TLS
    let code_offset = 64 + phnum * phdr_size;
    let tls_offset = code_offset + code.len();
    let total = tls_offset + tls_data.len();
    let mut elf = vec![0u8; total];

    // ELF header
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    #[cfg(target_arch = "x86_64")]
    elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    #[cfg(target_arch = "aarch64")]
    elf[18..20].copy_from_slice(&0xB7u16.to_le_bytes());
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());

    // PT_LOAD program header
    let ph = &mut elf[64..64 + phdr_size];
    ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    ph[4..8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    ph[8..16].copy_from_slice(&(code_offset as u64).to_le_bytes());
    ph[16..24].copy_from_slice(&0x401000u64.to_le_bytes());
    ph[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
    ph[32..40].copy_from_slice(&(code.len() as u64).to_le_bytes());
    ph[40..48].copy_from_slice(&(code.len() as u64).to_le_bytes());
    ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());

    // PT_TLS program header
    let tph = &mut elf[64 + phdr_size..64 + 2 * phdr_size];
    tph[0..4].copy_from_slice(&7u32.to_le_bytes()); // PT_TLS
    tph[4..8].copy_from_slice(&4u32.to_le_bytes()); // PF_R
    tph[8..16].copy_from_slice(&(tls_offset as u64).to_le_bytes());
    tph[16..24].copy_from_slice(&0x403000u64.to_le_bytes()); // vaddr
    tph[24..32].copy_from_slice(&0x403000u64.to_le_bytes()); // paddr
    tph[32..40].copy_from_slice(&(tls_data.len() as u64).to_le_bytes());
    tph[40..48].copy_from_slice(&tls_memsz.to_le_bytes());
    tph[48..56].copy_from_slice(&tls_align.to_le_bytes());

    // Segment data
    elf[code_offset..code_offset + code.len()].copy_from_slice(code);
    elf[tls_offset..tls_offset + tls_data.len()].copy_from_slice(tls_data);

    elf
}

#[test]
fn parse_pt_tls() {
    // 8 bytes of .tdata, 32 bytes total TLS (.tdata + .tbss), 16-byte aligned
    let elf = build_test_elf_with_tls(&[0xCC; 16], &[0x42; 8], 32, 16);
    let parsed = parse_elf(&elf).unwrap();

    let tls = parsed.tls.as_ref().expect("PT_TLS should be parsed");
    assert_eq!(tls.vaddr, 0x403000);
    assert_eq!(tls.filesz, 8);
    assert_eq!(tls.memsz, 32);
    assert_eq!(tls.align, 16);
}

#[test]
fn no_tls_for_elf_without_pt_tls() {
    let code = [0xCC; 16];
    let elf = build_test_elf(&code);
    let parsed = parse_elf(&elf).unwrap();
    assert!(parsed.tls.is_none());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-os elf::tests::parse_pt_tls -- --exact`
Expected: FAIL — `TlsInfo` type doesn't exist, `tls` field doesn't exist on `ParsedElf`.

**Step 3: Write minimal implementation**

In `crates/harmony-os/src/elf.rs`:

a) Add constant after line 26 (`const PT_INTERP: u32 = 3;`):

```rust
const PT_TLS: u32 = 7;
```

b) Add `TlsInfo` struct before `ParsedElf` (around line 86):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsInfo {
    /// Virtual address of the TLS template data (.tdata).
    pub vaddr: u64,
    /// Size of initialized TLS data (.tdata) in the ELF file.
    pub filesz: u64,
    /// Total TLS size in memory (.tdata + .tbss zero-fill).
    pub memsz: u64,
    /// TLS alignment requirement.
    pub align: u64,
}
```

c) Add field to `ParsedElf` (after `pub load_bias: u64,`):

```rust
/// Thread-local storage segment metadata (None if no PT_TLS).
pub tls: Option<TlsInfo>,
```

d) Add `tls` tracking variable in `parse_elf()` at line 216 (after `let mut interpreter = None;`):

```rust
let mut tls = None;
```

e) Add match arm in the phdr loop (after the `PT_INTERP` arm, replacing `_ => {}`):

```rust
PT_TLS => {
    let p_vaddr = u64_le(ph, 16);
    let p_filesz = u64_le(ph, 32);
    let p_memsz = u64_le(ph, 40);
    let p_align = u64_le(ph, 48);
    tls = Some(TlsInfo {
        vaddr: p_vaddr,
        filesz: p_filesz,
        memsz: p_memsz,
        align: p_align,
    });
}
_ => {}
```

f) Add `tls` field to the `Ok(ParsedElf { ... })` return (after `load_bias,`):

```rust
tls,
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os elf::tests -- --exact -q`
Expected: All existing tests PASS + 2 new tests PASS.

**Step 5: Commit**

```bash
git add crates/harmony-os/src/elf.rs
git commit -m "feat(elf): parse PT_TLS segment metadata

musl's __init_tls walks program headers to find the TLS template.
Store TlsInfo (vaddr, filesz, memsz, align) on ParsedElf so the
loader has TLS metadata for future bare-metal thread setup.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 2: Boot Stack Function — `prepare_process_stack()`

**Files:**
- Modify: `crates/harmony-os/src/elf_loader.rs:361-489` (reference only — `build_initial_stack()`)
- Modify: `crates/harmony-os/src/elf_loader.rs` (add `prepare_process_stack()` + tests)
- Modify: `crates/harmony-os/src/linuxulator.rs` (add `SyscallBackend::vm_map_anonymous()` if needed — check if it exists)

**Context:** `build_initial_stack()` constructs the Linux stack layout in a caller-provided `&mut [u8]` buffer and returns the SP value. But it operates on a raw byte slice — it doesn't allocate VM pages. We need a higher-level function that:
1. Allocates a stack region via `SyscallBackend::vm_mmap()` (or the `vm_map_anonymous` equivalent)
2. Calls `build_initial_stack()` to lay out argc/argv/envp/auxv
3. Writes the constructed stack into the process's VM
4. Returns the initial SP

This function bridges the ELF loader's `LoadResult` (which provides auxv) and the Linuxulator's boot path.

**Step 1: Write the failing test**

Add to `crates/harmony-os/src/elf_loader.rs` in the `tests` module:

```rust
#[test]
fn prepare_process_stack_builds_valid_layout() {
    let mut backend = LoaderMockBackend::new();

    let auxv = vec![
        (auxv::AT_PAGESZ, 4096),
        (auxv::AT_RANDOM, 0), // placeholder — gets patched
        (auxv::AT_NULL, 0),
    ];
    let random_bytes = [0x42u8; 16];

    let sp = prepare_process_stack(
        &mut backend,
        &["./hello", "--verbose"],
        &["HOME=/root"],
        &auxv,
        &random_bytes,
        0x7FFE_0000, // stack top (virtual address)
        8 * 4096,    // 8 pages
    );

    assert_ne!(sp, 0, "SP should be non-zero");
    assert_eq!(sp % 16, 0, "SP must be 16-byte aligned");

    // Verify argc was written at SP.
    let sp_offset = (sp - 0x7FFE_0000) as usize + (8 * 4096 - 8 * 4096);
    // The mock backend records writes — find the one containing SP.
    // argc = 2 (two argv entries).
    let writes = &backend.written;
    // Find the write that contains SP address.
    let stack_write = writes.iter().find(|(addr, data)| {
        let start = *addr;
        let end = start + data.len() as u64;
        sp >= start && sp < end
    });
    assert!(stack_write.is_some(), "stack data should be written to VM");
    let (base_addr, data) = stack_write.unwrap();
    let argc_offset = (sp - base_addr) as usize;
    let argc = u64::from_le_bytes(data[argc_offset..argc_offset + 8].try_into().unwrap());
    assert_eq!(argc, 2, "argc should be 2");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-os elf_loader::tests::prepare_process_stack_builds_valid_layout -- --exact`
Expected: FAIL — `prepare_process_stack` doesn't exist.

**Step 3: Write minimal implementation**

Add to `crates/harmony-os/src/elf_loader.rs`, after `build_initial_stack()` (after line 489):

```rust
/// Allocate a stack region, build the Linux-standard initial stack
/// layout (argc/argv/envp/auxv), write it into the process's VM,
/// and return the initial SP.
///
/// `stack_top` is the virtual address of the stack region's base
/// (lowest address). The stack grows downward from
/// `stack_top + stack_size`.
pub fn prepare_process_stack(
    backend: &mut dyn SyscallBackend,
    argv: &[&str],
    envp: &[&str],
    auxv: &[(u64, u64)],
    random_bytes: &[u8; 16],
    stack_top: u64,
    stack_size: usize,
) -> u64 {
    // Build the stack layout in a local buffer.
    let mut stack_buf = alloc::vec![0u8; stack_size];
    let sp = build_initial_stack(
        &mut stack_buf,
        stack_top,
        argv,
        envp,
        auxv,
        random_bytes,
    );

    // Write the entire stack buffer into the process's VM.
    backend.vm_write_bytes(stack_top, &stack_buf);

    sp
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os elf_loader::tests::prepare_process_stack_builds_valid_layout -- --exact`
Expected: PASS.

Also run the full elf_loader test suite:
Run: `cargo test -p harmony-os elf_loader -- -q`
Expected: All tests PASS.

**Step 5: Commit**

```bash
git add crates/harmony-os/src/elf_loader.rs
git commit -m "feat(elf_loader): add prepare_process_stack() for boot path

Bridges build_initial_stack() to the VM-backed SyscallBackend.
Allocates a local buffer, builds the Linux argc/argv/envp/auxv
layout, and writes it into the process address space.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 3: End-to-End Boot Function — `boot_static_elf()`

**Files:**
- Modify: `crates/harmony-os/src/elf_loader.rs` (add `boot_static_elf()` + test)

**Context:** This is the capstone function that composes everything:
1. Parse ELF via `parse_elf()`
2. Load segments via `InterpreterLoader::load()`
3. Call `prepare_process_stack()` with the resulting auxv
4. Return `(entry_point, sp)` — everything the boot path needs to start execution

**Step 1: Write the failing test**

Add to `crates/harmony-os/src/elf_loader.rs` in the `tests` module:

```rust
#[test]
fn boot_static_elf_returns_entry_and_sp() {
    let mut backend = LoaderMockBackend::new();
    let elf_bytes = build_static_elf(&[0xCC; 16]);
    let random_bytes = [0xAB; 16];

    let result = boot_static_elf(
        &mut backend,
        &elf_bytes,
        &["./hello"],
        &[],
        &random_bytes,
        0x7FFE_0000, // stack base
        8 * 4096,    // stack size
    );

    let (entry, sp) = result.expect("boot should succeed");
    assert_eq!(entry, 0x401000, "entry should be the ELF's entry_point");
    assert_eq!(sp % 16, 0, "SP must be 16-byte aligned");
    assert!(sp >= 0x7FFE_0000, "SP should be within stack region");
    assert!(sp < 0x7FFE_0000 + 8 * 4096, "SP should be within stack region");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-os elf_loader::tests::boot_static_elf_returns_entry_and_sp -- --exact`
Expected: FAIL — `boot_static_elf` doesn't exist.

**Step 3: Write minimal implementation**

Add to `crates/harmony-os/src/elf_loader.rs`, after `prepare_process_stack()`:

```rust
/// Parse, load, and set up the initial stack for a static ELF binary.
///
/// Returns `(entry_point, initial_sp)` — everything needed to start
/// execution. The caller sets PC and SP to these values.
///
/// This is the high-level boot function that composes:
/// - `parse_elf()` — extract ELF metadata
/// - `InterpreterLoader::load()` — map segments into VM
/// - `prepare_process_stack()` — build Linux stack layout
pub fn boot_static_elf(
    backend: &mut dyn SyscallBackend,
    elf_bytes: &[u8],
    argv: &[&str],
    envp: &[&str],
    random_bytes: &[u8; 16],
    stack_top: u64,
    stack_size: usize,
) -> Result<(u64, u64), ElfLoadError> {
    // 1. Load the ELF (parse + map segments + build auxv).
    let mut loader = InterpreterLoader::default();
    let result = loader.load(elf_bytes, backend)?;

    // 2. Build the initial stack with the auxv from the loader.
    let sp = prepare_process_stack(
        backend,
        argv,
        envp,
        &result.auxv,
        random_bytes,
        stack_top,
        stack_size,
    );

    Ok((result.entry_point, sp))
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-os elf_loader::tests::boot_static_elf_returns_entry_and_sp -- --exact`
Expected: PASS.

Run full test suite:
Run: `cargo test -p harmony-os elf_loader -- -q`
Expected: All tests PASS.

**Step 5: Commit**

```bash
git add crates/harmony-os/src/elf_loader.rs
git commit -m "feat(elf_loader): add boot_static_elf() composing load + stack

High-level boot function that parses an ELF, maps segments via
InterpreterLoader, builds the Linux-standard stack layout with
argc/argv/envp/auxv, and returns (entry_point, sp).

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: AT_RANDOM Stack Verification Test

**Files:**
- Modify: `crates/harmony-os/src/elf_loader.rs` (add integration test)

**Context:** The existing `build_initial_stack()` tests verify AT_RANDOM substitution works. This task adds a test through `boot_static_elf()` to verify the full pipeline: ELF load → auxv with AT_RANDOM placeholder → `prepare_process_stack()` patches AT_RANDOM → stack contains real entropy bytes.

**Step 1: Write the test**

Add to `crates/harmony-os/src/elf_loader.rs` in the `tests` module:

```rust
#[test]
fn boot_static_elf_at_random_contains_entropy() {
    let mut backend = LoaderMockBackend::new();
    let elf_bytes = build_static_elf(&[0xCC; 16]);
    let random_bytes: [u8; 16] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x13, 0x37, 0x42, 0x00, 0xFF, 0xEE, 0xDD, 0xCC,
    ];

    let (_, sp) = boot_static_elf(
        &mut backend,
        &elf_bytes,
        &["./test"],
        &[],
        &random_bytes,
        0x7FFE_0000,
        8 * 4096,
    )
    .expect("boot should succeed");

    // Find the stack write in the mock backend.
    let stack_write = backend
        .written
        .iter()
        .find(|(addr, data)| {
            let end = *addr + data.len() as u64;
            sp >= *addr && sp < end
        })
        .expect("stack data should be in mock backend writes");
    let (base, data) = stack_write;

    // Walk the stack from SP to find auxv.
    let sp_off = (sp - base) as usize;
    let read_u64 = |off: usize| -> u64 {
        u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
    };

    // argc
    let argc = read_u64(sp_off);
    let mut pos = sp_off + 8;

    // Skip argv pointers + NULL
    for _ in 0..argc {
        pos += 8;
    }
    pos += 8; // argv NULL terminator

    // Skip envp pointers + NULL
    loop {
        let val = read_u64(pos);
        pos += 8;
        if val == 0 {
            break;
        }
    }

    // Now at auxv. Find AT_RANDOM.
    let mut at_random_ptr = None;
    loop {
        let key = read_u64(pos);
        let val = read_u64(pos + 8);
        pos += 16;
        if key == auxv::AT_NULL {
            break;
        }
        if key == auxv::AT_RANDOM {
            at_random_ptr = Some(val);
        }
    }

    let ptr = at_random_ptr.expect("AT_RANDOM should be in auxv");

    // Read 16 bytes at the AT_RANDOM pointer from the stack data.
    let random_off = (ptr - base) as usize;
    let stored = &data[random_off..random_off + 16];
    assert_eq!(
        stored, &random_bytes,
        "AT_RANDOM should point to the provided entropy bytes"
    );
}
```

**Step 2: Run test to verify it passes**

Run: `cargo test -p harmony-os elf_loader::tests::boot_static_elf_at_random_contains_entropy -- --exact`
Expected: PASS (this test should pass immediately since the implementation is already in place from Tasks 2-3).

If it fails, debug by checking the AT_RANDOM patching logic in `build_initial_stack()` at line 453.

**Step 3: Run full suite**

Run: `cargo test -p harmony-os -- -q`
Expected: All tests PASS.

Run: `cargo clippy -p harmony-os`
Expected: No warnings.

**Step 4: Commit**

```bash
git add crates/harmony-os/src/elf_loader.rs
git commit -m "test(elf_loader): verify AT_RANDOM entropy through boot pipeline

End-to-end test walks the stack layout produced by boot_static_elf()
to verify AT_RANDOM points to the exact entropy bytes provided by
the caller. Validates the full ELF load → auxv → stack pipeline.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 5: PT_TLS Phdr Visibility Test

**Files:**
- Modify: `crates/harmony-os/src/elf_loader.rs` (add test)

**Context:** musl's `__init_tls` walks program headers via AT_PHDR to find PT_TLS. This test verifies that when an ELF contains PT_TLS, the program headers are mapped into the process's memory at the AT_PHDR address, and the PT_TLS entry is visible in those mapped headers.

This requires a test ELF builder that includes PT_TLS — extend the existing helpers.

**Step 1: Write the test**

Add a helper and test to `crates/harmony-os/src/elf_loader.rs` tests:

```rust
/// Build a static ET_EXEC ELF with PT_LOAD + PT_TLS.
fn build_static_elf_with_tls(code: &[u8], tls_memsz: u64) -> Vec<u8> {
    let phdr_size = 56usize;
    let phnum = 2usize; // PT_LOAD + PT_TLS
    let code_offset = 64 + phnum * phdr_size;
    let tls_data = [0u8; 8]; // 8 bytes of .tdata
    let tls_offset = code_offset + code.len();
    let total = tls_offset + tls_data.len();
    let mut elf = vec![0u8; total];

    // ELF header
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    #[cfg(target_arch = "x86_64")]
    elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    #[cfg(target_arch = "aarch64")]
    elf[18..20].copy_from_slice(&0xB7u16.to_le_bytes());
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // entry
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());

    // PT_LOAD: code at 0x401000 — but p_offset=0 so the ELF header+phdrs
    // are included in the mapped region (this is how real ELFs work — the
    // first LOAD segment starts at file offset 0 and covers everything).
    let ph = &mut elf[64..64 + phdr_size];
    ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    ph[4..8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    // p_offset = 0 (include headers in the mapping)
    ph[8..16].copy_from_slice(&0u64.to_le_bytes());
    ph[16..24].copy_from_slice(&0x400000u64.to_le_bytes()); // vaddr
    ph[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
    ph[32..40].copy_from_slice(&(total as u64).to_le_bytes()); // filesz = entire file
    ph[40..48].copy_from_slice(&(total as u64).to_le_bytes()); // memsz
    ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());

    // PT_TLS
    let tph = &mut elf[64 + phdr_size..64 + 2 * phdr_size];
    tph[0..4].copy_from_slice(&7u32.to_le_bytes()); // PT_TLS
    tph[4..8].copy_from_slice(&4u32.to_le_bytes()); // PF_R
    tph[8..16].copy_from_slice(&(tls_offset as u64).to_le_bytes());
    tph[16..24].copy_from_slice(&0x403000u64.to_le_bytes()); // vaddr
    tph[24..32].copy_from_slice(&0x403000u64.to_le_bytes());
    tph[32..40].copy_from_slice(&(tls_data.len() as u64).to_le_bytes());
    tph[40..48].copy_from_slice(&tls_memsz.to_le_bytes());
    tph[48..56].copy_from_slice(&16u64.to_le_bytes()); // align

    elf[tls_offset..tls_offset + tls_data.len()].copy_from_slice(&tls_data);

    // Set entry to 0x401000 (within the mapped range 0x400000..0x400000+total)
    elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes());

    elf
}

#[test]
fn boot_elf_with_tls_has_pt_tls_in_mapped_phdrs() {
    use crate::elf::parse_elf;

    let elf_bytes = build_static_elf_with_tls(&[0xCC; 16], 32);
    let parsed = parse_elf(&elf_bytes).unwrap();

    // Verify PT_TLS was parsed.
    assert!(parsed.tls.is_some(), "ParsedElf should contain TLS info");
    let tls = parsed.tls.unwrap();
    assert_eq!(tls.memsz, 32);

    // Verify phdr count includes PT_TLS.
    assert_eq!(parsed.phdr_count, 2, "should have PT_LOAD + PT_TLS");

    // Load via InterpreterLoader to verify no errors.
    let mut backend = LoaderMockBackend::new();
    let mut loader = InterpreterLoader::default();
    let result = loader.load(&elf_bytes, &mut backend);
    assert!(result.is_ok(), "loading ELF with PT_TLS should succeed");

    // Verify AT_PHDR is in the auxv and points within the mapped region.
    let load_result = result.unwrap();
    let at_phdr = load_result
        .auxv
        .iter()
        .find(|(k, _)| *k == auxv::AT_PHDR)
        .map(|(_, v)| *v)
        .expect("AT_PHDR should be in auxv");

    // AT_PHDR should point within the mapped region (0x400000...).
    assert!(
        at_phdr >= 0x400000,
        "AT_PHDR ({:#x}) should be within mapped region",
        at_phdr
    );

    // Verify the mapped memory at AT_PHDR contains the raw phdr bytes.
    // The mock backend stores all vm_write_bytes calls — find the one
    // that covers AT_PHDR.
    let phdr_write = backend.written.iter().find(|(addr, data)| {
        let end = *addr + data.len() as u64;
        at_phdr >= *addr && at_phdr + 56 * 2 <= end
    });
    assert!(
        phdr_write.is_some(),
        "program headers should be written to VM memory"
    );

    // Read the second phdr (PT_TLS) from the mapped data.
    let (base, data) = phdr_write.unwrap();
    let phdr_off = (at_phdr - base) as usize;
    let second_phdr_off = phdr_off + 56; // second phdr entry
    let p_type = u32::from_le_bytes(
        data[second_phdr_off..second_phdr_off + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(p_type, 7, "second phdr should be PT_TLS (type 7)");
}
```

**Step 2: Run test**

Run: `cargo test -p harmony-os elf_loader::tests::boot_elf_with_tls_has_pt_tls_in_mapped_phdrs -- --exact`
Expected: PASS.

**Step 3: Run full suite + clippy**

Run: `cargo test --workspace -- -q && cargo clippy --workspace`
Expected: All tests PASS, no clippy warnings.

**Step 4: Commit**

```bash
git add crates/harmony-os/src/elf_loader.rs
git commit -m "test(elf_loader): verify PT_TLS visible in mapped program headers

Verifies that when an ELF with PT_TLS is loaded, the program headers
at AT_PHDR contain the PT_TLS entry — essential for musl's __init_tls
which walks phdrs in-process to find TLS metadata.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 6: Final Quality Gate

**Files:** None — verification only.

**Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All tests PASS.

**Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: No warnings.

**Step 3: Run format check**

Run: `cargo fmt --all -- --check`
Expected: No formatting issues.

**Step 4: Review all changes since starting**

Run: `git log --oneline HEAD~5..HEAD`
Expected: 5 commits (Tasks 1-5), all with clear messages.

Run: `git diff HEAD~5..HEAD --stat`
Review: Only `elf.rs` and `elf_loader.rs` should have changes.
