# RPi5: W^X Hardening for aarch64 Boot

**Bead:** harmony-os-fg5
**Date:** 2026-03-22
**Status:** Draft

## Problem

All usable RAM is mapped RWX (readable + writable + executable) during boot.
The MMU and page table code fully support per-page permissions, but no section
boundaries are available to distinguish code from data. This allows code
injection attacks — a writable page that is also executable means an attacker
who can write to memory can also execute that memory.

## Solution

Parse the PE/COFF section headers at boot to discover `.text`, `.rdata`, and
`.data` boundaries. Use these boundaries when building the identity-mapped page
table to enforce W^X: code pages are RX (not writable), data pages are RW (not
executable), read-only data is RO.

## Design Decisions

### Parse PE/COFF headers, not linker symbols

UEFI loads the kernel as a PE/COFF binary. The section headers are already in
memory at the image base and encode per-section permissions (NX, writable).
This is the natural approach — no linker script needed, no build script hacks.
The headers are available before `ExitBootServices()` and remain in memory
after.

### Cache boundaries before ExitBootServices

The Loaded Image Protocol gives us the image base address. We parse the
PE/COFF headers while UEFI services are still available, cache the section
boundaries in a compact struct, then use them later in `mmu::init_and_enable()`.

### Conservative fallback

If PE parsing fails (malformed headers, unexpected layout), fall back to RWX
for the entire image range and log a warning on the serial console. The system
still boots — just without hardening. This keeps the boot path robust.

### Page-align section boundaries

PE section `VirtualSize` is not guaranteed to be page-aligned. Section start
addresses are rounded down and end addresses rounded up to 4 KiB page
boundaries. For pages that straddle two sections (partial overlap), the **more
permissive** flags win — this is safe because we only add permissions, never
remove them beyond what W^X requires. In practice, the Rust/LLVM PE linker
page-aligns sections, so straddling pages are unlikely.

### Sections with both WRITE and EXECUTE are rejected

If any PE section has both `IMAGE_SCN_MEM_WRITE` and `IMAGE_SCN_MEM_EXECUTE`,
the parser returns an error and the fallback (RWX for the image) applies. A
well-formed Rust PE binary never produces WX sections. If one appears, something
is wrong and we shouldn't silently accept it.

## Architecture

### Module Interface

```rust
// crates/harmony-boot-aarch64/src/pe.rs

const MAX_SECTIONS: usize = 16;

/// Cached section boundaries with per-section PageFlags.
pub struct ImageSections {
    pub image_base: u64,
    pub image_size: u64,
    entries: [(u64, u64, PageFlags); MAX_SECTIONS],  // (page_start, page_end, flags)
    count: usize,
}

#[derive(Debug)]
pub enum PeError {
    BadDosSignature,
    BadPeSignature,
    TooManySections,
    WriteExecuteSection,
}

/// Parse PE/COFF section headers from an in-memory image.
///
/// `image_base` is the physical address where UEFI loaded the image.
/// Returns cached page-aligned section boundaries with permission flags.
/// Fails if the PE headers are malformed or any section is WX.
pub fn parse_sections(image_base: u64, image_size: u64) -> Result<ImageSections, PeError>
```

`ImageSections` exposes:

```rust
impl ImageSections {
    /// Return the PageFlags for a given physical address, or None if
    /// the address is outside the image.
    pub fn flags_for_addr(&self, addr: u64) -> Option<PageFlags>

    /// True if the address falls within the image range.
    pub fn contains(&self, addr: u64) -> bool
}
```

### PE/COFF Parsing Steps

1. Read DOS header at image base → `e_lfanew` (u32 at offset 0x3C)
2. Verify PE signature (`PE\0\0` at `image_base + e_lfanew`)
3. Read COFF header at `+4`: `NumberOfSections` (u16), `SizeOfOptionalHeader` (u16)
4. Skip optional header: section table starts at `pe_offset + 24 + SizeOfOptionalHeader`
5. For each section (40 bytes each), extract:
   - `VirtualAddress` (u32 at offset +12, relative to image base)
   - `VirtualSize` (u32 at offset +8)
   - `Characteristics` (u32 at offset +36)
6. Convert to page-aligned ranges and PageFlags

PE characteristics to PageFlags:
- `IMAGE_SCN_MEM_EXECUTE` (0x2000_0000) → EXECUTABLE
- `IMAGE_SCN_MEM_WRITE` (0x8000_0000) → WRITABLE
- `IMAGE_SCN_MEM_READ` (0x4000_0000) → READABLE
- Both EXECUTE and WRITE → `Err(PeError::WriteExecuteSection)`

### MMU Init Changes

`mmu::init_and_enable()` gains an `Option<&ImageSections>` parameter:

For each page in a usable region:
1. If `image_sections.is_some()` and `sections.contains(page_addr)`:
   → use `sections.flags_for_addr(page_addr)`
2. If address is outside the image (or no sections provided):
   → map as RW (READABLE | WRITABLE) — heap, stack, bump allocator
3. If `image_sections.is_none()` (parse failed):
   → map everything as RWX (current behavior, with warning logged)

MMIO mapping for PL011 UART unchanged (RW | NO_CACHE).

### Boot Sequence

In `main.rs`, before the existing `exit_boot_services()` call:

```rust
// Query Loaded Image Protocol for image base/size
let loaded_image = boot_services.open_protocol_exclusive::<LoadedImage>(image_handle)?;
let (image_base, image_size) = loaded_image.info();

// Parse PE section headers
let image_sections = pe::parse_sections(image_base as u64, image_size as u64);
if let Err(ref e) = image_sections {
    // Log warning via UEFI console (still available)
    log::warn!("PE section parse failed ({e:?}), W^X disabled");
}
```

After `exit_boot_services()` and memory map collection, pass to MMU:

```rust
mmu::init_and_enable(&regions, region_count, image_sections.ok().as_ref());
```

## File Changes

| File | Change |
|------|--------|
| `crates/harmony-boot-aarch64/src/pe.rs` | New: `parse_sections()`, `ImageSections`, `PeError` |
| `crates/harmony-boot-aarch64/src/main.rs` | Query Loaded Image before ExitBootServices, pass to MMU |
| `crates/harmony-boot-aarch64/src/mmu.rs` | `init_and_enable()` takes `Option<&ImageSections>`, use for per-page flags |

## What is NOT in Scope

- No changes to the page table implementation itself (already supports all permission combos)
- No ELF section parsing (the boot image is PE/COFF, not ELF)
- No runtime permission changes (W^X is set at boot and stays)
- No user-space W^X (Linuxulator processes — separate concern)
- No x86_64 boot W^X (different boot crate, different bootloader)

## Testing

- `pe_parse_sections` — parse a crafted PE header byte buffer, verify section count and page-aligned boundaries
- `pe_parse_invalid_dos_signature` — bad DOS magic returns `BadDosSignature`
- `pe_parse_invalid_pe_signature` — bad PE magic returns `BadPeSignature`
- `pe_parse_wx_section_rejected` — section with WRITE+EXECUTE returns `WriteExecuteSection`
- `pe_characteristics_to_flags` — verify IMAGE_SCN_MEM_* → PageFlags conversion
- `pe_section_boundaries_page_aligned` — non-page-aligned VirtualSize rounds up correctly
- `image_sections_flags_for_addr` — verify lookup returns correct flags for addresses within/outside sections
- `mmu_text_pages_rx` — verify text range pages get RX (not W)
- `mmu_data_pages_rw` — verify data range pages get RW (not X)
- `mmu_outside_image_rw` — verify heap/stack pages get RW (not X)
- `mmu_fallback_rwx` — verify None sections → RWX (backward compatible)
- Existing MMU tests unchanged (page table mechanics not modified)
