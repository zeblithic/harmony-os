# Framebuffer Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a UEFI GOP framebuffer driver and 8x16 bitmap console renderer to `harmony-unikernel`, enabling text output on RPi5's display.

**Architecture:** `FramebufferDriver<B: RegisterBank>` for pixel operations, `ConsoleRenderer<B>` for text rendering with `core::fmt::Write`, and an embedded VGA font. All sans-I/O, testable with `MockRegisterBank`.

**Tech Stack:** Rust (no_std + alloc), existing `RegisterBank` trait and `MockRegisterBank` from `harmony-unikernel`

**Spec:** `docs/superpowers/specs/2026-03-27-framebuffer-design.md`

---

## File Structure

### New files in `crates/harmony-unikernel/src/drivers/`

| File | Responsibility |
|------|---------------|
| `framebuffer.rs` | `FramebufferInfo`, `PixelFormat`, `Color`, `FramebufferDriver<B>` |
| `console.rs` | `ConsoleRenderer<B>`, `putchar`, `fmt::Write`, scroll |
| `font_8x16.rs` | `pub const FONT_8X16: [u8; 4096]` — VGA bitmap font data |

### Modified

| File | Change |
|------|--------|
| `drivers/mod.rs` | Add `pub mod framebuffer; pub mod console; pub mod font_8x16;` |

---

## Task 1: Font data

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/font_8x16.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs`

**Context:**
- 256 characters × 16 bytes per glyph = 4096 bytes
- Standard IBM VGA 8x16 font (CP437), public domain / CC0
- MSB = leftmost pixel in each byte row
- Source: int10h.org "IBM VGA 8x16" font or equivalent

- [ ] **Step 1: Create font data file**

The file contains a single `pub const FONT_8X16: [u8; 4096]` array. The data is the standard VGA 8x16 font — 256 glyphs, 16 bytes each.

To generate: download the IBM VGA 8x16 .psf font from int10h.org, extract raw glyph data (skip PSF header), and format as a Rust byte array. Or copy the well-known byte values from any open-source bare-metal project.

Key glyphs to verify in tests:
- Glyph 0x00 (null): all zero bytes
- Glyph 0x20 (space): all zero bytes
- Glyph 0x41 ('A'): has non-zero bytes (identifiable pattern)

```rust
// crates/harmony-unikernel/src/drivers/font_8x16.rs
// SPDX-License-Identifier: GPL-2.0-or-later
//! IBM VGA 8x16 bitmap font (CP437).
//!
//! 256 characters, 16 bytes per glyph, MSB = leftmost pixel.
//! Public domain font data from the IBM VGA ROM.

/// 8x16 bitmap font: `FONT_8X16[ch * 16 .. (ch + 1) * 16]` gives 16 rows.
pub const FONT_8X16: [u8; 4096] = [
    // ... 4096 bytes of font data ...
];
```

- [ ] **Step 2: Add `pub mod font_8x16;` to drivers/mod.rs**

- [ ] **Step 3: Verify it compiles**

Run: `cargo test -p harmony-unikernel -- --list 2>&1 | head -5`
Expected: No compile errors

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/font_8x16.rs crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(unikernel): add IBM VGA 8x16 bitmap font data"
```

---

## Task 2: FramebufferDriver — pixel operations

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/framebuffer.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs`

**Context:**
- Generic over `RegisterBank` (stored in struct, like `Rp1Gpio`)
- `FramebufferInfo`: base, width, height, stride (bytes), pixel_format
- `PixelFormat`: Bgr32 (common) and Rgb32
- `Color`: r, g, b with const WHITE/BLACK/GREEN
- `write_pixel`: compute offset = y * stride + x * 4, pack color per format, call `bank.write(offset, packed)`
- `fill_rect`: loop write_pixel, clamped to bounds
- `clear`: fill_rect(0, 0, width, height, color)
- `read_raw`/`write_raw`: private, raw u32, for scroll
- Out-of-bounds silently ignored
- `new()` panics on zero width/height or stride < width * 4

### Tests (7 tests)

1. `new_panics_on_zero_width` — `#[should_panic]`
2. `write_pixel_rgb_format` — RGB32 at (1, 0), stride=32: verify `bank.writes` contains `(4, packed_rgb)`
3. `write_pixel_bgr_format` — BGR32: verify byte order swapped
4. `write_pixel_out_of_bounds_silent` — x=width, y=height: no writes, no panic
5. `fill_rect_writes_all_pixels` — fill 3×3 at (0,0) on 8×8 screen: verify 9 writes
6. `clear_fills_entire_screen` — clear 4×4 screen: verify 16 writes
7. `stride_respects_padding` — stride=20 (5 pixels × 4), write_pixel at (0, 1): verify offset = 20 (not 16)

Use `MockRegisterBank` with small resolutions (4×4, 8×8). Test helper:

```rust
fn make_info(w: u32, h: u32, fmt: PixelFormat) -> FramebufferInfo {
    FramebufferInfo {
        base: 0,
        width: w,
        height: h,
        stride: w * 4,
        pixel_format: fmt,
    }
}
```

- [ ] **Step 1: Write tests + implementation**
- [ ] **Step 2: Add `pub mod framebuffer;` to drivers/mod.rs**
- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel framebuffer`
Expected: All 7 pass

- [ ] **Step 4: Run workspace checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/framebuffer.rs crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(unikernel): add FramebufferDriver with pixel operations"
```

---

## Task 3: ConsoleRenderer — text output with fmt::Write

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/console.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs`

**Context:**
- Owns `FramebufferDriver<B>`, tracks cursor_x/cursor_y, computes cols/rows from info
- `putchar(ch: u8)`: render glyph from `FONT_8X16`, advance cursor
- `impl fmt::Write`: iterates `s.as_bytes()`, calls putchar per byte
- Glyph rendering: for each of 16 rows, read byte from font, for each of 8 bits (MSB left), write fg or bg pixel
- Scroll: copy rows using read_raw/write_raw, clear bottom row
- Tab: advance to next multiple of 8
- Control chars (except \n, \r, \t): silently ignored

### Tests (6 tests)

Tests use a **small mock resolution**: 32×32 pixels = 4 cols × 2 rows (8×16 font).

1. `putchar_renders_glyph` — render 'A' (0x41), verify some non-zero pixels written at character position (0,0). Check that `bank.writes` contains entries in the glyph's pixel region.

2. `putchar_newline_advances_row` — putchar('\n'), verify cursor_y=1, cursor_x=0.

3. `putchar_wraps_at_end_of_line` — on a 4-col display, putchar 5 printable chars. After 4th, cursor should be at (0, 1).

4. `putchar_tab_advances_to_next_stop` — cursor at col 3, putchar('\t'), verify cursor at col 8. On a narrow display (cols < 8), should wrap.

5. `putchar_control_char_ignored` — putchar(0x01), verify no writes to bank.

6. `fmt_write_works` — `write!(console, "Hi")`, verify two glyphs rendered (bank.writes.len() corresponds to two characters × 8×16 pixels).

**Important for scroll test:** A scroll test requires read_raw to return meaningful data. Since `read_raw` uses `bank.read(offset)`, the test must pre-populate the MockRegisterBank with `on_read` values for the source row offsets. This is complex for a mock — instead, test scroll indirectly: fill the screen with characters, trigger a scroll (write past last row), and verify the clear operation happened for the bottom row (new writes at the bottom row's pixel offsets).

7. `scroll_clears_bottom_row` — fill 2-row display (putchar 'A' × 8 chars to fill both rows), then putchar('\n') to trigger scroll. Verify that bank.writes includes writes to the bottom row's region (bg color fill for cleared row).

- [ ] **Step 1: Write tests + implementation**

- [ ] **Step 2: Add `pub mod console;` to drivers/mod.rs**

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel console`
Expected: All 7 pass

- [ ] **Step 4: Run workspace checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/console.rs crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(unikernel): add ConsoleRenderer with fmt::Write and VGA font"
```

---

## Dependencies

```
Task 1 (font data) — standalone
  ↓
Task 2 (FramebufferDriver) — standalone, no font dependency
  ↓
Task 3 (ConsoleRenderer) — depends on Tasks 1 + 2
```

Tasks 1 and 2 are independent and could run in parallel.
