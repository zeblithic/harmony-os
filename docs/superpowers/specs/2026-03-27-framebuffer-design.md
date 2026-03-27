# Native Rust Framebuffer Driver for RPi5

**Date:** 2026-03-27
**Status:** Draft
**Bead:** harmony-os-4zg

## Problem

Harmony OS needs visual output for boot diagnostics and debug console. The RPi5's UEFI firmware provides a GOP (Graphics Output Protocol) framebuffer — a linear pixel buffer at a known physical address. We need a driver to write pixels and render text to it.

## Constraints

- **Sans-I/O.** Generic over `RegisterBank` like all other drivers. Testable with `MockRegisterBank`.
- **UEFI GOP only.** No mailbox property interface — use the framebuffer UEFI already allocated. Simpler, always available on RPi5 UEFI.
- **No 9P server.** Direct use by boot/kernel for debug output. 9P exposure is a follow-up if needed.
- **8x16 VGA font.** Standard CP437 bitmap font, public domain, same as Linux fbcon/GRUB.
- **Bank stored in struct.** Unlike GENET/SDHCI which pass `&mut bank` per call, the framebuffer stores the bank in the struct (like `Rp1Gpio`). This is appropriate because the framebuffer is a single contiguous memory region, not a register-based peripheral, and avoids threading the bank through the deep `ConsoleRenderer → FramebufferDriver → bank` call chain.

## Architecture

```
UEFI GOP → FramebufferInfo { base, width, height, stride, pixel_format }
  ↓
FramebufferDriver<B: RegisterBank>
  write_pixel(x, y, color)
  fill_rect(x, y, w, h, color)
  clear(color)
  ↓
ConsoleRenderer<B>  (implements core::fmt::Write)
  putchar(ch) — renders 8x16 glyph
  write_str(s) — string output with cursor tracking
  scroll() — shifts rows up, clears bottom
```

Boot code captures `FramebufferInfo` from UEFI GOP before ExitBootServices. The UEFI GOP `PixelsPerScanLine` is in *pixels* — the boot code must convert to byte stride: `stride = pixels_per_scan_line * 4`. The framebuffer physical address is mapped as device memory (NO_CACHE) in the boot code's page tables.

**UEFI integration point:** The handoff will occur in `harmony-boot-aarch64` (or the platform-specific boot module). This is out of scope for this bead — the driver accepts a `FramebufferInfo` struct and doesn't know where it came from.

## File Layout

New files in `crates/harmony-unikernel/src/drivers/`:

| File | Responsibility |
|------|---------------|
| `framebuffer.rs` | `FramebufferInfo`, `PixelFormat`, `Color`, `FramebufferDriver<B>` |
| `console.rs` | `ConsoleRenderer<B>` — text rendering with cursor, wrap, scroll, `fmt::Write` |
| `font_8x16.rs` | `pub const FONT_8X16: [u8; 4096]` — 256-char VGA bitmap font |

Modified: `drivers/mod.rs` — add `pub mod framebuffer; pub mod console; pub mod font_8x16;`

## FramebufferDriver

### Types

```rust
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub base: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,          // Bytes per row (NOT pixels — boot code converts from GOP PixelsPerScanLine * 4)
    pub pixel_format: PixelFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Bgr32,  // UEFI PixelBlueGreenRedReserved8BitPerColor (most common)
    Rgb32,  // UEFI PixelRedGreenBlueReserved8BitPerColor
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub const WHITE: Self = Self { r: 255, g: 255, b: 255 };
    pub const BLACK: Self = Self { r: 0, g: 0, b: 0 };
    pub const GREEN: Self = Self { r: 0, g: 255, b: 0 };
}
```

### Driver

```rust
pub struct FramebufferDriver<B: RegisterBank> {
    bank: B,
    info: FramebufferInfo,
}

impl<B: RegisterBank> FramebufferDriver<B> {
    /// Create a new framebuffer driver.
    /// Panics if width == 0, height == 0, or stride < width * 4.
    pub fn new(bank: B, info: FramebufferInfo) -> Self;
    pub fn info(&self) -> &FramebufferInfo;

    /// Write a single pixel. Out-of-bounds x/y silently ignored.
    pub fn write_pixel(&mut self, x: u32, y: u32, color: Color);

    /// Fill a rectangle. Clamped to screen bounds.
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: Color);

    /// Clear entire screen to a single color.
    pub fn clear(&mut self, color: Color);

    /// Read a raw packed pixel at (x, y). Returns None if out of bounds.
    /// Private — used internally by scroll(). Returns the raw u32 from the
    /// bank, which can be passed directly to write() without format conversion.
    fn read_raw(&self, x: u32, y: u32) -> Option<u32>;

    /// Write a raw packed pixel at (x, y). Out-of-bounds silently ignored.
    /// Private — used internally by scroll() for bulk copy.
    fn write_raw(&mut self, x: u32, y: u32, packed: u32);
}
```

### Pixel packing

`write_pixel` computes the byte offset and packs the color:

```rust
let offset = (y * self.info.stride + x * 4) as usize;
let packed = match self.info.pixel_format {
    PixelFormat::Bgr32 => (color.b as u32) | (color.g as u32) << 8 | (color.r as u32) << 16,
    PixelFormat::Rgb32 => (color.r as u32) | (color.g as u32) << 8 | (color.b as u32) << 16,
};
self.bank.write(offset, packed);
```

`read_raw`/`write_raw` use `bank.read(offset)` / `bank.write(offset, packed)` directly — no color conversion, just raw u32 values. This is correct for scrolling because the source and destination use the same pixel format.

## ConsoleRenderer

```rust
use core::fmt;

pub struct ConsoleRenderer<B: RegisterBank> {
    fb: FramebufferDriver<B>,
    cursor_x: u32,
    cursor_y: u32,
    cols: u32,         // info.width / 8
    rows: u32,         // info.height / 16
    fg: Color,
    bg: Color,
}

impl<B: RegisterBank> ConsoleRenderer<B> {
    pub fn new(fb: FramebufferDriver<B>, fg: Color, bg: Color) -> Self;
    pub fn putchar(&mut self, ch: u8);
    pub fn clear(&mut self);
}

/// Enables `write!()` / `writeln!()` macro usage for debug output.
impl<B: RegisterBank> fmt::Write for ConsoleRenderer<B> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Iterate over bytes (not chars) — CP437 is a byte encoding.
        // Non-ASCII UTF-8 sequences are rendered byte-by-byte as
        // their CP437 glyph equivalents (intentional — debug output
        // is ASCII-dominated and this avoids UTF-8 decoding overhead).
        for &b in s.as_bytes() {
            self.putchar(b);
        }
        Ok(())
    }
}
```

### putchar behavior

- `\n` (0x0A) → cursor_y += 1, cursor_x = 0. If cursor_y >= rows, scroll.
- `\r` (0x0D) → cursor_x = 0.
- `\t` (0x09) → advance cursor_x to next multiple of 8 (tab stop). If past end of line, wrap.
- All other control codes (0x00-0x1F except above) → silently ignored.
- Printable (0x20..=0xFF) → render glyph, advance cursor_x. If cursor_x >= cols, wrap to next row.

### Glyph rendering

For each character `ch`, the font data is `FONT_8X16[ch as usize * 16 .. (ch as usize + 1) * 16]` — 16 bytes, one per row. Each byte is 8 pixels, MSB = leftmost. For each set bit, write `fg` color; for each clear bit, write `bg` color.

### Scrolling

`scroll()` copies pixel rows using `read_raw`/`write_raw`: for each row `r` in `1..rows`, copy the 16 pixel rows of character row `r` to row `r-1`. Then clear the bottom character row to `bg` via `fill_rect`.

Performance: O(width × height) — ~8M read + ~8M write calls for 1080p. Acceptable for a debug console. Tests use a small mock resolution (e.g., 32×32 pixels = 4 cols × 2 rows) to keep MockRegisterBank vectors manageable.

## Font Data

`font_8x16.rs` contains `pub const FONT_8X16: [u8; 4096]`. Standard VGA/CP437 8x16 bitmap font, 256 characters × 16 bytes = 4096 bytes.

**Source:** The font data from the [Cozette](https://github.com/slavfox/Cozette) project (MIT licensed) or the classic IBM VGA font from [int10h.org](https://int10h.org/oldschool-pc-fonts/) (CC0/public domain). The implementer should use the int10h.org "IBM VGA 8x16" font dump as a `[u8; 4096]` array. A Python one-liner can extract the raw bytes from a .psf file: `python3 -c "open('font.psf','rb').read()[32:]"` (skip PSF header).

## Testing Strategy

All tests use `MockRegisterBank` with a **small mock resolution** (e.g., 32×32 pixels, stride=128 bytes) to keep register logs manageable.

| Test | What |
|------|------|
| `new_panics_on_zero_width` | `FramebufferInfo { width: 0, .. }` panics |
| `write_pixel_rgb_format` | RGB32: verify `bank.read(offset)` matches `(r, g, b, 0)` packing |
| `write_pixel_bgr_format` | BGR32: verify byte order swapped |
| `write_pixel_out_of_bounds_silent` | x/y past width/height — no panic, no write |
| `fill_rect_writes_all_pixels` | Fill 3×3, verify 9 writes |
| `clear_fills_entire_screen` | Clear 4×4 screen, verify 16 writes |
| `putchar_renders_glyph` | Render 'A', verify non-zero pixels at expected glyph positions |
| `putchar_newline_advances_row` | '\n' moves cursor_y, resets cursor_x |
| `putchar_wraps_at_end_of_line` | Write past last column → cursor wraps to next row |
| `putchar_tab_advances_to_next_stop` | '\t' at col 3 → col 8 |
| `putchar_control_char_ignored` | 0x01 (SOH) produces no output |
| `fmt_write_works` | `write!(console, "Hi")` renders two glyphs |
| `scroll_shifts_rows_up` | Write to row 0, scroll, verify content moved |

## Out of Scope

- Mailbox property interface (mode switching, resolution changes)
- UEFI GOP integration (boot code captures FramebufferInfo — separate bead)
- Hardware cursor
- VSync / double buffering
- 9P FramebufferServer (follow-up if needed)
- GPU acceleration / 3D
- Alpha blending / compositing
