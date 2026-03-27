// SPDX-License-Identifier: GPL-2.0-or-later

//! Text console renderer built on top of [`FramebufferDriver`].
//!
//! Renders characters from the VGA 8×16 bitmap font, with full [`fmt::Write`]
//! support so that `write!` / `writeln!` macros work directly.

use core::fmt;

use super::font_8x16::FONT_8X16;
use super::framebuffer::{Color, FramebufferDriver};
use super::RegisterBank;

/// A text console rendered onto a framebuffer.
///
/// Character cells are 8 pixels wide and 16 pixels tall (VGA 8×16 font).
/// The number of columns and rows is derived from the framebuffer dimensions
/// at construction time.
pub struct ConsoleRenderer<B: RegisterBank> {
    fb: FramebufferDriver<B>,
    /// Current character column (0-based).
    cursor_x: u32,
    /// Current character row (0-based).
    cursor_y: u32,
    /// Number of character columns: `info.width / 8`.
    cols: u32,
    /// Number of character rows: `info.height / 16`.
    rows: u32,
    /// Foreground (text) colour.
    fg: Color,
    /// Background colour.
    bg: Color,
}

impl<B: RegisterBank> ConsoleRenderer<B> {
    /// Create a new [`ConsoleRenderer`].
    ///
    /// `cols` and `rows` are computed from `fb.info()`. The cursor starts at
    /// `(0, 0)`. The screen is **not** cleared on construction; call
    /// [`clear`](Self::clear) explicitly if needed.
    /// # Panics
    ///
    /// Panics if the framebuffer is too small for even one character cell
    /// (width < 8 or height < 16).
    pub fn new(fb: FramebufferDriver<B>, fg: Color, bg: Color) -> Self {
        let info = *fb.info();
        let cols = info.width / 8;
        let rows = info.height / 16;
        assert!(
            cols > 0,
            "framebuffer width must be at least 8 pixels for a console"
        );
        assert!(
            rows > 0,
            "framebuffer height must be at least 16 pixels for a console"
        );
        Self {
            fb,
            cursor_x: 0,
            cursor_y: 0,
            cols,
            rows,
            fg,
            bg,
        }
    }

    /// Write a single byte to the console.
    ///
    /// Special byte handling:
    /// - `\n` (0x0A): advance to the next row, reset column to 0.
    /// - `\r` (0x0D): reset column to 0.
    /// - `\t` (0x09): advance to the next tab stop (multiples of 8 columns).
    /// - Other control bytes (0x00–0x1F): silently ignored.
    /// - All other bytes (0x20–0xFF): render as a VGA glyph.
    pub fn putchar(&mut self, ch: u8) {
        match ch {
            0x0A => {
                // Newline
                self.cursor_y += 1;
                self.cursor_x = 0;
                if self.cursor_y >= self.rows {
                    self.scroll();
                    self.cursor_y = self.rows - 1;
                }
            }
            0x0D => {
                // Carriage return
                self.cursor_x = 0;
            }
            0x09 => {
                // Horizontal tab — advance to next multiple-of-8 column
                self.cursor_x = (self.cursor_x / 8 + 1) * 8;
                if self.cursor_x >= self.cols {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                    if self.cursor_y >= self.rows {
                        self.scroll();
                        self.cursor_y = self.rows - 1;
                    }
                }
            }
            0x00..=0x1F => {
                // Other control characters — silently ignored
            }
            _ => {
                // Printable character: render glyph then advance cursor
                self.render_glyph(ch);
                self.cursor_x += 1;
                if self.cursor_x >= self.cols {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                    if self.cursor_y >= self.rows {
                        self.scroll();
                        self.cursor_y = self.rows - 1;
                    }
                }
            }
        }
    }

    /// Clear the entire screen to the background colour and reset the cursor
    /// to `(0, 0)`.
    pub fn clear(&mut self) {
        self.fb.clear(self.bg);
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    // -----------------------------------------------------------------------
    // Crate-internal accessors (for tests)
    // -----------------------------------------------------------------------

    /// Return a shared reference to the underlying register bank.
    ///
    /// Used by unit tests to inspect write logs.
    #[cfg(test)]
    pub(crate) fn bank(&self) -> &B {
        self.fb.bank()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Render the glyph for `ch` at the current cursor position.
    fn render_glyph(&mut self, ch: u8) {
        let glyph = &FONT_8X16[ch as usize * 16..(ch as usize + 1) * 16];
        let px = self.cursor_x * 8;
        let py = self.cursor_y * 16;
        for (row, &bits) in glyph.iter().enumerate() {
            for col in 0..8u32 {
                let color = if bits & (0x80 >> col) != 0 {
                    self.fg
                } else {
                    self.bg
                };
                self.fb.write_pixel(px + col, py + row as u32, color);
            }
        }
    }

    /// Scroll the display up by one character row (16 pixels).
    ///
    /// Copies pixel rows 16..height to rows 0..height-16, then clears the
    /// bottom character row to the background colour. After scrolling the
    /// cursor row is decremented by the caller.
    // TODO: replace pixel-by-pixel copy with bulk memmove once RegisterBank
    // exposes a raw slice. Current approach issues 2 × (rows-1) × 16 × width
    // MMIO ops per scroll (~2M on 1080p). Acceptable for early-boot debug
    // console but will stall on high-res displays.
    fn scroll(&mut self) {
        let info = *self.fb.info();
        for y in 16..(self.rows * 16) {
            for x in 0..info.width {
                if let Some(pixel) = self.fb.read_raw(x, y) {
                    self.fb.write_raw(x, y - 16, pixel);
                }
            }
        }
        let bottom_y = (self.rows - 1) * 16;
        self.fb.fill_rect(0, bottom_y, info.width, 16, self.bg);
    }
}

/// NOTE: `write_str` iterates over raw bytes (`s.as_bytes()`), rendering each
/// byte as its CP437 glyph. Non-ASCII UTF-8 characters will be split into
/// their component bytes and rendered as unrelated CP437 glyphs. Restrict
/// output to ASCII for correct visual results.
impl<B: RegisterBank> fmt::Write for ConsoleRenderer<B> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            self.putchar(b);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::framebuffer::{FramebufferDriver, FramebufferInfo, PixelFormat};
    use super::super::register_bank::mock::MockRegisterBank;
    use super::*;
    use core::fmt::Write;

    /// Build a 32×32 console (4 cols × 2 rows at 8×16 font).
    fn make_console() -> ConsoleRenderer<MockRegisterBank> {
        let bank = MockRegisterBank::new();
        let info = FramebufferInfo {
            base: 0,
            width: 32,
            height: 32,
            stride: 128,
            pixel_format: PixelFormat::Rgb32,
        };
        let fb = FramebufferDriver::new(bank, info);
        ConsoleRenderer::new(fb, Color::WHITE, Color::BLACK)
    }

    #[test]
    fn putchar_renders_glyph() {
        let mut con = make_console();
        con.putchar(b'A');
        // 'A' (0x41) has non-zero rows, so bank should have writes
        assert!(
            !con.bank().writes.is_empty(),
            "glyph 'A' should produce writes"
        );
        // All writes must be within the first character cell (0..8 pixels wide, 0..16 pixels tall)
        // offset = y * stride + x * 4; stride=128, char cell: x in [0,8), y in [0,16)
        // max offset in cell = 15*128 + 7*4 = 1920 + 28 = 1948
        // Every write for the first glyph should have offset < 128*16 = 2048
        for &(offset, _) in &con.bank().writes {
            assert!(
                offset < 2048,
                "write offset {offset} outside first character row"
            );
        }
    }

    #[test]
    fn putchar_newline_advances_row() {
        let mut con = make_console();
        con.putchar(b'\n');
        let writes_before = con.bank().writes.len();
        con.putchar(b'A');
        let writes_after = con.bank().writes.len();
        assert!(
            writes_after > writes_before,
            "putchar after \\n should write glyphs"
        );
        // Writes after newline must be in the second character row (y >= 16)
        // offset for y=16, x=0: 16*128+0 = 2048
        let new_writes = &con.bank().writes[writes_before..];
        for &(offset, _) in new_writes {
            assert!(
                offset >= 2048,
                "after \\n, glyph write offset {offset} should be in second row (>= 2048)"
            );
        }
    }

    #[test]
    fn putchar_wraps_at_end_of_line() {
        let mut con = make_console();
        // 4-col display: first 4 'A's fill row 0, 5th should wrap to row 1
        for _ in 0..4 {
            con.putchar(b'A');
        }
        let writes_before = con.bank().writes.len();
        con.putchar(b'A'); // 5th character — should be in row 1
        let new_writes = &con.bank().writes[writes_before..];
        for &(offset, _) in new_writes {
            assert!(
                offset >= 2048,
                "5th character write offset {offset} should be in second row (>= 2048)"
            );
        }
    }

    #[test]
    fn putchar_tab_advances_to_next_stop() {
        let mut con = make_console();
        // putchar 'A' → cursor at col 1
        con.putchar(b'A');
        // putchar '\t' → next tab stop at multiple of 8, so col 8; but cols=4, wraps to row 1 col 0
        con.putchar(b'\t');
        // Next char 'B' should be in row 1 (y >= 16), x = 0 (col 0)
        let writes_before = con.bank().writes.len();
        con.putchar(b'B');
        let new_writes = &con.bank().writes[writes_before..];
        for &(offset, _) in new_writes {
            assert!(
                offset >= 2048,
                "after tab wrap, write offset {offset} should be in second row (>= 2048)"
            );
        }
    }

    #[test]
    fn putchar_control_char_ignored() {
        let mut con = make_console();
        let before = con.bank().writes.len();
        con.putchar(0x01); // SOH — should be silently ignored
        let after = con.bank().writes.len();
        assert_eq!(
            before, after,
            "control character 0x01 should produce no writes"
        );
    }

    #[test]
    fn fmt_write_works() {
        let mut con = make_console();
        write!(con, "Hi").expect("write! should not fail");
        assert!(
            !con.bank().writes.is_empty(),
            "fmt::Write should produce glyph writes"
        );
    }

    #[test]
    fn scroll_clears_bottom_row() {
        let mut con = make_console();
        // Fill row 0 (4 chars) then row 1 (4 chars): 8 total
        for _ in 0..8 {
            con.putchar(b'X');
        }
        // One more char triggers scroll (cursor_y would become 2 >= rows=2)
        let writes_before = con.bank().writes.len();
        con.putchar(b'\n');
        let new_writes = &con.bank().writes[writes_before..];
        // scroll() calls fill_rect for bottom row; bottom_y = (rows-1)*16 = 16
        // fill_rect writes offsets in [16*128 .. 32*128) = [2048..4096)
        let bottom_row_writes: Vec<_> = new_writes
            .iter()
            .filter(|&&(offset, _)| (2048..4096).contains(&offset))
            .collect();
        assert!(
            !bottom_row_writes.is_empty(),
            "scroll should write to the bottom row region (offsets 2048..4096)"
        );
    }
}
