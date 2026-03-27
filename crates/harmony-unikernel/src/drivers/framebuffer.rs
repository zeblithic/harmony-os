// SPDX-License-Identifier: GPL-2.0-or-later

//! Framebuffer driver providing pixel-level operations over a [`RegisterBank`].
//!
//! Supports BGR32 (UEFI common) and RGB32 pixel formats. All operations are
//! bounds-checked; out-of-bounds writes are silently ignored or clamped.

use super::RegisterBank;

/// Metadata describing a linear framebuffer.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical base address (unused by driver logic; caller provides the bank).
    pub base: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per row (NOT pixels — may include padding).
    pub stride: u32,
    /// Pixel encoding format.
    pub pixel_format: PixelFormat,
}

/// Supported pixel wire formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// UEFI common: byte order `[B, G, R, 0]`.
    Bgr32,
    /// Standard RGB: byte order `[R, G, B, 0]`.
    Rgb32,
}

/// An RGB color triplet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub const WHITE: Self = Self {
        r: 255,
        g: 255,
        b: 255,
    };
    pub const BLACK: Self = Self { r: 0, g: 0, b: 0 };
    pub const GREEN: Self = Self { r: 0, g: 255, b: 0 };
}

/// Framebuffer driver generic over any [`RegisterBank`].
pub struct FramebufferDriver<B: RegisterBank> {
    bank: B,
    info: FramebufferInfo,
}

impl<B: RegisterBank> FramebufferDriver<B> {
    /// Create a new [`FramebufferDriver`].
    ///
    /// # Panics
    ///
    /// Panics if `width == 0`, `height == 0`, or `stride < width * 4`.
    pub fn new(bank: B, info: FramebufferInfo) -> Self {
        assert!(info.width > 0, "framebuffer width must be non-zero");
        assert!(info.height > 0, "framebuffer height must be non-zero");
        assert!(
            info.stride >= info.width * 4,
            "framebuffer stride must be at least width * 4"
        );
        Self { bank, info }
    }

    /// Return a reference to the [`FramebufferInfo`] describing this buffer.
    pub fn info(&self) -> &FramebufferInfo {
        &self.info
    }

    /// Write a single pixel at `(x, y)`. Out-of-bounds coordinates are silently
    /// ignored.
    pub fn write_pixel(&mut self, x: u32, y: u32, color: Color) {
        if x >= self.info.width || y >= self.info.height {
            return;
        }
        let packed = self.pack_color(color);
        let offset = self.pixel_offset(x, y);
        self.bank.write(offset, packed);
    }

    /// Fill the rectangle `(x, y, w, h)` with `color`. The rectangle is
    /// clamped to the screen bounds.
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: Color) {
        let x_end = (x.saturating_add(w)).min(self.info.width);
        let y_end = (y.saturating_add(h)).min(self.info.height);
        let packed = self.pack_color(color);
        for py in y..y_end {
            for px in x..x_end {
                let offset = self.pixel_offset(px, py);
                self.bank.write(offset, packed);
            }
        }
    }

    /// Clear the entire screen to `color`.
    pub fn clear(&mut self, color: Color) {
        let w = self.info.width;
        let h = self.info.height;
        self.fill_rect(0, 0, w, h, color);
    }

    /// Read a raw packed pixel at `(x, y)`. Returns `None` if out of bounds.
    // Used by ConsoleRenderer for scroll operations.
    #[allow(dead_code)]
    pub(crate) fn read_raw(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.info.width || y >= self.info.height {
            return None;
        }
        let offset = self.pixel_offset(x, y);
        Some(self.bank.read(offset))
    }

    /// Write a raw packed pixel at `(x, y)`. Silently ignores out-of-bounds.
    // Used by ConsoleRenderer for scroll operations.
    #[allow(dead_code)]
    pub(crate) fn write_raw(&mut self, x: u32, y: u32, packed: u32) {
        if x >= self.info.width || y >= self.info.height {
            return;
        }
        let offset = self.pixel_offset(x, y);
        self.bank.write(offset, packed);
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn pack_color(&self, color: Color) -> u32 {
        match self.info.pixel_format {
            PixelFormat::Bgr32 => (color.b as u32) | (color.g as u32) << 8 | (color.r as u32) << 16,
            PixelFormat::Rgb32 => (color.r as u32) | (color.g as u32) << 8 | (color.b as u32) << 16,
        }
    }

    fn pixel_offset(&self, x: u32, y: u32) -> usize {
        (y * self.info.stride + x * 4) as usize
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::register_bank::mock::MockRegisterBank;
    use super::*;

    fn make_info(w: u32, h: u32, fmt: PixelFormat) -> FramebufferInfo {
        FramebufferInfo {
            base: 0,
            width: w,
            height: h,
            stride: w * 4,
            pixel_format: fmt,
        }
    }

    #[test]
    #[should_panic]
    fn new_panics_on_zero_width() {
        let bank = MockRegisterBank::new();
        let info = make_info(0, 4, PixelFormat::Rgb32);
        let _ = FramebufferDriver::new(bank, info);
    }

    #[test]
    fn write_pixel_rgb_format() {
        let bank = MockRegisterBank::new();
        let info = make_info(4, 4, PixelFormat::Rgb32);
        let mut fb = FramebufferDriver::new(bank, info);

        let color = Color {
            r: 0x11,
            g: 0x22,
            b: 0x33,
        };
        fb.write_pixel(1, 0, color);

        // offset = y*stride + x*4 = 0*16 + 1*4 = 4
        let expected_packed: u32 =
            (color.r as u32) | (color.g as u32) << 8 | (color.b as u32) << 16;
        assert_eq!(fb.bank.writes, alloc::vec![(4, expected_packed)]);
    }

    #[test]
    fn write_pixel_bgr_format() {
        let bank = MockRegisterBank::new();
        let info = make_info(4, 4, PixelFormat::Bgr32);
        let mut fb = FramebufferDriver::new(bank, info);

        let color = Color {
            r: 0x11,
            g: 0x22,
            b: 0x33,
        };
        fb.write_pixel(1, 0, color);

        // offset = 4
        let expected_packed: u32 =
            (color.b as u32) | (color.g as u32) << 8 | (color.r as u32) << 16;
        assert_eq!(fb.bank.writes, alloc::vec![(4, expected_packed)]);
    }

    #[test]
    fn write_pixel_out_of_bounds_silent() {
        let bank = MockRegisterBank::new();
        let info = make_info(4, 4, PixelFormat::Rgb32);
        let mut fb = FramebufferDriver::new(bank, info);

        fb.write_pixel(4, 4, Color::WHITE); // exactly at width/height — out of bounds
        assert!(fb.bank.writes.is_empty());
    }

    #[test]
    fn fill_rect_writes_all_pixels() {
        let bank = MockRegisterBank::new();
        let info = make_info(8, 8, PixelFormat::Rgb32);
        let mut fb = FramebufferDriver::new(bank, info);

        fb.fill_rect(0, 0, 3, 3, Color::GREEN);
        assert_eq!(fb.bank.writes.len(), 9);
    }

    #[test]
    fn clear_fills_entire_screen() {
        let bank = MockRegisterBank::new();
        let info = make_info(4, 4, PixelFormat::Rgb32);
        let mut fb = FramebufferDriver::new(bank, info);

        fb.clear(Color::BLACK);
        assert_eq!(fb.bank.writes.len(), 16);
    }

    #[test]
    fn stride_respects_padding() {
        // stride=20 means 5 pixels × 4 bytes, but width=4
        let bank = MockRegisterBank::new();
        let info = FramebufferInfo {
            base: 0,
            width: 4,
            height: 4,
            stride: 20,
            pixel_format: PixelFormat::Rgb32,
        };
        let mut fb = FramebufferDriver::new(bank, info);

        fb.write_pixel(0, 1, Color::WHITE);
        // offset = y*stride + x*4 = 1*20 + 0*4 = 20
        assert_eq!(fb.bank.writes[0].0, 20);
    }
}
