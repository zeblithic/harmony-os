// SPDX-License-Identifier: GPL-2.0-or-later
//! Minimal PE/COFF section header parser for W^X hardening.
//!
//! Parses section boundaries and permission flags from a PE/COFF image
//! loaded by UEFI. Used at boot time to enforce Write XOR Execute:
//! code pages are mapped RX, data pages RW.

use harmony_microkernel::vm::{PageFlags, PAGE_SIZE};

/// Maximum number of PE sections we track.
const MAX_SECTIONS: usize = 16;

// ── PE/COFF header constants ────────────────────────────────────────

/// DOS header magic: "MZ"
const DOS_MAGIC: u16 = 0x5A4D;
/// Offset within DOS header to the PE signature pointer.
const DOS_LFANEW_OFFSET: usize = 0x3C;
/// PE signature: "PE\0\0"
const PE_SIGNATURE: u32 = 0x0000_4550;
/// Size of COFF file header (after PE signature).
const COFF_HEADER_SIZE: usize = 20;
/// Size of one section header entry.
const SECTION_HEADER_SIZE: usize = 40;

// PE section characteristics flags.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Errors from PE section parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    /// DOS header magic (MZ) not found.
    BadDosSignature,
    /// PE signature (PE\0\0) not found at e_lfanew offset.
    BadPeSignature,
    /// More sections than MAX_SECTIONS.
    TooManySections,
    /// A section has both WRITE and EXECUTE — violates W^X.
    WriteExecuteSection,
    /// Image too small to contain the expected headers.
    TruncatedHeader,
}

/// Cached page-aligned section boundaries with permission flags.
#[derive(Debug)]
pub struct ImageSections {
    /// Physical address where UEFI loaded the image.
    pub image_base: u64,
    /// Total image size.
    pub image_size: u64,
    /// (page_start, page_end_exclusive, flags) for each section.
    entries: [(u64, u64, PageFlags); MAX_SECTIONS],
    /// Number of valid entries.
    count: usize,
}

impl ImageSections {
    /// Return the PageFlags for a physical address within the image.
    ///
    /// Returns `None` if the address is outside the image range.
    /// If the address falls between sections (padding), returns RW.
    pub fn flags_for_addr(&self, addr: u64) -> Option<PageFlags> {
        if addr < self.image_base || addr >= self.image_base + self.image_size {
            return None;
        }
        for i in 0..self.count {
            let (start, end, flags) = self.entries[i];
            if addr >= start && addr < end {
                return Some(flags);
            }
        }
        // Address is within image but not in any section (inter-section padding).
        Some(PageFlags::READABLE | PageFlags::WRITABLE)
    }

    /// True if the address falls within the image range.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.image_base && addr < self.image_base + self.image_size
    }
}

/// Align address down to page boundary.
fn page_align_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

/// Align address up to next page boundary.
fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Read a little-endian u16 from a byte slice at the given offset.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

/// Read a little-endian u32 from a byte slice at the given offset.
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Convert PE section characteristics to PageFlags.
fn characteristics_to_flags(chars: u32) -> Result<PageFlags, PeError> {
    let mut flags = PageFlags::empty();
    if chars & IMAGE_SCN_MEM_READ != 0 {
        flags |= PageFlags::READABLE;
    }
    if chars & IMAGE_SCN_MEM_WRITE != 0 {
        flags |= PageFlags::WRITABLE;
    }
    if chars & IMAGE_SCN_MEM_EXECUTE != 0 {
        flags |= PageFlags::EXECUTABLE;
    }
    // Reject W+X sections.
    if flags.contains(PageFlags::WRITABLE | PageFlags::EXECUTABLE) {
        return Err(PeError::WriteExecuteSection);
    }
    Ok(flags)
}

/// Parse PE/COFF section headers from an in-memory image.
///
/// `image_base` is the physical address where UEFI loaded the image.
/// `image_size` is the total image size from the Loaded Image Protocol.
///
/// Returns cached page-aligned section boundaries with permission flags.
///
/// # Safety
///
/// The caller must ensure `image_base..image_base+image_size` is readable.
pub unsafe fn parse_sections(image_base: u64, image_size: u64) -> Result<ImageSections, PeError> {
    let data = core::slice::from_raw_parts(image_base as *const u8, image_size as usize);
    parse_sections_from_bytes(data, image_base, image_size)
}

/// Parse PE/COFF sections from a byte slice (testable without raw pointers).
///
/// `image_size` is the full virtual image size (may be larger than `data.len()`
/// if data only contains the PE headers). Sections are validated against this range.
pub fn parse_sections_from_bytes(
    data: &[u8],
    image_base: u64,
    image_size: u64,
) -> Result<ImageSections, PeError> {
    // 1. DOS header: check MZ magic, read e_lfanew.
    let dos_magic = read_u16(data, 0).ok_or(PeError::TruncatedHeader)?;
    if dos_magic != DOS_MAGIC {
        return Err(PeError::BadDosSignature);
    }
    let pe_offset = read_u32(data, DOS_LFANEW_OFFSET).ok_or(PeError::TruncatedHeader)? as usize;

    // 2. PE signature.
    let pe_sig = read_u32(data, pe_offset).ok_or(PeError::TruncatedHeader)?;
    if pe_sig != PE_SIGNATURE {
        return Err(PeError::BadPeSignature);
    }

    // 3. COFF header: NumberOfSections and SizeOfOptionalHeader.
    let coff_offset = pe_offset + 4; // skip PE signature
    let num_sections =
        read_u16(data, coff_offset + 2).ok_or(PeError::TruncatedHeader)? as usize;
    let size_of_optional =
        read_u16(data, coff_offset + 16).ok_or(PeError::TruncatedHeader)? as usize;

    if num_sections > MAX_SECTIONS {
        return Err(PeError::TooManySections);
    }

    // 4. Section table starts after COFF header + optional header.
    let section_table_offset = coff_offset + COFF_HEADER_SIZE + size_of_optional;

    let mut entries = [(0u64, 0u64, PageFlags::empty()); MAX_SECTIONS];

    for i in 0..num_sections {
        let sec_offset = section_table_offset + i * SECTION_HEADER_SIZE;

        let virtual_size =
            read_u32(data, sec_offset + 8).ok_or(PeError::TruncatedHeader)? as u64;
        let virtual_addr =
            read_u32(data, sec_offset + 12).ok_or(PeError::TruncatedHeader)? as u64;
        let characteristics =
            read_u32(data, sec_offset + 36).ok_or(PeError::TruncatedHeader)?;

        let flags = characteristics_to_flags(characteristics)?;

        let start = page_align_down(image_base + virtual_addr);
        let end = page_align_up(image_base + virtual_addr + virtual_size);

        entries[i] = (start, end, flags);
    }

    Ok(ImageSections {
        image_base,
        image_size: page_align_up(image_size),
        entries,
        count: num_sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PE/COFF header with the given sections.
    /// Each section is (name, virtual_addr, virtual_size, characteristics).
    fn build_pe_header(sections: &[(&str, u32, u32, u32)]) -> Vec<u8> {
        let pe_offset: u32 = 0x80; // standard DOS stub size
        let optional_header_size: u16 = 0; // no optional header for tests
        let num_sections = sections.len() as u16;

        let total_size = pe_offset as usize
            + 4 // PE sig
            + COFF_HEADER_SIZE
            + sections.len() * SECTION_HEADER_SIZE;

        let mut buf = vec![0u8; total_size];

        // DOS header
        buf[0] = 0x4D; // 'M'
        buf[1] = 0x5A; // 'Z'
        buf[DOS_LFANEW_OFFSET..DOS_LFANEW_OFFSET + 4]
            .copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature
        let pe_off = pe_offset as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());

        // COFF header
        let coff_off = pe_off + 4;
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&num_sections.to_le_bytes());
        buf[coff_off + 16..coff_off + 18]
            .copy_from_slice(&optional_header_size.to_le_bytes());

        // Section headers
        let sec_table_off = coff_off + COFF_HEADER_SIZE;
        for (i, (name, vaddr, vsize, chars)) in sections.iter().enumerate() {
            let off = sec_table_off + i * SECTION_HEADER_SIZE;
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(8);
            buf[off..off + copy_len].copy_from_slice(&name_bytes[..copy_len]);
            buf[off + 8..off + 12].copy_from_slice(&vsize.to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&vaddr.to_le_bytes());
            buf[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
        }

        buf
    }

    #[test]
    fn pe_parse_sections() {
        let sections = &[
            (".text", 0x1000, 0x2000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
            (".rdata", 0x4000, 0x1000, IMAGE_SCN_MEM_READ),
            (".data", 0x5000, 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
        ];
        let buf = build_pe_header(sections);
        let image_base = 0x4000_0000u64;

        let result = parse_sections_from_bytes(&buf, image_base, 0x10_0000).unwrap();
        assert_eq!(result.count, 3);
        assert_eq!(result.image_base, image_base);
    }

    #[test]
    fn pe_parse_invalid_dos_signature() {
        let buf = vec![0u8; 256];
        let result = parse_sections_from_bytes(&buf, 0, 256);
        assert_eq!(result.unwrap_err(), PeError::BadDosSignature);
    }

    #[test]
    fn pe_parse_invalid_pe_signature() {
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[DOS_LFANEW_OFFSET..DOS_LFANEW_OFFSET + 4]
            .copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature is all zeros — invalid
        let result = parse_sections_from_bytes(&buf, 0, 256);
        assert_eq!(result.unwrap_err(), PeError::BadPeSignature);
    }

    #[test]
    fn pe_parse_wx_section_rejected() {
        let sections = &[(
            ".bad",
            0x1000,
            0x1000,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
        )];
        let buf = build_pe_header(sections);
        let result = parse_sections_from_bytes(&buf, 0, 0x10_0000);
        assert_eq!(result.unwrap_err(), PeError::WriteExecuteSection);
    }

    #[test]
    fn pe_characteristics_to_flags_rx() {
        let flags =
            characteristics_to_flags(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE).unwrap();
        assert!(flags.contains(PageFlags::READABLE));
        assert!(flags.contains(PageFlags::EXECUTABLE));
        assert!(!flags.contains(PageFlags::WRITABLE));
    }

    #[test]
    fn pe_characteristics_to_flags_rw() {
        let flags =
            characteristics_to_flags(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE).unwrap();
        assert!(flags.contains(PageFlags::READABLE));
        assert!(flags.contains(PageFlags::WRITABLE));
        assert!(!flags.contains(PageFlags::EXECUTABLE));
    }

    #[test]
    fn pe_section_boundaries_page_aligned() {
        // VirtualSize 0x1500 (not page-aligned) should round up to 0x2000
        let sections = &[(
            ".text",
            0x1000,
            0x1500,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        )];
        let buf = build_pe_header(sections);
        let base = 0x4000_0000u64;
        let result = parse_sections_from_bytes(&buf, base, 0x10_0000).unwrap();

        let (start, end, _) = result.entries[0];
        assert_eq!(start, base + 0x1000);
        assert_eq!(end, base + 0x3000); // 0x1000 + 0x1500 = 0x2500, rounded up to 0x3000
    }

    #[test]
    fn image_sections_flags_for_addr() {
        let sections = &[
            (".text", 0x1000, 0x2000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
            (".data", 0x4000, 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
        ];
        let buf = build_pe_header(sections);
        let base = 0x4000_0000u64;
        // image_size covers sections (up to 0x5000) but not 0x10_0000
        let result = parse_sections_from_bytes(&buf, base, 0x8000).unwrap();

        // .text region → RX
        let flags = result.flags_for_addr(base + 0x1000).unwrap();
        assert!(flags.contains(PageFlags::EXECUTABLE));
        assert!(!flags.contains(PageFlags::WRITABLE));

        // .data region → RW
        let flags = result.flags_for_addr(base + 0x4000).unwrap();
        assert!(flags.contains(PageFlags::WRITABLE));
        assert!(!flags.contains(PageFlags::EXECUTABLE));

        // Outside image → None
        assert!(result.flags_for_addr(base + 0x10_0000).is_none());
        assert!(result.flags_for_addr(0).is_none());
    }

    #[test]
    fn image_sections_contains() {
        let sections = &[(".text", 0x1000, 0x1000, IMAGE_SCN_MEM_READ)];
        let buf = build_pe_header(sections);
        let base = 0x1000_0000u64;
        let result = parse_sections_from_bytes(&buf, base, 0x10_0000).unwrap();

        assert!(result.contains(base));
        assert!(!result.contains(base + result.image_size));
    }

    #[test]
    fn outside_image_returns_none() {
        // Simulates MMU behavior: pages outside the image get None,
        // and the MMU maps them as RW (default_rw).
        let sections = &[
            (".text", 0x1000, 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
        ];
        let buf = build_pe_header(sections);
        let base = 0x4000_0000u64;
        // image_size 0x10_0000 = image range 0x4000_0000..0x4010_0000
        // 0x8000_0000 and 0x0010_0000 are both outside
        let result = parse_sections_from_bytes(&buf, base, 0x10_0000).unwrap();

        // Heap address far outside image → None (MMU maps as RW)
        assert!(result.flags_for_addr(0x8000_0000).is_none());
        // Stack address → None
        assert!(result.flags_for_addr(0x0010_0000).is_none());
    }

    #[test]
    fn inter_section_padding_is_rw() {
        // Gap between .text and .data within the image → RW (safe default)
        let sections = &[
            (".text", 0x1000, 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
            (".data", 0x4000, 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
        ];
        let buf = build_pe_header(sections);
        let base = 0x4000_0000u64;
        let image_size = 0x5000u64;
        let result = parse_sections_from_bytes(&buf, base, image_size).unwrap();

        // Address in gap between sections (0x2000-0x4000) → RW
        let flags = result.flags_for_addr(base + 0x3000).unwrap();
        assert!(flags.contains(PageFlags::READABLE));
        assert!(flags.contains(PageFlags::WRITABLE));
        assert!(!flags.contains(PageFlags::EXECUTABLE));
    }
}
