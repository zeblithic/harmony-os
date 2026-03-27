// SPDX-License-Identifier: GPL-2.0-or-later

//! Guest VM boot orchestration — DTB embedding and memory layout constants.
//!
//! This module owns the guest device-tree blob (compiled by harmony-hypervisor)
//! and provides helpers to place the kernel, initramfs, and DTB at their
//! correct Intermediate Physical Addresses (IPAs) inside the guest RAM window.

static GUEST_DTB: &[u8] = include_bytes!("../../harmony-hypervisor/blobs/guest-virt.dtb");

/// IPA layout constants for the guest VM's RAM window.
pub mod layout {
    /// Base IPA of the guest RAM region.
    pub const RAM_BASE: u64 = 0x4000_0000;
    /// Total guest RAM size (128 MiB).
    pub const RAM_SIZE: u64 = 128 * 1024 * 1024;
    /// Kernel is placed at the start of RAM.
    pub const KERNEL_OFFSET: u64 = 0;
    /// Initramfs is placed at the 64 MiB mark.
    pub const INITRAMFS_OFFSET: u64 = 64 * 1024 * 1024;
    /// DTB is placed at the 120 MiB mark, leaving 8 MiB before the RAM ceiling.
    pub const DTB_OFFSET: u64 = 120 * 1024 * 1024;

    /// IPA of the guest kernel image.
    pub const KERNEL_IPA: u64 = RAM_BASE + KERNEL_OFFSET;
    /// IPA of the guest initramfs archive.
    pub const INITRAMFS_IPA: u64 = RAM_BASE + INITRAMFS_OFFSET;
    /// IPA of the guest device-tree blob.
    pub const DTB_IPA: u64 = RAM_BASE + DTB_OFFSET;
}

/// Patch the initrd-end placeholder inside a mutable DTB buffer.
///
/// The pre-compiled DTB reserves `0x44500000` as a two-cell big-endian u32
/// placeholder for the initrd end address.  The cells are stored as:
///
/// ```text
/// [0x00, 0x00, 0x00, 0x00,  0x44, 0x50, 0x00, 0x00]
///  ──── high u32 ────────   ──── low u32 ────────────
/// ```
///
/// This function replaces the first occurrence of that 8-byte pattern with
/// `initrd_end` split into two big-endian u32 cells (high word first).
///
/// Returns `true` if the placeholder was found and patched, `false` otherwise.
pub fn patch_dtb_initrd_end(dtb: &mut [u8], initrd_end: u64) -> bool {
    const PLACEHOLDER_HIGH: u32 = 0x0000_0000;
    const PLACEHOLDER_LOW: u32 = 0x4450_0000;

    let needle: [u8; 8] = {
        let mut n = [0u8; 8];
        n[0..4].copy_from_slice(&PLACEHOLDER_HIGH.to_be_bytes());
        n[4..8].copy_from_slice(&PLACEHOLDER_LOW.to_be_bytes());
        n
    };

    // Slide a window over the DTB looking for the 8-byte needle.
    let limit = dtb.len().saturating_sub(7);
    for i in 0..limit {
        if dtb[i..i + 8] == needle {
            let high = (initrd_end >> 32) as u32;
            let low = initrd_end as u32;
            dtb[i..i + 4].copy_from_slice(&high.to_be_bytes());
            dtb[i + 4..i + 8].copy_from_slice(&low.to_be_bytes());
            return true;
        }
    }

    false
}

/// Return the embedded guest device-tree blob.
pub fn guest_dtb() -> &'static [u8] {
    GUEST_DTB
}

/// A planned sequence of HVC operations to boot a guest VM.
/// Computed from blob sizes; the caller executes the actual HVC calls.
pub struct BootPlan {
    /// Total pages to allocate (RAM_SIZE / 4096).
    pub total_pages: u32,
    /// (ipa, page_count) pairs for VM_MAP calls (2 MiB chunks).
    pub map_chunks: alloc::vec::Vec<(u64, u16)>,
    /// Entry IPA (where kernel starts).
    pub entry_ipa: u64,
    /// DTB IPA (passed as x0 to guest).
    pub dtb_ipa: u64,
    /// Byte offsets within allocated RAM for blob copies.
    pub kernel_offset: u64,
    pub initramfs_offset: u64,
    pub dtb_offset: u64,
}

impl BootPlan {
    /// Compute a boot plan for the given blob sizes.
    pub fn new(kernel_size: usize, initramfs_size: usize, dtb_size: usize) -> Self {
        let total_pages = (layout::RAM_SIZE / 4096) as u32;

        // Build 2 MiB chunk list for VM_MAP
        let pages_per_chunk: u16 = 512; // 2 MiB / 4096
        let full_chunks = total_pages / pages_per_chunk as u32;
        let remainder = total_pages % pages_per_chunk as u32;

        let mut map_chunks = alloc::vec::Vec::new();
        for i in 0..full_chunks {
            let ipa = layout::RAM_BASE + (i as u64) * (pages_per_chunk as u64 * 4096);
            map_chunks.push((ipa, pages_per_chunk));
        }
        if remainder > 0 {
            let ipa = layout::RAM_BASE + (full_chunks as u64) * (pages_per_chunk as u64 * 4096);
            map_chunks.push((ipa, remainder as u16));
        }

        assert!(
            kernel_size as u64 <= layout::INITRAMFS_OFFSET,
            "kernel too large"
        );
        assert!(
            layout::INITRAMFS_OFFSET + initramfs_size as u64 <= layout::DTB_OFFSET,
            "initramfs too large"
        );
        assert!(
            layout::DTB_OFFSET + dtb_size as u64 <= layout::RAM_SIZE,
            "DTB doesn't fit"
        );

        Self {
            total_pages,
            map_chunks,
            entry_ipa: layout::KERNEL_IPA,
            dtb_ipa: layout::DTB_IPA,
            kernel_offset: layout::KERNEL_OFFSET,
            initramfs_offset: layout::INITRAMFS_OFFSET,
            dtb_offset: layout::DTB_OFFSET,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn layout_constants_are_consistent() {
        // IPA derivations must match their component parts.
        assert_eq!(layout::KERNEL_IPA, layout::RAM_BASE + layout::KERNEL_OFFSET);
        assert_eq!(
            layout::INITRAMFS_IPA,
            layout::RAM_BASE + layout::INITRAMFS_OFFSET
        );
        assert_eq!(layout::DTB_IPA, layout::RAM_BASE + layout::DTB_OFFSET);

        // DTB must fit within the RAM window.
        assert!(
            layout::DTB_OFFSET < layout::RAM_SIZE,
            "DTB_OFFSET {:#x} must be < RAM_SIZE {:#x}",
            layout::DTB_OFFSET,
            layout::RAM_SIZE,
        );
    }

    #[test]
    fn guest_dtb_is_valid_fdt() {
        let dtb = guest_dtb();
        // Flattened Device Tree magic: 0xd00dfeed (big-endian).
        assert!(
            dtb.len() >= 4,
            "DTB blob is too small to contain FDT header"
        );
        assert_eq!(
            &dtb[0..4],
            &[0xd0, 0x0d, 0xfe, 0xed],
            "FDT magic mismatch — blob may be corrupt or not a DTB"
        );
    }

    #[test]
    fn patch_dtb_initrd_end_replaces_placeholder() {
        let mut buf: Vec<u8> = guest_dtb().to_vec();
        let initrd_end: u64 = 0x0000_0000_4500_1234;

        let patched = patch_dtb_initrd_end(&mut buf, initrd_end);
        assert!(
            patched,
            "placeholder should have been found in the real DTB"
        );

        // The original 8-byte placeholder must no longer be present.
        let needle = {
            let mut n = [0u8; 8];
            n[0..4].copy_from_slice(&0x0000_0000_u32.to_be_bytes());
            n[4..8].copy_from_slice(&0x4450_0000_u32.to_be_bytes());
            n
        };
        let still_present = buf.windows(8).any(|w| w == needle);
        assert!(
            !still_present,
            "placeholder bytes should have been overwritten"
        );

        // Verify the patched value is present.
        let expected = {
            let mut e = [0u8; 8];
            e[0..4].copy_from_slice(&((initrd_end >> 32) as u32).to_be_bytes());
            e[4..8].copy_from_slice(&(initrd_end as u32).to_be_bytes());
            e
        };
        let value_present = buf.windows(8).any(|w| w == expected);
        assert!(value_present, "patched initrd_end value not found in DTB");
    }

    #[test]
    fn patch_dtb_initrd_end_fails_on_missing_placeholder() {
        // A garbage buffer that does not contain the placeholder.
        let mut buf = [0xAA_u8; 64];
        let result = patch_dtb_initrd_end(&mut buf, 0x1234_5678);
        assert!(!result, "should return false when placeholder is absent");
    }

    #[test]
    fn boot_plan_computes_correct_chunks() {
        let plan = BootPlan::new(10 * 1024 * 1024, 3 * 1024 * 1024, 4096);
        // 128 MiB / 2 MiB = 64 chunks
        assert_eq!(plan.map_chunks.len(), 64);
        assert_eq!(plan.total_pages, 32768);
        assert_eq!(plan.entry_ipa, 0x4000_0000);
        assert_eq!(plan.dtb_ipa, 0x4780_0000);
        // First chunk starts at RAM base
        assert_eq!(plan.map_chunks[0], (0x4000_0000, 512));
        // Last chunk
        assert_eq!(
            plan.map_chunks[63],
            (0x4000_0000 + 63u64 * 2 * 1024 * 1024, 512)
        );
    }
}
