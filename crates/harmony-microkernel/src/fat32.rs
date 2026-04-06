// SPDX-License-Identifier: GPL-2.0-or-later

//! Read-only FAT32 filesystem parser.
//!
//! Supports FAT32 only (not FAT12/16), 512-byte sectors, 8.3 short
//! names, and VFAT long file names (LFN). No write support.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::block_device::BlockDevice;
use crate::IpcError;

/// A parsed directory entry (file or subdirectory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub start_cluster: u32,
    pub size: u32,
}

/// Read-only FAT32 filesystem parser.
///
/// Reads BPB metadata on construction, then provides on-demand
/// cluster chain following, directory listing, and file range reads.
/// All I/O goes through the provided `BlockDevice`.
pub struct Fat32<D: BlockDevice> {
    block_dev: D,
    pub(crate) sectors_per_cluster: u8,
    pub(crate) reserved_sectors: u16,
    // Stored for completeness; used only during BPB parsing to derive data_start_lba.
    #[allow(dead_code)]
    num_fats: u8,
    #[allow(dead_code)]
    fat_size_32: u32,
    // read by FatServer (Task 3); suppress until fat_server.rs is added
    #[allow(dead_code)]
    pub(crate) root_cluster: u32,
    pub(crate) data_start_lba: u32,
}

impl<D: BlockDevice> Fat32<D> {
    /// Parse the BPB from sector 0 and initialize the parser.
    ///
    /// Takes ownership of `block_dev` for subsequent reads.
    /// Returns `InvalidArgument` if the volume is not valid FAT32.
    pub fn new(mut block_dev: D) -> Result<Self, IpcError> {
        let mut bpb = [0u8; 512];
        block_dev.read_block(0, &mut bpb)?;

        let bytes_per_sector = u16::from_le_bytes([bpb[11], bpb[12]]);
        if bytes_per_sector != 512 {
            return Err(IpcError::InvalidArgument);
        }

        let sectors_per_cluster = bpb[13];
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(IpcError::InvalidArgument);
        }

        let reserved_sectors = u16::from_le_bytes([bpb[14], bpb[15]]);
        let num_fats = bpb[16];
        let fat_size_32 = u32::from_le_bytes([bpb[36], bpb[37], bpb[38], bpb[39]]);
        if fat_size_32 == 0 {
            return Err(IpcError::InvalidArgument);
        }

        let root_cluster = u32::from_le_bytes([bpb[44], bpb[45], bpb[46], bpb[47]]);
        if root_cluster < 2 {
            return Err(IpcError::InvalidArgument);
        }

        let total_sectors_32 = u32::from_le_bytes([bpb[32], bpb[33], bpb[34], bpb[35]]);
        if total_sectors_32 == 0 {
            return Err(IpcError::InvalidArgument);
        }

        let data_start_lba = reserved_sectors as u32 + num_fats as u32 * fat_size_32;

        Ok(Self {
            block_dev,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            fat_size_32,
            root_cluster,
            data_start_lba,
        })
    }

    /// Follow the FAT chain: given a cluster, return the next cluster
    /// or `None` if this is the end of the chain (>= 0x0FFFFFF8).
    pub fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, IpcError> {
        let fat_offset = cluster as u64 * 4;
        let fat_sector = self.reserved_sectors as u32 + (fat_offset / 512) as u32;
        let entry_offset = (fat_offset % 512) as usize;

        let mut sector = [0u8; 512];
        self.block_dev.read_block(fat_sector, &mut sector)?;

        let raw = u32::from_le_bytes([
            sector[entry_offset],
            sector[entry_offset + 1],
            sector[entry_offset + 2],
            sector[entry_offset + 3],
        ]) & 0x0FFFFFFF;

        if raw >= 0x0FFFFFF7 {
            // 0x0FFFFFF7 = bad cluster, >= 0x0FFFFFF8 = end of chain
            Ok(None)
        } else if raw < 2 {
            Err(IpcError::InvalidArgument)
        } else {
            Ok(Some(raw))
        }
    }

    /// Read an entire cluster into `buf`.
    ///
    /// `buf` must be exactly `sectors_per_cluster * 512` bytes.
    pub fn read_cluster(&mut self, cluster: u32, buf: &mut [u8]) -> Result<(), IpcError> {
        let cluster_size = self.sectors_per_cluster as usize * 512;
        if buf.len() != cluster_size {
            return Err(IpcError::InvalidArgument);
        }

        let start_lba = self.data_start_lba + (cluster - 2) * self.sectors_per_cluster as u32;
        let mut sector_buf = [0u8; 512];
        for i in 0..self.sectors_per_cluster as u32 {
            self.block_dev.read_block(start_lba + i, &mut sector_buf)?;
            let offset = i as usize * 512;
            buf[offset..offset + 512].copy_from_slice(&sector_buf);
        }
        Ok(())
    }

    /// Read directory entries from a directory starting at `start_cluster`.
    ///
    /// Follows the cluster chain, parses 32-byte entries, reassembles
    /// LFN sequences, and skips deleted (0xE5), volume label (0x08),
    /// and dot/dotdot entries.
    pub fn read_dir(&mut self, start_cluster: u32) -> Result<Vec<DirEntry>, IpcError> {
        let cluster_size = self.sectors_per_cluster as usize * 512;
        let mut cluster_buf = alloc::vec![0u8; cluster_size];
        let mut entries = Vec::new();
        let mut lfn_buf: Vec<(u8, [u16; 13])> = Vec::new();
        let mut cluster = start_cluster;

        loop {
            self.read_cluster(cluster, &mut cluster_buf)?;

            for i in (0..cluster_size).step_by(32) {
                let entry = &cluster_buf[i..i + 32];

                if entry[0] == 0x00 {
                    return Ok(entries); // end of directory
                }
                if entry[0] == 0xE5 {
                    lfn_buf.clear();
                    continue; // deleted
                }

                let attr = entry[11];

                if attr == 0x0F {
                    // LFN entry
                    let seq = entry[0];
                    let mut chars = [0u16; 13];
                    for j in 0..5 {
                        chars[j] = u16::from_le_bytes([entry[1 + j * 2], entry[2 + j * 2]]);
                    }
                    for j in 0..6 {
                        chars[5 + j] = u16::from_le_bytes([entry[14 + j * 2], entry[15 + j * 2]]);
                    }
                    for j in 0..2 {
                        chars[11 + j] = u16::from_le_bytes([entry[28 + j * 2], entry[29 + j * 2]]);
                    }
                    lfn_buf.push((seq, chars));
                    continue;
                }

                // Skip volume labels
                if attr & 0x08 != 0 && attr & 0x10 == 0 {
                    lfn_buf.clear();
                    continue;
                }

                // Skip . and .. entries
                if entry[0] == b'.' {
                    lfn_buf.clear();
                    continue;
                }

                let name = if !lfn_buf.is_empty() {
                    reassemble_lfn(&mut lfn_buf)
                } else {
                    parse_short_name(entry)
                };

                let is_dir = attr & 0x10 != 0;
                let hi = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                let lo = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let start_cluster = (hi << 16) | lo;
                let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);

                entries.push(DirEntry {
                    name,
                    is_dir,
                    start_cluster,
                    size,
                });
            }

            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(entries),
            }
        }
    }

    /// Read `count` bytes starting at `offset` from a file's cluster chain.
    ///
    /// Follows the chain from `start_cluster`, skipping clusters to
    /// reach `offset`, then reads data. Clamps to `file_size`.
    /// Returns an empty vec if `offset >= file_size`.
    pub fn read_file_range(
        &mut self,
        start_cluster: u32,
        file_size: u32,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, IpcError> {
        let file_size = file_size as u64;
        if offset >= file_size {
            return Ok(Vec::new());
        }

        let cluster_size = self.sectors_per_cluster as u64 * 512;
        let end = (offset + count as u64).min(file_size);
        let bytes_to_read = (end - offset) as usize;

        // Skip clusters to reach the one containing `offset`
        let clusters_to_skip = offset / cluster_size;
        let mut cluster = start_cluster;
        for _ in 0..clusters_to_skip {
            cluster = self
                .next_cluster(cluster)?
                .ok_or(IpcError::InvalidArgument)?;
        }

        let mut result = Vec::with_capacity(bytes_to_read);
        let mut cluster_buf = alloc::vec![0u8; cluster_size as usize];
        let mut pos_in_cluster = (offset % cluster_size) as usize;

        while result.len() < bytes_to_read {
            self.read_cluster(cluster, &mut cluster_buf)?;
            let available = cluster_size as usize - pos_in_cluster;
            let needed = bytes_to_read - result.len();
            let to_copy = available.min(needed);
            result.extend_from_slice(&cluster_buf[pos_in_cluster..pos_in_cluster + to_copy]);
            pos_in_cluster = 0;

            if result.len() < bytes_to_read {
                cluster = self
                    .next_cluster(cluster)?
                    .ok_or(IpcError::InvalidArgument)?;
            }
        }

        Ok(result)
    }
}

/// Reassemble a long file name from collected LFN entry fragments.
fn reassemble_lfn(lfn_buf: &mut Vec<(u8, [u16; 13])>) -> String {
    lfn_buf.sort_by_key(|(seq, _)| seq & 0x1F);

    let mut utf16: Vec<u16> = Vec::new();
    for (_, chars) in lfn_buf.iter() {
        for &c in chars {
            if c == 0x0000 || c == 0xFFFF {
                break;
            }
            utf16.push(c);
        }
    }
    lfn_buf.clear();

    String::from_utf16(&utf16).unwrap_or_else(|_| {
        utf16
            .iter()
            .map(|&c| if c < 128 { c as u8 as char } else { '?' })
            .collect()
    })
}

/// Parse an 8.3 directory entry name into a lowercase "name.ext" string.
fn parse_short_name(entry: &[u8]) -> String {
    let name_part: String = entry[0..8]
        .iter()
        .copied()
        .take_while(|&b| b != b' ')
        .map(|b| (b as char).to_ascii_lowercase())
        .collect();
    let ext_part: String = entry[8..11]
        .iter()
        .copied()
        .take_while(|&b| b != b' ')
        .map(|b| (b as char).to_ascii_lowercase())
        .collect();

    if ext_part.is_empty() {
        name_part
    } else {
        alloc::format!("{}.{}", name_part, ext_part)
    }
}

/// Build a synthetic FAT32 image for testing.
///
/// Layout (sectors_per_cluster=1, reserved=2, 2 FATs of 1 sector each):
/// - Sector 0: BPB
/// - Sector 1: reserved
/// - Sector 2: FAT #1
/// - Sector 3: FAT #2
/// - Sector 4: Cluster 2 — root directory
/// - Sector 5: Cluster 3 — overlays/ subdirectory
/// - Sector 6: Cluster 4 — config.txt ("hello world")
/// - Sector 7: Cluster 5 — bcm2712-rpi-5-b.dtb (first 512 bytes, 0xAA)
/// - Sector 8: Cluster 6 — bcm2712-rpi-5-b.dtb (88 bytes 0xBB + padding)
/// - Sector 9: Cluster 7 — readme.txt ("overlay file")
///
/// FAT chain: [2]=EOC, [3]=EOC, [4]=EOC, [5]→6, [6]=EOC, [7]=EOC
#[cfg(test)]
pub(crate) fn build_fat32_image() -> crate::block_device::MemoryBlockDevice {
    let mut sectors = vec![[0u8; 512]; 64];

    // ── Sector 0: BPB ────────────────────────────────────────────
    let bpb = &mut sectors[0];
    bpb[0] = 0xEB;
    bpb[1] = 0x58;
    bpb[2] = 0x90; // jump
    bpb[3..11].copy_from_slice(b"MSDOS5.0"); // OEM name
    bpb[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector
    bpb[13] = 1; // sectors_per_cluster
    bpb[14..16].copy_from_slice(&2u16.to_le_bytes()); // reserved_sectors
    bpb[16] = 2; // num_fats
                 // bpb[17..19] root_entry_count = 0 (FAT32)
                 // bpb[19..21] total_sectors_16 = 0 (FAT32)
    bpb[21] = 0xF8; // media type
                    // bpb[22..24] fat_size_16 = 0 (FAT32)
    bpb[32..36].copy_from_slice(&64u32.to_le_bytes()); // total_sectors_32
    bpb[36..40].copy_from_slice(&1u32.to_le_bytes()); // fat_size_32
    bpb[44..48].copy_from_slice(&2u32.to_le_bytes()); // root_cluster
    bpb[510] = 0x55;
    bpb[511] = 0xAA; // boot signature

    // ── Sectors 2-3: FAT tables ──────────────────────────────────
    let fat = &mut sectors[2];
    // Each FAT entry is 4 bytes, little-endian
    fat[0..4].copy_from_slice(&0x0FFFFFF8u32.to_le_bytes()); // FAT[0] media
    fat[4..8].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[1] reserved
    fat[8..12].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[2] root dir EOC
    fat[12..16].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[3] overlays EOC
    fat[16..20].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[4] config.txt EOC
    fat[20..24].copy_from_slice(&6u32.to_le_bytes()); // FAT[5] → cluster 6
    fat[24..28].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[6] bcm2712 EOC
    fat[28..32].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[7] readme EOC
                                                               // Copy to FAT #2
    sectors[3] = sectors[2];

    // ── Sector 4: Root directory (cluster 2) ─────────────────────
    let root = &mut sectors[4];

    // Entry 0 (offset 0): LFN sequence 2 (last) for "bcm2712-rpi-5-b.dtb"
    // Full name: "bcm2712-rpi-5-b.dtb" = 19 chars
    // LFN entry 2 (seq 0x42): chars 14-19 = '-','b','.','d','t','b' then null+pad
    root[0] = 0x42; // sequence: last (0x40) | 2
                    // Bytes 1-10: chars 14-18 as UTF-16LE: '-','b','.','d','t'
    root[1] = 0x2D;
    root[2] = 0x00; // '-'
    root[3] = 0x62;
    root[4] = 0x00; // 'b'
    root[5] = 0x2E;
    root[6] = 0x00; // '.'
    root[7] = 0x64;
    root[8] = 0x00; // 'd'
    root[9] = 0x74;
    root[10] = 0x00; // 't'
    root[11] = 0x0F; // attr = LFN
    root[12] = 0x00; // type
    root[13] = 0x00; // checksum (ignored for now)
                     // Bytes 14-25: char 19 = 'b', then null, then 0xFFFF padding
    root[14] = 0x62;
    root[15] = 0x00; // 'b'
    root[16] = 0x00;
    root[17] = 0x00; // null terminator
    root[18] = 0xFF;
    root[19] = 0xFF; // padding
    root[20] = 0xFF;
    root[21] = 0xFF;
    root[22] = 0xFF;
    root[23] = 0xFF;
    root[24] = 0xFF;
    root[25] = 0xFF;
    // Byte 26-27: first cluster (always 0 for LFN)
    root[26] = 0x00;
    root[27] = 0x00;
    // Bytes 28-31: more padding
    root[28] = 0xFF;
    root[29] = 0xFF;
    root[30] = 0xFF;
    root[31] = 0xFF;

    // Entry 1 (offset 32): LFN sequence 1 for "bcm2712-rpi-5-b.dtb"
    // Chars 1-13: 'b','c','m','2','7','1','2','-','r','p','i','-','5'
    root[32] = 0x01; // sequence 1
    root[33] = 0x62;
    root[34] = 0x00; // 'b'
    root[35] = 0x63;
    root[36] = 0x00; // 'c'
    root[37] = 0x6D;
    root[38] = 0x00; // 'm'
    root[39] = 0x32;
    root[40] = 0x00; // '2'
    root[41] = 0x37;
    root[42] = 0x00; // '7'
    root[43] = 0x0F; // attr = LFN
    root[44] = 0x00;
    root[45] = 0x00; // checksum
    root[46] = 0x31;
    root[47] = 0x00; // '1'
    root[48] = 0x32;
    root[49] = 0x00; // '2'
    root[50] = 0x2D;
    root[51] = 0x00; // '-'
    root[52] = 0x72;
    root[53] = 0x00; // 'r'
    root[54] = 0x70;
    root[55] = 0x00; // 'p'
    root[56] = 0x69;
    root[57] = 0x00; // 'i'
    root[58] = 0x00;
    root[59] = 0x00; // cluster (0 for LFN)
    root[60] = 0x2D;
    root[61] = 0x00; // '-'
    root[62] = 0x35;
    root[63] = 0x00; // '5'

    // Entry 2 (offset 64): 8.3 entry for bcm2712 file
    root[64..72].copy_from_slice(b"BCM271~1"); // name
    root[72..75].copy_from_slice(b"DTB"); // ext
    root[75] = 0x20; // attr = ARCHIVE
                     // cluster high (offset 84-85) = 0
    root[84] = 0x00;
    root[85] = 0x00;
    // cluster low (offset 90-91) = 5
    root[90] = 0x05;
    root[91] = 0x00;
    // size (offset 92-95) = 600
    root[92..96].copy_from_slice(&600u32.to_le_bytes());

    // Entry 3 (offset 96): 8.3 entry for config.txt
    root[96..104].copy_from_slice(b"CONFIG  "); // name
    root[104..107].copy_from_slice(b"TXT"); // ext
    root[107] = 0x20; // attr = ARCHIVE
    root[116] = 0x00;
    root[117] = 0x00; // cluster high = 0
    root[122] = 0x04;
    root[123] = 0x00; // cluster low = 4
    root[124..128].copy_from_slice(&11u32.to_le_bytes()); // size = 11

    // Entry 4 (offset 128): 8.3 entry for overlays/ directory
    root[128..136].copy_from_slice(b"OVERLAYS");
    root[136..139].copy_from_slice(b"   "); // no extension
    root[139] = 0x10; // attr = DIRECTORY
    root[148] = 0x00;
    root[149] = 0x00; // cluster high = 0
    root[154] = 0x03;
    root[155] = 0x00; // cluster low = 3
    root[156..160].copy_from_slice(&0u32.to_le_bytes()); // size = 0

    // ── Sector 5: overlays/ subdirectory (cluster 3) ─────────────
    let subdir = &mut sectors[5];

    // Entry 0: "." (self)
    subdir[0..8].copy_from_slice(b".       ");
    subdir[8..11].copy_from_slice(b"   ");
    subdir[11] = 0x10; // DIRECTORY
    subdir[26] = 0x03;
    subdir[27] = 0x00; // cluster 3

    // Entry 1: ".." (parent)
    subdir[32..40].copy_from_slice(b"..      ");
    subdir[40..43].copy_from_slice(b"   ");
    subdir[43] = 0x10; // DIRECTORY
    subdir[58] = 0x02;
    subdir[59] = 0x00; // cluster 2

    // Entry 2: readme.txt
    subdir[64..72].copy_from_slice(b"README  ");
    subdir[72..75].copy_from_slice(b"TXT");
    subdir[75] = 0x20; // ARCHIVE
    subdir[84] = 0x00;
    subdir[85] = 0x00; // cluster high
    subdir[90] = 0x07;
    subdir[91] = 0x00; // cluster low = 7
    subdir[92..96].copy_from_slice(&12u32.to_le_bytes()); // size = 12

    // ── Sector 6: config.txt data (cluster 4) ────────────────────
    sectors[6][..11].copy_from_slice(b"hello world");

    // ── Sector 7: bcm2712 data part 1 (cluster 5) ───────────────
    sectors[7] = [0xAA; 512];

    // ── Sector 8: bcm2712 data part 2 (cluster 6) ───────────────
    sectors[8][..88].fill(0xBB);

    // ── Sector 9: readme.txt data (cluster 7) ───────────────────
    sectors[9][..12].copy_from_slice(b"overlay file");

    crate::block_device::MemoryBlockDevice { sectors }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_bpb_valid() {
        let dev = build_fat32_image();
        let fat = Fat32::new(dev).unwrap();
        assert_eq!(fat.sectors_per_cluster, 1);
        assert_eq!(fat.reserved_sectors, 2);
        assert_eq!(fat.root_cluster, 2);
        assert_eq!(fat.data_start_lba, 4); // 2 reserved + 2 FATs * 1 sector
    }

    #[test]
    fn parse_bpb_not_fat32() {
        let mut dev = build_fat32_image();
        // Corrupt: set fat_size_32 to 0 (not FAT32)
        dev.sectors[0][36] = 0;
        dev.sectors[0][37] = 0;
        dev.sectors[0][38] = 0;
        dev.sectors[0][39] = 0;
        assert_eq!(Fat32::new(dev).err(), Some(IpcError::InvalidArgument));
    }

    #[test]
    fn parse_bpb_bad_sector_size() {
        let mut dev = build_fat32_image();
        // Set bytes_per_sector to 1024
        dev.sectors[0][11] = 0x00;
        dev.sectors[0][12] = 0x04;
        assert_eq!(Fat32::new(dev).err(), Some(IpcError::InvalidArgument));
    }

    #[test]
    fn cluster_chain_end() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Cluster 2 (root dir) → EOC
        assert_eq!(fat.next_cluster(2).unwrap(), None);
    }

    #[test]
    fn cluster_chain_continues() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Cluster 5 → 6 (bcm2712 file spans two clusters)
        assert_eq!(fat.next_cluster(5).unwrap(), Some(6));
        // Cluster 6 → EOC
        assert_eq!(fat.next_cluster(6).unwrap(), None);
    }

    #[test]
    fn read_dir_short_names() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap(); // root dir
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"config.txt"));
        assert!(names.contains(&"overlays"));
    }

    #[test]
    fn read_dir_lfn() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"bcm2712-rpi-5-b.dtb"));
    }

    #[test]
    fn read_dir_mixed() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        // Should have exactly 3 entries: bcm2712 (LFN), config.txt (short), overlays (short dir)
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn read_dir_skips_deleted() {
        let mut dev = build_fat32_image();
        // Mark config.txt entry as deleted (it's at a known offset in sector 4)
        // The root dir has: 2 LFN entries + 1 8.3 for bcm2712, then config.txt, then overlays
        // Each entry is 32 bytes. LFN1 at 0, LFN2 at 32, 8.3 at 64, config at 96, overlays at 128
        // Actually LFN entries are stored in reverse: last first.
        // On disk: LFN seq 2 at offset 0, LFN seq 1 at offset 32, 8.3 at offset 64, config at 96
        dev.sectors[4][96] = 0xE5; // mark config.txt as deleted
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        assert_eq!(entries.len(), 2); // bcm2712 + overlays
        assert!(!entries.iter().any(|e| e.name == "config.txt"));
    }

    #[test]
    fn read_dir_skips_volume_label() {
        let mut dev = build_fat32_image();
        // Insert a volume label entry before config.txt by modifying its attr
        // Actually, let's corrupt the config.txt entry to be a volume label
        dev.sectors[4][96 + 11] = 0x08; // attr = volume label
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        assert_eq!(entries.len(), 2); // bcm2712 + overlays (config became label, skipped)
    }

    #[test]
    fn read_dir_end_marker() {
        let mut dev = build_fat32_image();
        // Place end marker before overlays entry (offset 128)
        dev.sectors[4][128] = 0x00;
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        assert_eq!(entries.len(), 2); // bcm2712 + config.txt (overlays hidden by end marker)
    }

    #[test]
    fn read_dir_subdirectory_entry() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        let overlays = entries.iter().find(|e| e.name == "overlays").unwrap();
        assert!(overlays.is_dir);
        assert_eq!(overlays.start_cluster, 3);
    }

    #[test]
    fn read_dir_subdir_contents() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(3).unwrap(); // overlays dir at cluster 3
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "readme.txt");
        assert_eq!(entries[0].size, 12);
    }

    #[test]
    fn read_file_single_cluster() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // config.txt: cluster 4, size 11, "hello world"
        let data = fat.read_file_range(4, 11, 0, 11).unwrap();
        assert_eq!(&data, b"hello world");
    }

    #[test]
    fn read_file_multi_cluster() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // bcm2712: clusters 5→6, size 600
        let data = fat.read_file_range(5, 600, 0, 600).unwrap();
        assert_eq!(data.len(), 600);
        assert!(data[..512].iter().all(|&b| b == 0xAA));
        assert!(data[512..600].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn read_file_with_offset() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Read "world" from config.txt (offset 6, count 5)
        let data = fat.read_file_range(4, 11, 6, 5).unwrap();
        assert_eq!(&data, b"world");
    }

    #[test]
    fn read_file_offset_spans_clusters() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Read 10 bytes starting at offset 508 of bcm2712 (crosses cluster boundary)
        let data = fat.read_file_range(5, 600, 508, 10).unwrap();
        assert_eq!(data.len(), 10);
        assert!(data[..4].iter().all(|&b| b == 0xAA)); // last 4 bytes of cluster 5
        assert!(data[4..].iter().all(|&b| b == 0xBB)); // first 6 bytes of cluster 6
    }

    #[test]
    fn read_file_clamped_to_size() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Request 1000 bytes but file is only 11
        let data = fat.read_file_range(4, 11, 0, 1000).unwrap();
        assert_eq!(data.len(), 11);
    }

    #[test]
    fn read_file_offset_past_end() {
        let dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let data = fat.read_file_range(4, 11, 100, 5).unwrap();
        assert!(data.is_empty());
    }
}
