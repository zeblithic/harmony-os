// SPDX-License-Identifier: GPL-2.0-or-later

//! NCM NTH16/NDP16 transfer block encode/decode.
//!
//! Implements parsing and construction of NCM Transfer Blocks (NTBs) using the
//! 16-bit variant of the headers as specified in USB CDC NCM section 3.3.
//!
//! # Frame layout
//!
//! ```text
//! NTH16 (12 bytes)
//!   [0..4]   dwSignature = "NCMH" (0x484D_434E LE)
//!   [4..6]   wHeaderLength = 12
//!   [6..8]   wSequence
//!   [8..10]  wBlockLength  (total NTB length)
//!   [10..12] wNdpIndex     (offset of first NDP16)
//!
//! NDP16 (16+ bytes, at offset wNdpIndex)
//!   [0..4]   dwSignature = "NCM0" (0x304D_434E LE)
//!   [4..6]   wLength      (NDP16 struct length including entries)
//!   [6..8]   wNextNdpIndex (0 = end of chain)
//!   [8..]    datagram entries: (wDatagramIndex u16, wDatagramLength u16) pairs
//!            terminated by (0, 0)
//! ```

use alloc::vec::Vec;

use super::CdcError;

// ── Constants ────────────────────────────────────────────────────

/// NTH16 signature: "NCMH" in little-endian.
const NTH16_SIGNATURE: u32 = 0x484D_434E;

/// Fixed size of an NTH16 header in bytes.
const NTH16_SIZE: usize = 12;

/// NDP16 signature for non-CRC datagrams: "NCM0" in little-endian.
const NDP16_SIGNATURE_NO_CRC: u32 = 0x304D_434E;

/// Minimum size of an NDP16 structure (header + one terminating entry).
const NDP16_MIN_SIZE: usize = 16;

/// Size of one NDP16 datagram pointer entry: wDatagramIndex + wDatagramLength.
const DATAGRAM_ENTRY_SIZE: usize = 4;

/// Maximum number of NDP16 structures we will follow in a chain before
/// treating the NTB as malformed (prevents infinite-loop on corrupt data).
const MAX_NDP_CHAIN: usize = 16;

// ── Decode ───────────────────────────────────────────────────────

/// Decode an NTB (NCM Transfer Block) and append all contained Ethernet frames
/// to `out`.
///
/// The function validates the NTH16 header, then walks the NDP16 chain,
/// extracting every datagram referenced by a non-zero entry.
///
/// # Errors
///
/// Returns [`CdcError::MalformedNtb`] for any of:
/// - Input shorter than 12 bytes.
/// - Wrong NTH16 or NDP16 signature.
/// - `wBlockLength` larger than `data`.
/// - Any pointer or length that would read outside `data`.
/// - NDP16 chain longer than 16 links.
pub fn decode_ntb(data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), CdcError> {
    // ── NTH16 validation ──────────────────────────────────────────
    if data.len() < NTH16_SIZE {
        return Err(CdcError::MalformedNtb);
    }

    let sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if sig != NTH16_SIGNATURE {
        return Err(CdcError::MalformedNtb);
    }

    let header_length = u16::from_le_bytes([data[4], data[5]]) as usize;
    if header_length != NTH16_SIZE {
        return Err(CdcError::MalformedNtb);
    }

    // wSequence at [6..8] — ignored during decode.
    let block_length = u16::from_le_bytes([data[8], data[9]]) as usize;
    let ndp_index = u16::from_le_bytes([data[10], data[11]]) as usize;

    if block_length > data.len() {
        return Err(CdcError::MalformedNtb);
    }

    // Use the declared block_length as the bounds for all further reads.
    let block = &data[..block_length];

    // ── NDP16 chain walk ──────────────────────────────────────────
    let mut next_ndp = ndp_index;
    let mut chain_depth = 0usize;

    loop {
        if next_ndp == 0 {
            // A zero NdpIndex from the NTH16 means no NDP at all.
            break;
        }

        if chain_depth >= MAX_NDP_CHAIN {
            return Err(CdcError::MalformedNtb);
        }

        // NDP16 must fit the minimum structure.
        if next_ndp + NDP16_MIN_SIZE > block.len() {
            return Err(CdcError::MalformedNtb);
        }

        let ndp = &block[next_ndp..];

        let ndp_sig = u32::from_le_bytes([ndp[0], ndp[1], ndp[2], ndp[3]]);
        if ndp_sig != NDP16_SIGNATURE_NO_CRC {
            return Err(CdcError::MalformedNtb);
        }

        let ndp_length = u16::from_le_bytes([ndp[4], ndp[5]]) as usize;
        let next_ndp_index = u16::from_le_bytes([ndp[6], ndp[7]]) as usize;

        // NDP length must be at least the minimum and fit within the block.
        if ndp_length < NDP16_MIN_SIZE || next_ndp + ndp_length > block.len() {
            return Err(CdcError::MalformedNtb);
        }

        // ── Datagram entries ──────────────────────────────────────
        // Entries start at offset 8 within the NDP16.  The last entry is
        // a (0, 0) terminator which we stop at without extracting.
        let entries_area = &ndp[8..ndp_length];
        let entry_count = entries_area.len() / DATAGRAM_ENTRY_SIZE;

        for i in 0..entry_count {
            let base = i * DATAGRAM_ENTRY_SIZE;
            let dg_index =
                u16::from_le_bytes([entries_area[base], entries_area[base + 1]]) as usize;
            let dg_length =
                u16::from_le_bytes([entries_area[base + 2], entries_area[base + 3]]) as usize;

            // (0, 0) is the terminator.
            if dg_index == 0 && dg_length == 0 {
                break;
            }

            // Validate the datagram window is inside the block.
            if dg_index + dg_length > block.len() {
                return Err(CdcError::MalformedNtb);
            }

            out.push(block[dg_index..dg_index + dg_length].to_vec());
        }

        chain_depth += 1;
        next_ndp = next_ndp_index;

        if next_ndp == 0 {
            break;
        }
    }

    Ok(())
}

// ── Encode ───────────────────────────────────────────────────────

/// Encode a single Ethernet frame into an NTB.
///
/// Layout of the returned buffer:
/// ```text
/// [0..12]        NTH16 header
/// [12..28]       NDP16 with one datagram entry + (0,0) terminator
/// [28..28+frame] frame payload
/// ```
///
/// # Errors
///
/// Returns [`CdcError::FrameTooLarge`] if `frame` is empty.
pub fn encode_ntb(frame: &[u8], sequence: u16) -> Result<Vec<u8>, CdcError> {
    if frame.is_empty() {
        return Err(CdcError::FrameTooLarge);
    }

    let total_len = NTH16_SIZE + NDP16_MIN_SIZE + frame.len();
    if total_len > u16::MAX as usize {
        return Err(CdcError::FrameTooLarge);
    }

    // Fixed offsets:
    //   NTH16       : bytes  0..12  (12 bytes)
    //   NDP16       : bytes 12..28  (16 bytes: header 8 + 1 entry 4 + terminator 4)
    //   frame       : bytes 28..
    let frame_offset: u16 = (NTH16_SIZE + NDP16_MIN_SIZE) as u16; // 28
    let total_len = NTH16_SIZE + NDP16_MIN_SIZE + frame.len();
    let ndp_offset: u16 = NTH16_SIZE as u16; // 12

    let mut buf = Vec::with_capacity(total_len);

    // ── NTH16 ─────────────────────────────────────────────────────
    buf.extend_from_slice(&NTH16_SIGNATURE.to_le_bytes()); // [0..4]  dwSignature
    buf.extend_from_slice(&(NTH16_SIZE as u16).to_le_bytes()); // [4..6]  wHeaderLength
    buf.extend_from_slice(&sequence.to_le_bytes()); // [6..8]  wSequence
    buf.extend_from_slice(&(total_len as u16).to_le_bytes()); // [8..10] wBlockLength
    buf.extend_from_slice(&ndp_offset.to_le_bytes()); // [10..12] wNdpIndex

    // ── NDP16 ─────────────────────────────────────────────────────
    let ndp_length: u16 = NDP16_MIN_SIZE as u16; // 16: header(8) + entry(4) + term(4)
    buf.extend_from_slice(&NDP16_SIGNATURE_NO_CRC.to_le_bytes()); // [12..16] dwSignature
    buf.extend_from_slice(&ndp_length.to_le_bytes()); // [16..18] wLength
    buf.extend_from_slice(&0u16.to_le_bytes()); // [18..20] wNextNdpIndex = 0
                                                // Datagram entry 0: the one frame.
    buf.extend_from_slice(&frame_offset.to_le_bytes()); // [20..22] wDatagramIndex
    buf.extend_from_slice(&(frame.len() as u16).to_le_bytes()); // [22..24] wDatagramLength
                                                                // Terminator entry.
    buf.extend_from_slice(&0u16.to_le_bytes()); // [24..26] wDatagramIndex = 0
    buf.extend_from_slice(&0u16.to_le_bytes()); // [26..28] wDatagramLength = 0

    // ── Frame payload ──────────────────────────────────────────────
    buf.extend_from_slice(frame); // [28..28+frame.len()]

    Ok(buf)
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Encode tests ──────────────────────────────────────────────

    /// Verify every byte of an encoded NTB against expected values.
    #[test]
    fn encode_single_frame_structure() {
        let frame = b"HelloEthernet";
        let buf = encode_ntb(frame, 7).unwrap();

        // Total length: 12 + 16 + 13 = 41
        assert_eq!(buf.len(), 41);

        // NTH16 signature "NCMH"
        assert_eq!(&buf[0..4], &[0x4E, 0x43, 0x4D, 0x48]);
        // wHeaderLength = 12
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 12);
        // wSequence = 7
        assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), 7);
        // wBlockLength = 41
        assert_eq!(u16::from_le_bytes([buf[8], buf[9]]), 41);
        // wNdpIndex = 12
        assert_eq!(u16::from_le_bytes([buf[10], buf[11]]), 12);

        // NDP16 signature "NCM0"
        assert_eq!(&buf[12..16], &[0x4E, 0x43, 0x4D, 0x30]);
        // wLength = 16
        assert_eq!(u16::from_le_bytes([buf[16], buf[17]]), 16);
        // wNextNdpIndex = 0
        assert_eq!(u16::from_le_bytes([buf[18], buf[19]]), 0);
        // wDatagramIndex = 28
        assert_eq!(u16::from_le_bytes([buf[20], buf[21]]), 28);
        // wDatagramLength = 13
        assert_eq!(u16::from_le_bytes([buf[22], buf[23]]), 13);
        // terminator (0, 0)
        assert_eq!(u16::from_le_bytes([buf[24], buf[25]]), 0);
        assert_eq!(u16::from_le_bytes([buf[26], buf[27]]), 0);

        // Frame payload
        assert_eq!(&buf[28..], b"HelloEthernet");
    }

    /// Empty frames must be rejected.
    #[test]
    fn encode_empty_frame_rejected() {
        assert_eq!(encode_ntb(b"", 0), Err(CdcError::FrameTooLarge));
    }

    /// Sequence number is reflected in the NTH16 wSequence field.
    #[test]
    fn encode_sequence_increments() {
        let frame = &[0u8; 64];
        let buf0 = encode_ntb(frame, 0).unwrap();
        let buf1 = encode_ntb(frame, 1).unwrap();
        let buf255 = encode_ntb(frame, 255).unwrap();

        assert_eq!(u16::from_le_bytes([buf0[6], buf0[7]]), 0);
        assert_eq!(u16::from_le_bytes([buf1[6], buf1[7]]), 1);
        assert_eq!(u16::from_le_bytes([buf255[6], buf255[7]]), 255);
    }

    // ── Decode tests ──────────────────────────────────────────────

    /// Round-trip: encode then decode recovers the original frame.
    #[test]
    fn decode_single_frame_roundtrip() {
        let original = b"EthernetFrameData";
        let ntb = encode_ntb(original, 3).unwrap();
        let mut out = Vec::new();
        decode_ntb(&ntb, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], original);
    }

    /// Manually construct an NTB with two frames in one NDP16.
    #[test]
    fn decode_multi_frame_ntb() {
        // Layout:
        //   [0..12]   NTH16
        //   [12..28]  NDP16 (header 8 + 2 entries 8 + terminator 4 = 20 bytes)
        //             — BUT NDP16 with 2 entries = 8 header + 2*4 + 4 term = 24 bytes
        //   [32..37]  frame1 "hello"
        //   [37..42]  frame2 "world"
        //
        // NDP16 length = 8 (header) + 2*4 (entries) + 4 (term) = 20
        let frame1 = b"hello";
        let frame2 = b"world";

        let nth16_size = 12usize;
        let ndp16_length = 8 + 2 * 4 + 4; // = 24 (header + 2 entries + terminator)
        let frame1_offset = nth16_size + ndp16_length; // = 36
        let frame2_offset = frame1_offset + frame1.len(); // = 41
        let total_len = frame2_offset + frame2.len(); // = 46

        let mut ntb = Vec::with_capacity(total_len);

        // NTH16
        ntb.extend_from_slice(&NTH16_SIGNATURE.to_le_bytes());
        ntb.extend_from_slice(&(nth16_size as u16).to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes()); // sequence
        ntb.extend_from_slice(&(total_len as u16).to_le_bytes());
        ntb.extend_from_slice(&(nth16_size as u16).to_le_bytes()); // wNdpIndex = 12

        // NDP16
        ntb.extend_from_slice(&NDP16_SIGNATURE_NO_CRC.to_le_bytes());
        ntb.extend_from_slice(&(ndp16_length as u16).to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes()); // wNextNdpIndex = 0
                                                    // entry 0
        ntb.extend_from_slice(&(frame1_offset as u16).to_le_bytes());
        ntb.extend_from_slice(&(frame1.len() as u16).to_le_bytes());
        // entry 1
        ntb.extend_from_slice(&(frame2_offset as u16).to_le_bytes());
        ntb.extend_from_slice(&(frame2.len() as u16).to_le_bytes());
        // terminator
        ntb.extend_from_slice(&0u16.to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes());

        // Frame payloads
        ntb.extend_from_slice(frame1);
        ntb.extend_from_slice(frame2);

        assert_eq!(ntb.len(), total_len);

        let mut out = Vec::new();
        decode_ntb(&ntb, &mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], b"hello");
        assert_eq!(out[1], b"world");
    }

    /// NDP16 chain: NDP #1 (one frame) links to NDP #2 (one frame).
    #[test]
    fn decode_chained_ndp() {
        // Layout:
        //   [0..12]   NTH16 (wNdpIndex = 12)
        //   [12..28]  NDP16 #1 (wLength=16, wNextNdpIndex=28, 1 entry + terminator)
        //   [28..44]  NDP16 #2 (wLength=16, wNextNdpIndex=0, 1 entry + terminator)
        //   [44..49]  frame1 "alpha"
        //   [49..54]  frame2 "beta!" — pad to 5 bytes for alignment
        let frame1 = b"alpha";
        let frame2 = b"beta!";

        let ndp1_offset = 12usize;
        let ndp2_offset = 28usize;
        let frame1_offset = 44usize;
        let frame2_offset = frame1_offset + frame1.len(); // = 49
        let total_len = frame2_offset + frame2.len(); // = 54

        let mut ntb = Vec::with_capacity(total_len);

        // NTH16
        ntb.extend_from_slice(&NTH16_SIGNATURE.to_le_bytes());
        ntb.extend_from_slice(&12u16.to_le_bytes()); // wHeaderLength
        ntb.extend_from_slice(&0u16.to_le_bytes()); // wSequence
        ntb.extend_from_slice(&(total_len as u16).to_le_bytes());
        ntb.extend_from_slice(&(ndp1_offset as u16).to_le_bytes()); // wNdpIndex = 12

        // NDP16 #1
        ntb.extend_from_slice(&NDP16_SIGNATURE_NO_CRC.to_le_bytes());
        ntb.extend_from_slice(&16u16.to_le_bytes()); // wLength = 16
        ntb.extend_from_slice(&(ndp2_offset as u16).to_le_bytes()); // wNextNdpIndex = 28
                                                                    // entry: frame1
        ntb.extend_from_slice(&(frame1_offset as u16).to_le_bytes());
        ntb.extend_from_slice(&(frame1.len() as u16).to_le_bytes());
        // terminator
        ntb.extend_from_slice(&0u16.to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes());

        // NDP16 #2
        ntb.extend_from_slice(&NDP16_SIGNATURE_NO_CRC.to_le_bytes());
        ntb.extend_from_slice(&16u16.to_le_bytes()); // wLength = 16
        ntb.extend_from_slice(&0u16.to_le_bytes()); // wNextNdpIndex = 0 (end)
                                                    // entry: frame2
        ntb.extend_from_slice(&(frame2_offset as u16).to_le_bytes());
        ntb.extend_from_slice(&(frame2.len() as u16).to_le_bytes());
        // terminator
        ntb.extend_from_slice(&0u16.to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes());

        // Payloads
        ntb.extend_from_slice(frame1);
        ntb.extend_from_slice(frame2);

        assert_eq!(ntb.len(), total_len);

        let mut out = Vec::new();
        decode_ntb(&ntb, &mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], b"alpha");
        assert_eq!(out[1], b"beta!");
    }

    /// Input shorter than 12 bytes must fail.
    #[test]
    fn decode_too_short() {
        let buf = [0u8; 8];
        let mut out = Vec::new();
        assert_eq!(decode_ntb(&buf, &mut out), Err(CdcError::MalformedNtb));
    }

    /// Wrong NTH16 signature must fail.
    #[test]
    fn decode_bad_nth_signature() {
        let mut ntb = encode_ntb(b"test", 0).unwrap();
        // Corrupt the signature.
        ntb[0] = 0xFF;
        let mut out = Vec::new();
        assert_eq!(decode_ntb(&ntb, &mut out), Err(CdcError::MalformedNtb));
    }

    /// Wrong NDP16 signature must fail.
    #[test]
    fn decode_bad_ndp_signature() {
        let mut ntb = encode_ntb(b"test", 0).unwrap();
        // Corrupt the NDP16 signature (at offset 12).
        ntb[12] = 0xFF;
        let mut out = Vec::new();
        assert_eq!(decode_ntb(&ntb, &mut out), Err(CdcError::MalformedNtb));
    }

    /// wBlockLength larger than the data slice must fail.
    #[test]
    fn decode_block_length_exceeds_data() {
        let mut ntb = encode_ntb(b"test", 0).unwrap();
        // Set wBlockLength to a value larger than the actual buffer.
        let too_large = (ntb.len() + 100) as u16;
        ntb[8] = (too_large & 0xFF) as u8;
        ntb[9] = (too_large >> 8) as u8;
        let mut out = Vec::new();
        assert_eq!(decode_ntb(&ntb, &mut out), Err(CdcError::MalformedNtb));
    }

    /// A datagram entry pointing outside the block must fail.
    #[test]
    fn decode_datagram_out_of_bounds() {
        let mut ntb = encode_ntb(b"test", 0).unwrap();
        // Set wDatagramIndex to a value that would read past the block.
        // wDatagramIndex is at offset 20..22 in the NTB.
        let bad_index = (ntb.len() + 1) as u16;
        ntb[20] = (bad_index & 0xFF) as u8;
        ntb[21] = (bad_index >> 8) as u8;
        // Keep wDatagramLength non-zero so it is not treated as a terminator.
        ntb[22] = 4;
        ntb[23] = 0;
        // Fix wBlockLength to match actual slice length so the first check passes.
        let actual_len = ntb.len() as u16;
        ntb[8] = (actual_len & 0xFF) as u8;
        ntb[9] = (actual_len >> 8) as u8;
        let mut out = Vec::new();
        assert_eq!(decode_ntb(&ntb, &mut out), Err(CdcError::MalformedNtb));
    }

    /// NDP16 with wLength less than the minimum (16) must be rejected.
    #[test]
    fn decode_ndp_length_too_small() {
        let mut ntb = encode_ntb(&[0x01; 10], 0).unwrap();
        // Set NDP wLength to less than minimum (16)
        ntb[16] = 8;
        ntb[17] = 0;
        assert_eq!(
            decode_ntb(&ntb, &mut Vec::new()),
            Err(CdcError::MalformedNtb)
        );
    }

    /// wNdpIndex of 0 (no NDP present) must succeed with zero frames.
    #[test]
    fn decode_zero_ndp_index() {
        // Build an NTH16 with wNdpIndex = 0.
        let mut buf = vec![0u8; 12];
        buf[0..4].copy_from_slice(&NTH16_SIGNATURE.to_le_bytes());
        buf[4] = 12; // wHeaderLength
        buf[5] = 0;
        // wSequence = 0, wBlockLength = 12, wNdpIndex = 0
        buf[8] = 12; // wBlockLength
        buf[9] = 0;
        buf[10] = 0; // wNdpIndex = 0
        buf[11] = 0;

        let mut out = Vec::new();
        decode_ntb(&buf, &mut out).unwrap();
        assert_eq!(out.len(), 0);
    }
}
