// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC Ethernet codec — dispatches between ECM and NCM data encoding.
//!
//! ECM: raw Ethernet frame per USB transfer (passthrough).
//! NCM: frames wrapped in NTH16/NDP16 headers (see [`super::ncm`]).

use alloc::vec::Vec;

use super::CdcError;

/// Codec variant selected at USB enumeration time based on `bInterfaceSubclass`.
///
/// - [`CdcCodec::Ecm`]: one raw Ethernet frame per USB bulk transfer.
/// - [`CdcCodec::Ncm`]: frames batched inside NTH16/NDP16 transfer blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcCodec {
    /// ECM (Ethernet Control Model): passthrough, one frame per transfer.
    Ecm,
    /// NCM (Network Control Model): frames wrapped in NTH16/NDP16 headers.
    Ncm {
        /// Maximum NTB size negotiated during `SET_NTB_PARAMETERS`.
        max_ntb_size: u32,
        /// Monotonic sequence counter written into each NTH16 `wSequence` field.
        sequence: u16,
    },
}

impl CdcCodec {
    /// Decode a received USB bulk transfer into Ethernet frames.
    ///
    /// # ECM
    /// If `data` is non-empty, it is pushed as-is into `out`.
    /// An empty slice produces no output (not an error).
    ///
    /// # NCM
    /// Delegates to [`super::ncm::decode_ntb`], which parses the NTH16/NDP16
    /// headers and extracts all contained datagrams.
    ///
    /// # Errors
    ///
    /// Returns [`CdcError::MalformedNtb`] if the NCM NTB is malformed.
    pub fn decode_rx(&self, data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), CdcError> {
        match self {
            CdcCodec::Ecm => {
                if !data.is_empty() {
                    out.push(data.to_vec());
                }
                Ok(())
            }
            CdcCodec::Ncm { .. } => super::ncm::decode_ntb(data, out),
        }
    }

    /// Encode an Ethernet frame for transmission over USB bulk OUT.
    ///
    /// # ECM
    /// Returns `frame.to_vec()` — no wrapping.
    ///
    /// # NCM
    /// Wraps `frame` in an NTH16/NDP16 block via [`super::ncm::encode_ntb`],
    /// then increments the sequence counter with wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`CdcError::FrameTooLarge`] if the frame is empty or too large
    /// to fit in a u16 length field (NCM path only).
    pub fn encode_tx(&mut self, frame: &[u8]) -> Result<Vec<u8>, CdcError> {
        match self {
            CdcCodec::Ecm => Ok(frame.to_vec()),
            CdcCodec::Ncm {
                max_ntb_size,
                sequence,
            } => {
                // 28 = NTH16 (12) + NDP16 (16) overhead for single-frame NTB
                let ntb_size = 28 + frame.len();
                if ntb_size > *max_ntb_size as usize {
                    return Err(CdcError::FrameTooLarge);
                }
                let seq = *sequence;
                let encoded = super::ncm::encode_ntb(frame, seq)?;
                *sequence = sequence.wrapping_add(1);
                Ok(encoded)
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// ECM decode: a non-empty slice is pushed to out unchanged.
    #[test]
    fn ecm_decode_passthrough() {
        let codec = CdcCodec::Ecm;
        let frame = b"EthernetFrame";
        let mut out = Vec::new();
        codec.decode_rx(frame, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], frame);
    }

    /// ECM decode: an empty slice produces no frames (not an error).
    #[test]
    fn ecm_decode_empty_produces_nothing() {
        let codec = CdcCodec::Ecm;
        let mut out = Vec::new();
        codec.decode_rx(&[], &mut out).unwrap();
        assert_eq!(out.len(), 0);
    }

    /// ECM encode: frame is returned as-is.
    #[test]
    fn ecm_encode_passthrough() {
        let mut codec = CdcCodec::Ecm;
        let frame = b"RawFrame";
        let encoded = codec.encode_tx(frame).unwrap();
        assert_eq!(encoded, frame);
    }

    /// NCM round-trip: encode then decode recovers the original frame.
    #[test]
    fn ncm_roundtrip() {
        let mut codec = CdcCodec::Ncm {
            max_ntb_size: 16_384,
            sequence: 0,
        };
        let frame = b"NcmEthernetPayload";
        let ntb = codec.encode_tx(frame).unwrap();

        let decode_codec = CdcCodec::Ncm {
            max_ntb_size: 16_384,
            sequence: 0,
        };
        let mut out = Vec::new();
        decode_codec.decode_rx(&ntb, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], frame);
    }

    /// NCM encode: sequence number is reflected in wSequence bytes of NTH16.
    /// First encode uses sequence 0, second uses sequence 1.
    #[test]
    fn ncm_sequence_increments() {
        let mut codec = CdcCodec::Ncm {
            max_ntb_size: 16_384,
            sequence: 0,
        };
        let frame = &[0xABu8; 32];

        let ntb0 = codec.encode_tx(frame).unwrap();
        let ntb1 = codec.encode_tx(frame).unwrap();

        // wSequence is at NTH16 bytes [6..8].
        let seq0 = u16::from_le_bytes([ntb0[6], ntb0[7]]);
        let seq1 = u16::from_le_bytes([ntb1[6], ntb1[7]]);

        assert_eq!(seq0, 0);
        assert_eq!(seq1, 1);
    }

    /// NCM sequence wraps from u16::MAX back to 0.
    #[test]
    fn ncm_sequence_wraps() {
        let mut codec = CdcCodec::Ncm {
            max_ntb_size: 16_384,
            sequence: u16::MAX,
        };
        let frame = &[0x55u8; 16];

        // First encode uses u16::MAX.
        let ntb_max = codec.encode_tx(frame).unwrap();
        // After encode, sequence should have wrapped to 0.
        let ntb_zero = codec.encode_tx(frame).unwrap();

        let seq_max = u16::from_le_bytes([ntb_max[6], ntb_max[7]]);
        let seq_zero = u16::from_le_bytes([ntb_zero[6], ntb_zero[7]]);

        assert_eq!(seq_max, u16::MAX);
        assert_eq!(seq_zero, 0);
    }
}
