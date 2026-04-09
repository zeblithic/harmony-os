// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC2 FIFO partition constants for CDC-ECM gadget mode.
//!
//! The DWC2 has ~4KB of shared internal RAM that must be partitioned
//! across endpoint FIFOs. FIFO sizes are specified in 32-bit words.

pub const FIFO_RAM_WORDS: u32 = 1024;
pub const RX_FIFO_WORDS: u32 = 256;
pub const TX0_FIFO_WORDS: u32 = 32;
pub const TX1_FIFO_WORDS: u32 = 384;
pub const TX3_FIFO_WORDS: u32 = 16;

pub const fn gnptxfsiz_value() -> u32 {
    (TX0_FIFO_WORDS << 16) | RX_FIFO_WORDS
}
pub const fn dieptxf_value(start_word: u32, depth_words: u32) -> u32 {
    (depth_words << 16) | start_word
}

pub const TX1_START: u32 = RX_FIFO_WORDS + TX0_FIFO_WORDS;
pub const TX3_START: u32 = TX1_START + TX1_FIFO_WORDS;
pub const TOTAL_FIFO_WORDS: u32 =
    RX_FIFO_WORDS + TX0_FIFO_WORDS + TX1_FIFO_WORDS + TX3_FIFO_WORDS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_partition_fits_in_4kb() {
        assert!(
            TOTAL_FIFO_WORDS <= FIFO_RAM_WORDS,
            "FIFO partition ({} words) exceeds 4KB RAM ({} words)",
            TOTAL_FIFO_WORDS,
            FIFO_RAM_WORDS
        );
    }

    #[test]
    fn fifo_regions_do_not_overlap() {
        // TX1 starts right after RX + TX0
        assert_eq!(TX1_START, RX_FIFO_WORDS + TX0_FIFO_WORDS);
        // TX3 starts right after TX1
        assert_eq!(TX3_START, TX1_START + TX1_FIFO_WORDS);
        // Total is the sum of all regions
        let expected_end = TX3_START + TX3_FIFO_WORDS;
        assert_eq!(TOTAL_FIFO_WORDS, expected_end);
    }

    #[test]
    fn gnptxfsiz_register_value() {
        let val = gnptxfsiz_value();
        // Lower 16 bits = RX FIFO start (which is used as the TX0 start address)
        let start = val & 0xFFFF;
        // Upper 16 bits = TX0 depth
        let depth = val >> 16;
        assert_eq!(start, RX_FIFO_WORDS);
        assert_eq!(depth, TX0_FIFO_WORDS);
    }

    #[test]
    fn dieptxf_register_values() {
        // EP1 TX FIFO register
        let ep1_val = dieptxf_value(TX1_START, TX1_FIFO_WORDS);
        assert_eq!(ep1_val & 0xFFFF, TX1_START);
        assert_eq!(ep1_val >> 16, TX1_FIFO_WORDS);

        // EP3 TX FIFO register
        let ep3_val = dieptxf_value(TX3_START, TX3_FIFO_WORDS);
        assert_eq!(ep3_val & 0xFFFF, TX3_START);
        assert_eq!(ep3_val >> 16, TX3_FIFO_WORDS);
    }

    #[test]
    fn rx_fifo_holds_two_bulk_packets() {
        // Each bulk packet is 512 bytes = 128 words; two packets = 256 words
        assert!(
            RX_FIFO_WORDS >= 256,
            "RX FIFO ({} words) too small for two bulk packets (256 words)",
            RX_FIFO_WORDS
        );
    }

    #[test]
    fn tx1_fifo_holds_ethernet_frame() {
        // Max Ethernet frame: 1514 bytes, rounded up to 32-bit words = (1514+3)/4 = 379 words
        let min_words = (1514u32 + 3) / 4;
        assert!(
            TX1_FIFO_WORDS >= min_words,
            "TX1 FIFO ({} words) too small for max Ethernet frame ({} words)",
            TX1_FIFO_WORDS,
            min_words
        );
    }
}
