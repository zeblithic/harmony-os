// SPDX-License-Identifier: GPL-2.0-or-later

//! Hardware register abstraction for sans-I/O drivers.

/// Abstraction over memory-mapped I/O registers.
///
/// Implementations provide read/write access to a peripheral's
/// register space.  The real implementation uses volatile pointer
/// access; the mock records all operations for testing.
pub trait RegisterBank {
    /// Read a 32-bit register at `offset` bytes from the peripheral base.
    fn read(&self, offset: usize) -> u32;

    /// Write a 32-bit value to the register at `offset` bytes from the
    /// peripheral base.
    fn write(&mut self, offset: usize, value: u32);
}

#[cfg(any(test, feature = "test-utils"))]
pub mod mock {
    use super::RegisterBank;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::Cell;

    pub struct MockRegisterBank {
        reads: BTreeMap<usize, Vec<u32>>,
        read_cursor: BTreeMap<usize, Cell<usize>>,
        pub writes: Vec<(usize, u32)>,
    }

    impl Default for MockRegisterBank {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockRegisterBank {
        pub fn new() -> Self {
            Self {
                reads: BTreeMap::new(),
                read_cursor: BTreeMap::new(),
                writes: Vec::new(),
            }
        }

        /// Queue a sequence of values that `read(offset)` will return.
        /// Each call to `read(offset)` pops the next value. If exhausted,
        /// returns the last value (sticky).
        pub fn on_read(&mut self, offset: usize, values: Vec<u32>) {
            self.reads.insert(offset, values);
            self.read_cursor.insert(offset, Cell::new(0));
        }
    }

    impl RegisterBank for MockRegisterBank {
        fn read(&self, offset: usize) -> u32 {
            let values = match self.reads.get(&offset) {
                Some(v) => v,
                None => return 0,
            };
            let cursor = match self.read_cursor.get(&offset) {
                Some(c) => c,
                None => return 0,
            };
            let idx = cursor.get();
            if idx < values.len() {
                cursor.set(idx + 1);
                values[idx]
            } else {
                values.last().copied().unwrap_or(0)
            }
        }

        fn write(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockRegisterBank;
    use super::RegisterBank;
    use alloc::vec;

    #[test]
    fn mock_records_writes() {
        let mut bank = MockRegisterBank::new();
        bank.write(0x030, 0x301);
        bank.write(0x024, 13);
        assert_eq!(bank.writes, vec![(0x030, 0x301), (0x024, 13)]);
    }

    #[test]
    fn mock_returns_preconfigured_reads() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(0x018, vec![0x20, 0x00]);
        assert_eq!(bank.read(0x018), 0x20);
        assert_eq!(bank.read(0x018), 0x00);
    }

    #[test]
    fn mock_read_unconfigured_returns_zero() {
        let bank = MockRegisterBank::new();
        assert_eq!(bank.read(0x000), 0);
    }

    #[test]
    fn mock_read_exhausted_returns_last() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(0x018, vec![0x20]);
        assert_eq!(bank.read(0x018), 0x20);
        assert_eq!(bank.read(0x018), 0x20);
    }
}
