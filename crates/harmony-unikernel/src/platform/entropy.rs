// SPDX-License-Identifier: GPL-2.0-or-later

use rand_core::{CryptoRng, RngCore};

pub struct KernelEntropy<F: FnMut(&mut [u8])> {
    fill_fn: F,
}

impl<F: FnMut(&mut [u8])> KernelEntropy<F> {
    pub fn new(fill_fn: F) -> Self {
        KernelEntropy { fill_fn }
    }
}

impl<F: FnMut(&mut [u8])> RngCore for KernelEntropy<F> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        (self.fill_fn)(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// # Safety contract
///
/// The caller MUST provide a fill function backed by a hardware CSPRNG
/// (e.g., x86 RDRAND, ARM RNDR). Using a weak or deterministic source
/// will produce insecure cryptographic keys — the type system cannot
/// enforce this. Test code may use deterministic fills, but those
/// `KernelEntropy` instances must never be used for real key generation.
impl<F: FnMut(&mut [u8])> CryptoRng for KernelEntropy<F> {}

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_platform::EntropySource;

    fn counting_fill() -> impl FnMut(&mut [u8]) {
        let mut counter: u8 = 0;
        move |buf: &mut [u8]| {
            for byte in buf.iter_mut() {
                *byte = counter;
                counter = counter.wrapping_add(1);
            }
        }
    }

    #[test]
    fn fill_bytes_uses_provided_function() {
        let mut entropy = KernelEntropy::new(counting_fill());
        let mut buf = [0u8; 4];
        RngCore::fill_bytes(&mut entropy, &mut buf);
        assert_eq!(buf, [0, 1, 2, 3]);
    }

    #[test]
    fn next_u32_returns_le_bytes() {
        let mut entropy = KernelEntropy::new(counting_fill());
        let val = entropy.next_u32();
        assert_eq!(val, u32::from_le_bytes([0, 1, 2, 3]));
    }

    #[test]
    fn next_u64_returns_le_bytes() {
        let mut entropy = KernelEntropy::new(counting_fill());
        let val = entropy.next_u64();
        assert_eq!(val, u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]));
    }

    #[test]
    fn satisfies_entropy_source_trait() {
        let mut entropy = KernelEntropy::new(counting_fill());
        let source: &mut dyn EntropySource = &mut entropy;
        let mut buf = [0u8; 4];
        source.fill_bytes(&mut buf);
        assert_eq!(buf, [0, 1, 2, 3]);
    }

    #[test]
    fn satisfies_crypto_rng_core() {
        let mut entropy = KernelEntropy::new(counting_fill());
        fn takes_crypto_rng(_rng: &mut impl rand_core::CryptoRngCore) {}
        takes_crypto_rng(&mut entropy);
    }

    #[test]
    fn sequential_calls_advance_state() {
        let mut entropy = KernelEntropy::new(counting_fill());
        let mut buf1 = [0u8; 4];
        let mut buf2 = [0u8; 4];
        RngCore::fill_bytes(&mut entropy, &mut buf1);
        RngCore::fill_bytes(&mut entropy, &mut buf2);
        assert_eq!(buf1, [0, 1, 2, 3]);
        assert_eq!(buf2, [4, 5, 6, 7]);
    }
}
