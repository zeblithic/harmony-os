// SPDX-License-Identifier: GPL-2.0-or-later
//! RNDR hardware random number generator (ARMv8.5-RNG).
//!
//! QEMU supports RNDR with `-cpu max`. Each read of the RNDR system
//! register returns 64 bits of hardware entropy.

// Hardware functions are only compiled for aarch64; suppress warnings on
// the host test runner (x86_64).
#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code, unused_imports))]

// ── Hardware access (aarch64 only) ────────────────────────────────────

/// Check if RNDR is available by reading ID_AA64ISAR0_EL1 bits [63:60].
///
/// # Safety
/// Must be called at EL1 (EL0 may not have access to this register).
#[cfg(target_arch = "aarch64")]
pub unsafe fn is_available() -> bool {
    let isar0: u64;
    core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0);
    // RNDR field is bits [63:60], value >= 1 means RNDR is supported
    (isar0 >> 60) & 0xF >= 1
}

/// Read a single 64-bit random value from the RNDR register.
///
/// Retries on failure (NZCV.Z set means retry needed), up to
/// [`MAX_RETRIES`] attempts. Panics if all retries are exhausted.
///
/// # Safety
/// RNDR must be supported by the CPU (verify with [`is_available`] first).
#[cfg(target_arch = "aarch64")]
pub unsafe fn read_u64() -> u64 {
    const MAX_RETRIES: u32 = 1024;

    for _ in 0..MAX_RETRIES {
        let val: u64;
        let success: u64;
        // RNDR register — numeric encoding (s3_3_c2_c4_0) used because
        // aarch64-unknown-uefi may not enable the `rand` target feature
        // needed for the named `rndr` form.
        core::arch::asm!(
            "mrs {val}, s3_3_c2_c4_0",
            "cset {success}, ne",         // NE = success
            val = out(reg) val,
            success = out(reg) success,
        );
        if success != 0 {
            return val;
        }
        // Yield before retry
        core::arch::asm!("yield");
    }
    panic!("RNDR failed after {} retries", MAX_RETRIES);
}

/// Fill a byte buffer with hardware random data from RNDR.
///
/// # Safety
/// RNDR must be supported by the CPU (verify with [`is_available`] first).
#[cfg(target_arch = "aarch64")]
pub unsafe fn fill(buf: &mut [u8]) {
    fill_from_u64(buf, || read_u64());
}

// ── Pure logic (testable on host) ─────────────────────────────────────

/// Fill a byte buffer from 64-bit random values.
///
/// `read_u64` is called repeatedly to get 8 bytes at a time. Any
/// trailing bytes (if `buf.len()` is not a multiple of 8) are filled
/// from the last 64-bit read.
pub fn fill_from_u64(buf: &mut [u8], mut read_u64: impl FnMut() -> u64) {
    let mut offset = 0;
    while offset + 8 <= buf.len() {
        let val = read_u64();
        buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        offset += 8;
    }
    if offset < buf.len() {
        let val = read_u64();
        let remaining = &val.to_le_bytes()[..buf.len() - offset];
        buf[offset..].copy_from_slice(remaining);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_exact_multiple_of_8() {
        let mut buf = [0u8; 16];
        let mut counter = 0u64;
        fill_from_u64(&mut buf, || {
            counter += 1;
            counter
        });
        // First 8 bytes = 1u64 LE, next 8 bytes = 2u64 LE
        assert_eq!(&buf[0..8], &1u64.to_le_bytes());
        assert_eq!(&buf[8..16], &2u64.to_le_bytes());
    }

    #[test]
    fn fill_non_multiple_of_8() {
        let mut buf = [0u8; 5];
        fill_from_u64(&mut buf, || 0x0807060504030201u64);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn fill_empty_buffer() {
        let mut buf = [0u8; 0];
        fill_from_u64(&mut buf, || panic!("should not be called"));
    }

    #[test]
    fn fill_single_byte() {
        let mut buf = [0u8; 1];
        fill_from_u64(&mut buf, || 0xABu64);
        assert_eq!(buf, [0xAB]);
    }
}
