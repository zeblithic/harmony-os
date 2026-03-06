// SPDX-License-Identifier: GPL-2.0-or-later

use core::fmt::Write;

pub struct SerialWriter<F: FnMut(u8)> {
    write_byte: F,
}

impl<F: FnMut(u8)> SerialWriter<F> {
    pub fn new(write_byte: F) -> Self {
        SerialWriter { write_byte }
    }

    pub fn log(&mut self, tag: &str, msg: &str) {
        let _ = writeln!(self, "[{}] {}", tag, msg);
    }
}

impl<F: FnMut(u8)> Write for SerialWriter<F> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            (self.write_byte)(byte);
        }
        Ok(())
    }
}

pub fn hex_encode(bytes: &[u8], buf: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in bytes.iter().enumerate() {
        buf[i * 2] = HEX[(b >> 4) as usize];
        buf[i * 2 + 1] = HEX[(b & 0xf) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    fn capture_writer() -> (SerialWriter<impl FnMut(u8)>, Arc<RefCell<Vec<u8>>>) {
        let buf = Arc::new(RefCell::new(Vec::new()));
        let buf_clone = buf.clone();
        let writer = SerialWriter::new(move |byte| {
            buf_clone.borrow_mut().push(byte);
        });
        (writer, buf)
    }

    #[test]
    fn write_str_captures_bytes() {
        let (mut writer, buf) = capture_writer();
        write!(writer, "hello").unwrap();
        assert_eq!(&*buf.borrow(), b"hello");
    }

    #[test]
    fn log_formats_structured_tag() {
        let (mut writer, buf) = capture_writer();
        writer.log("BOOT", "Harmony unikernel v0.1.0");
        let output = String::from_utf8(buf.borrow().clone()).unwrap();
        assert_eq!(output, "[BOOT] Harmony unikernel v0.1.0\n");
    }

    #[test]
    fn log_identity_format() {
        let (mut writer, buf) = capture_writer();
        writer.log("IDENTITY", "deadbeef01234567deadbeef01234567");
        let output = String::from_utf8(buf.borrow().clone()).unwrap();
        assert!(output.starts_with("[IDENTITY] "));
        assert!(output.ends_with("\n"));
    }

    #[test]
    fn hex_encode_produces_lowercase_hex() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let mut buf = [0u8; 8];
        hex_encode(&bytes, &mut buf);
        assert_eq!(&buf, b"deadbeef");
    }

    #[test]
    fn hex_encode_16_bytes_produces_32_chars() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut buf = [0u8; 32];
        hex_encode(&bytes, &mut buf);
        assert_eq!(&buf, b"0123456789abcdeffedcba9876543210");
    }
}
