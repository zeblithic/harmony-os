// SPDX-License-Identifier: GPL-2.0-or-later

//! GpioServer — 9P file server for GPIO pins.
//!
//! Exposes 28 GPIO pins as individual files under a root directory.
//! Read returns `"0\n"` or `"1\n"`. Write accepts value or configuration
//! strings: `"0"`, `"1"`, `"in"`, `"out"`, `"alt0"`-`"alt5"`,
//! `"pull_up"`, `"pull_down"`, `"pull_none"`.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_unikernel::drivers::gpio::{GpioController, PinDirection, PinFunction, Pull};

use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

const QPATH_ROOT: QPath = 0;
const NUM_PINS: u8 = 28;

fn pin_qpath(pin: u8) -> QPath {
    1 + pin as QPath
}

fn qpath_to_pin(qpath: QPath) -> Option<u8> {
    if qpath >= 1 && qpath <= NUM_PINS as QPath {
        Some((qpath - 1) as u8)
    } else {
        None
    }
}

struct FidState {
    qpath: QPath,
    is_open: bool,
    mode: Option<OpenMode>,
}

/// A 9P file server wrapping a [`GpioController`].
///
/// Walk to a pin number (`"0"` through `"27"`) to get a file handle.
/// Read returns the pin's current logic level as `"0\n"` or `"1\n"`.
/// Write accepts value or configuration commands.
pub struct GpioServer<G: GpioController> {
    pub(crate) gpio: G,
    fids: BTreeMap<Fid, FidState>,
}

impl<G: GpioController> GpioServer<G> {
    /// Create a new `GpioServer` wrapping the given GPIO controller.
    pub fn new(gpio: G) -> Self {
        let mut fids = BTreeMap::new();
        fids.insert(
            0,
            FidState {
                qpath: QPATH_ROOT,
                is_open: false,
                mode: None,
            },
        );
        Self { gpio, fids }
    }
}

impl<G: GpioController> FileServer for GpioServer<G> {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if state.qpath != QPATH_ROOT {
            return Err(IpcError::NotDirectory);
        }
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let pin: u8 = name.parse().map_err(|_| IpcError::NotFound)?;
        if pin >= NUM_PINS {
            return Err(IpcError::NotFound);
        }
        let qpath = pin_qpath(pin);
        self.fids.insert(
            new_fid,
            FidState {
                qpath,
                is_open: false,
                mode: None,
            },
        );
        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let state = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if state.is_open {
            return Err(IpcError::PermissionDenied);
        }
        if state.qpath == QPATH_ROOT && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::IsDirectory);
        }
        state.is_open = true;
        state.mode = Some(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, _offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if state.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(state.mode, Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }
        let pin = qpath_to_pin(state.qpath).ok_or(IpcError::NotFound)?;
        let value = self.gpio.read_pin(pin).map_err(|_| IpcError::NotFound)?;
        let full: &[u8] = if value { b"1\n" } else { b"0\n" };
        let n = (count as usize).min(full.len());
        Ok(full[..n].to_vec())
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if state.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(state.mode, Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }
        let pin = qpath_to_pin(state.qpath).ok_or(IpcError::NotFound)?;
        let cmd = core::str::from_utf8(data)
            .map_err(|_| IpcError::InvalidArgument)?
            .trim();
        let len = u32::try_from(data.len()).map_err(|_| IpcError::ResourceExhausted)?;
        match cmd {
            "0" => self
                .gpio
                .write_pin(pin, false)
                .map_err(|_| IpcError::NotFound)?,
            "1" => self
                .gpio
                .write_pin(pin, true)
                .map_err(|_| IpcError::NotFound)?,
            "in" => {
                self.gpio
                    .set_function(pin, PinFunction::Input)
                    .map_err(|_| IpcError::NotFound)?;
                self.gpio
                    .set_direction(pin, PinDirection::Input)
                    .map_err(|_| IpcError::NotFound)?;
            }
            "out" => {
                self.gpio
                    .set_function(pin, PinFunction::Output)
                    .map_err(|_| IpcError::NotFound)?;
                self.gpio
                    .set_direction(pin, PinDirection::Output)
                    .map_err(|_| IpcError::NotFound)?;
            }
            "alt0" => self
                .gpio
                .set_function(pin, PinFunction::Alt0)
                .map_err(|_| IpcError::NotFound)?,
            "alt1" => self
                .gpio
                .set_function(pin, PinFunction::Alt1)
                .map_err(|_| IpcError::NotFound)?,
            "alt2" => self
                .gpio
                .set_function(pin, PinFunction::Alt2)
                .map_err(|_| IpcError::NotFound)?,
            "alt3" => self
                .gpio
                .set_function(pin, PinFunction::Alt3)
                .map_err(|_| IpcError::NotFound)?,
            "alt4" => self
                .gpio
                .set_function(pin, PinFunction::Alt4)
                .map_err(|_| IpcError::NotFound)?,
            "alt5" => self
                .gpio
                .set_function(pin, PinFunction::Alt5)
                .map_err(|e| match e {
                    harmony_unikernel::drivers::gpio::GpioError::UnsupportedFunction => {
                        IpcError::InvalidArgument
                    }
                    _ => IpcError::NotFound,
                })?,
            "pull_up" => self
                .gpio
                .set_pull(pin, Pull::Up)
                .map_err(|_| IpcError::NotFound)?,
            "pull_down" => self
                .gpio
                .set_pull(pin, Pull::Down)
                .map_err(|_| IpcError::NotFound)?,
            "pull_none" => self
                .gpio
                .set_pull(pin, Pull::None)
                .map_err(|_| IpcError::NotFound)?,
            _ => return Err(IpcError::InvalidArgument),
        }
        Ok(len)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Err(IpcError::PermissionDenied); // Root fid is permanent.
        }
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        match state.qpath {
            QPATH_ROOT => Ok(FileStat {
                qpath: QPATH_ROOT,
                name: Arc::from("/"),
                size: 0,
                file_type: FileType::Directory,
            }),
            qpath => {
                let pin = qpath_to_pin(qpath).ok_or(IpcError::NotFound)?;
                let mut name_buf = [0u8; 3]; // max "27" = 2 digits + spare
                let name = pin_to_str(pin, &mut name_buf);
                Ok(FileStat {
                    qpath,
                    name: Arc::from(name),
                    size: 0,
                    file_type: FileType::Regular,
                })
            }
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let qpath = state.qpath;
        self.fids.insert(
            new_fid,
            FidState {
                qpath,
                is_open: false,
                mode: None,
            },
        );
        Ok(qpath)
    }
}

/// Format a pin number (0-27) as a string without heap allocation.
fn pin_to_str(pin: u8, buf: &mut [u8; 3]) -> &str {
    if pin >= 10 {
        buf[0] = b'0' + pin / 10;
        buf[1] = b'0' + pin % 10;
        // SAFETY: digits are always valid UTF-8.
        unsafe { core::str::from_utf8_unchecked(&buf[..2]) }
    } else {
        buf[0] = b'0' + pin;
        // SAFETY: a single digit is always valid UTF-8.
        unsafe { core::str::from_utf8_unchecked(&buf[..1]) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_unikernel::drivers::gpio::GpioError;

    struct MockGpio {
        pins: [bool; 28],
        last_function: Option<(u8, PinFunction)>,
        last_direction: Option<(u8, PinDirection)>,
        last_pull: Option<(u8, Pull)>,
        last_write: Option<(u8, bool)>,
    }

    impl MockGpio {
        fn new() -> Self {
            Self {
                pins: [false; 28],
                last_function: None,
                last_direction: None,
                last_pull: None,
                last_write: None,
            }
        }
    }

    impl GpioController for MockGpio {
        fn set_function(&mut self, pin: u8, func: PinFunction) -> Result<(), GpioError> {
            if pin >= 28 {
                return Err(GpioError::InvalidPin);
            }
            if func == PinFunction::Alt5 {
                return Err(GpioError::UnsupportedFunction);
            }
            self.last_function = Some((pin, func));
            Ok(())
        }

        fn set_direction(&mut self, pin: u8, dir: PinDirection) -> Result<(), GpioError> {
            if pin >= 28 {
                return Err(GpioError::InvalidPin);
            }
            self.last_direction = Some((pin, dir));
            Ok(())
        }

        fn set_pull(&mut self, pin: u8, pull: Pull) -> Result<(), GpioError> {
            if pin >= 28 {
                return Err(GpioError::InvalidPin);
            }
            self.last_pull = Some((pin, pull));
            Ok(())
        }

        fn read_pin(&self, pin: u8) -> Result<bool, GpioError> {
            if pin >= 28 {
                return Err(GpioError::InvalidPin);
            }
            Ok(self.pins[pin as usize])
        }

        fn write_pin(&mut self, pin: u8, value: bool) -> Result<(), GpioError> {
            if pin >= 28 {
                return Err(GpioError::InvalidPin);
            }
            self.pins[pin as usize] = value;
            self.last_write = Some((pin, value));
            Ok(())
        }
    }

    fn test_server() -> GpioServer<MockGpio> {
        GpioServer::new(MockGpio::new())
    }

    // ── Walk tests ───────────────────────────────────────────────────

    #[test]
    fn walk_to_pin_14() {
        let mut srv = test_server();
        let qpath = srv.walk(0, 1, "14").unwrap();
        assert_eq!(qpath, pin_qpath(14)); // = 15
    }

    #[test]
    fn walk_to_pin_0() {
        let mut srv = test_server();
        let qpath = srv.walk(0, 1, "0").unwrap();
        assert_eq!(qpath, pin_qpath(0)); // = 1
    }

    #[test]
    fn walk_to_pin_27() {
        let mut srv = test_server();
        let qpath = srv.walk(0, 1, "27").unwrap();
        assert_eq!(qpath, pin_qpath(27)); // = 28
    }

    #[test]
    fn walk_invalid_pin_28() {
        let mut srv = test_server();
        assert_eq!(srv.walk(0, 1, "28"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_non_numeric() {
        let mut srv = test_server();
        assert_eq!(srv.walk(0, 1, "foo"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_from_non_root() {
        let mut srv = test_server();
        srv.walk(0, 1, "14").unwrap();
        assert_eq!(srv.walk(1, 2, "15"), Err(IpcError::NotDirectory));
    }

    // ── Read tests ───────────────────────────────────────────────────

    #[test]
    fn read_returns_one() {
        let mut srv = test_server();
        srv.gpio.pins[14] = true;
        srv.walk(0, 1, "14").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 256).unwrap();
        assert_eq!(data, b"1\n");
    }

    #[test]
    fn read_returns_zero() {
        let mut srv = test_server();
        srv.walk(0, 1, "14").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 256).unwrap();
        assert_eq!(data, b"0\n");
    }

    #[test]
    fn read_denied_in_write_mode() {
        let mut srv = test_server();
        srv.walk(0, 1, "14").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        assert_eq!(srv.read(1, 0, 256), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn read_respects_count_zero() {
        let mut srv = test_server();
        srv.walk(0, 1, "14").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 0).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn read_respects_count_one() {
        let mut srv = test_server();
        srv.gpio.pins[14] = true;
        srv.walk(0, 1, "14").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 1).unwrap();
        assert_eq!(data, b"1");
    }

    // ── Write tests ──────────────────────────────────────────────────

    #[test]
    fn write_sets_output_high() {
        let mut srv = test_server();
        srv.walk(0, 1, "3").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        srv.write(1, 0, b"1").unwrap();
        assert_eq!(srv.gpio.last_write, Some((3, true)));
    }

    #[test]
    fn write_sets_output_low() {
        let mut srv = test_server();
        srv.walk(0, 1, "3").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        srv.write(1, 0, b"0").unwrap();
        assert_eq!(srv.gpio.last_write, Some((3, false)));
    }

    #[test]
    fn write_configures_input() {
        let mut srv = test_server();
        srv.walk(0, 1, "5").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        srv.write(1, 0, b"in").unwrap();
        assert_eq!(srv.gpio.last_function, Some((5, PinFunction::Input)));
        assert_eq!(srv.gpio.last_direction, Some((5, PinDirection::Input)));
    }

    #[test]
    fn write_configures_output() {
        let mut srv = test_server();
        srv.walk(0, 1, "5").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        srv.write(1, 0, b"out").unwrap();
        assert_eq!(srv.gpio.last_function, Some((5, PinFunction::Output)));
        assert_eq!(srv.gpio.last_direction, Some((5, PinDirection::Output)));
    }

    #[test]
    fn write_configures_alt0() {
        let mut srv = test_server();
        srv.walk(0, 1, "5").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        srv.write(1, 0, b"alt0").unwrap();
        assert_eq!(srv.gpio.last_function, Some((5, PinFunction::Alt0)));
    }

    #[test]
    fn write_configures_pull_up() {
        let mut srv = test_server();
        srv.walk(0, 1, "5").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        srv.write(1, 0, b"pull_up").unwrap();
        assert_eq!(srv.gpio.last_pull, Some((5, Pull::Up)));
    }

    #[test]
    fn write_alt5_returns_invalid_argument() {
        let mut srv = test_server();
        srv.walk(0, 1, "5").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        // Alt5 is unsupported on RP1 — should map to InvalidArgument, not NotFound
        assert_eq!(srv.write(1, 0, b"alt5"), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn write_invalid_command() {
        let mut srv = test_server();
        srv.walk(0, 1, "5").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        assert_eq!(srv.write(1, 0, b"bogus"), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn write_denied_in_read_mode() {
        let mut srv = test_server();
        srv.walk(0, 1, "5").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        assert_eq!(srv.write(1, 0, b"1"), Err(IpcError::PermissionDenied));
    }

    // ── Stat / clunk / clone tests ───────────────────────────────────

    #[test]
    fn stat_root() {
        let mut srv = test_server();
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "/");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_pin() {
        let mut srv = test_server();
        srv.walk(0, 1, "14").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "14");
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.size, 0);
    }

    #[test]
    fn clunk_root_rejected() {
        let mut srv = test_server();
        assert_eq!(srv.clunk(0), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn clunk_releases_fid() {
        let mut srv = test_server();
        srv.walk(0, 1, "14").unwrap();
        srv.clunk(1).unwrap();
        assert_eq!(srv.stat(1), Err(IpcError::InvalidFid));
    }

    #[test]
    fn clone_fid_duplicates() {
        let mut srv = test_server();
        srv.walk(0, 1, "14").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, pin_qpath(14));
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "14");
        assert_eq!(srv.read(2, 0, 256), Err(IpcError::NotOpen));
    }
}
