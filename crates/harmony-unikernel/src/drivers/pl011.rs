// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O PL011 UART driver.
//!
//! Uses the [`RegisterBank`] trait for all register access, enabling
//! full unit testing without hardware.
