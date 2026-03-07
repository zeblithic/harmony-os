// SPDX-License-Identifier: GPL-2.0-or-later
//! Book — portable athenaeum metadata serialization.

/// Error when parsing a book from bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookError {
    TooShort,
}

/// A single blob entry in a book.
pub struct BookEntry;

/// A book — portable athenaeum metadata.
pub struct Book;
