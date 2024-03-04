//! This crate provides tools and utilities for handling TLV data as
//! defined in [ISO7816-4][iso7816-4].
//!
//! This include BER-TLV data or SIMPLE-TLV data objects.
//!
//!
//!
//!
//! [iso7816-4]: https://www.iso.org/standard/54550.html

#![deny(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::all))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::pedantic))]
// otherwise cargo doc fails with
// error: no global memory allocator found but one is required; link to std or add #[global_allocator] to
// a static item that implements the GlobalAlloc trait.
#![cfg_attr(not(doc), no_std)]

// use custom allocator for tests
#[cfg(test)]
use static_alloc::Bump;
#[cfg(test)]
#[global_allocator]
static ALLOC: Bump<[u8; 1 << 28]> = Bump::uninit();

// use vectors
#[macro_use]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

use core::result;

// internal organization
pub mod ber;
mod error;
pub mod simple;

// custom reexport (structs at same level for users)
pub use error::TlvError;

type Result<T> = result::Result<T, TlvError>;

#[cfg(test)]
mod tests {
    use crate::simple::{Tag, Tlv};
    use core::convert::TryFrom;

    #[test]
    fn simple_tag_match() {
        let tlv = Tlv::new(Tag::try_from(10).unwrap(), vec![0x0, 0x1]).unwrap();

        let m = match tlv.tag().to_u8() {
            10 => true,
            _ => false,
        };
        assert_eq!(m, true);

    }

    #[test]
    fn simple_tag_match_with_public_member() {
        let tlv = Tlv::new(Tag::try_from(10).unwrap(), vec![0x0, 0x1]).unwrap();

        let m = match tlv.tag() {
            Tag(10) => true,
            _ => false
        };
        assert_eq!(m, true);
    }
}
