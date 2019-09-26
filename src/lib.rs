//! This crate provides tools and utilities for handling BER-TLV data as
//! defined in [ISO7819-4][iso7816-4].
//!
//!
//!
//!
//! [iso7816-4]: https://www.iso.org/standard/54550.html

#![deny(missing_docs)]

// internal organization
mod error;
mod tag;
mod tlv;
mod value;

// custom reexport (structs at same level for users)
pub use error::TlvError;
pub use tag::{Class, Tag};
pub use tlv::Tlv;
pub use value::Value;

type Result<T> = std::result::Result<T, TlvError>;
