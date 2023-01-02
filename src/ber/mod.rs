//! This module provides tools and utilities for handling BER-TLV data as
//! defined in [ISO7816-4][iso7816-4].
//!
//!
//!
//!
//! [iso7816-4]: https://www.iso.org/standard/54550.html

// internal organization
mod iso7816_tag;
pub mod tag;
pub mod tlv;
pub mod value;

// custom reexport (structs at same level for users)
pub use iso7816_tag::{Class, Tag};

/// BER-TLV structure, following ISO/IEC 7816-4.
pub type Tlv = tlv::Tlv<Tag>;

/// Value definition of ISO7816-4 BER-TLV data
pub type Value = value::Value<Tag>;
