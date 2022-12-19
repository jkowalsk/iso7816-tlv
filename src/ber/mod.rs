//! This module provides tools and utilities for handling BER-TLV data as
//! defined in [ISO7816-4][iso7816-4].
//!
//! In PIV, data object's inner tag does not necessarily follow BER-TLV
//! requirement (see [NIST specification, Section
//! 4.1][NIST-SP-800-73-4]). When using the `piv` feature, the
//! consistency of the tag class with the actual value is not checked.
//!
//!
//!
//! [iso7816-4]: https://www.iso.org/standard/54550.html
//! [NIST-SP-800-73-4](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-73-4.pdf)

// internal organization
mod tag;
mod tlv;
mod value;

// custom reexport (structs at same level for users)
pub use tag::{Class, Tag};
pub use tlv::Tlv;
pub use value::Value;
