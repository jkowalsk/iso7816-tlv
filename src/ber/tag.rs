//! Tag trait for BER-TLV data
//!

use core::fmt::Display;

use crate::Result;
use untrusted::Reader;

/// Trait defining required method for BER-TLV Tags
#[allow(clippy::module_name_repetitions)]
pub trait Tag: Sized + PartialEq + Display {
    /// serializes the tag as byte array
    #[must_use]
    fn to_bytes(&self) -> &[u8];
    /// length of the tag as byte array
    #[must_use]
    fn len_as_bytes(&self) -> usize;
    /// Wether the tag is constructed or not
    #[must_use]
    fn is_constructed(&self) -> bool;
    /// read tag from reader.
    /// # Errors
    /// see `TlvError`
    fn read(r: &mut Reader) -> Result<Self>;
}
