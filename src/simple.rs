//! This module provides tools and utilities for handling SIMPLE-TLV data as
//! defined in [ISO7816-4][iso7816-4].
//!
//!
//!
//!
//! [iso7816-4]: https://www.iso.org/standard/54550.html
//!
use std::convert::TryFrom;
use untrusted::{Input, Reader};

use crate::{Result, TlvError};

/// Tag for SIMPLE-TLV data as defined in [ISO7816-4].
/// > The tag field consists of a single byte encoding a tag number from 1 to 254.
/// > The values '00' and 'FF' are invalid for tag fields.
///
/// Tags can be generated using the [TryFrom][TryFrom] trait
/// from u8 or hex [str][str].
///
/// [TryFrom]: https://doc.rust-lang.org/std/convert/trait.TryFrom.html
/// [str]:https://doc.rust-lang.org/std/str/
///
/// # Example
/// ```rust
/// use std::convert::TryFrom;
/// use iso7816_tlv::simple::Tag;
/// # use iso7816_tlv::TlvError;
/// # fn main() -> () {
///
/// assert!(Tag::try_from("80").is_ok());
/// assert!(Tag::try_from(8u8).is_ok());
/// assert!(Tag::try_from(0x80).is_ok());
/// assert!(Tag::try_from(127).is_ok());
///
/// assert!(Tag::try_from("er").is_err());
/// assert!(Tag::try_from("00").is_err());
/// assert!(Tag::try_from("ff").is_err());
/// # }
/// #
/// ```
#[derive(PartialEq, Debug, Clone)]
pub struct Tag(u8);

/// Value for SIMPLE-TLV data as defined in [ISO7816].
/// > the value field consists of N consecutive bytes.
/// N may be zero. In this case there is no value field
#[derive(PartialEq, Debug, Clone)]
pub struct Value(Vec<u8>);

/// SIMPLE-TLV data object representation.
/// > Each SIMPLE-TLV data object shall consist of two or three consecutive fields:
/// a mandatory tag field, a mandatory length field and a conditional value field
#[derive(PartialEq, Debug, Clone)]
pub struct Tlv {
  tag: Tag,
  value: Value,
}

impl TryFrom<u8> for Tag {
  type Error = TlvError;
  fn try_from(v: u8) -> Result<Self> {
    match v {
      0x00 | 0xFF => Err(TlvError::InvalidInput),
      _ => Ok(Tag(v)),
    }
  }
}

impl TryFrom<&str> for Tag {
  type Error = TlvError;
  fn try_from(v: &str) -> Result<Self> {
    let x = u8::from_str_radix(v, 16)?;
    Tag::try_from(x)
  }
}

impl Tlv {
  /// Create a SIMPLE-TLV data object from valid tag and value.
  /// A value has a maximum size of 65_535 bytes.
  /// Otherwise this fonction fails with TlvError::InvalidLength.
  pub fn new(tag: Tag, value: Value) -> Result<Self> {
    if value.0.len() > 65_536 {
      Err(TlvError::InvalidLength)
    } else {
      Ok(Tlv { tag, value })
    }
  }

  /// serializes self into a byte vector.
  pub fn to_vec(&self) -> Vec<u8> {
    let mut ret = Vec::new();
    ret.push(self.tag.0);
    let len = self.value.0.len();
    match len {
      0..=254 => ret.push(len as u8),
      _ => {
        ret.push(0xFF);
        ret.push((len >> 8) as u8);
        ret.push(len as u8);
      }
    };
    ret.extend(&self.value.0);
    ret
  }

  fn read_len(r: &mut Reader) -> Result<usize> {
    let mut ret: usize = 0;
    let x = r.read_byte()?;
    if x == 0xFF {
      for _ in 0..2 {
        let x = r.read_byte()?;
        ret = ret << 8 | x as usize;
      }
    } else {
      ret = x as usize;
    }
    Ok(ret)
  }

  fn read(r: &mut Reader) -> Result<Self> {
    let tag = Tag::try_from(r.read_byte()?)?;
    let len = Tlv::read_len(r)?;
    let content = r.read_bytes(len)?;

    Ok(Tlv {
      tag,
      value: Value(content.as_slice_less_safe().to_vec()),
    })
  }

  /// Parses a byte array into a SIMPLE-TLV structure.
  /// This also returns the unprocessed data.
  pub fn parse(input: &[u8]) -> (Result<Self>, &[u8]) {
    let mut r = Reader::new(Input::from(input));
    (
      Tlv::read(&mut r),
      r.read_bytes_to_end().as_slice_less_safe(),
    )
  }

  /// Parses a byte array into a SIMPLE-TLV structure.
  /// Input must exactly match a SIMPLE-TLV object.
  pub fn from_bytes(input: &[u8]) -> Result<Self> {
    let (r, n) = Tlv::parse(input);
    if !n.is_empty() {
      Err(TlvError::InvalidInput)
    } else {
      r
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::convert::TryFrom;

  #[test]
  fn tag_import() {
    assert!(Tag::try_from("80").is_ok());
    assert!(Tag::try_from(8u8).is_ok());
    assert!(Tag::try_from(0x80).is_ok());
    assert!(Tag::try_from(127).is_ok());

    assert!(Tag::try_from("er").is_err());
    assert!(Tag::try_from("00").is_err());
    assert!(Tag::try_from("ff").is_err());
  }
}
