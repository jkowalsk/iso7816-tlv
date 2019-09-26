//! Tag definition and utilities for BER-TLV data as defined in [ISO7819-4]
//!
use std::convert::TryFrom;
use std::fmt;
use std::str;

use crate::{Result, TlvError};
use untrusted::Reader;

/// Class of a BER-TLV Tag field.
/// > Bits 8 and 7 of the first byte of the tag field indicate a class.
/// > - The value 00 indicates a data object of the universal class.
/// > - The value 01 indicates a data object of the application class.
/// > - The value 10 indicates a data object of the context-specific class.
/// > - The value 11 indicates a data object of the private class.
#[derive(PartialEq, Clone, Debug)]
pub enum Class {
  /// Universal class, not defined in ISO/IEC 7816
  Universal,
  /// Application class, identification defined in [ISO7819-4]
  Application,
  /// Context-specific class, defined in ISO/IEC 7816
  ContextSpecific,
  /// Private class, not defined in ISO/IEC 7816
  Private,
}

impl From<u8> for Class {
  fn from(val: u8) -> Self {
    match val & Tag::CLASS_MASK {
      0b0000_0000 => Class::Universal,
      0b0100_0000 => Class::Application,
      0b1000_0000 => Class::ContextSpecific,
      _ => Class::Private,
    }
  }
}

/// Tag for BER-TLV data as defined in [ISO7819-4].
/// > ISO/IEC 7816 supports tag fields of one, two and three bytes;
/// > longer tag fields are reserved for future use
#[derive(PartialEq, Clone)]
pub struct Tag {
  raw: [u8; 3],
  len: usize,
}

impl Tag {
  const CLASS_MASK: u8 = 0b1100_0000;
  const CONSTRUCTED_MASK: u8 = 0b0010_0000;
  const VALUE_MASK: u8 = 0b0111_1111;
  const MORE_BYTES_MASK: u8 = 0b1000_0000;

  /// serializes the tag as byte array
  pub fn to_bytes(&self) -> &[u8] {
    &self.raw[self.raw.len() - self.len..]
  }

  /// length of the tag as byte array
  pub fn len(&self) -> usize {
    self.len
  }

  /// Wether the tag is constructed or not
  /// > Bit 6 of the first byte of the tag field indicates an encoding.
  /// > - The value 0 indicates a primitive encoding of the data object, i.e., the value field is not encoded in BER - TLV .
  /// > - The value 1 indicates a constructed encoding of the data object, i.e., the value field is encoded in BER - TLV
  pub fn is_constructed(&self) -> bool {
    match &self.raw[3 - self.len] & Tag::CONSTRUCTED_MASK {
      0 => false,
      _ => true,
    }
  }

  /// Get the tag class
  pub fn class(&self) -> Class {
    self.raw[3 - self.len].into()
  }

  pub(crate) fn read(r: &mut Reader) -> Result<Self> {
    let first = r.read_byte()?;
    let mut value = first as u64;
    if first & Tag::VALUE_MASK == Tag::VALUE_MASK {
      loop {
        value = value.checked_shl(8).ok_or_else(|| TlvError::InvalidTag)?;
        let x = r.read_byte()?;
        value |= x as u64;
        if x & 0x80 == 0 {
          break;
        }
      }
    }
    let r = Tag::try_from(value)?;
    Ok(r)
  }
}

impl fmt::Display for Tag {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let t = [0, self.raw[0], self.raw[1], self.raw[2]];
    let as_int: u32 = u32::from_be_bytes(t);
    write!(f, "Tag {:x} ({:?})", as_int, self.class())
  }
}

impl fmt::Debug for Tag {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let t = [0, self.raw[0], self.raw[1], self.raw[2]];
    let as_int: u32 = u32::from_be_bytes(t);
    let constructed = if self.is_constructed() {
      "Contructed"
    } else {
      "Primitive"
    };
    write!(f, "Tag {:x} ({:?}; {})", as_int, self.class(), constructed)
  }
}

impl TryFrom<u64> for Tag {
  type Error = TlvError;
  fn try_from(v: u64) -> Result<Self> {
    let bytes = v.to_be_bytes();
    let mut first_non_zero = 0;
    for &x in bytes.iter() {
      if x == 0 {
        first_non_zero += 1;
      } else {
        break;
      }
    }
    let raw = [
      bytes[bytes.len() - 3],
      bytes[bytes.len() - 2],
      bytes[bytes.len() - 1],
    ];
    let bytes = &bytes[first_non_zero..];

    match bytes.len() {
      0 => return Err(TlvError::InvalidTag),
      1 => {
        if (bytes[0] & Tag::VALUE_MASK) == Tag::VALUE_MASK {
          return Err(TlvError::InvalidTag);
        }
      }
      2 => {
        if (bytes[1] & Tag::MORE_BYTES_MASK) == Tag::MORE_BYTES_MASK {
          return Err(TlvError::InvalidTag);
        }
      }
      3 => {
        if (bytes[1] & Tag::MORE_BYTES_MASK) == 0 {
          return Err(TlvError::InvalidTag);
        }
        if (bytes[2] & Tag::MORE_BYTES_MASK) == Tag::MORE_BYTES_MASK {
          return Err(TlvError::InvalidTag);
        }
      }
      _ => return Err(TlvError::TagIsRFU),
    }

    Ok(Tag {
      raw: raw,
      len: bytes.len(),
    })
  }
}

impl TryFrom<usize> for Tag {
  type Error = TlvError;
  fn try_from(v: usize) -> Result<Self> {
    Tag::try_from(v as u64)
  }
}

impl TryFrom<u32> for Tag {
  type Error = TlvError;
  fn try_from(v: u32) -> Result<Self> {
    Tag::try_from(v as u64)
  }
}

impl TryFrom<u16> for Tag {
  type Error = TlvError;
  fn try_from(v: u16) -> Result<Self> {
    Tag::try_from(v as u64)
  }
}

impl TryFrom<u8> for Tag {
  type Error = TlvError;
  fn try_from(v: u8) -> Result<Self> {
    Tag::try_from(v as u64)
  }
}

impl TryFrom<i32> for Tag {
  type Error = TlvError;
  fn try_from(v: i32) -> Result<Self> {
    Tag::try_from(v as u64)
  }
}

impl TryFrom<i16> for Tag {
  type Error = TlvError;
  fn try_from(v: i16) -> Result<Self> {
    Tag::try_from(v as u64)
  }
}

impl TryFrom<i8> for Tag {
  type Error = TlvError;
  fn try_from(v: i8) -> Result<Self> {
    Tag::try_from(v as u64)
  }
}
use std::u64;
impl TryFrom<&str> for Tag {
  type Error = TlvError;
  fn try_from(v: &str) -> Result<Self> {
    let x = u64::from_str_radix(v, 16)?;
    Tag::try_from(x)
  }
}

#[cfg(test)]
mod tests {
  // Note this useful idiom: importing names from outer (for mod tests) scope.
  use super::*;
  use untrusted::Input;

  #[test]
  fn tag_import_ok() {
    assert!(Tag::try_from(0x1).is_ok());
    assert!(Tag::try_from(0x7f22).is_ok());
    assert!(Tag::try_from(0x7fff22).is_ok());
    assert_eq!(Err(TlvError::InvalidTag), Tag::try_from(0));
    assert_eq!(Err(TlvError::InvalidTag), Tag::try_from(0x7f));
    assert_eq!(Err(TlvError::InvalidTag), Tag::try_from(0x7f80));
    assert_eq!(Err(TlvError::InvalidTag), Tag::try_from(0x7f7f00));
    assert_eq!(Err(TlvError::TagIsRFU), Tag::try_from(0x7f808000));

    assert!(Tag::try_from("7fff22").is_ok());
    assert_eq!(Err(TlvError::ParseIntError), Tag::try_from("bad one"));
  }

  #[test]
  fn tag_import() {
    let vectors = ["01", "7f22", "7fff22"];
    for &v in vectors.iter() {
      let x = Tag::try_from(v).unwrap();
      assert_eq!(v.len() / 2, x.len());
      assert_eq!(v.len() / 2, x.to_bytes().len());
    }
  }

  #[test]
  fn tag_read() {
    let vectors: [&[u8]; 3] = [&[1], &[0x7f, 0x22], &[0x7f, 0xff, 0x22]];
    for &v in vectors.iter() {
      let mut r = Reader::new(Input::from(v));
      let x = Tag::read(&mut r).unwrap();
      assert_eq!(v.len(), x.len());
      assert_eq!(v.len(), x.to_bytes().len());
      assert_eq!(v, x.to_bytes());
    }

    let bad_vectors: [&[u8]; 2] = [&[0x7f, 0xff], &[0x7f, 0xff, 0xff]];
    for &v in bad_vectors.iter() {
      let mut r = Reader::new(Input::from(v));
      assert_eq!(Err(TlvError::TruncatedInput), Tag::read(&mut r));
    }
  }
}