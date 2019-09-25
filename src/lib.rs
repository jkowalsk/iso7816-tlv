//! This crate provides tools and utilities for handling BER-TLV data as
//! defined in [ISO7819-4][iso7816-4].
//!
//!
//!
//!
//! [iso7816-4]: https://www.iso.org/standard/54550.html

pub mod error;
pub mod tag;
pub mod value;

use std::fmt;
use untrusted::{Input, Reader};

use error::TlvError;
use tag::Tag;
use value::Value;

type Result<T> = std::result::Result<T, TlvError>;

#[derive(PartialEq, Debug, Clone)]
pub struct Tlv {
  tag: Tag,
  value: Value,
}

impl Tlv {
  pub fn new(tag: Tag, value: &Value) -> Result<Tlv> {
    match value {
      Value::Constructed(_) => {
        if !tag.is_constructed() {
          return Err(TlvError::Inconsistant);
        }
      }
      Value::Primitive(_) => {
        if tag.is_constructed() {
          return Err(TlvError::Inconsistant);
        }
      }
    }
    Ok(Tlv {
      tag: tag,
      value: value.clone(),
    })
  }

  fn len_length(l: u32) -> usize {
    match l {
      0..=127 => 1,
      128..=255 => 2,
      256..=65_535 => 3,
      65_536..=16_777_215 => 4,
      _ => 5,
    }
  }

  fn inner_len_to_vec(&self) -> Vec<u8> {
    let l = self.inner_len();
    if l < 0x7f {
      vec![l as u8]
    } else {
      let mut ret: Vec<u8> = l
        .to_be_bytes()
        .iter()
        .skip_while(|&x| *x == 0)
        .cloned()
        .collect();
      ret.insert(0, 0x80 | ret.len() as u8);
      ret
    }
  }

  pub fn inner_len(&self) -> usize {
    match &self.value {
      Value::Primitive(v) => v.len(),
      Value::Constructed(tlv) => tlv.iter().fold(0, |sum, x| sum + x.len()),
    }
  }

  pub fn len(&self) -> usize {
    let inner_len = self.inner_len();
    self.tag.len() + Tlv::len_length(inner_len as u32) + inner_len
  }

  pub fn to_vec(&self) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    ret.extend(self.tag.to_bytes().iter());
    ret.append(&mut self.inner_len_to_vec());
    match &self.value {
      Value::Primitive(v) => ret.extend(v.iter()),
      Value::Constructed(tlv) => {
        for t in tlv {
          ret.append(&mut t.to_vec());
        }
      }
    };
    ret
  }

  fn read_len(r: &mut Reader) -> Result<usize> {
    let mut ret: usize = 0;
    let x = r.read_byte()?;
    if x & 0x80 != 0 {
      let n_bytes = x as usize & 0x7f;
      if n_bytes > 4 {
        return Err(TlvError::InvalidLength);
      }
      for _ in 0..n_bytes {
        let x = r.read_byte()?;
        ret = ret << 8 | x as usize;
      }
    } else {
      ret = x as usize;
    }
    Ok(ret)
  }

  fn read(r: &mut Reader) -> Result<Self> {
    let tag = Tag::read(r)?;
    let len = Tlv::read_len(r)?;

    let ret = if tag.is_constructed() {
      let mut val = Value::Constructed(vec![]);
      while val.len() < len {
        let tlv = Tlv::read(r)?;
        val.push(&tlv)?;
      }
      Tlv::new(tag, &val)?
    } else {
      let content = r.read_bytes(len)?;
      Tlv::new(
        tag,
        &Value::Primitive(content.as_slice_less_safe().to_vec()),
      )?
    };
    if ret.value.len() != len {
      Err(TlvError::Inconsistant)
    } else {
      Ok(ret)
    }
  }

  pub fn parse(input: &[u8]) -> Result<Self> {
    let mut r = Reader::new(Input::from(input));
    Tlv::read(&mut r)
  }
}

impl fmt::Display for Tlv {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}, ", self.tag)?;
    write!(f, "len={}, ", self.value.len())?;
    write!(f, "value:")?;

    match &self.value {
      Value::Primitive(e) => {
        for x in e {
          write!(f, "{:02X}", x)?
        }
      }
      Value::Constructed(e) => {
        let padding_len = if let Some(width) = f.width() {
          width + 4
        } else {
          4
        };
        for x in e {
          write!(f, "\n")?;
          write!(
            f,
            "{}{:>padding$}",
            " ".repeat(padding_len),
            x,
            padding = padding_len
          )?;
        }
      }
    };
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::Tag;
  use std::convert::TryFrom;

  #[test]
  fn tlv_to_from_vec_primitive() {
    let tlv = Tlv::new(Tag::try_from(1u32).unwrap(), &Value::Primitive(vec![0])).unwrap();
    assert_eq!(vec![1, 1, 0], tlv.to_vec());
    {
      let mut data = vec![0u8; 255];
      let tlv = Tlv::new(
        Tag::try_from(1u32).unwrap(),
        &Value::Primitive(data.clone()),
      )
      .unwrap();
      let mut expected = vec![1u8, 0x81, 0xFF];
      expected.append(&mut data);
      assert_eq!(expected, tlv.to_vec());

      let mut r = Reader::new(Input::from(&expected));
      let read = Tlv::read(&mut r).unwrap();
      assert_eq!(tlv, read);
    }
    {
      let mut data = vec![0u8; 256];
      let tlv = Tlv::new(
        Tag::try_from(1u32).unwrap(),
        &Value::Primitive(data.clone()),
      )
      .unwrap();
      let mut expected = vec![1u8, 0x82, 0x01, 0x00];
      expected.append(&mut data);
      assert_eq!(expected, tlv.to_vec());

      let mut r = Reader::new(Input::from(&expected));
      let read = Tlv::read(&mut r).unwrap();
      assert_eq!(tlv, read);
    }
    {
      let mut data = vec![0u8; 65_536];
      let tlv = Tlv::new(
        Tag::try_from(1u32).unwrap(),
        &Value::Primitive(data.clone()),
      )
      .unwrap();
      let mut expected = vec![1u8, 0x83, 0x01, 0x00, 0x00];
      expected.append(&mut data);
      assert_eq!(expected, tlv.to_vec());

      let mut r = Reader::new(Input::from(&expected));
      let read = Tlv::read(&mut r).unwrap();
      assert_eq!(tlv, read);
    }
  }

  #[test]
  fn tlv_to_from_vec_constructed() {
    let base = Tlv::new(Tag::try_from(1u32).unwrap(), &Value::Primitive(vec![0])).unwrap();
    let mut construct = Value::Constructed(vec![base.clone(), base.clone(), base.clone()]);

    let tlv = Tlv::new(Tag::try_from("7f22").unwrap(), &construct).unwrap();
    let mut expected = vec![0x7fu8, 0x22, 9];
    expected.append(&mut base.to_vec());
    expected.append(&mut base.to_vec());
    expected.append(&mut base.to_vec());
    assert_eq!(expected, tlv.to_vec());

    let mut r = Reader::new(Input::from(&expected));
    let read = Tlv::read(&mut r).unwrap();
    assert_eq!(tlv, read);

    construct.push(&base).unwrap();
    expected[2] += base.len() as u8;
    expected.append(&mut base.to_vec());
    let tlv = Tlv::new(Tag::try_from("7f22").unwrap(), &construct).unwrap();
    assert_eq!(expected, tlv.to_vec());

    let mut r = Reader::new(Input::from(&expected));
    let read = Tlv::read(&mut r).unwrap();
    assert_eq!(tlv, read);

    println!("{}", tlv)
  }

  #[test]
  fn display() {
    let base = Tlv::new(Tag::try_from(0x80u32).unwrap(), &Value::Primitive(vec![0])).unwrap();
    let construct = Value::Constructed(vec![base.clone(), base.clone()]);
    let tlv = Tlv::new(Tag::try_from("7f22").unwrap(), &construct).unwrap();

    let mut construct2 = construct.clone();
    construct2.push(&tlv).unwrap();
    construct2.push(&base).unwrap();
    let t = Tag::try_from("3F32").unwrap();
    let tlv = Tlv::new(t, &construct2).unwrap();
    println!("{}", tlv)
  }

}
