//! Value definition of BER-TLV data

use crate::error::TlvError;
use crate::Result;
use crate::Tlv;

#[derive(PartialEq, Debug, Clone)]
pub enum Value {
  Constructed(Vec<Tlv>),
  Primitive(Vec<u8>),
}

impl Value {
  pub fn is_constructed(&self) -> bool {
    match self {
      Value::Constructed(_) => true,
      Value::Primitive(_) => false,
    }
  }

  pub fn len(&self) -> usize {
    match &self {
      Value::Primitive(v) => v.len(),
      Value::Constructed(tlv) => tlv.iter().fold(0, |sum, x| sum + x.len()),
    }
  }

  pub fn push(&mut self, tlv: &Tlv) -> Result<()> {
    match self {
      Value::Primitive(_) => Err(TlvError::Inconsistant),
      Value::Constructed(t) => Ok(t.push(tlv.clone())),
    }
  }
}
