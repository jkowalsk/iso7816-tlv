use crate::error::TlvError;
use crate::Result;
use super::Tlv;

/// Value definition of BER-TLV data
#[derive(PartialEq, Debug, Clone)]
pub enum Value {
  /// constructed data object, i.e., the value is encoded in BER-TLV
  Constructed(Vec<Tlv>),
  /// primitive data object, i.e., the value is not encoded in BER-TLV
  /// (may be empty)
  Primitive(Vec<u8>),
}

impl Value {
  /// Wether the value is constructed or not
  pub fn is_constructed(&self) -> bool {
    match self {
      Value::Constructed(_) => true,
      _ => false,
    }
  }

  /// Get value length once serialized into BER-TLV data
  pub fn len(&self) -> usize {
    match &self {
      Value::Primitive(v) => v.len(),
      Value::Constructed(tlv) => tlv.iter().fold(0, |sum, x| sum + x.len()),
    }
  }

  /// Append a BER-TLV data object.
  /// input is borrowed to forbid further modification to this object
  /// Fails with TlvError::Inconsistant on primitive or empty values.
  pub fn push(&mut self, tlv: Tlv) -> Result<()> {
    match self {
      Value::Constructed(t) => Ok(t.push(tlv)),
      _ => Err(TlvError::Inconsistant),
    }
  }
}
