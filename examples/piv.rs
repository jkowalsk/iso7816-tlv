//! Example for PIV tag implementation.
use core::fmt;
use iso7816_tlv::ber::tag::Tag as TagTrait;
use iso7816_tlv::ber::{tlv::Tlv, Tag};
use iso7816_tlv::Reader;
use iso7816_tlv::TlvError;
use std::convert::TryFrom;

/// dummy
fn main() -> Result<(), TlvError> {
    let tag = PivTag {
        inner: Tag::try_from(0x34)?,
    };
    println!("tag 0x34: {}", tag);
    println!("Is Piv tag 0x34 constructed : {}", tag.is_constructed());
    println!(
        "Is ISO7816 tag 0x34 constructed : {}",
        tag.inner.is_constructed()
    );

    let tlv34bytes = [0x34u8, 2, 1, 2];
    let tlv34 = Tlv::<PivTag>::parse_all(&tlv34bytes);
    println!("TLV 0x34: {:?}", tlv34);

    Ok(())
}

/// Piv Tag
#[derive(Debug, PartialEq, Clone)]
struct PivTag {
    inner: Tag,
}

impl fmt::Display for PivTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.inner.to_bytes();
        write!(f, "Tag {:X?}", bytes)
    }
}

impl TagTrait for PivTag {
    fn to_bytes(&self) -> &[u8] {
        self.inner.to_bytes()
    }
    fn len_as_bytes(&self) -> usize {
        self.inner.len_as_bytes()
    }
    fn is_constructed(&self) -> bool {
        // to handle specific non ISO7816-4 compliant Tags
        if self.inner.to_bytes() == [0x34] {
            false
        } else {
            self.inner.is_constructed()
        }
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, TlvError> {
        Ok(Self {
            inner: Tag::read(r)?,
        })
    }
}
