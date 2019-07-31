use std::convert::TryInto;

use nom::IResult;

use crate::attribute::{Attribute, Tlv};

#[derive(Debug, PartialEq)]
pub struct ComprehensionOptional {
    // TODO: implement typ
    // typ: u32,
    value: Vec<u8>,
}

impl Tlv for ComprehensionOptional {
    fn typ(&self) -> u16 {
        // TODO: replace with self.typ
        0x_0000
    }

    fn length(&self) -> u16 {
        self.value.len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.value.to_vec()
    }
}

pub(crate) fn comprehension_optional(input: &[u8]) -> IResult<&[u8], Attribute> {
    let value = input.to_vec();

    let inner = ComprehensionOptional { value };
    let attribute = Attribute::ComprehensionOptional(inner);

    Ok((&[], attribute))
}
