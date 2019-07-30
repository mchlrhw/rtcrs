use std::convert::TryInto;

use nom::{
    IResult,
};

use crate::attribute::Attribute;

#[derive(Debug, PartialEq)]
pub struct ComprehensionOptional {
    // TODO: implement type
    // r#type: u32,
    value: Vec<u8>,
}

impl Attribute for ComprehensionOptional {
    fn r#type(&self) -> u16 {
        // TODO: replace with self.type
        0x_0000
    }

    fn length(&self) -> u16 {
        self.value.len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.value.to_vec()
    }
}

pub(crate) fn comprehension_optional(input: &[u8]) -> IResult<&[u8], impl Attribute> {
    let value = input.to_vec();
    let attribute = ComprehensionOptional { value };

    Ok((&[], attribute))
}
