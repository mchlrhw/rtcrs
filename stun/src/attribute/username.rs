use std::convert::TryInto;

use nom::{
    IResult,
};

use crate::attribute::Attribute;

#[derive(Debug, PartialEq)]
struct Username(String);

impl Attribute for Username {
    fn r#type(&self) -> u16 {
        0x_0006
    }

    fn length(&self) -> u16 {
        self.0.len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

pub(crate) fn username(input: &[u8]) -> IResult<&[u8], impl Attribute> {
    // TODO: check the input length is < 513
    // TODO: return Err here
    let value = String::from_utf8(input.to_vec()).unwrap();
    let attribute = Username(value);

    Ok((&[], attribute))
}
