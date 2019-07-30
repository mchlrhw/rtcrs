use std::convert::TryInto;

use nom::{
    IResult,
};

use crate::attribute::Attribute;

#[derive(Debug, PartialEq)]
pub struct MessageIntegrity(pub Vec<u8>);

impl Attribute for MessageIntegrity {
    fn r#type(&self) -> u16 {
        0x_0008
    }

    fn length(&self) -> u16 {
        self.0.len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub(crate) fn message_integrity(input: &[u8]) -> IResult<&[u8], impl Attribute> {
    let (input, remainder) = input.split_at(20);
    let attribute = MessageIntegrity(input.to_vec());

    Ok((remainder, attribute))
}
