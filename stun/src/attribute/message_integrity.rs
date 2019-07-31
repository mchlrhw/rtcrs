use std::convert::TryInto;

use nom::IResult;

use crate::attribute::{Attribute, Tlv};

#[derive(Debug, PartialEq)]
pub struct MessageIntegrity(Vec<u8>);

impl MessageIntegrity {
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Tlv for MessageIntegrity {
    fn typ(&self) -> u16 {
        0x_0008
    }

    fn length(&self) -> u16 {
        self.0.len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub(crate) fn message_integrity(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (input, remainder) = input.split_at(20);
    let value = input.to_vec();

    let inner = MessageIntegrity(value);
    let attribute = Attribute::MessageIntegrity(inner);

    Ok((remainder, attribute))
}
