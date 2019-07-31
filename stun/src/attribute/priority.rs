use std::convert::TryInto;

use nom::IResult;

use crate::attribute::{Attribute, Tlv};

#[derive(Debug, PartialEq)]
pub struct Priority(u32);

impl Tlv for Priority {
    fn typ(&self) -> u16 {
        0x_0024
    }

    fn length(&self) -> u16 {
        std::mem::size_of::<u32>().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

pub(crate) fn priority(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (input, remainder) = input.split_at(4);
    let input: [u8; 4] = input.try_into().unwrap();
    let value = u32::from_be_bytes(input);

    let inner = Priority(value);
    let attribute = Attribute::Priority(inner);

    Ok((remainder, attribute))
}
