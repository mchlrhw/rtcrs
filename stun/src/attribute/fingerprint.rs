use std::convert::TryInto;

use nom::IResult;

use crate::attribute::{Attribute, Tlv};

#[derive(Debug, PartialEq)]
pub struct Fingerprint(pub u32);

impl Tlv for Fingerprint {
    fn typ(&self) -> u16 {
        0x_8028
    }

    fn length(&self) -> u16 {
        std::mem::size_of::<u32>().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

pub(crate) fn fingerprint(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (input, remainder) = input.split_at(4);
    let input: [u8; 4] = input.try_into().unwrap();
    let value = u32::from_be_bytes(input);

    let inner = Fingerprint(value);
    let attribute = Attribute::Fingerprint(inner);

    Ok((remainder, attribute))
}
