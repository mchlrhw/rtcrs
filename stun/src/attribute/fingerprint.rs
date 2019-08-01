use std::convert::TryInto;

use nom::{
    bytes::complete::tag, multi::length_data, number::complete::be_u16, sequence::preceded, IResult,
};

use crate::attribute::{Attribute, Tlv};

const TYPE: u16 = 0x_8028;
const MAGIC_NUMBER: u32 = 0x_5354_554E;

#[derive(Debug, PartialEq)]
pub struct Fingerprint(u32);

impl Fingerprint {
    pub fn new(value: u32) -> Self {
        Self(value)
    }
}

impl Tlv for Fingerprint {
    fn typ(&self) -> u16 {
        TYPE
    }

    fn length(&self) -> u16 {
        std::mem::size_of::<u32>().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        let xored = self.0 ^ MAGIC_NUMBER;

        xored.to_be_bytes().to_vec()
    }
}

pub(crate) fn fingerprint(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (remainder, value_field) = preceded(tag(TYPE.to_be_bytes()), length_data(be_u16))(input)?;

    // TODO: return Err here
    let value_field: [u8; 4] = value_field.try_into().unwrap();
    let xored = u32::from_be_bytes(value_field);
    let value = xored ^ MAGIC_NUMBER;

    let inner = Fingerprint(value);
    let attribute = Attribute::Fingerprint(inner);

    Ok((remainder, attribute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bytes() {
        #[rustfmt::skip]
        let input = [
            0x_80, 0x_28, 0x_00, 0x_04,
            0x_DE, 0x_AD, 0x_BE, 0x_EF,
        ];

        let (_, attribute) = fingerprint(&input).unwrap();
        let attribute_bytes = attribute.to_bytes();

        assert_eq!(attribute_bytes, input);
    }
}
