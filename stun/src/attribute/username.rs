use std::convert::TryInto;

use nom::{
    bytes::complete::tag, multi::length_data, number::complete::be_u16, sequence::preceded, IResult,
};

use crate::attribute::{Attribute, Tlv};

const TYPE: u16 = 0x_0006;

#[derive(Debug, PartialEq)]
pub struct Username(String);

impl Username {
    pub fn new(username: &str) -> Self {
        Self(username.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Tlv for Username {
    fn typ(&self) -> u16 {
        TYPE
    }

    fn length(&self) -> u16 {
        self.0.len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        let mut value_field = self.0.as_bytes().to_vec();

        let pad_len = (4 - (value_field.len() % 4)) % 4;
        for _ in 0..pad_len {
            value_field.push(0x_00);
        }

        value_field
    }
}

pub(crate) fn username(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (remainder, value_field) = preceded(tag(TYPE.to_be_bytes()), length_data(be_u16))(input)?;

    let pad_len = (4 - (value_field.len() % 4)) % 4;
    let remainder = &remainder[pad_len..];

    // TODO: check the input length is < 513
    // TODO: return Err here
    let value = String::from_utf8(value_field.to_vec()).unwrap();

    let inner = Username(value);
    let attribute = Attribute::Username(inner);

    Ok((remainder, attribute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bytes() {
        #[rustfmt::skip]
        let input = [
            0x_00, 0x_06, 0x_00, 0x_07,
            0x_6D, 0x_63, 0x_68, 0x_6C,
            0x_72, 0x_68, 0x_77, 0x_00,
        ];

        let (_, attribute) = username(&input).unwrap();
        let attribute_bytes = attribute.to_bytes();

        assert_eq!(attribute_bytes, input);
    }
}
