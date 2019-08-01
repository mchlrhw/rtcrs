use std::convert::TryInto;

use nom::{
    bytes::complete::tag, multi::length_data, number::complete::be_u16, sequence::preceded, IResult,
};

use crate::attribute::{Attribute, Tlv};

const TYPE: u16 = 0x_0024;

#[derive(Debug, PartialEq)]
pub struct Priority(u32);

impl Tlv for Priority {
    fn typ(&self) -> u16 {
        TYPE
    }

    fn length(&self) -> u16 {
        std::mem::size_of::<u32>().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

pub(crate) fn priority(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (remainder, value_field) = preceded(tag(TYPE.to_be_bytes()), length_data(be_u16))(input)?;

    // TODO: return Err here
    let value_field: [u8; 4] = value_field.try_into().unwrap();
    let value = u32::from_be_bytes(value_field);

    let inner = Priority(value);
    let attribute = Attribute::Priority(inner);

    Ok((remainder, attribute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bytes() {
        #[rustfmt::skip]
        let input = [
            0x_00, 0x_24, 0x_00, 0x_04,
            0x_DE, 0x_AD, 0x_BE, 0x_EF,
        ];

        let (_, attribute) = priority(&input).unwrap();
        let attribute_bytes = attribute.to_bytes();

        assert_eq!(attribute_bytes, input);
    }
}
