use std::convert::TryInto;

use nom::{multi::length_data, number::complete::be_u16, sequence::tuple, IResult};

use crate::attribute::{Attribute, Tlv};

#[derive(Debug, PartialEq)]
pub struct ComprehensionOptional {
    typ: u16,
    value: Vec<u8>,
}

impl Tlv for ComprehensionOptional {
    fn typ(&self) -> u16 {
        self.typ
    }

    fn length(&self) -> u16 {
        self.value.len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.value.to_vec()
    }
}

pub(crate) fn comprehension_optional(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (remainder, (typ, value_field)) = tuple((be_u16, length_data(be_u16)))(input)?;

    // TODO: assert that typ is within the comprehension optional range

    let value = value_field.to_vec();

    let inner = ComprehensionOptional { typ, value };
    let attribute = Attribute::ComprehensionOptional(inner);

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

        let (_, attribute) = comprehension_optional(&input).unwrap();
        let attribute_bytes = attribute.to_bytes();

        assert_eq!(attribute_bytes, input);
    }
}
