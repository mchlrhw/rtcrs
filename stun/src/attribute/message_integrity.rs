use std::convert::TryInto;

use nom::{
    bytes::complete::tag, multi::length_data, number::complete::be_u16, sequence::preceded, IResult,
};

use crate::attribute::{Attribute, Tlv};

const TYPE: u16 = 0x_0008;

#[derive(Debug, PartialEq)]
pub struct MessageIntegrity(Vec<u8>);

impl MessageIntegrity {
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Tlv for MessageIntegrity {
    fn typ(&self) -> u16 {
        TYPE
    }

    fn length(&self) -> u16 {
        self.0.len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub(crate) fn message_integrity(
    input: &[u8],
) -> IResult<&[u8], Attribute, crate::ParseError<&[u8]>> {
    let (remainder, value_field) = preceded(tag(TYPE.to_be_bytes()), length_data(be_u16))(input)?;

    // TODO: assert that value_field.len() == 20
    let value = value_field.to_vec();

    let inner = MessageIntegrity(value);
    let attribute = Attribute::MessageIntegrity(inner);

    Ok((remainder, attribute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bytes() {
        #[rustfmt::skip]
        let input = [
            0x_00, 0x_08, 0x_00, 0x_14,
            0x_DE, 0x_AD, 0x_BE, 0x_EF,
            0x_CA, 0x_FE, 0x_BA, 0x_BE,
            0x_CA, 0x_FE, 0x_D0, 0x_0D,
            0x_FE, 0x_E1, 0x_DE, 0x_AD,
            0x_FE, 0x_ED, 0x_FA, 0x_CE,
        ];

        let (_, attribute) = message_integrity(&input).unwrap();
        let attribute_bytes = attribute.to_bytes();

        assert_eq!(attribute_bytes, input);
    }
}
