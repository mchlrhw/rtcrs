use nom::{
    bytes::complete::tag, multi::length_data, number::complete::be_u16, sequence::preceded, IResult,
};

use crate::attribute::{Attribute, Tlv};

const TYPE: u16 = 0x_0025;

#[derive(Debug, PartialEq)]
pub struct UseCandidate;

impl Tlv for UseCandidate {
    fn typ(&self) -> u16 {
        TYPE
    }

    fn length(&self) -> u16 {
        0
    }

    fn value(&self) -> Vec<u8> {
        vec![]
    }
}

pub(crate) fn use_candidate(input: &[u8]) -> IResult<&[u8], Attribute, crate::ParseError<&[u8]>> {
    let (remainder, _value_field) = preceded(tag(TYPE.to_be_bytes()), length_data(be_u16))(input)?;

    // TODO: Assert that value_field is empty.
    let attribute = Attribute::UseCandidate(UseCandidate);

    Ok((remainder, attribute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bytes() {
        #[rustfmt::skip]
        let input = [
            0x_00, 0x_25, 0x_00, 0x_00,
        ];

        let (_, attribute) = use_candidate(&input).unwrap();
        let attribute_bytes = attribute.to_bytes();

        assert_eq!(attribute_bytes, input);
    }
}
