use std::convert::TryInto;

use nom::IResult;

use crate::attribute::{Attribute, Tlv};

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
        0x_8028
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
    let (input, remainder) = input.split_at(4);
    let input: [u8; 4] = input.try_into().unwrap();
    let xored = u32::from_be_bytes(input);

    let value = xored ^ MAGIC_NUMBER;

    let inner = Fingerprint(value);
    let attribute = Attribute::Fingerprint(inner);

    Ok((remainder, attribute))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::attribute;

    #[test]
    fn round_trip_bytes() {
        let input = [0x_80, 0x_28, 0x_00, 0x_04, 0x_DE, 0x_AD, 0x_BE, 0x_EF];

        let (_, attribute) = attribute(&input).unwrap();
        let attribute_bytes = attribute.to_bytes();

        assert_eq!(attribute_bytes, input);
    }
}
