use std::convert::{TryFrom, TryInto};

use fehler::{throw, throws};
use nom::{
    bytes::complete::tag, multi::length_data, number::complete::be_u16, sequence::preceded, IResult,
};

use super::{Attribute, Tlv};
use crate::{Error, ParseError};

const TYPE: u16 = 0x_0008;
const MESSAGE_INTEGRITY_LEN: usize = 20;

type MessageIntegrityBuf = [u8; MESSAGE_INTEGRITY_LEN];

#[derive(Debug, PartialEq)]
pub struct MessageIntegrity(MessageIntegrityBuf);

impl TryFrom<&[u8]> for MessageIntegrity {
    type Error = Error;

    #[throws]
    fn try_from(bytes: &[u8]) -> Self {
        if bytes.len() != MESSAGE_INTEGRITY_LEN {
            throw!(Error::InvalidMessageIntegrity(bytes.to_vec()));
        }

        let mut buf = [0u8; MESSAGE_INTEGRITY_LEN];
        buf.copy_from_slice(bytes);

        Self(buf)
    }
}

impl Tlv for MessageIntegrity {
    fn typ(&self) -> u16 {
        TYPE
    }

    fn length(&self) -> u16 {
        MESSAGE_INTEGRITY_LEN as u16
    }

    fn value(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub(crate) fn message_integrity(input: &[u8]) -> IResult<&[u8], Attribute, ParseError<&[u8]>> {
    let (remainder, value_field) = preceded(tag(TYPE.to_be_bytes()), length_data(be_u16))(input)?;

    let inner = value_field
        .try_into()
        .map_err(|err| nom::Err::Error(ParseError::from(err)))?;
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
