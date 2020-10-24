use std::convert::TryInto;

use nom::{
    bits::{bits, complete::take},
    bytes::complete::tag,
    multi::length_data,
    number::complete::be_u16,
    sequence::{preceded, tuple},
    IResult,
};
use num_enum::TryFromPrimitive;

use crate::{
    attribute::{Attribute, Tlv},
    Error,
};

const TYPE: u16 = 0x_0009;

#[derive(Copy, Clone, Debug, PartialEq, TryFromPrimitive)]
#[repr(u16)]
pub enum NumericCode {
    // 0-299: (Reserved)
    TryAlternate = 300,
    // 301-399: (Unassigned)
    BadRequest = 400,
    Unauthenticated = 401,
    // 402: (Unassigned)
    Forbidden = 403,
    // 404: (Unassigned)
    MobilityForbidden = 405,
    // 406-419: (Unassigned)
    UnknownAttribute = 420,
    // 421-436: (Unassigned)
    AllocationMismatch = 437,
    StaleNonce = 438,
    // 439: (Unassigned)
    AddressFamilyNotSupported = 440,
    WrongCredentials = 441,
    UnsupportedTransportProtocol = 442,
    PeerAddressFamilyMismatch = 443,
    // 444-445: (Unassigned)
    ConnectionAlreadyExists = 446,
    ConnectionTimeoutOrFailure = 447,
    // 448-485: (Unassigned)
    AllocationQuotaReached = 486,
    RoleConflict = 487,
    // 488-499: (Unassigned)
    ServerError = 500,
    // 501-507: (Unassigned)
    InsufficientCapacity = 508,
    // 509-699: (Unassigned)
}

#[derive(Debug, PartialEq)]
pub struct ErrorCode {
    numeric_code: NumericCode,
    reason_phrase: String,
}

impl ErrorCode {
    pub fn new(numeric_code: NumericCode, reason_phrase: &str) -> Self {
        // TODO: Ensure the phrase is < 128 chars (and < 509 bytes).
        let reason_phrase = reason_phrase.to_owned();

        Self {
            numeric_code,
            reason_phrase,
        }
    }
}

impl Tlv for ErrorCode {
    fn typ(&self) -> u16 {
        TYPE
    }

    fn length(&self) -> u16 {
        (4 + self.reason_phrase.len()).try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        let class_and_number = self.numeric_code as u32;
        let class = class_and_number / 100;
        let number = class_and_number % 100;
        let class_and_number_encoded = class << 8 | number;

        let mut value_field = class_and_number_encoded.to_be_bytes().to_vec();
        value_field.extend_from_slice(self.reason_phrase.as_bytes());

        let pad_len = (4 - (value_field.len() % 4)) % 4;
        let new_len = value_field.len() + pad_len;
        value_field.resize(new_len, 0x_00);

        value_field
    }
}

pub(crate) fn error_code(input: &[u8]) -> IResult<&[u8], Attribute, crate::ParseError<&[u8]>> {
    let (remainder, value_field) = preceded(tag(TYPE.to_be_bytes()), length_data(be_u16))(input)?;

    let (value_remainder, (class, number)): (&[u8], (u16, u16)) = bits::<_, _, (_, _), _, _>(
        preceded::<_, u32, _, _, _, _>(take(21_usize), tuple((take(3_usize), take(8_usize)))),
    )(value_field)?;
    // TODO: Ensure class < 6 and number is < 100.
    let class_and_number = (class * 100) + number;
    let numeric_code = class_and_number
        .try_into()
        .map_err(|_| nom::Err::Error(Error::InvalidErrorCode(class_and_number).into()))?;

    // TODO: Ensure the phrase is < 128 chars (and < 763 bytes).
    let reason_phrase = String::from_utf8(value_remainder.to_vec()).unwrap();

    let inner = ErrorCode {
        numeric_code,
        reason_phrase,
    };
    let attribute = Attribute::ErrorCode(inner);

    Ok((remainder, attribute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bytes() {
        #[rustfmt::skip]
        let input = [
            0x_00, 0x_09, 0x_00, 0x_0B,
            0x_00, 0x_00, 0x_03, 0x_00,
            0x_6D, 0x_63, 0x_68, 0x_6C,
            0x_72, 0x_68, 0x_77, 0x_00,
        ];

        let (_, attribute) = error_code(&input).unwrap();
        let attribute_bytes = attribute.to_bytes();

        assert_eq!(attribute_bytes, input);
    }
}
