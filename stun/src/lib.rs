mod attribute;

use std::convert::{TryFrom, TryInto};

use crc::crc32;
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use fehler::{throw, throws};
use nom::{
    bits::{
        bits,
        complete::{tag as tag_bits, take as take_bits},
    },
    bytes::complete::{tag as tag_bytes, take as take_bytes},
    combinator::{all_consuming, map, map_parser},
    multi::many0,
    number::complete::be_u16,
    sequence::{preceded, tuple},
    IResult,
};
use num_enum::TryFromPrimitive;
use rand::Rng;

pub use crate::attribute::Attribute;
use crate::attribute::{attribute, fingerprint::Fingerprint};

const MAGIC_COOKIE: u32 = 0x_2112_A442;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid class ({0})")]
    InvalidClass(u8),
    #[error("invalid error code ({0})")]
    InvalidErrorCode(u16),
    #[error("invalid message integrity ({0:?})")]
    InvalidMessageIntegrity(Vec<u8>),
    #[error("invalid method ({0})")]
    InvalidMethod(u16),
    #[error("invalid transaction id ({0:?})")]
    InvalidTransactionId(Vec<u8>),
    #[error("unimplemented attribute ({0})")]
    UnimplementedAttribute(u16),
}

#[derive(Debug, PartialEq)]
pub enum ParseError<I> {
    Stun(Error),
    Nom(I, nom::error::ErrorKind),
}

impl<I> From<Error> for ParseError<I> {
    fn from(err: Error) -> Self {
        Self::Stun(err)
    }
}

impl<I> nom::error::ParseError<I> for ParseError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self::Nom(input, kind)
    }

    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I> nom::ErrorConvert<ParseError<I>> for ((I, usize), nom::error::ErrorKind) {
    fn convert(self) -> ParseError<I> {
        ParseError::Nom((self.0).0, self.1)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, TryFromPrimitive)]
#[repr(u16)]
pub enum Method {
    // 0x000: (Reserved)
    Binding = 0x_0001,
    // 0x002: (Reserved; was SharedSecret)
    Allocate = 0x_0003,
    Refresh = 0x_0004,
    // 0x005: (Unassigned)
    Send = 0x_0006,
    Data = 0x_0007,
    CreatePermission = 0x_0008,
    ChannelBind = 0x_0009,
    Connect = 0x_000A,
    ConnectionBind = 0x_000B,
    ConnectionAttempt = 0x_000C,
    // 0x00D-0x07F: (Unassigned)
    GoogPing = 0x_0080,
    // 0x081-0x0FF: (Unassigned)
    // 0x100-0xFFF: (Reserved)
}

#[derive(Copy, Clone, Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum Class {
    Request = 0b_00,
    Indication = 0b_01,
    Success = 0b_10,
    Error = 0b_11,
}

//         0                 1
//         2  3  4 5 6 7 8 9 0 1 2 3 4 5
//
//        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
//        |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
//        |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
//        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Figure 3: Format of STUN Message Type Field
//
// https://tools.ietf.org/html/rfc5389#section-6
fn message_type(input: &[u8]) -> IResult<&[u8], (Method, Class), ParseError<&[u8]>> {
    let (remainder, (m_11_7, c_1, m_6_4, c_0, m_3_0)): (&[u8], (u16, u8, u16, u8, u16)) =
        bits::<_, _, (_, _), _, _>(preceded(
            tag_bits(0b_00, 2_usize),
            tuple((
                take_bits(5_usize),
                take_bits(1_usize),
                take_bits(3_usize),
                take_bits(1_usize),
                take_bits(4_usize),
            )),
        ))(input)?;

    let c = (c_1 << 1) | c_0;
    let class = c
        .try_into()
        .map_err(|_| nom::Err::Error(Error::InvalidClass(c).into()))?;

    let m = (m_11_7 << 6) | (m_6_4 << 3) | m_3_0;
    let method = m
        .try_into()
        .map_err(|_| nom::Err::Error(Error::InvalidMethod(m).into()))?;

    Ok((remainder, (method, class)))
}

fn message_length(input: &[u8]) -> IResult<&[u8], u16, ParseError<&[u8]>> {
    be_u16(input)
}

fn magic_cookie(input: &[u8]) -> IResult<&[u8], &[u8], ParseError<&[u8]>> {
    tag_bytes(MAGIC_COOKIE.to_be_bytes())(input)
}

const TRANSACTION_ID_LEN: usize = 12;

type TransactionIdBuf = [u8; TRANSACTION_ID_LEN];

#[derive(Debug, PartialEq)]
pub struct TransactionId(TransactionIdBuf);

impl TransactionId {
    pub fn new() -> Self {
        let rng = &mut rand::thread_rng();

        let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
        rng.fill(&mut transaction_id);

        Self(transaction_id)
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<TransactionIdBuf> for TransactionId {
    fn from(buf: TransactionIdBuf) -> Self {
        Self(buf)
    }
}

impl TryFrom<&[u8]> for TransactionId {
    type Error = Error;

    #[throws]
    fn try_from(bytes: &[u8]) -> Self {
        if bytes.len() != TRANSACTION_ID_LEN {
            throw!(Error::InvalidTransactionId(bytes.to_vec()));
        }

        let mut buf = [0u8; TRANSACTION_ID_LEN];
        buf.copy_from_slice(bytes);

        Self(buf)
    }
}

fn transaction_id(input: &[u8]) -> IResult<&[u8], TransactionId, ParseError<&[u8]>> {
    let (remainder, bytes) = take_bytes(TRANSACTION_ID_LEN)(input)?;
    let transaction_id = bytes
        .try_into()
        .map_err(|err| nom::Err::Error(ParseError::from(err)))?;

    Ok((remainder, transaction_id))
}

#[derive(Debug, PartialEq)]
pub struct Header {
    pub method: Method,
    pub class: Class,
    pub length: u16,
    pub transaction_id: TransactionId,
}

impl Header {
    pub fn new(method: Method, class: Class, transaction_id: TransactionId) -> Self {
        Self {
            method,
            class,
            length: 0,
            transaction_id,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let m = self.method as u16;
        let c = self.class as u16;

        let m_3_0 = m & 0b_0000_0000_1111;
        let m_6_4 = (m & 0b_0000_0111_0000) >> 4;
        let m_11_7 = (m & 0b_1111_1000_0000) >> 7;

        let c_0 = c & 0b_01;
        let c_1 = (c & 0b_10) >> 1;

        let mt = (m_11_7 << 9) | (c_1 << 8) | (m_6_4 << 5) | (c_0 << 4) | m_3_0;

        let mut header_bytes = vec![];
        header_bytes.extend(&mt.to_be_bytes());
        header_bytes.extend(&self.length.to_be_bytes());
        header_bytes.extend(&MAGIC_COOKIE.to_be_bytes());
        header_bytes.extend(&self.transaction_id.0);

        header_bytes
    }
}

type HeaderArgs = ((Method, Class), u16, TransactionId);

impl Header {
    fn from_tuple(args: HeaderArgs) -> Self {
        Self {
            method: (args.0).0,
            class: (args.0).1,
            length: args.1,
            transaction_id: args.2,
        }
    }
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0 0|     STUN Message Type     |         Message Length        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Magic Cookie                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                     Transaction ID (96 bits)                  |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//             Figure 2: Format of STUN Message Header
//
// https://tools.ietf.org/html/rfc5389#section-6
pub fn header(input: &[u8]) -> IResult<&[u8], Header, ParseError<&[u8]>> {
    map(
        tuple((
            message_type,
            message_length,
            preceded(magic_cookie, transaction_id),
        )),
        Header::from_tuple,
    )(input)
}

#[derive(Debug, PartialEq)]
pub struct Message {
    pub header: Header,
    pub attributes: Vec<Attribute>,
}

pub fn message(input: &[u8]) -> IResult<&[u8], Message, ParseError<&[u8]>> {
    let (remainder, header) = header(input)?;
    let (remainder, attributes) =
        map_parser(take_bytes(header.length), all_consuming(many0(attribute)))(remainder)?;

    let message = Message { header, attributes };

    Ok((remainder, message))
}

impl Message {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut attributes_bytes = vec![];
        for attribute in &self.attributes {
            attributes_bytes.extend(attribute.to_bytes());
        }

        let header_bytes = self.header.to_bytes();

        let mut message_bytes = header_bytes;
        message_bytes.extend(attributes_bytes);

        message_bytes
    }
}

impl Message {
    pub fn base(header: Header) -> Self {
        Self {
            header,
            attributes: vec![],
        }
    }

    pub fn with_attributes(mut self, attributes: Vec<Attribute>) -> Self {
        let mut length = 0;
        for attribute in &attributes {
            let attribute_length: u16 = attribute.to_bytes().len().try_into().unwrap();
            length += attribute_length;
        }
        self.header.length = length;
        self.attributes = attributes;

        self
    }

    pub fn and_attribute(mut self, attribute: Attribute) -> Self {
        let attribute_length: u16 = attribute.to_bytes().len().try_into().unwrap();
        self.header.length += attribute_length;
        self.attributes.push(attribute);
        self
    }

    pub fn with_message_integrity(mut self, key: &[u8]) -> Self {
        // account for the MESSAGE-INTEGRITY attribute itself
        self.header.length += 24;

        let mut mac = Hmac::new(Sha1::new(), key);
        mac.input(&self.to_bytes());

        let inner = mac
            .result()
            .code()
            .try_into()
            .expect("hmac generated an invalid message integrity");
        let attribute = Attribute::MessageIntegrity(inner);

        self.attributes.push(attribute);

        self
    }

    pub fn with_fingerprint(mut self) -> Self {
        // account for the FINGERPRINT attribute itself
        self.header.length += 8;

        let checksum = crc32::checksum_ieee(&self.to_bytes());

        let inner = Fingerprint::new(checksum);
        let attribute = Attribute::Fingerprint(inner);

        self.attributes.push(attribute);

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header() {
        #[rustfmt::skip]
        let input = vec![
            0x_01, 0x_01, 0x_00, 0x_00,
            0x_21, 0x_12, 0x_A4, 0x_42,
            0x_00, 0x_00, 0x_00, 0x_00,
            0x_00, 0x_00, 0x_00, 0x_00,
            0x_00, 0x_00, 0x_00, 0x_00,
        ];
        let expected = Header {
            class: Class::Success,
            method: Method::Binding,
            length: 0,
            transaction_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into(),
        };
        let actual = header(&input).unwrap().1;
        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_header() {
        let header = Header {
            class: Class::Success,
            method: Method::Binding,
            length: 0,
            transaction_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into(),
        };
        #[rustfmt::skip]
        let expected = vec![
            0x_01, 0x_01, 0x_00, 0x_00,
            0x_21, 0x_12, 0x_A4, 0x_42,
            0x_00, 0x_00, 0x_00, 0x_00,
            0x_00, 0x_00, 0x_00, 0x_00,
            0x_00, 0x_00, 0x_00, 0x_00,
        ];
        let actual = header.to_bytes();
        assert_eq!(expected, actual);
    }

    #[test]
    fn with_message_integrity() {
        let message = Message::base(Header {
            class: Class::Success,
            method: Method::Binding,
            length: 0,
            transaction_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into(),
        })
        .with_message_integrity(&[1, 2, 3, 4]);

        assert_eq!(message.header.length, 24);
    }

    #[test]
    fn with_attributes_and_message_integrity() {
        let message = Message::base(Header {
            class: Class::Success,
            method: Method::Binding,
            length: 0,
            transaction_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into(),
        })
        .with_attributes(vec![Attribute::username("knuth")])
        .with_message_integrity(&[1, 2, 3, 4]);

        assert_eq!(message.header.length, 36);
    }
}
