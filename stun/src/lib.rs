mod attribute;

use crc::crc32;
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use nom::{
    bits::{
        bits,
        complete::{tag as tag_bits, take as take_bits},
    },
    bytes::complete::{tag as tag_bytes, take as take_bytes},
    combinator::{map, map_parser},
    multi::many0,
    number::complete::be_u16,
    sequence::{preceded, terminated, tuple},
    IResult,
};

pub use crate::attribute::Attribute;
use crate::attribute::{
    attribute, fingerprint::Fingerprint, message_integrity::MessageIntegrity, Tlv,
};

const MAGIC_COOKIE: u32 = 0x_2112_A442;
const FINGERPRINT_COOKIE: u32 = 0x_5354_554E;

#[derive(Debug, PartialEq)]
pub enum Method {
    Binding,
}

#[derive(Debug, PartialEq)]
pub enum Class {
    Error,
    Indication,
    Request,
    Success,
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
fn message_type(input: &[u8]) -> IResult<&[u8], (Class, Method)> {
    let (remainder, (m_11_7, c_1, m_6_4, c_0, m_3_0)): (&[u8], (u8, u8, u8, u8, u8)) =
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
    let class = match c {
        0b_00 => Class::Request,
        0b_01 => Class::Indication,
        0b_10 => Class::Success,
        0b_11 => Class::Error,
        _ => unreachable!(),
    };

    let m = (m_11_7 << 6) | (m_6_4 << 3) | m_3_0;
    let method = match m {
        0b_0000_0000_0001 => Method::Binding,
        // TODO: return Err here
        _ => unimplemented!(),
    };

    Ok((remainder, (class, method)))
}

#[derive(Debug, PartialEq)]
pub struct Header {
    pub class: Class,
    pub method: Method,
    pub length: u16,
    pub transaction_id: Vec<u8>,
}

impl Header {
    pub fn to_bytes(&self) -> Vec<u8> {
        let c = match self.class {
            Class::Request => 0b_00,
            Class::Indication => 0b_01,
            Class::Success => 0b_10,
            Class::Error => 0b_11,
        };

        let m = match self.method {
            Method::Binding => 0b_0000_0000_0001,
        };

        let c_0 = c & 0b_01;
        let c_1 = (c & 0b_10) >> 1;

        let m_3_0 = m & 0b_0000_0000_1111;
        let m_6_4 = (m & 0b_0000_0111_0000) >> 4;
        let m_11_7 = (m & 0b_1111_1000_0000) >> 7;

        let mt: u16 = (m_11_7 << 9) | (c_1 << 8) | (m_6_4 << 5) | (c_0 << 4) | m_3_0;

        let mut header_bytes = vec![];
        header_bytes.extend(&mt.to_be_bytes());
        header_bytes.extend(&self.length.to_be_bytes());
        header_bytes.extend(&MAGIC_COOKIE.to_be_bytes());
        header_bytes.extend(&self.transaction_id);

        header_bytes
    }
}

type HeaderArgs = ((Class, Method), u16, Vec<u8>);

impl Header {
    fn from_tuple(args: HeaderArgs) -> Self {
        Self {
            class: (args.0).0,
            method: (args.0).1,
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
pub fn header(input: &[u8]) -> IResult<&[u8], Header> {
    map(
        tuple((
            map_parser(take_bytes(2_usize), message_type),
            terminated(be_u16, tag_bytes(MAGIC_COOKIE.to_be_bytes())),
            map(take_bytes(12_usize), Vec::from),
        )),
        Header::from_tuple,
    )(input)
}

#[derive(Debug, PartialEq)]
pub struct Message {
    pub header: Header,
    pub attributes: Vec<Attribute>,
}

type MessageArgs = (Header, Vec<Attribute>);

impl Message {
    fn from_tuple(args: MessageArgs) -> Self {
        Self {
            header: args.0,
            attributes: args.1,
        }
    }
}

pub fn message(input: &[u8]) -> IResult<&[u8], Message> {
    let (remainder, message) = map(tuple((header, many0(attribute))), Message::from_tuple)(input)?;

    // TODO: if MessageIntegrity in attributes, check input against it
    // TODO: if Fingerprint in attributes, check input against it

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
        for attribute in &self.attributes {
            length += attribute.length();
        }
        self.header.length = length;
        self.attributes = attributes;
        self
    }

    pub fn and_attribute(mut self, attribute: Attribute) -> Self {
        self.header.length += attribute.length();
        self.attributes.push(attribute);
        self
    }

    pub fn with_message_integrity(self, key: &[u8]) -> Self {
        let mut mac = Hmac::new(Sha1::new(), key);
        mac.input(&self.to_bytes());
        let code = mac.result().code().to_vec();

        let inner = MessageIntegrity::new(code);
        let attribute = Attribute::MessageIntegrity(inner);

        self.and_attribute(attribute)
    }

    pub fn with_fingerprint(self) -> Self {
        let checksum = crc32::checksum_ieee(&self.to_bytes());
        let value = checksum ^ FINGERPRINT_COOKIE;

        let inner = Fingerprint(value);
        let attribute = Attribute::Fingerprint(inner);

        self.and_attribute(attribute)
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
            transaction_id: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
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
            transaction_id: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
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
}
