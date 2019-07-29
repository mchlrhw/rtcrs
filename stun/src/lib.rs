use std::{
    convert::TryInto,
    net::{IpAddr, Ipv4Addr},
};

use crc::crc32;
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use log::trace;
use nom::{
    bits::{
        bits,
        complete::{tag as tag_bits, take as take_bits},
    },
    bytes::complete::{tag as tag_bytes, take as take_bytes},
    combinator::{all_consuming, map, map_parser},
    multi::{length_data, many0},
    number::complete::be_u16,
    sequence::{preceded, terminated, tuple},
    IResult,
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
pub enum Attribute {
    ComprehensionOptional(Vec<u8>),
    Fingerprint(u32),
    MessageIntegrity(Vec<u8>),
    Priority(u32),
    Username(String),
    XorMappedAddress { address: IpAddr, port: u16 },
}

fn fingerprint_to_bytes(checksum: u32) -> Vec<u8> {
    let checksum = checksum.to_be_bytes();
    let length: u16 = checksum.len().try_into().unwrap();
    let length_field = length.to_be_bytes();

    let typ: u16 = 0x_8028;
    let type_field = typ.to_be_bytes();

    let mut bytes = type_field.to_vec();
    bytes.extend_from_slice(&length_field);
    bytes.extend_from_slice(&checksum);

    bytes
}

fn message_integrity_to_bytes(code: &[u8]) -> Vec<u8> {
    let length: u16 = code.len().try_into().unwrap();
    let length_field = length.to_be_bytes();

    let typ: u16 = 0x_0008;
    let type_field = typ.to_be_bytes();

    let mut bytes = type_field.to_vec();
    bytes.extend_from_slice(&length_field);
    bytes.extend_from_slice(&code);

    bytes
}

fn username_to_bytes(username: String) -> Vec<u8> {
    let value_field = username.as_bytes();

    let length: u16 = value_field.len().try_into().unwrap();
    let length_field = length.to_be_bytes();

    let typ: u16 = 0x_0006;
    let type_field = typ.to_be_bytes();

    let mut bytes = type_field.to_vec();
    bytes.extend_from_slice(&length_field);
    bytes.extend_from_slice(value_field);

    bytes
}

fn xor_mapped_address_to_bytes(address: &IpAddr, port: u16) -> Vec<u8> {
    let (family_field, x_address_field) = match address {
        IpAddr::V4(addr) => {
            let family_field = 0x_01_u16.to_be_bytes();

            let addr = u32::from_be_bytes(addr.octets());
            let x_address_field = (addr ^ MAGIC_COOKIE).to_be_bytes();

            (family_field, x_address_field)
        }
        _ => unimplemented!(),
    };

    let x_port_field = (port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes();

    let mut value_field = family_field.to_vec();
    value_field.extend_from_slice(&x_port_field);
    value_field.extend_from_slice(&x_address_field);

    let length: u16 = value_field.len().try_into().unwrap();
    let length_field = length.to_be_bytes();

    let typ: u16 = 0x_0020;
    let type_field = typ.to_be_bytes();

    let mut bytes = type_field.to_vec();
    bytes.extend_from_slice(&length_field);
    bytes.extend_from_slice(&value_field);

    bytes
}

impl Attribute {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Attribute::Fingerprint(checksum) => fingerprint_to_bytes(*checksum),
            Attribute::MessageIntegrity(code) => message_integrity_to_bytes(code),
            Attribute::Username(username) => username_to_bytes(username.to_string()),
            Attribute::XorMappedAddress { address, port } => {
                xor_mapped_address_to_bytes(address, *port)
            }
            _ => unimplemented!(),
        }
    }
}

fn comprehension_optional(input: &[u8]) -> IResult<&[u8], Attribute> {
    let value = input.to_vec();
    let attribute = Attribute::ComprehensionOptional(value);

    Ok((&[], attribute))
}

fn fingerprint(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (input, remainder) = input.split_at(4);
    let input: [u8; 4] = input.try_into().unwrap();
    let value = u32::from_be_bytes(input);
    let attribute = Attribute::Fingerprint(value);

    Ok((remainder, attribute))
}

fn message_integrity(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (input, remainder) = input.split_at(20);
    let attribute = Attribute::MessageIntegrity(input.to_vec());

    Ok((remainder, attribute))
}

fn priority(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (input, remainder) = input.split_at(4);
    let input: [u8; 4] = input.try_into().unwrap();
    let value = u32::from_be_bytes(input);
    let attribute = Attribute::Priority(value);

    Ok((remainder, attribute))
}

fn username(input: &[u8]) -> IResult<&[u8], Attribute> {
    // TODO: check the input length is < 513 bytes
    // TODO: return Err here
    let value = String::from_utf8(input.to_vec()).unwrap();
    let attribute = Attribute::Username(value);

    Ok((&[], attribute))
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |x x x x x x x x|    Family     |         X-Port                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                X-Address (Variable)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//         Figure 6: Format of XOR-MAPPED-ADDRESS Attribute
//
// https://tools.ietf.org/html/rfc5389#section-15.2
fn xor_mapped_address(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (x_address_field, (mut family_field, x_port_field)) = tuple((be_u16, be_u16))(input)?;

    let port = x_port_field ^ (MAGIC_COOKIE >> 16) as u16;

    family_field &= 0b_0000_0000_1111_1111;
    let (remainder, address) = match family_field {
        0x_01 => {
            // TODO: convert std::array::TryFromSliceError to nom::internal::Err
            let (x_address_field, remainder) = x_address_field.split_at(4);
            let x_address_field: [u8; 4] = x_address_field.try_into().unwrap();
            let address_bytes = u32::from_be_bytes(x_address_field) ^ MAGIC_COOKIE;

            (remainder, IpAddr::V4(Ipv4Addr::from(address_bytes)))
        }
        // TODO: implement v6 addresses
        0x_02 => unimplemented!(),
        // TODO: return Err here
        _ => unimplemented!(),
    };

    let attribute = Attribute::XorMappedAddress { port, address };

    Ok((remainder, attribute))
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Type                  |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Value (variable)                ....
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//               Figure 4: Format of STUN Attributes
//
// https://tools.ietf.org/html/rfc5389#section-15
fn attribute(input: &[u8]) -> IResult<&[u8], Attribute> {
    let (remainder, (typ_field, value_field)) = tuple((be_u16, length_data(be_u16)))(input)?;

    let pad_len = (4 - (value_field.len() % 4)) % 4;
    let padding = remainder[0..pad_len].to_vec();
    let remainder = &remainder[pad_len..];

    trace!(
        "Parsing attribute: {:04X?} {:02X?} {:02X?}",
        typ_field,
        value_field,
        padding
    );

    let parser = match typ_field {
        // Comprehension-required range (0x0000-0x7FFF)
        // 0x0000: (Reserved)
        // TODO: 0x_0001 => AttributeType::MappedAddress
        // 0x0002: (Reserved; was RESPONSE-ADDRESS)
        // 0x0003: (Reserved; was CHANGE-ADDRESS)
        // 0x0004: (Reserved; was SOURCE-ADDRESS)
        // 0x0005: (Reserved; was CHANGED-ADDRESS)
        0x_0006 => username,
        // 0x0007: (Reserved; was PASSWORD)
        0x_0008 => message_integrity,
        // TODO: 0x_0009 => AttributeType::ErrorCode
        // TODO: 0x_000A => AttributeType::UnknownAttributes
        // 0x000B: (Reserved; was REFLECTED-FROM)
        // TODO: 0x_0014 => AttributeType::Realm
        // TODO: 0x_0015 => AttributeType::Nonce
        0x_0020 => xor_mapped_address,
        0x_0024 => priority,
        // Comprehension-optional range (0x8000-0xFFFF)
        0x_8000..=0x_8027 => comprehension_optional,
        // TODO: 0x_8022 => AttributeType::Software
        // TODO: 0x_8023 => AttributeType::AlternateServer
        0x_8028 => fingerprint,
        0x_8029..=0x_FFFF => comprehension_optional,
        // TODO: return Err here
        _ => unimplemented!(),
    };
    let (_, attribute) = all_consuming(parser)(value_field)?;

    Ok((remainder, attribute))
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
        for attribute in &self.attributes {
            let attribute_length: u16 = attribute.to_bytes().len().try_into().unwrap();
            self.header.length += attribute_length;
        }
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
        // account for the message integrity attritibute itself:
        // 20 for the HMAC and 4 for the attribute header
        self.header.length += 24;

        let mut mac = Hmac::new(Sha1::new(), key);
        mac.input(&self.to_bytes());
        let code = mac.result().code().to_vec();

        let attribute = Attribute::MessageIntegrity(code);
        self.attributes.push(attribute);

        self
    }

    pub fn with_fingerprint(mut self) -> Self {
        // account for the fingerprint attribute itself:
        // 32 for the CRC and 4 for the attribute header
        self.header.length += 36;

        let checksum = crc32::checksum_ieee(&self.to_bytes());
        let value = checksum ^ FINGERPRINT_COOKIE;

        let attribute = Attribute::Fingerprint(value);
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
