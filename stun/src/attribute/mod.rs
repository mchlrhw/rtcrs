mod comprehension_optional;
pub(crate) mod fingerprint;
pub(crate) mod message_integrity;
mod priority;
mod username;
mod xor_mapped_address;

use std::net::IpAddr;

use log::trace;
use nom::{
    combinator::all_consuming, multi::length_data, number::complete::be_u16, sequence::tuple,
    IResult,
};

use crate::attribute::{
    comprehension_optional::{comprehension_optional, ComprehensionOptional},
    fingerprint::{fingerprint, Fingerprint},
    message_integrity::{message_integrity, MessageIntegrity},
    priority::{priority, Priority},
    username::{username, Username},
    xor_mapped_address::{xor_mapped_address, XorMappedAddress},
};

pub trait Tlv {
    fn typ(&self) -> u16;

    fn length(&self) -> u16;

    fn value(&self) -> Vec<u8>;

    fn to_bytes(&self) -> Vec<u8> {
        let value_field = self.value();
        let length_field = self.length().to_be_bytes();
        let type_field = self.typ().to_be_bytes();

        let mut bytes = type_field.to_vec();
        bytes.extend_from_slice(&length_field);
        bytes.extend_from_slice(&value_field);

        bytes
    }
}

#[derive(Debug, PartialEq)]
pub enum Attribute {
    ComprehensionOptional(ComprehensionOptional),
    Fingerprint(Fingerprint),
    MessageIntegrity(MessageIntegrity),
    Priority(Priority),
    Username(Username),
    XorMappedAddress(XorMappedAddress),
}

impl Attribute {
    pub fn username(value: &str) -> Self {
        let inner = Username::new(value);

        Attribute::Username(inner)
    }

    pub fn xor_mapped_address(address: IpAddr, port: u16) -> Self {
        let inner = XorMappedAddress::new(address, port);

        Attribute::XorMappedAddress(inner)
    }
}

impl Tlv for Attribute {
    fn typ(&self) -> u16 {
        match self {
            Attribute::ComprehensionOptional(inner) => inner.typ(),
            Attribute::Fingerprint(inner) => inner.typ(),
            Attribute::MessageIntegrity(inner) => inner.typ(),
            Attribute::Priority(inner) => inner.typ(),
            Attribute::Username(inner) => inner.typ(),
            Attribute::XorMappedAddress(inner) => inner.typ(),
        }
    }

    fn length(&self) -> u16 {
        match self {
            Attribute::ComprehensionOptional(inner) => inner.length(),
            Attribute::Fingerprint(inner) => inner.length(),
            Attribute::MessageIntegrity(inner) => inner.length(),
            Attribute::Priority(inner) => inner.length(),
            Attribute::Username(inner) => inner.length(),
            Attribute::XorMappedAddress(inner) => inner.length(),
        }
    }

    fn value(&self) -> Vec<u8> {
        match self {
            Attribute::ComprehensionOptional(inner) => inner.value(),
            Attribute::Fingerprint(inner) => inner.value(),
            Attribute::MessageIntegrity(inner) => inner.value(),
            Attribute::Priority(inner) => inner.value(),
            Attribute::Username(inner) => inner.value(),
            Attribute::XorMappedAddress(inner) => inner.value(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Attribute::ComprehensionOptional(inner) => inner.to_bytes(),
            Attribute::Fingerprint(inner) => inner.to_bytes(),
            Attribute::MessageIntegrity(inner) => inner.to_bytes(),
            Attribute::Priority(inner) => inner.to_bytes(),
            Attribute::Username(inner) => inner.to_bytes(),
            Attribute::XorMappedAddress(inner) => inner.to_bytes(),
        }
    }
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
pub(crate) fn attribute(input: &[u8]) -> IResult<&[u8], Attribute> {
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
