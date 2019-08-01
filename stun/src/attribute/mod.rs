mod comprehension_optional;
pub(crate) mod fingerprint;
pub(crate) mod message_integrity;
mod priority;
mod username;
mod xor_mapped_address;

use std::net::IpAddr;

use nom::{branch::alt, IResult};

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
    alt((
        // Comprehension-required range (0x0000-0x7FFF)
        // 0x0000: (Reserved)
        // TODO: 0x0001: MAPPED-ADDRESS
        // 0x0002: (Reserved; was RESPONSE-ADDRESS)
        // 0x0003: (Reserved; was CHANGE-ADDRESS)
        // 0x0004: (Reserved; was SOURCE-ADDRESS)
        // 0x0005: (Reserved; was CHANGED-ADDRESS)
        // 0x0006: USERNAME
        username,
        // 0x0007: (Reserved; was PASSWORD)
        // 0x0008: MESSAGE-INTEGIRTY
        message_integrity,
        // TODO: 0x0009: ERROR-CODE
        // TODO: 0x000A: UNKNOWN-ATTRIBUTES
        // 0x000B: (Reserved; was REFLECTED-FROM)
        // TODO: 0x0014: REALM
        // TODO: 0x0015: NONCE
        // 0x0020: XOR-MAPPED-ADDRESS
        xor_mapped_address,
        // 0x0024: PRIORITY
        priority,
        // Comprehension-optional range (0x8000-0xFFFF)
        // TODO: 0x8022: SOFTWARE
        // TODO: 0x8023: ALTERNATE-SERVER
        // 0x8028: FINGERPRINT
        fingerprint,
        comprehension_optional,
    ))(input)
}
