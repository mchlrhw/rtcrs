mod comprehension_optional;
mod error_code;
pub(crate) mod fingerprint;
pub(crate) mod message_integrity;
mod priority;
mod username;
mod xor_mapped_address;

use std::net::IpAddr;

use nom::{combinator::peek, number::complete::be_u16, IResult};
use simplified_enum::simplified;

use crate::{
    attribute::{
        comprehension_optional::{comprehension_optional, ComprehensionOptional},
        error_code::{error_code, ErrorCode},
        fingerprint::{fingerprint, Fingerprint},
        message_integrity::{message_integrity, MessageIntegrity},
        priority::{priority, Priority},
        username::{username, Username},
        xor_mapped_address::{xor_mapped_address, XorMappedAddress},
    },
    Error,
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

#[simplified]
#[impl_enum::with_methods {
    fn typ(&self) -> u16 {}
    fn length(&self) -> u16 {}
    fn value(&self) -> Vec<u8> {}
    pub fn to_bytes(&self) -> Vec<u8> {}
}]
#[derive(Debug, PartialEq)]
pub enum Attribute {
    ComprehensionOptional,
    ErrorCode,
    Fingerprint,
    MessageIntegrity,
    Priority,
    Username,
    XorMappedAddress,
}

impl Attribute {
    pub fn username(value: &str) -> Self {
        let inner = Username::new(value);

        Self::Username(inner)
    }

    pub fn xor_mapped_address(address: IpAddr, port: u16) -> Self {
        let inner = XorMappedAddress::new(address, port);

        Self::XorMappedAddress(inner)
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
// https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml
pub(crate) fn attribute(input: &[u8]) -> IResult<&[u8], Attribute, crate::ParseError<&[u8]>> {
    let (input, attribute_type) = peek(be_u16)(input)?;
    let parser = match attribute_type {
        // Attribute Registry
        // https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml
        //
        // Comprehension-required range (0x0000-0x7FFF)
        // 0x0000: (Reserved)
        // 0x0001: MAPPED-ADDRESS
        // 0x0002: (Reserved; was RESPONSE-ADDRESS)
        // 0x0003: (Reserved; was CHANGE-ADDRESS)
        // 0x0004: (Reserved; was SOURCE-ADDRESS)
        // 0x0005: (Reserved; was CHANGED-ADDRESS)
        0x_0006 => username,
        // 0x0007: (Reserved; was PASSWORD)
        0x_0008 => message_integrity,
        0x_0009 => error_code,
        // 0x000A: UNKNOWN-ATTRIBUTES
        // 0x000B: (Reserved; was REFLECTED-FROM)
        // 0x000C: CHANNEL-NUMBER
        // 0x000D: LIFETIME
        // 0x000E-0x000F: (Reserved)
        // 0x0010: (Reserved; was BANDWIDTH)
        // 0x0011: (Reserved)
        // 0x0012: XOR-PEER-ADDRESS
        // 0x0013: DATA
        // 0x0014: REALM
        // 0x0015: NONCE
        // 0x0016: XOR-RELAYED-ADDRESS
        // 0x0017: REQUESTED-ADDRESS-FAMILY
        // 0x0018: EVEN-PORT
        // 0x0019: REQUESTED-TRANSPORT
        // 0x001A: DONT-FRAGMENT
        // 0x001B: ACCESS-TOKEN
        // 0x001C: MESSAGE-INTEGRITY-SHA256
        // 0x001D: PASSWORD-ALGORITHM
        // 0x001E: USERHASH
        // 0x001F: (Unassigned)
        0x_0020 => xor_mapped_address,
        // 0x0021: (Reserved; was TIMER-VAL)
        // 0x0022: RESERVATION-TOKEN
        // 0x0023: (Reserved)
        0x_0024 => priority,
        // 0x0025: USE-CANDIDATE
        // 0x0026: PADDING
        // 0x0027: RESPONSE-PORT
        // 0x0028-0x0029: (Reserved)
        // 0x002A: CONNECTION-ID
        // 0x002B-0x002F: (Unassigned)
        // 0x0030: (Reserved)
        // 0x0031-0x7FFF: (Unassigned)
        //
        // Comprehension-optional range (0x8000-0xFFFF)
        // 0x8000: ADDITIONAL-ADDRESS-FAMILY
        // 0x8001: ADDRESS-ERROR-CODE
        // 0x8002: PASSWORD-ALGORITHMS
        // 0x8003: ALTERNATE-DOMAIN
        // 0x8004: ICMP
        // 0x8005-0x8021: (Unassigned)
        // 0x8022: SOFTWARE
        // 0x8023: ALTERNATE-SERVER
        // 0x8024: (Reserved)
        // 0x8025: TRANSACTION_TRANSMIT_COUNTER
        // 0x8026: (Reserved)
        // 0x8027: CACHE-TIMEOUT
        0x_8028 => fingerprint,
        // 0x8029: ICE-CONTROLLED
        // 0x802A: ICE-CONTROLLING
        // 0x802B: RESPONSE-ORIGIN
        // 0x802C: OTHER-ADDRESS
        // 0x802D: ECN-CHECK STUN
        // 0x802E: THIRD-PARTY-AUTHORIZATION
        // 0x802F: (Unassigned)
        // 0x8030: MOBILITY-TICKET
        // 0x8031-0xBFFF: (Unassigned)
        // 0xC000: CISCO-STUN-FLOWDATA
        // 0xC001: ENF-FLOW-DESCRIPTION
        // 0xC002: ENF-NETWORK-STATUS
        // 0xC003-0xC058: (Unassigned)
        // 0xC059: GOOG-MISC-INFO
        // 0xC05A: GOOG-MESSAGE-INTEGRITY-32
        // 0xC05B-0xFFFF: (Unassigned)
        typ if typ >= 0x_8000 => comprehension_optional,

        _ => {
            return Err(nom::Err::Error(
                Error::UnimplementedAttribute(attribute_type).into(),
            ))
        }
    };

    parser(input)
}
