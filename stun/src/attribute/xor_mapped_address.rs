use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr};

use nom::{
    bytes::complete::tag,
    multi::length_data,
    number::complete::be_u16,
    sequence::{preceded, tuple},
    IResult,
};

use crate::{
    attribute::{Attribute, Tlv},
    MAGIC_COOKIE,
};

const TYPE: u16 = 0x_0020;

#[derive(Debug, PartialEq)]
pub struct XorMappedAddress {
    address: IpAddr,
    port: u16,
}

impl XorMappedAddress {
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self { address, port }
    }
}

impl Tlv for XorMappedAddress {
    fn typ(&self) -> u16 {
        TYPE
    }

    fn length(&self) -> u16 {
        self.value().len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        let (family_field, x_address_field) = match self.address {
            IpAddr::V4(addr) => {
                let family_code: u16 = 0x_01;
                let family_field = family_code.to_be_bytes();

                let addr = u32::from_be_bytes(addr.octets());
                let x_address_field = (addr ^ MAGIC_COOKIE).to_be_bytes();

                (family_field, x_address_field)
            }
            _ => unimplemented!(),
        };

        let magic_cookie_upper_16: u16 = (MAGIC_COOKIE >> 16).try_into().unwrap();
        let x_port_field = (self.port ^ magic_cookie_upper_16).to_be_bytes();

        let mut value_field = family_field.to_vec();
        value_field.extend_from_slice(&x_port_field);
        value_field.extend_from_slice(&x_address_field);

        value_field
    }
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
pub(crate) fn xor_mapped_address(
    input: &[u8],
) -> IResult<&[u8], Attribute, crate::ParseError<&[u8]>> {
    let (remainder, value_field) = preceded(tag(TYPE.to_be_bytes()), length_data(be_u16))(input)?;
    let (x_address_field, (mut family_field, x_port_field)) = tuple((be_u16, be_u16))(value_field)?;

    let magic_cookie_upper_16: u16 = (MAGIC_COOKIE >> 16).try_into().unwrap();
    let port = x_port_field ^ magic_cookie_upper_16;

    family_field &= 0b_0000_0000_1111_1111;
    let address = match family_field {
        0x_01 => {
            // TODO: assert that remainder is &[]
            let (x_address_field, _remainder) = x_address_field.split_at(4);
            // TODO: convert std::array::TryFromSliceError to nom::internal::Err
            let x_address_field: [u8; 4] = x_address_field.try_into().unwrap();
            let address_bytes = u32::from_be_bytes(x_address_field) ^ MAGIC_COOKIE;

            IpAddr::V4(Ipv4Addr::from(address_bytes))
        }
        // TODO: implement v6 addresses
        0x_02 => unimplemented!(),
        // TODO: return Err here
        _ => unimplemented!(),
    };

    let inner = XorMappedAddress { address, port };
    let attribute = Attribute::XorMappedAddress(inner);

    Ok((remainder, attribute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bytes() {
        #[rustfmt::skip]
        let input = [
            0x_00, 0x_20, 0x_00, 0x_08,
            0x_00, 0x_01, 0x_BE, 0x_EF,
            0x_C0, 0x_01, 0x_D0, 0x_0D,
        ];

        let (_, attribute) = xor_mapped_address(&input).unwrap();
        let attribute_bytes = attribute.to_bytes();

        assert_eq!(attribute_bytes, input);
    }
}
