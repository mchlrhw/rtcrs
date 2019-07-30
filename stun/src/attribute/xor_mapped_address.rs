use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr};

use nom::{
    number::complete::be_u16,
    sequence::tuple,
    IResult,
};

use crate::{
    MAGIC_COOKIE,
    attribute::Attribute,
};

#[derive(Debug, PartialEq)]
struct XorMappedAddress {
    address: IpAddr,
    port: u16,
}

impl Attribute for XorMappedAddress {
    fn r#type(&self) -> u16 {
        0x_0020
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

        let x_port_field = (self.port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes();

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
pub(crate) fn xor_mapped_address(input: &[u8]) -> IResult<&[u8], impl Attribute> {
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

    let attribute = XorMappedAddress { address, port };

    Ok((remainder, attribute))
}
