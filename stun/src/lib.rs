use nom::{
    bits::{
        bits,
        complete::{tag as tag_bits, take as take_bits},
    },
    bytes::complete::{tag as tag_bytes, take as take_bytes},
    combinator::{map, map_parser},
    number::complete::be_u16,
    sequence::{preceded, terminated, tuple},
    IResult,
};

const MAGIC_COOKIE: u32 = 0x2112_A442;

#[derive(Debug, PartialEq)]
pub enum Class {
    Error,
    Indication,
    Request,
    Success,
}

#[derive(Debug, PartialEq)]
pub enum Method {
    Binding,
}

#[derive(Debug, PartialEq)]
pub struct Header {
    class: Class,
    method: Method,
    length: u16,
    transaction_id: Vec<u8>,
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
            tag_bits(0b00, 2_usize),
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
        0b00 => Class::Request,
        0b01 => Class::Indication,
        0b10 => Class::Success,
        0b11 => Class::Error,
        _ => unreachable!(),
    };

    let m = (m_11_7 << 6) | (m_6_4 << 3) | m_3_0;
    let method = match m {
        0b0000_0000_0001 => Method::Binding,
        // TODO: return Err here
        _ => unimplemented!(),
    };

    Ok((remainder, (class, method)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header() {
        #[rustfmt::skip]
        let input = vec![
            0x01, 0x01, 0x00, 0x00,
            0x21, 0x12, 0xA4, 0x42,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
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
}
