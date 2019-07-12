use nom::{
    IResult,
    bytes::complete::{ tag, take_till1 },
    character::complete::{ line_ending, not_line_ending },
    sequence::{ delimited, preceded },
};

use crate::sdp::Span;

#[derive(Debug, PartialEq)]
pub struct Connection {
    pub network_type: String,
    pub address_type: String,
    pub connection_address: String,
}

// c=<nettype> <addrtype> <connection-address>
// https://tools.ietf.org/html/rfc4566#section-5.7
pub fn connection(input: Span) -> IResult<Span, Connection> {
    let (remainder, span) = preceded(
        tag("c="),
        take_till1(|c| c == ' '),
    )(input)?;

    let network_type = span.fragment.to_owned();

    let (remainder, span) = preceded(
        tag(" "),
        take_till1(|c| c == ' '),
    )(remainder)?;

    let address_type = span.fragment.to_owned();

    let (remainder, span) = delimited(
        tag(" "),
        not_line_ending,
        line_ending,
    )(remainder)?;

    let connection_address = span.fragment.to_owned();

    let connection = Connection {
        network_type,
        address_type,
        connection_address,
    };

    Ok((remainder, connection))
}

#[test]
fn test_connection() {
    let input = Span::new("c=IN IP4 127.0.0.1\r\n");
    let expected = Connection {
        network_type: "IN".to_owned(),
        address_type: "IP4".to_owned(),
        connection_address: "127.0.0.1".to_owned(),
    };
    let actual = connection(input).unwrap().1;
    assert_eq!(expected, actual);
}
