use std::fmt;

use nom::{
    IResult,
    bytes::complete::tag,
    character::complete::{ digit1, line_ending },
    sequence::delimited,
};

use crate::sdp::Span;

#[derive(Debug, PartialEq)]
pub struct Version(pub u8);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v={}\r\n", self.0)
    }
}

#[test]
fn test_serialize_version() {
    let version = Version(0);
    let expected = "v=0\r\n";
    let actual = version.to_string();
    assert_eq!(expected, actual);
}

pub fn version(input: Span) -> IResult<Span, Version> {
    let (remainder, span) = delimited(
        tag("v="),
        digit1,
        line_ending,
    )(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let version = Version(u8::from_str_radix(span.fragment, 10).unwrap());

    Ok((remainder, version))
}

#[test]
fn test_version() {
    let input = Span::new("v=0\r\n");
    let expected = Version(0);
    let actual = version(input).unwrap().1;
    assert_eq!(expected, actual);
}
