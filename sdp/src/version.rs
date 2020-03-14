use std::fmt;

use nom::{
    bytes::complete::tag,
    character::complete::{digit1, line_ending},
    sequence::delimited,
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct Version(pub u8);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v={}\r\n", self.0)
    }
}

// v=0
// https://tools.ietf.org/html/rfc4566#section-5.1
pub fn version(input: Span) -> IResult<Span, Version> {
    let (remainder, span) = delimited(tag("v="), digit1, line_ending)(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let version = Version(u8::from_str_radix(span.fragment(), 10).unwrap());

    Ok((remainder, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_version() {
        let version = Version(0);
        let expected = "v=0\r\n";
        let actual = version.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_version() {
        let input = Span::new("v=0\r\n");
        let expected = Version(0);
        let actual = version(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
