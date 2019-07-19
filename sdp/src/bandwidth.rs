use std::fmt;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_till1},
    character::complete::{digit1, line_ending},
    combinator::map,
    sequence::{delimited, preceded, tuple},
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub enum BandwidthType {
    CT,
    AS,
    Experimental(String),
}

impl fmt::Display for BandwidthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BandwidthType::Experimental(x) => write!(f, "X-{}", x),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Bandwidth {
    pub typ: BandwidthType,
    pub value: u64,
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b={}:{}\r\n", self.typ, self.value)
    }
}

fn bandwidth_type(input: Span) -> IResult<Span, BandwidthType> {
    map(
        preceded(
            tag("b="),
            alt((
                tag("CT"),
                tag("AS"),
                preceded(tag("X-"), take_till1(|c| c == ':')),
            )),
        ),
        |span: Span| match span.fragment {
            "CT" => BandwidthType::CT,
            "AS" => BandwidthType::AS,
            s => BandwidthType::Experimental(s.to_owned()),
        },
    )(input)
}

fn bandwidth_value(input: Span) -> IResult<Span, u64> {
    map(delimited(tag(":"), digit1, line_ending), |s: Span| {
        u64::from_str_radix(s.fragment, 10).unwrap()
    })(input)
}

// b=<bwtype>:<bandwidth>
// https://tools.ietf.org/html/rfc4566#section-5.8
pub fn bandwidth(input: Span) -> IResult<Span, Bandwidth> {
    map(tuple((bandwidth_type, bandwidth_value)), |(typ, value)| {
        Bandwidth { typ, value }
    })(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_bandwidth() {
        let bandwidth = Bandwidth {
            typ: BandwidthType::CT,
            value: 42,
        };
        let expected = "b=CT:42\r\n";
        let actual = bandwidth.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_bandwidth() {
        let input = Span::new("b=X-YZ:128\r\n");
        let expected = Bandwidth {
            typ: BandwidthType::Experimental("YZ".to_owned()),
            value: 128,
        };
        let actual = bandwidth(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
