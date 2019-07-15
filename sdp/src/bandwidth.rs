use nom::{
    branch::alt,
    bytes::complete::{tag, take_till1},
    character::complete::{digit1, line_ending},
    sequence::{delimited, preceded},
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub enum BandwidthType {
    CT,
    AS,
    Experimental(String),
}

#[derive(Debug, PartialEq)]
pub struct Bandwidth {
    pub typ: BandwidthType,
    pub value: u64,
}

// b=<bwtype>:<bandwidth>
// https://tools.ietf.org/html/rfc4566#section-5.8
pub fn bandwidth(input: Span) -> IResult<Span, Bandwidth> {
    let (remainder, span) = preceded(
        tag("b="),
        alt((
            tag("CT"),
            tag("AS"),
            preceded(tag("X-"), take_till1(|c| c == ':')),
        )),
    )(input)?;

    let typ = match span.fragment {
        "CT" => BandwidthType::CT,
        "AS" => BandwidthType::AS,
        s => BandwidthType::Experimental(s.to_owned()),
    };

    let (remainder, span) = delimited(tag(":"), digit1, line_ending)(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let value = u64::from_str_radix(span.fragment, 10).unwrap();

    let bandwidth = Bandwidth { typ, value };

    Ok((remainder, bandwidth))
}

#[test]
fn test_bandwidth() {
    let input = Span::new("b=X-YZ:128\r\n");
    let expected = Bandwidth {
        typ: BandwidthType::Experimental("YZ".to_owned()),
        value: 128,
    };
    let actual = bandwidth(input).unwrap().1;
    assert_eq!(expected, actual);
}
