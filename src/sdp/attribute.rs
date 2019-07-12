use nom::{
    branch::alt,
    bytes::complete::{tag, take_till1},
    character::complete::{line_ending, not_line_ending},
    sequence::{delimited, pair, preceded},
    IResult,
};

use crate::sdp::Span;

#[derive(Debug, PartialEq)]
pub enum Attribute {
    Property(String),
    Value(String, String),
}

// a=<attribute>
// https://tools.ietf.org/html/rfc4566#section-5.13
fn property_attribute(input: Span) -> IResult<Span, Attribute> {
    let (remainder, span) = not_line_ending(input)?;

    let attribute = Attribute::Property(span.fragment.to_owned());

    Ok((remainder, attribute))
}

#[test]
fn test_property_attribute() {
    let input = Span::new("recvonly");
    let expected = Attribute::Property("recvonly".to_owned());
    let actual = property_attribute(input).unwrap().1;
    assert_eq!(expected, actual);
}

// a=<attribute>:<value>
// https://tools.ietf.org/html/rfc4566#section-5.13
fn value_attribute(input: Span) -> IResult<Span, Attribute> {
    let (remainder, (property_span, value_span)) = pair(
        take_till1(|c: char| c == ':' || c.is_whitespace()),
        preceded(tag(":"), not_line_ending),
    )(input)?;

    let attribute = Attribute::Value(
        property_span.fragment.to_owned(),
        value_span.fragment.to_owned(),
    );

    Ok((remainder, attribute))
}

#[test]
fn test_value_attribute() {
    let input = Span::new("msid-semantic: WMS stream");
    let expected = Attribute::Value("msid-semantic".to_owned(), " WMS stream".to_owned());
    let actual = value_attribute(input).unwrap().1;
    assert_eq!(expected, actual);
}

pub fn attribute(input: Span) -> IResult<Span, Attribute> {
    delimited(
        tag("a="),
        alt((value_attribute, property_attribute)),
        line_ending,
    )(input)
}

#[test]
fn test_attribute() {
    let input = Span::new("a=msid-semantic: WMS stream\r\n");
    let expected = Attribute::Value("msid-semantic".to_owned(), " WMS stream".to_owned());
    let actual = attribute(input).unwrap().1;
    assert_eq!(expected, actual);
}
