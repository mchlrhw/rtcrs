use std::fmt;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_till1},
    character::complete::{line_ending, not_line_ending},
    combinator::map,
    sequence::{delimited, pair, preceded},
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub enum Attribute {
    Property(String),
    Value(String, String),
}

impl Attribute {
    pub fn property(p: &str) -> Self {
        Self::Property(p.to_string())
    }

    pub fn value(k: &str, v: &str) -> Self {
        Self::Value(k.to_string(), v.to_owned())
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Property(p) => write!(f, "a={}\r\n", p),
            Self::Value(k, v) => write!(f, "a={}:{}\r\n", k, v),
        }
    }
}

// a=<attribute>
// https://tools.ietf.org/html/rfc4566#section-5.13
fn property_attribute(input: Span) -> IResult<Span, Attribute> {
    map(
        map(not_line_ending, |s: Span| s.fragment().to_string()),
        Attribute::Property,
    )(input)
}

// a=<attribute>:<value>
// https://tools.ietf.org/html/rfc4566#section-5.13
fn value_attribute(input: Span) -> IResult<Span, Attribute> {
    map(
        pair(
            map(
                take_till1(|c: char| c == ':' || c.is_whitespace()),
                |s: Span| s.fragment().to_string(),
            ),
            map(preceded(tag(":"), not_line_ending), |s: Span| {
                s.fragment().to_string()
            }),
        ),
        |(k, v)| Attribute::Value(k, v),
    )(input)
}

pub fn attribute(input: Span) -> IResult<Span, Attribute> {
    delimited(
        tag("a="),
        alt((value_attribute, property_attribute)),
        line_ending,
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_property_attribute() {
        let attribute = Attribute::property("recvonly");
        let expected = "a=recvonly\r\n";
        let actual = attribute.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn display_value_attribute() {
        let attribute = Attribute::value("msid-semantic", " WMS stream");
        let expected = "a=msid-semantic: WMS stream\r\n";
        let actual = attribute.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_value_attribute() {
        let input = Span::new("msid-semantic: WMS stream");
        let expected = Attribute::value("msid-semantic", " WMS stream");
        let actual = value_attribute(input).unwrap().1;
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_property_attribute() {
        let input = Span::new("recvonly");
        let expected = Attribute::property("recvonly");
        let actual = property_attribute(input).unwrap().1;
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_attribute() {
        let input = Span::new("a=msid-semantic: WMS stream\r\n");
        let expected = Attribute::value("msid-semantic", " WMS stream");
        let actual = attribute(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
