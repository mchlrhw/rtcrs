use std::fmt;

use nom::{
    bytes::complete::{tag, take_till1},
    character::complete::{digit1, line_ending, not_line_ending},
    sequence::{delimited, preceded},
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct Origin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub network_type: String,
    pub address_type: String,
    pub unicast_address: String,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "o={} {} {} {} {} {}\r\n",
            self.username,
            self.session_id,
            self.session_version,
            self.network_type,
            self.address_type,
            self.unicast_address,
        )
    }
}

// o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
// https://tools.ietf.org/html/rfc4566#section-5.2
pub fn origin(input: Span) -> IResult<Span, Origin> {
    let (remainder, span) = preceded(tag("o="), take_till1(|c| c == ' '))(input)?;

    let username = span.fragment.to_owned();

    let (remainder, span) = preceded(tag(" "), digit1)(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let session_id = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = preceded(tag(" "), digit1)(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let session_version = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = preceded(tag(" "), take_till1(|c| c == ' '))(remainder)?;

    let network_type = span.fragment.to_owned();

    let (remainder, span) = preceded(tag(" "), take_till1(|c| c == ' '))(remainder)?;

    let address_type = span.fragment.to_owned();

    let (remainder, span) = delimited(tag(" "), not_line_ending, line_ending)(remainder)?;

    let unicast_address = span.fragment.to_owned();

    let origin = Origin {
        username,
        session_id,
        session_version,
        network_type,
        address_type,
        unicast_address,
    };

    Ok((remainder, origin))
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;

    #[test]
    fn display_origin() {
        let origin = Origin {
            username: "-".to_owned(),
            session_id: 1433832402044130222,
            session_version: 3,
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            unicast_address: "127.0.0.1".to_owned(),
        };
        let expected = "o=- 1433832402044130222 3 IN IP4 127.0.0.1\r\n";
        let actual = origin.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_origin() {
        let input = Span::new("o=- 1433832402044130222 3 IN IP4 127.0.0.1\r\n");
        let expected = Origin {
            username: "-".to_owned(),
            session_id: 1433832402044130222,
            session_version: 3,
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            unicast_address: "127.0.0.1".to_owned(),
        };
        let actual = origin(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
