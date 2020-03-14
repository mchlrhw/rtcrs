use std::fmt;

use nom::{
    bytes::complete::tag,
    character::complete::{line_ending, not_line_ending},
    combinator::map,
    sequence::delimited,
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct EmailAddress(pub String);

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "e={}\r\n", self.0)
    }
}

// e=<email-address>
// https://tools.ietf.org/html/rfc4566#section-5.6
pub fn email_address(input: Span) -> IResult<Span, EmailAddress> {
    map(
        map(
            delimited(tag("e="), not_line_ending, line_ending),
            |s: Span| (*s.fragment()).to_string(),
        ),
        EmailAddress,
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_email_address() {
        let email_address = EmailAddress("j.doe@example.com (Jane Doe)".to_string());
        let expected = "e=j.doe@example.com (Jane Doe)\r\n";
        let actual = email_address.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_email_address() {
        let input = Span::new("e=j.doe@example.com (Jane Doe)\r\n");
        let expected = EmailAddress("j.doe@example.com (Jane Doe)".to_string());
        let actual = email_address(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
