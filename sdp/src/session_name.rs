use std::borrow::Cow;
use std::fmt;

use nom::{
    bytes::complete::tag,
    character::complete::{line_ending, not_line_ending},
    sequence::delimited,
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct SessionName<'a> {
    name: Cow<'a, str>,
}

impl<'a> SessionName<'a> {
    pub fn new<S>(raw: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        Self { name: raw.into() }
    }
}

impl fmt::Display for SessionName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s={}\r\n", self.name)
    }
}

// s=<session name>
// https://tools.ietf.org/html/rfc4566#section-5.3
pub fn session_name(input: Span) -> IResult<Span, SessionName> {
    let (remainder, span) = delimited(tag("s="), not_line_ending, line_ending)(input)?;

    let session_name = SessionName::new(*span.fragment());

    Ok((remainder, session_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_session_name() {
        let session_name = SessionName::new("-");
        let expected = "s=-\r\n";
        let actual = session_name.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_session_name() {
        let input = Span::new("s=-\r\n");
        let expected = SessionName::new("-");
        let actual = session_name(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
