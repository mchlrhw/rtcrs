use std::fmt;

use nom::{
    bytes::complete::tag,
    character::complete::{line_ending, not_line_ending},
    sequence::delimited,
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct SessionName(pub String);

impl fmt::Display for SessionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s={}\r\n", self.0)
    }
}

// s=<session name>
// https://tools.ietf.org/html/rfc4566#section-5.3
pub fn session_name(input: Span) -> IResult<Span, SessionName> {
    let (remainder, span) = delimited(tag("s="), not_line_ending, line_ending)(input)?;

    let session_name = SessionName((*span.fragment()).to_string());

    Ok((remainder, session_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_session_name() {
        let session_name = SessionName("-".to_owned());
        let expected = "s=-\r\n";
        let actual = session_name.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_session_name() {
        let input = Span::new("s=-\r\n");
        let expected = SessionName("-".to_owned());
        let actual = session_name(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
