use std::fmt;

use nom::{
    bytes::complete::tag,
    character::complete::{line_ending, not_line_ending},
    sequence::delimited,
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct SessionInformation(pub String);

impl fmt::Display for SessionInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "i={}\r\n", self.0)
    }
}

// i=<session description>
// https://tools.ietf.org/html/rfc4566#section-5.4
pub fn session_information(input: Span) -> IResult<Span, SessionInformation> {
    let (remainder, span) = delimited(tag("i="), not_line_ending, line_ending)(input)?;

    let session_information = SessionInformation(span.fragment.to_owned());

    Ok((remainder, session_information))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_session_information() {
        let session_information =
            SessionInformation("A Seminar on the session description protocol".to_owned());
        let expected = "i=A Seminar on the session description protocol\r\n";
        let actual = session_information.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_session_information() {
        let input = Span::new("i=A Seminar on the session description protocol\r\n");
        let expected =
            SessionInformation("A Seminar on the session description protocol".to_owned());
        let actual = session_information(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
