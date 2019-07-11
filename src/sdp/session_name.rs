use nom::{
    IResult,
    bytes::complete::tag,
    character::complete::{ line_ending, not_line_ending },
    sequence::delimited,
};

use crate::sdp::Span;

#[derive(Debug, PartialEq)]
pub struct SessionName(pub String);

pub fn session_name(input: Span) -> IResult<Span, SessionName> {
    let (remainder, span) = delimited(
        tag("s="),
        not_line_ending,
        line_ending,
    )(input)?;

    let session_name = SessionName(span.fragment.to_owned());

    Ok((remainder, session_name))
}

#[test]
fn test_session_name() {
    let input = Span::new("s=-\r\n");
    let expected = SessionName("-".to_owned());
    let actual = session_name(input).unwrap().1;
    assert_eq!(expected, actual);
}
