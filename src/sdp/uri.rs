use nom::{
    bytes::complete::tag,
    character::complete::{line_ending, not_line_ending},
    sequence::delimited,
    IResult,
};

use crate::sdp::Span;

#[derive(Debug, PartialEq)]
pub struct URI(pub String);

// u=<uri>
// https://tools.ietf.org/html/rfc4566#section-5.5
pub fn uri(input: Span) -> IResult<Span, URI> {
    // TODO: parse this against https://tools.ietf.org/html/rfc3986
    let (remainder, span) = delimited(tag("u="), not_line_ending, line_ending)(input)?;

    let uri = URI(span.fragment.to_owned());

    Ok((remainder, uri))
}

#[test]
fn test_uri() {
    let input = Span::new("u=http://www.example.com/seminars/sdp.pdf\r\n");
    let expected = URI("http://www.example.com/seminars/sdp.pdf".to_owned());
    let actual = uri(input).unwrap().1;
    assert_eq!(expected, actual);
}
