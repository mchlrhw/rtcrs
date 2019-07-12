use nom::{
    bytes::complete::tag,
    character::complete::{line_ending, not_line_ending},
    sequence::delimited,
    IResult,
};

use crate::sdp::Span;

#[derive(Debug, PartialEq)]
pub struct EmailAddress(pub String);

// e=<email-address>
// https://tools.ietf.org/html/rfc4566#section-5.6
pub fn email_address(input: Span) -> IResult<Span, EmailAddress> {
    let (remainder, span) = delimited(tag("e="), not_line_ending, line_ending)(input)?;

    let email_address = EmailAddress(span.fragment.to_owned());

    Ok((remainder, email_address))
}

#[test]
fn test_email_address() {
    let input = Span::new("e=j.doe@example.com (Jane Doe)\r\n");
    let expected = EmailAddress("j.doe@example.com (Jane Doe)".to_owned());
    let actual = email_address(input).unwrap().1;
    assert_eq!(expected, actual);
}
