use nom::{
    bytes::complete::tag,
    character::complete::{line_ending, not_line_ending},
    sequence::delimited,
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct PhoneNumber(pub String);

// p=<phone-number>
// https://tools.ietf.org/html/rfc4566#section-5.6
pub fn phone_number(input: Span) -> IResult<Span, PhoneNumber> {
    let (remainder, span) = delimited(tag("p="), not_line_ending, line_ending)(input)?;

    let phone_number = PhoneNumber(span.fragment.to_owned());

    Ok((remainder, phone_number))
}

#[test]
fn test_phone_number() {
    let input = Span::new("p=+1 617 555-6011\r\n");
    let expected = PhoneNumber("+1 617 555-6011".to_owned());
    let actual = phone_number(input).unwrap().1;
    assert_eq!(expected, actual);
}
