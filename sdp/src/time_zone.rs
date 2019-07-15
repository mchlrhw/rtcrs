use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{digit1, line_ending, one_of},
    combinator::opt,
    multi::many1,
    sequence::{preceded, separated_pair, terminated, tuple},
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct Adjustment {
    pub time: u64,
    pub offset: i64,
}

fn offset(input: Span) -> IResult<Span, i64> {
    let (remainder, (sign, value_span, units)) =
        tuple((opt(one_of("+-")), digit1, opt(one_of("dhms"))))(input)?;

    let offset_string = sign.map_or("".to_owned(), |c| c.to_string()) + value_span.fragment;

    // SAFE: since we've parsed this as +/- digit1, so we don't
    //       need to guard against parse errors in from_str_radix
    let mut offset = i64::from_str_radix(&offset_string, 10).unwrap();

    offset *= match units {
        Some(c) => match c {
            'd' => 86400,
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => unreachable!(),
        },
        None => 1,
    };

    Ok((remainder, offset))
}

fn adjustment(input: Span) -> IResult<Span, Adjustment> {
    let (remainder, (span, offset)) = separated_pair(digit1, tag(" "), offset)(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let time = u64::from_str_radix(span.fragment, 10).unwrap();

    let adjustment = Adjustment { time, offset };

    Ok((remainder, adjustment))
}

#[derive(Debug, PartialEq)]
pub struct TimeZone {
    pub adjustments: Vec<Adjustment>,
}

// z=<adjustment time> <offset> <adjustment time> <offset> ....
// https://tools.ietf.org/html/rfc4566#section-5.11
pub fn time_zone(input: Span) -> IResult<Span, TimeZone> {
    let (remainder, adjustments) = preceded(
        tag("z="),
        many1(terminated(adjustment, alt((tag(" "), line_ending)))),
    )(input)?;

    let time_zone = TimeZone { adjustments };

    Ok((remainder, time_zone))
}

#[test]
fn test_time_zone() {
    let input = Span::new("z=2882844526 -1h 2898848070 0\r\n");
    let expected = TimeZone {
        adjustments: vec![
            Adjustment {
                time: 2882844526,
                offset: -3600,
            },
            Adjustment {
                time: 2898848070,
                offset: 0,
            },
        ],
    };
    let actual = time_zone(input).unwrap().1;
    assert_eq!(expected, actual);
}
