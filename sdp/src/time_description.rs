use nom::{
    bytes::complete::tag,
    character::complete::{digit1, line_ending},
    combinator::map,
    multi::{many0, many1},
    sequence::{delimited, preceded, terminated, tuple},
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct Timing {
    pub start_time: u64,
    pub stop_time: u64,
}

// t=<start-time> <stop-time>
// https://tools.ietf.org/html/rfc4566#section-5.9
pub fn timing(input: Span) -> IResult<Span, Timing> {
    let (remainder, span) = preceded(tag("t="), digit1)(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let start_time = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = delimited(tag(" "), digit1, line_ending)(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let stop_time = u64::from_str_radix(span.fragment, 10).unwrap();

    let timing = Timing {
        start_time,
        stop_time,
    };

    Ok((remainder, timing))
}

#[test]
fn test_timing() {
    let input = Span::new("t=0 0\r\n");
    let expected = Timing {
        start_time: 0,
        stop_time: 0,
    };
    let actual = timing(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[derive(Debug, PartialEq)]
pub struct Repeat {
    pub interval: u64,
    pub active_duration: u64,
    pub offsets: Vec<u64>,
}

fn offset(input: Span) -> IResult<Span, u64> {
    let (remainder, span) = preceded(tag(" "), digit1)(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let offset = u64::from_str_radix(span.fragment, 10).unwrap();

    Ok((remainder, offset))
}

// r=<repeat interval> <active duration> <offsets from start-time>
// https://tools.ietf.org/html/rfc4566#section-5.10
pub fn repeat(input: Span) -> IResult<Span, Repeat> {
    let (remainder, span) = preceded(tag("r="), digit1)(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let interval = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = preceded(tag(" "), digit1)(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let active_duration = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, offsets) = terminated(many1(offset), line_ending)(remainder)?;

    let repeat = Repeat {
        interval,
        active_duration,
        offsets,
    };

    Ok((remainder, repeat))
}

#[test]
#[allow(clippy::unreadable_literal)]
fn test_repeat() {
    let input = Span::new("r=604800 3600 0 90000\r\n");
    let expected = Repeat {
        interval: 604800,
        active_duration: 3600,
        offsets: vec![0, 90000],
    };
    let actual = repeat(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[derive(Debug, PartialEq)]
pub struct TimeDescription {
    pub timing: Timing,
    pub repeat_times: Vec<Repeat>,
}

impl TimeDescription {
    fn from_tuple(args: (Timing, Vec<Repeat>)) -> Self {
        Self {
            timing: args.0,
            repeat_times: args.1,
        }
    }
}

// t=  (time the session is active)
// r=* (zero or more repeat times)
// https://tools.ietf.org/html/rfc4566#section-5
pub fn time_description(input: Span) -> IResult<Span, TimeDescription> {
    map(tuple((timing, many0(repeat))), TimeDescription::from_tuple)(input)
}

#[test]
#[allow(clippy::unreadable_literal)]
fn test_time_description() {
    let input = Span::new("t=3034423619 3042462419\r\n");
    let expected = TimeDescription {
        timing: Timing {
            start_time: 3034423619,
            stop_time: 3042462419,
        },
        repeat_times: vec![],
    };
    let actual = time_description(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[test]
#[allow(clippy::unreadable_literal)]
fn test_time_description_with_repeat_times() {
    let input = Span::new("t=3034423619 3042462419\r\nr=604800 3600 0 90000\r\n");
    let expected = TimeDescription {
        timing: Timing {
            start_time: 3034423619,
            stop_time: 3042462419,
        },
        repeat_times: vec![Repeat {
            interval: 604800,
            active_duration: 3600,
            offsets: vec![0, 90000],
        }],
    };
    let actual = time_description(input).unwrap().1;
    assert_eq!(expected, actual);
}
