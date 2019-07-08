use nom::{
    IResult,
    bytes::complete::{
        tag,
        take_till1,
    },
    combinator::all_consuming,
    character::complete::{
        digit1,
        line_ending,
    },
    sequence::{
        delimited,
        preceded,
        terminated,
    },
};
use nom_locate::LocatedSpan;

type Span<'a> = LocatedSpan<&'a str>;

type Version = u8;

fn version(input: Span) -> IResult<Span, Version> {
    let (remainder, span) = preceded(
        tag("v="),
        digit1,
    )(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let version = u8::from_str_radix(span.fragment, 10).unwrap();

    Ok((remainder, version))
}

#[cfg(test)]
#[test]
fn test_version() {
    let input = Span::new("v=0");
    let expected = 0;
    let actual = version(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[derive(Debug, PartialEq)]
struct Origin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub network_type: String,
    pub address_type: String,
    pub unicast_address: String,
}

fn origin(input: Span) -> IResult<Span, Origin> {
    let (remainder, span) = delimited(
        tag("o="),
        take_till1(|c| c == ' '),
        tag(" "),
    )(input)?;

    let username = span.fragment.to_owned();

    let (remainder, span) = terminated(
        digit1,
        tag(" ")
    )(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let session_id = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = terminated(
        digit1,
        tag(" ")
    )(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let session_version = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = terminated(
        take_till1(|c| c == ' '),
        tag(" ")
    )(remainder)?;

    let network_type = span.fragment.to_owned();

    let (remainder, span) = terminated(
        take_till1(|c| c == ' '),
        tag(" ")
    )(remainder)?;

    let address_type = span.fragment.to_owned();

    let (remainder, span) = take_till1(|c: char| c.is_whitespace())(remainder)?;

    let unicast_address = span.fragment.to_owned();

    let origin = Origin {
        username,
        session_id,
        session_version,
        network_type,
        address_type,
        unicast_address,
    };

    Ok((remainder, origin))
}

#[cfg(test)]
#[test]
fn test_origin() {
    let input = Span::new("o=- 1433832402044130222 3 IN IP4 127.0.0.1");
    let expected = Origin {
        username: "-".to_owned(),
        session_id: 1433832402044130222,
        session_version: 3,
        network_type: "IN".to_owned(),
        address_type: "IP4".to_owned(),
        unicast_address: "127.0.0.1".to_owned(),
    };
    let actual = origin(input).unwrap().1;
    assert_eq!(expected, actual);
}

type SessionName = String;

fn session_name(input: Span) -> IResult<Span, SessionName> {
    let (remainder, span) = preceded(
        tag("s="),
        take_till1(|c: char| c.is_whitespace()),
    )(input)?;

    let session_name = span.fragment.to_owned();

    Ok((remainder, session_name))
}

#[cfg(test)]
#[test]
fn test_session_name() {
    let input = Span::new("s=-");
    let expected = "-".to_owned();
    let actual = session_name(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[derive(Debug, PartialEq)]
struct Timing {
    pub start_time: u64,
    pub stop_time: u64,
}

fn timing(input: Span) -> IResult<Span, Timing> {
    let (remainder, span) = preceded(
        tag("t="),
        digit1,
    )(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let start_time = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = preceded(
        tag(" "),
        digit1,
    )(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let stop_time = u64::from_str_radix(span.fragment, 10).unwrap();

    let timing = Timing {
        start_time,
        stop_time,
    };

    Ok((remainder, timing))
}

#[cfg(test)]
#[test]
fn test_timing() {
    let input = Span::new("t=0 0");
    let expected = Timing {
        start_time: 0,
        stop_time: 0,
    };
    let actual = timing(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[derive(Debug, PartialEq)]
struct SessionDescription {
    // v=0
    // https://tools.ietf.org/html/rfc4566#section-5.1
    pub version: Version,

    // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
    // https://tools.ietf.org/html/rfc4566#section-5.2
    pub origin: Origin,

    // s=<session name>
    // https://tools.ietf.org/html/rfc4566#section-5.3
    pub session_name: SessionName,

    // i=<session description>
    // https://tools.ietf.org/html/rfc4566#section-5.4

    // u=<uri>
    // https://tools.ietf.org/html/rfc4566#section-5.5

    // e=<email-address>
    // https://tools.ietf.org/html/rfc4566#section-5.6

    // p=<phone-number>
    // https://tools.ietf.org/html/rfc4566#section-5.6

    // c=<nettype> <addrtype> <connection-address>
    // https://tools.ietf.org/html/rfc4566#section-5.7

    // b=<bwtype>:<bandwidth>
    // https://tools.ietf.org/html/rfc4566#section-5.8

    // t=<start-time> <stop-time>
    // https://tools.ietf.org/html/rfc4566#section-5.9
    // TODO: implement this as TimeDescription
    pub timing: Timing,

    // r=<repeat interval> <active duration> <offsets from start-time>
    // https://tools.ietf.org/html/rfc4566#section-5.10

    // z=<adjustment time> <offset> <adjustment time> <offset> ...
    // https://tools.ietf.org/html/rfc4566#section-5.11

    // k=<method>
    // k=<method>:<encryption key>
    // https://tools.ietf.org/html/rfc4566#section-5.12

    // a=<attribute>
    // a=<attribute>:<value>
    // https://tools.ietf.org/html/rfc4566#section-5.13

    // m=<media> <port> <proto> <fmt> ...
    // https://tools.ietf.org/html/rfc4566#section-5.14
}

fn session_description(input: Span) -> IResult<Span, SessionDescription> {
    let (remainder, version) = terminated(version, line_ending)(input)?;
    let (remainder, origin) = terminated(origin, line_ending)(remainder)?;
    let (remainder, session_name) = terminated(session_name, line_ending)(remainder)?;
    let (remainder, timing) = terminated(timing, line_ending)(remainder)?;

    let session_description = SessionDescription {
        version,
        origin,
        session_name,
        timing,
    };

    Ok((remainder, session_description))
}

impl SessionDescription {
    pub fn from_str(sdp: &str) -> SessionDescription {
        let input = Span::new(sdp);
        // TODO: change signature to return Result and don't unwrap here
        let (_, session_description) = all_consuming(session_description)(input).unwrap();

        session_description
    }
}

#[cfg(test)]
#[test]
fn test_from_str() {
    let sdp = r#"v=0
o=- 1433832402044130222 3 IN IP4 127.0.0.1
s=-
t=0 0
"#;
    let expected = SessionDescription {
        version: 0,
        origin: Origin {
            username: "-".to_owned(),
            session_id: 1433832402044130222,
            session_version: 3,
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            unicast_address: "127.0.0.1".to_owned(),
        },
        session_name: "-".to_owned(),
        timing: Timing {
            start_time: 0,
            stop_time: 0,
        },
    };
    let actual = SessionDescription::from_str(sdp);
    assert_eq!(expected, actual);
}

