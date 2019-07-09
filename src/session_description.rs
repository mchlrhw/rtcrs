use nom::{
    IResult,
    branch::alt,
    bytes::complete::{
        tag,
        take_till1,
    },
    combinator::{
        all_consuming,
        opt,
    },
    character::complete::{
        digit1,
        line_ending,
        not_line_ending,
    },
    multi::{
        many0,
        many1,
    },
    sequence::{
        delimited,
        pair,
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

#[test]
fn test_session_name() {
    let input = Span::new("s=-");
    let expected = "-".to_owned();
    let actual = session_name(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[derive(Debug, PartialEq)]
struct Connection {
    pub network_type: String,
    pub address_type: String,
    pub connection_address: String,
}

fn connection(input: Span) -> IResult<Span, Connection> {
    let (remainder, span) = preceded(
        tag("c="),
        take_till1(|c: char| c.is_whitespace()),
    )(input)?;

    let network_type = span.fragment.to_owned();

    let (remainder, span) = preceded(
        tag(" "),
        take_till1(|c: char| c.is_whitespace()),
    )(remainder)?;

    let address_type = span.fragment.to_owned();

    let (remainder, span) = preceded(
        tag(" "),
        take_till1(|c: char| c.is_whitespace()),
    )(remainder)?;

    let connection_address = span.fragment.to_owned();

    let connection = Connection {
        network_type,
        address_type,
        connection_address,
    };

    Ok((remainder, connection))
}

#[test]
fn test_connection() {
    let input = Span::new("c=IN IP4 127.0.0.1");
    let expected = Connection {
        network_type: "IN".to_owned(),
        address_type: "IP4".to_owned(),
        connection_address: "127.0.0.1".to_owned(),
    };
    let actual = connection(input).unwrap().1;
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
struct Repeat {
    pub interval: u64,
    pub active_duration: u64,
    pub offsets: Vec<u64>,
}

fn offset(input: Span) -> IResult<Span, u64> {
    let (remainder, span) = preceded(
        tag(" "),
        digit1,
    )(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let offset = u64::from_str_radix(span.fragment, 10).unwrap();

    Ok((remainder, offset))
}

fn repeat(input: Span) -> IResult<Span, Repeat> {
    let (remainder, span) = preceded(
        tag("r="),
        digit1,
    )(input)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let interval = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = preceded(
        tag(" "),
        digit1,
    )(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let active_duration = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, offsets) = many1(offset)(remainder)?;

    let repeat = Repeat {
        interval,
        active_duration,
        offsets,
    };

    Ok((remainder, repeat))
}

#[test]
fn test_repeat() {
    let input = Span::new("r=604800 3600 0 90000");
    let expected = Repeat {
        interval: 604800,
        active_duration: 3600,
        offsets: vec![0, 90000],
    };
    let actual = repeat(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[derive(Debug, PartialEq)]
struct TimeDescription {
    pub timing: Timing,
    pub repeat_times: Vec<Repeat>,
}

fn time_description(input: Span) -> IResult<Span, TimeDescription> {
    let (remainder, timing) = timing(input)?;
    let (remainder, repeat_times) = many0(preceded(line_ending, repeat))(remainder)?;

    let time_description = TimeDescription {
        timing,
        repeat_times,
    };

    Ok((remainder, time_description))
}

#[test]
fn test_time_description() {
    let input = Span::new(r#"t=3034423619 3042462419"#);
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
fn test_time_description_with_repeat_times() {
    let input = Span::new(r#"t=3034423619 3042462419
r=604800 3600 0 90000"#);
    let expected = TimeDescription {
        timing: Timing {
            start_time: 3034423619,
            stop_time: 3042462419,
        },
        repeat_times: vec![
            Repeat {
                interval: 604800,
                active_duration: 3600,
                offsets: vec![0, 90000],
            },
        ],
    };
    let actual = time_description(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[derive(Debug, PartialEq)]
enum Attribute {
    Property(String),
    Value(String, String),
}

fn property_attribute(input: Span) -> IResult<Span, Attribute> {
    let (remainder, span) = preceded(
        tag("a="),
        not_line_ending,
    )(input)?;

    let attribute = Attribute::Property(span.fragment.to_owned());

    Ok((remainder, attribute))
}

#[test]
fn test_property_attribute() {
    let input = Span::new("a=recvonly");
    let expected = Attribute::Property("recvonly".to_owned());
    let actual = property_attribute(input).unwrap().1;
    assert_eq!(expected, actual);
}

fn value_attribute(input: Span) -> IResult<Span, Attribute> {
    let (remainder, (property_span, value_span)) = pair(
        preceded(
            tag("a="),
            take_till1(|c| c == ':'),
        ),
        preceded(
            tag(":"),
            not_line_ending
        ),
    )(input)?;

    let attribute = Attribute::Value(
        property_span.fragment.to_owned(),
        value_span.fragment.to_owned(),
    );

    Ok((remainder, attribute))
}

#[test]
fn test_value_attribute() {
    let input = Span::new("a=msid-semantic: WMS stream");
    let expected = Attribute::Value(
        "msid-semantic".to_owned(),
        " WMS stream".to_owned(),
    );
    let actual = value_attribute(input).unwrap().1;
    assert_eq!(expected, actual);
}

fn attribute(input: Span) -> IResult<Span, Attribute> {
    alt((
        value_attribute,
        property_attribute,
    ))(input)
}

#[test]
fn test_attribute() {
    let input = Span::new("a=msid-semantic: WMS stream");
    let expected = Attribute::Value(
        "msid-semantic".to_owned(),
        " WMS stream".to_owned(),
    );
    let actual = attribute(input).unwrap().1;
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
    pub connection: Option<Connection>,

    // b=<bwtype>:<bandwidth>
    // https://tools.ietf.org/html/rfc4566#section-5.8

    // t=<start-time> <stop-time>
    // https://tools.ietf.org/html/rfc4566#section-5.9
    // r=<repeat interval> <active duration> <offsets from start-time>
    // https://tools.ietf.org/html/rfc4566#section-5.10
    pub time_description: TimeDescription,

    // z=<adjustment time> <offset> <adjustment time> <offset> ...
    // https://tools.ietf.org/html/rfc4566#section-5.11

    // k=<method>
    // k=<method>:<encryption key>
    // https://tools.ietf.org/html/rfc4566#section-5.12

    // a=<attribute>
    // a=<attribute>:<value>
    // https://tools.ietf.org/html/rfc4566#section-5.13
    pub attributes: Vec<Attribute>,

    // m=<media> <port> <proto> <fmt> ...
    // https://tools.ietf.org/html/rfc4566#section-5.14
}

fn session_description(input: Span) -> IResult<Span, SessionDescription> {
    let (remainder, version) = terminated(version, line_ending)(input)?;
    let (remainder, origin) = terminated(origin, line_ending)(remainder)?;
    let (remainder, session_name) = terminated(session_name, line_ending)(remainder)?;
    let (remainder, connection) = opt(terminated(connection, line_ending))(remainder)?;
    let (remainder, time_description) = terminated(time_description, line_ending)(remainder)?;
    let (remainder, attributes) = many0(terminated(attribute, line_ending))(remainder)?;

    let session_description = SessionDescription {
        version,
        origin,
        session_name,
        connection,
        time_description,
        attributes,
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

#[test]
fn test_from_str() {
    let sdp = r#"v=0
o=- 1433832402044130222 3 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
a=group:BUNDLE 0 1
a=msid-semantic: WMS stream
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
        connection: Some(Connection {
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            connection_address: "127.0.0.1".to_owned(),
        }),
        time_description: TimeDescription {
            timing: Timing {
                start_time: 0,
                stop_time: 0,
            },
            repeat_times: vec![],
        },
        attributes: vec![
            Attribute::Value("group".to_owned(), "BUNDLE 0 1".to_owned()),
            Attribute::Value("msid-semantic".to_owned(), " WMS stream".to_owned()),
        ],
    };
    let actual = SessionDescription::from_str(sdp);
    assert_eq!(expected, actual);
}
