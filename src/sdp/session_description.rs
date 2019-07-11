use nom::{
    IResult,
    combinator::{ all_consuming, map, opt },
    multi::many0,
    sequence::tuple,
};

use crate::sdp::{
    Span,
    attribute::{ Attribute, attribute },
    connection::{ Connection, connection },
    media_description::{ Media, MediaType, MediaDescription, media_description },
    origin::{ Origin, origin },
    session_name::{ SessionName, session_name },
    time_description::{ TimeDescription, Timing, time_description },
    version::{ Version, version },
};

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
    pub media_descriptions: Vec<MediaDescription>,
}

impl SessionDescription {
    fn from_tuple(args: (
        Version,
        Origin,
        SessionName,
        Option<Connection>,
        TimeDescription,
        Vec<Attribute>,
        Vec<MediaDescription>,
    )) -> Self {
        Self {
            version: args.0,
            origin: args.1,
            session_name: args.2,
            connection: args.3,
            time_description: args.4,
            attributes: args.5,
            media_descriptions: args.6,
        }
    }
}

fn session_description(input: Span) -> IResult<Span, SessionDescription> {
    map(
        tuple((
            version,
            origin,
            session_name,
            opt(connection),
            time_description,
            many0(attribute),
            many0(media_description),
        )),
        SessionDescription::from_tuple,
    )(input)
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
a=recvonly
a=group:BUNDLE 0 1
a=msid-semantic: WMS stream
m=audio 49170 RTP/AVP 0
m=video 51372 RTP/AVP 99
a=rtpmap:99 h263-1998/90000
"#;
    let expected = SessionDescription {
        version: Version(0),
        origin: Origin {
            username: "-".to_owned(),
            session_id: 1433832402044130222,
            session_version: 3,
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            unicast_address: "127.0.0.1".to_owned(),
        },
        session_name: SessionName("-".to_owned()),
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
            Attribute::Property("recvonly".to_owned()),
            Attribute::Value("group".to_owned(), "BUNDLE 0 1".to_owned()),
            Attribute::Value("msid-semantic".to_owned(), " WMS stream".to_owned()),
        ],
        media_descriptions: vec![
            MediaDescription {
                media: Media {
                    typ: MediaType::Audio,
                    port: 49170,
                    protocol: "RTP/AVP".to_owned(),
                    format: "0".to_owned(),
                },
                connection: None,
                attributes: vec![],
            },
            MediaDescription {
                media: Media {
                    typ: MediaType::Video,
                    port: 51372,
                    protocol: "RTP/AVP".to_owned(),
                    format: "99".to_owned(),
                },
                connection: None,
                attributes: vec![
                    Attribute::Value(
                        "rtpmap".to_owned(),
                        "99 h263-1998/90000".to_owned(),
                    ),
                ],
            },
        ],
    };
    let actual = SessionDescription::from_str(sdp);
    assert_eq!(expected, actual);
}

