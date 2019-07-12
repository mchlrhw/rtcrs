use nom::{
    combinator::{all_consuming, map, opt},
    multi::many0,
    sequence::tuple,
    IResult,
};

use crate::sdp::{
    attribute::{attribute, Attribute},
    connection::{connection, Connection},
    email_address::{email_address, EmailAddress},
    media_description::{media_description, Media, MediaDescription, MediaType},
    origin::{origin, Origin},
    phone_number::{phone_number, PhoneNumber},
    session_information::{session_information, SessionInformation},
    session_name::{session_name, SessionName},
    time_description::{time_description, TimeDescription, Timing},
    uri::{uri, URI},
    version::{version, Version},
    Span,
};

#[derive(Debug, PartialEq)]
struct SessionDescription {
    pub version: Version,
    pub origin: Origin,
    pub session_name: SessionName,
    pub session_information: Option<SessionInformation>,
    pub uri: Option<URI>,
    pub email_addresses: Vec<EmailAddress>,
    pub phone_numbers: Vec<PhoneNumber>,
    pub connection: Option<Connection>,
    pub time_description: TimeDescription,
    pub attributes: Vec<Attribute>,
    pub media_descriptions: Vec<MediaDescription>,
}

impl SessionDescription {
    fn from_tuple(
        args: (
            Version,
            Origin,
            SessionName,
            Option<SessionInformation>,
            Option<URI>,
            Vec<EmailAddress>,
            Vec<PhoneNumber>,
            Option<Connection>,
            TimeDescription,
            Vec<Attribute>,
            Vec<MediaDescription>,
        ),
    ) -> Self {
        Self {
            version: args.0,
            origin: args.1,
            session_name: args.2,
            session_information: args.3,
            uri: args.4,
            email_addresses: args.5,
            phone_numbers: args.6,
            connection: args.7,
            time_description: args.8,
            attributes: args.9,
            media_descriptions: args.10,
        }
    }
}

// v=  (protocol version)
// o=  (originator and session identifier)
// s=  (session name)
// i=* (session information)
// u=* (URI of description)
// e=* (email address)
// p=* (phone number)
// c=* (connection information -- not required if included in all media)
// b=* (zero or more bandwidth information lines)
// One or more time descriptions ("t=" and "r=" lines; see below)
// z=* (time zone adjustments)
// k=* (encryption key)
// a=* (zero or more session attribute lines)
// Zero or more media descriptions
// https://tools.ietf.org/html/rfc4566#section-5
fn session_description(input: Span) -> IResult<Span, SessionDescription> {
    map(
        tuple((
            version,
            origin,
            session_name,
            opt(session_information),
            opt(uri),
            many0(email_address),
            many0(phone_number),
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
        session_information: None,
        uri: None,
        email_addresses: vec![],
        phone_numbers: vec![],
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
                attributes: vec![Attribute::Value(
                    "rtpmap".to_owned(),
                    "99 h263-1998/90000".to_owned(),
                )],
            },
        ],
    };
    let actual = SessionDescription::from_str(sdp);
    assert_eq!(expected, actual);
}
