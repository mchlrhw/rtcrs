use nom::{
    branch::alt,
    bytes::complete::{tag, take_till1},
    character::complete::{digit1, line_ending, not_line_ending},
    combinator::{map, opt},
    multi::many0,
    sequence::{delimited, preceded, tuple},
    IResult,
};

use crate::{
    attribute::{attribute, Attribute},
    bandwidth::{bandwidth, Bandwidth},
    connection::{connection, Connection},
    encryption_key::{encryption_key, EncryptionKey},
    session_information::{session_information, SessionInformation},
    Span,
};

#[derive(Debug, PartialEq)]
pub enum MediaType {
    Application,
    Audio,
    Message,
    Text,
    Video,
}

#[derive(Debug, PartialEq)]
pub struct Media {
    pub typ: MediaType,
    pub port: u64,
    pub protocol: String,
    pub format: String,
}

// m=<media> <port> <proto> <fmt> ...
// https://tools.ietf.org/html/rfc4566#section-5.14
fn media(input: Span) -> IResult<Span, Media> {
    let (remainder, span) = preceded(
        tag("m="),
        alt((
            tag("application"),
            tag("audio"),
            tag("message"),
            tag("text"),
            tag("video"),
        )),
    )(input)?;

    let typ = match span.fragment {
        "application" => MediaType::Application,
        "audio" => MediaType::Audio,
        "message" => MediaType::Message,
        "text" => MediaType::Text,
        "video" => MediaType::Video,
        _ => unreachable!(),
    };

    // TODO: support <port>/<number of ports> format
    let (remainder, span) = preceded(tag(" "), digit1)(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let port = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = preceded(tag(" "), take_till1(|c| c == ' '))(remainder)?;

    // TODO: we might want to parse this into an enum
    let protocol = span.fragment.to_owned();

    let (remainder, span) = delimited(tag(" "), not_line_ending, line_ending)(remainder)?;

    // TODO: parse this based on the protocol field
    let format = span.fragment.to_owned();

    let media = Media {
        typ,
        port,
        protocol,
        format,
    };

    Ok((remainder, media))
}

#[test]
fn test_media() {
    let input = Span::new(
        "m=audio 51596 UDP/TLS/RTP/SAVPF 111 103 104 9 102 0 8 106 105 13 110 112 113 126\r\n",
    );
    let expected = Media {
        typ: MediaType::Audio,
        port: 51596,
        protocol: "UDP/TLS/RTP/SAVPF".to_owned(),
        format: "111 103 104 9 102 0 8 106 105 13 110 112 113 126".to_owned(),
    };
    let actual = media(input).unwrap().1;
    assert_eq!(expected, actual);
}

#[derive(Debug, PartialEq)]
pub struct MediaDescription {
    pub media: Media,
    pub title: Option<SessionInformation>,
    pub connection: Option<Connection>,
    pub bandwidths: Vec<Bandwidth>,
    pub encryption_key: Option<EncryptionKey>,
    pub attributes: Vec<Attribute>,
}

impl MediaDescription {
    fn from_tuple(
        args: (
            Media,
            Option<SessionInformation>,
            Option<Connection>,
            Vec<Bandwidth>,
            Option<EncryptionKey>,
            Vec<Attribute>,
        ),
    ) -> Self {
        Self {
            media: args.0,
            title: args.1,
            connection: args.2,
            bandwidths: args.3,
            encryption_key: args.4,
            attributes: args.5,
        }
    }
}

// m=  (media name and transport address)
// i=* (media title)
// c=* (connection information -- optional if included at session level)
// b=* (zero or more bandwidth information lines)
// k=* (encryption key)
// a=* (zero or more media attribute lines)
// https://tools.ietf.org/html/rfc4566#section-5
pub fn media_description(input: Span) -> IResult<Span, MediaDescription> {
    map(
        tuple((
            media,
            opt(session_information),
            // TODO: make this non-optional if no connection at session level
            opt(connection),
            many0(bandwidth),
            opt(encryption_key),
            many0(attribute),
        )),
        MediaDescription::from_tuple,
    )(input)
}

#[test]
fn test_media_description() {
    let input = Span::new("m=audio 51596 UDP/TLS/RTP/SAVPF 111 103 104 9 102 0 8 106 105 13 110 112 113 126\r\na=rtcp:9 IN IP4 0.0.0.0\r\n");
    let expected = MediaDescription {
        media: Media {
            typ: MediaType::Audio,
            port: 51596,
            protocol: "UDP/TLS/RTP/SAVPF".to_owned(),
            format: "111 103 104 9 102 0 8 106 105 13 110 112 113 126".to_owned(),
        },
        title: None,
        connection: None,
        bandwidths: vec![],
        encryption_key: None,
        attributes: vec![Attribute::Value(
            "rtcp".to_owned(),
            "9 IN IP4 0.0.0.0".to_owned(),
        )],
    };
    let actual = media_description(input).unwrap().1;
    assert_eq!(expected, actual);
}
