use nom::{
    IResult,
    branch::alt,
    bytes::complete::{ tag, take_till1 },
    combinator::{ map, opt },
    character::complete::{ digit1, line_ending, not_line_ending },
    multi::many0,
    sequence::{ delimited, preceded, tuple },
};

use crate::sdp::{
    Span,
    attribute::{ Attribute, attribute },
    connection::{ Connection, connection },
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
    let (remainder, span) = preceded(
        tag(" "),
        digit1,
    )(remainder)?;

    // SAFE: since we've parsed this as digit1, so we don't need
    //       to guard against parse errors in from_str_radix
    let port = u64::from_str_radix(span.fragment, 10).unwrap();

    let (remainder, span) = preceded(
        tag(" "),
        take_till1(|c| c == ' '),
    )(remainder)?;

    // TODO: we might want to parse this into an enum
    let protocol = span.fragment.to_owned();

    let (remainder, span) = delimited(
        tag(" "),
        not_line_ending,
        line_ending,
    )(remainder)?;

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
    let input = Span::new("m=audio 51596 UDP/TLS/RTP/SAVPF 111 103 104 9 102 0 8 106 105 13 110 112 113 126\r\n");
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
    pub connection: Option<Connection>,
    pub attributes: Vec<Attribute>,
}

impl MediaDescription {
    fn from_tuple(args: (
        Media,
        Option<Connection>,
        Vec<Attribute>,
    )) -> Self {
        Self {
            media: args.0,
            connection: args.1,
            attributes: args.2,
        }
    }
}

pub fn media_description(input: Span) -> IResult<Span, MediaDescription> {
    map(
        tuple((
            media,
            // TODO: make this non-optional if no connection at session level
            opt(connection),
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
        connection: None,
        attributes: vec![
            Attribute::Value(
                "rtcp".to_owned(),
                "9 IN IP4 0.0.0.0".to_owned(),
            ),
        ],
    };
    let actual = media_description(input).unwrap().1;
    assert_eq!(expected, actual);
}
