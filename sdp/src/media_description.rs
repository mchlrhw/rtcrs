use std::fmt;

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

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Application => write!(f, "application"),
            Self::Audio => write!(f, "audio"),
            Self::Message => write!(f, "message"),
            Self::Text => write!(f, "text"),
            Self::Video => write!(f, "video"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Media {
    pub typ: MediaType,
    pub port: u64,
    pub protocol: String,
    pub format: String,
}

impl fmt::Display for Media {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "m={} {} {} {}\r\n",
            self.typ, self.port, self.protocol, self.format,
        )
    }
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

    let typ = match *span.fragment() {
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
    let port = u64::from_str_radix(span.fragment(), 10).unwrap();

    let (remainder, span) = preceded(tag(" "), take_till1(|c| c == ' '))(remainder)?;

    // TODO: we might want to parse this into an enum
    let protocol = (*span.fragment()).to_string();

    let (remainder, span) = delimited(tag(" "), not_line_ending, line_ending)(remainder)?;

    // TODO: parse this based on the protocol field
    let format = (*span.fragment()).to_string();

    let media = Media {
        typ,
        port,
        protocol,
        format,
    };

    Ok((remainder, media))
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
    pub fn base(media: Media) -> Self {
        Self {
            media,
            title: None,
            connection: None,
            bandwidths: vec![],
            encryption_key: None,
            attributes: vec![],
        }
    }

    pub fn with_title(mut self, title: SessionInformation) -> Self {
        self.title = Some(title);
        self
    }

    pub fn with_connection(mut self, connection: Connection) -> Self {
        self.connection = Some(connection);
        self
    }

    pub fn with_bandwidths(mut self, bandwidths: Vec<Bandwidth>) -> Self {
        self.bandwidths = bandwidths;
        self
    }

    pub fn with_encryption_key(mut self, encryption_key: EncryptionKey) -> Self {
        self.encryption_key = Some(encryption_key);
        self
    }

    pub fn with_attributes(mut self, attributes: Vec<Attribute>) -> Self {
        self.attributes = attributes;
        self
    }

    pub fn and_attribute(mut self, attribute: Attribute) -> Self {
        self.attributes.push(attribute);
        self
    }
}

type MediaDescriptionArgs = (
    Media,
    Option<SessionInformation>,
    Option<Connection>,
    Vec<Bandwidth>,
    Option<EncryptionKey>,
    Vec<Attribute>,
);

impl MediaDescription {
    fn from_tuple(args: MediaDescriptionArgs) -> Self {
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

impl fmt::Display for MediaDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let title_string = match &self.title {
            Some(s) => s.to_string(),
            None => "".to_string(),
        };

        let connection_string = match &self.connection {
            Some(c) => c.to_string(),
            None => "".to_string(),
        };

        let mut bandwidths_string = "".to_string();
        for bandwidth in &self.bandwidths {
            bandwidths_string += &bandwidth.to_string();
        }

        let encryption_key_string = match &self.encryption_key {
            Some(e) => e.to_string(),
            None => "".to_string(),
        };

        let mut attributes_string = "".to_string();
        for attribute in &self.attributes {
            attributes_string += &attribute.to_string();
        }

        write!(
            f,
            "{}{}{}{}{}{}",
            self.media,
            title_string,
            connection_string,
            bandwidths_string,
            encryption_key_string,
            attributes_string,
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_media() {
        let media = Media {
            typ: MediaType::Audio,
            port: 51596,
            protocol: "UDP/TLS/RTP/SAVPF".to_string(),
            format: "111 103 104 9 102 0 8 106 105 13 110 112 113 126".to_string(),
        };
        let expected =
            "m=audio 51596 UDP/TLS/RTP/SAVPF 111 103 104 9 102 0 8 106 105 13 110 112 113 126\r\n";
        let actual = media.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_media() {
        let input = Span::new(
            "m=audio 51596 UDP/TLS/RTP/SAVPF 111 103 104 9 102 0 8 106 105 13 110 112 113 126\r\n",
        );
        let expected = Media {
            typ: MediaType::Audio,
            port: 51596,
            protocol: "UDP/TLS/RTP/SAVPF".to_string(),
            format: "111 103 104 9 102 0 8 106 105 13 110 112 113 126".to_string(),
        };
        let actual = media(input).unwrap().1;
        assert_eq!(expected, actual);
    }

    #[test]
    fn display_media_description() {
        let media_description = MediaDescription::base(Media {
            typ: MediaType::Audio,
            port: 51596,
            protocol: "UDP/TLS/RTP/SAVPF".to_string(),
            format: "111 103 104 9 102 0 8 106 105 13 110 112 113 126".to_string(),
        })
        .and_attribute(Attribute::value("rtcp", "9 IN IP4 0.0.0.0"));

        let expected = "m=audio 51596 UDP/TLS/RTP/SAVPF 111 103 104 9 102 0 8 106 105 13 110 112 113 126\r\na=rtcp:9 IN IP4 0.0.0.0\r\n";
        let actual = media_description.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_media_description() {
        let input = Span::new("m=audio 51596 UDP/TLS/RTP/SAVPF 111 103 104 9 102 0 8 106 105 13 110 112 113 126\r\na=rtcp:9 IN IP4 0.0.0.0\r\n");
        let expected = MediaDescription::base(Media {
            typ: MediaType::Audio,
            port: 51596,
            protocol: "UDP/TLS/RTP/SAVPF".to_string(),
            format: "111 103 104 9 102 0 8 106 105 13 110 112 113 126".to_string(),
        })
        .and_attribute(Attribute::value("rtcp", "9 IN IP4 0.0.0.0"));

        let actual = media_description(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
