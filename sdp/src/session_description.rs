use std::{fmt, str::FromStr};

use fehler::throws;
use nom::{
    combinator::{all_consuming, map, opt},
    multi::many0,
    sequence::tuple,
    IResult,
};
use serde::{Deserialize, Serialize};

use crate::{
    attribute::{attribute, Attribute},
    bandwidth::{bandwidth, Bandwidth},
    connection::{connection, Connection},
    email_address::{email_address, EmailAddress},
    encryption_key::{encryption_key, EncryptionKey},
    media_description::{media_description, MediaDescription},
    origin::{origin, Origin},
    phone_number::{phone_number, PhoneNumber},
    session_information::{session_information, SessionInformation},
    session_name::{session_name, SessionName},
    time_description::{time_description, TimeDescription},
    time_zone::{time_zone, TimeZone},
    uri::{uri, URI},
    version::{version, Version},
    Error, Span,
};

#[derive(Debug, PartialEq)]
pub struct SessionDescription {
    pub version: Version,
    pub origin: Origin,
    pub session_name: SessionName,
    pub session_information: Option<SessionInformation>,
    pub uri: Option<URI>,
    pub email_addresses: Vec<EmailAddress>,
    pub phone_numbers: Vec<PhoneNumber>,
    pub connection: Option<Connection>,
    pub bandwidths: Vec<Bandwidth>,
    pub time_description: TimeDescription,
    pub time_zone: Option<TimeZone>,
    pub encryption_key: Option<EncryptionKey>,
    pub attributes: Vec<Attribute>,
    pub media_descriptions: Vec<MediaDescription>,
}

impl SessionDescription {
    pub fn base(
        version: Version,
        origin: Origin,
        session_name: SessionName,
        time_description: TimeDescription,
    ) -> Self {
        Self {
            version,
            origin,
            session_name,
            session_information: None,
            uri: None,
            email_addresses: vec![],
            phone_numbers: vec![],
            connection: None,
            bandwidths: vec![],
            time_description,
            time_zone: None,
            encryption_key: None,
            attributes: vec![],
            media_descriptions: vec![],
        }
    }

    pub fn with_connection(mut self, connection: Connection) -> Self {
        self.connection = Some(connection);
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

    pub fn with_media_descriptions(mut self, media_descriptions: Vec<MediaDescription>) -> Self {
        self.media_descriptions = media_descriptions;
        self
    }

    pub fn and_media_description(mut self, media_description: MediaDescription) -> Self {
        self.media_descriptions.push(media_description);
        self
    }
}

impl SessionDescription {
    pub fn candidates(&self) -> Vec<Attribute> {
        let mut candidates = vec![];

        for media_description in &self.media_descriptions {
            for attribute in &media_description.attributes {
                if attribute.is_ice_candidate() {
                    candidates.push(attribute.clone());
                }
            }
        }

        candidates
    }
}

type SessionDescriptionArgs = (
    Version,
    Origin,
    SessionName,
    Option<SessionInformation>,
    Option<URI>,
    Vec<EmailAddress>,
    Vec<PhoneNumber>,
    Option<Connection>,
    Vec<Bandwidth>,
    TimeDescription,
    Option<TimeZone>,
    Option<EncryptionKey>,
    Vec<Attribute>,
    Vec<MediaDescription>,
);

impl SessionDescription {
    fn from_tuple(args: SessionDescriptionArgs) -> Self {
        Self {
            version: args.0,
            origin: args.1,
            session_name: args.2,
            session_information: args.3,
            uri: args.4,
            email_addresses: args.5,
            phone_numbers: args.6,
            connection: args.7,
            bandwidths: args.8,
            time_description: args.9,
            time_zone: args.10,
            encryption_key: args.11,
            attributes: args.12,
            media_descriptions: args.13,
        }
    }
}

impl fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let session_information_string = match &self.session_information {
            Some(s) => s.to_string(),
            None => "".to_owned(),
        };

        let uri_string = match &self.uri {
            Some(u) => u.to_string(),
            None => "".to_owned(),
        };

        let mut email_addresses_string = "".to_owned();
        for email_address in &self.email_addresses {
            email_addresses_string += &email_address.to_string();
        }

        let mut phone_numbers_string = "".to_owned();
        for phone_number in &self.phone_numbers {
            phone_numbers_string += &phone_number.to_string();
        }

        let connection_string = match &self.connection {
            Some(c) => c.to_string(),
            None => "".to_owned(),
        };

        let mut bandwidths_string = "".to_owned();
        for bandwidth in &self.bandwidths {
            bandwidths_string += &bandwidth.to_string();
        }

        let time_zone_string = match &self.time_zone {
            Some(t) => t.to_string(),
            None => "".to_owned(),
        };

        let encryption_key_string = match &self.encryption_key {
            Some(e) => e.to_string(),
            None => "".to_owned(),
        };

        let mut attributes_string = "".to_owned();
        for attribute in &self.attributes {
            attributes_string += &attribute.to_string();
        }

        let mut media_descriptions_string = "".to_owned();
        for media_description in &self.media_descriptions {
            media_descriptions_string += &media_description.to_string();
        }

        write!(
            f,
            "{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
            self.version,
            self.origin,
            self.session_name,
            session_information_string,
            uri_string,
            email_addresses_string,
            phone_numbers_string,
            connection_string,
            bandwidths_string,
            self.time_description,
            time_zone_string,
            encryption_key_string,
            attributes_string,
            media_descriptions_string,
        )
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
            many0(bandwidth),
            time_description,
            opt(time_zone),
            opt(encryption_key),
            many0(attribute),
            many0(media_description),
        )),
        SessionDescription::from_tuple,
    )(input)
}

impl FromStr for SessionDescription {
    type Err = Error;

    #[throws]
    fn from_str(s: &str) -> Self {
        let input = Span::new(s);
        let (_, session_description) =
            all_consuming(session_description)(input).or(Err(Error::InvalidSessionDescription))?;

        session_description
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SdpType {
    Offer,
    Answer,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionDescriptionWrapper {
    #[serde(rename = "type")]
    ty: SdpType,
    sdp: String,
}

impl SessionDescription {
    #[throws]
    pub fn from_base64(encoded: &str) -> Self {
        let bytes = base64::decode(encoded)?;
        let wrapper_string = String::from_utf8(bytes)?;
        let wrapper: SessionDescriptionWrapper = serde_json::from_str(&wrapper_string)?;

        Self::from_str(&wrapper.sdp)?
    }
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;
    use crate::{
        media_description::{Media, MediaType},
        time_description::Timing,
    };

    #[test]
    fn display_session_description() {
        let session_description = SessionDescription::base(
            Version(0),
            Origin {
                username: "-".to_owned(),
                session_id: 1433832402044130222,
                session_version: 3,
                network_type: "IN".to_owned(),
                address_type: "IP4".to_owned(),
                unicast_address: "127.0.0.1".to_owned(),
            },
            SessionName("-".to_owned()),
            TimeDescription::base(Timing {
                start_time: 0,
                stop_time: 0,
            }),
        )
        .with_connection(Connection {
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            connection_address: "127.0.0.1".to_owned(),
        })
        .with_attributes(vec![
            Attribute::property("recvonly"),
            Attribute::value("group", "BUNDLE 0 1"),
            Attribute::value("msid-semantic", " WMS stream"),
        ])
        .with_media_descriptions(vec![
            MediaDescription::base(Media {
                typ: MediaType::Audio,
                port: 49170,
                protocol: "RTP/AVP".to_owned(),
                format: "0".to_owned(),
            }),
            MediaDescription::base(Media {
                typ: MediaType::Video,
                port: 51372,
                protocol: "RTP/AVP".to_owned(),
                format: "99".to_owned(),
            })
            .and_attribute(Attribute::value("rtpmap", "99 h263-1998/90000")),
        ]);
        let expected = "v=0\r\no=- 1433832402044130222 3 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\na=recvonly\r\na=group:BUNDLE 0 1\r\na=msid-semantic: WMS stream\r\nm=audio 49170 RTP/AVP 0\r\nm=video 51372 RTP/AVP 99\r\na=rtpmap:99 h263-1998/90000\r\n";
        let actual = session_description.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    #[throws]
    fn parse_session_description() {
        let sdp = "v=0
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
";
        let expected = SessionDescription::base(
            Version(0),
            Origin {
                username: "-".to_owned(),
                session_id: 1433832402044130222,
                session_version: 3,
                network_type: "IN".to_owned(),
                address_type: "IP4".to_owned(),
                unicast_address: "127.0.0.1".to_owned(),
            },
            SessionName("-".to_owned()),
            TimeDescription::base(Timing {
                start_time: 0,
                stop_time: 0,
            }),
        )
        .with_connection(Connection {
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            connection_address: "127.0.0.1".to_owned(),
        })
        .with_attributes(vec![
            Attribute::property("recvonly"),
            Attribute::value("group", "BUNDLE 0 1"),
            Attribute::value("msid-semantic", " WMS stream"),
        ])
        .with_media_descriptions(vec![
            MediaDescription::base(Media {
                typ: MediaType::Audio,
                port: 49170,
                protocol: "RTP/AVP".to_owned(),
                format: "0".to_owned(),
            }),
            MediaDescription::base(Media {
                typ: MediaType::Video,
                port: 51372,
                protocol: "RTP/AVP".to_owned(),
                format: "99".to_owned(),
            })
            .and_attribute(Attribute::value("rtpmap", "99 h263-1998/90000")),
        ]);
        let actual = SessionDescription::from_str(sdp)?;
        assert_eq!(expected, actual);
    }
}
