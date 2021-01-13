#![allow(clippy::write_with_newline)]

mod attribute;
mod bandwidth;
mod connection;
mod email_address;
mod encryption_key;
mod media_description;
mod origin;
mod phone_number;
mod session_description;
mod session_information;
mod session_name;
mod time_description;
mod time_zone;
mod uri;
mod version;

use nom_locate::LocatedSpan;

pub use attribute::Attribute;
pub use connection::Connection;
pub use media_description::{Media, MediaDescription, MediaType};
pub use origin::Origin;
pub use session_description::SessionDescription;
pub use session_name::SessionName;
pub use time_description::{TimeDescription, Timing};
pub use version::Version;

type Span<'a> = LocatedSpan<&'a str>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("invalid json: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid session description")]
    InvalidSessionDescription,
    #[error("bytes are not valid UTF-8: {0}")]
    InvalidString(#[from] std::string::FromUtf8Error),
}
