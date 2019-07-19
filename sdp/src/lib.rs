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

use failure::Fail;
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

#[derive(Debug, Fail)]
pub enum SDPError {
    #[fail(display = "invalid session description")]
    InvalidSessionDescription,
}
