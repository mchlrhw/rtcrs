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

pub use session_description::SessionDescription;

type Span<'a> = LocatedSpan<&'a str>;

#[derive(Debug, Fail)]
pub enum SDPError {
    #[fail(display = "invalid session description")]
    InvalidSessionDescription,
}
