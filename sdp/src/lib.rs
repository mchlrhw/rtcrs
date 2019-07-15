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

type Span<'a> = LocatedSpan<&'a str>;

pub use session_description::SessionDescription;
