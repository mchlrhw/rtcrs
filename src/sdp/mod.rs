mod attribute;
mod connection;
mod media_description;
mod origin;
mod session_description;
mod session_name;
mod time_description;
mod version;

use nom_locate::LocatedSpan;

type Span<'a> = LocatedSpan<&'a str>;
