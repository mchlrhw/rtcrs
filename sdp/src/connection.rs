use std::fmt;

use nom::{
    bytes::complete::{tag, take_till1},
    character::complete::{line_ending, not_line_ending},
    combinator::map,
    sequence::{delimited, preceded, tuple},
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub struct Connection {
    pub network_type: String,
    pub address_type: String,
    pub connection_address: String,
}

type ConnectionArgs = (String, String, String);

impl Connection {
    fn from_tuple(args: ConnectionArgs) -> Self {
        Self {
            network_type: args.0,
            address_type: args.1,
            connection_address: args.2,
        }
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "c={} {} {}\r\n",
            self.network_type, self.address_type, self.connection_address
        )
    }
}

// c=<nettype> <addrtype> <connection-address>
// https://tools.ietf.org/html/rfc4566#section-5.7
pub fn connection(input: Span) -> IResult<Span, Connection> {
    map(
        tuple((
            map(preceded(tag("c="), take_till1(|c| c == ' ')), |s: Span| {
                s.fragment().to_string()
            }),
            map(preceded(tag(" "), take_till1(|c| c == ' ')), |s: Span| {
                s.fragment().to_string()
            }),
            map(
                delimited(tag(" "), not_line_ending, line_ending),
                |s: Span| s.fragment().to_string(),
            ),
        )),
        Connection::from_tuple,
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_connection() {
        let connection = Connection {
            network_type: "IN".to_string(),
            address_type: "IP4".to_string(),
            connection_address: "127.0.0.1".to_string(),
        };
        let expected = "c=IN IP4 127.0.0.1\r\n";
        let actual = connection.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_connection() {
        let input = Span::new("c=IN IP4 127.0.0.1\r\n");
        let expected = Connection {
            network_type: "IN".to_string(),
            address_type: "IP4".to_string(),
            connection_address: "127.0.0.1".to_string(),
        };
        let actual = connection(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
