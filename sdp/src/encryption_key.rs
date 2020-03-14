use std::fmt;

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{line_ending, not_line_ending},
    combinator::opt,
    sequence::{delimited, pair, preceded},
    IResult,
};

use crate::Span;

#[derive(Debug, PartialEq)]
pub enum RetrievalMethod {
    Base64,
    Clear,
    Prompt,
    URI,
}

impl fmt::Display for RetrievalMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base64 => write!(f, "base64"),
            Self::Clear => write!(f, "clear"),
            Self::Prompt => write!(f, "prompt"),
            Self::URI => write!(f, "uri"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct EncryptionKey {
    pub method: RetrievalMethod,
    pub data: Option<String>,
}

impl fmt::Display for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "k={}{}\r\n",
            self.method,
            match &self.data {
                Some(s) => format!(":{}", s),
                None => "".to_owned(),
            },
        )
    }
}

// k=<method>
// k=<method>:<encryption key>
// https://tools.ietf.org/html/rfc4566#section-5.12
pub fn encryption_key(input: Span) -> IResult<Span, EncryptionKey> {
    let (remainder, (method_span, data_opt)) = delimited(
        tag("k="),
        pair(
            alt((tag("base64"), tag("clear"), tag("prompt"), tag("uri"))),
            opt(preceded(tag(":"), not_line_ending)),
        ),
        line_ending,
    )(input)?;

    let method = match *method_span.fragment() {
        "base64" => RetrievalMethod::Base64,
        "clear" => RetrievalMethod::Clear,
        "prompt" => RetrievalMethod::Prompt,
        "uri" => RetrievalMethod::URI,
        _ => unreachable!(),
    };
    // TODO: ensure base64, clear and uri all have Some(data)
    let data = data_opt.map(|s| (*s.fragment()).to_string());

    let encryption_key = EncryptionKey { method, data };

    Ok((remainder, encryption_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_encryption_key_with_data() {
        let encryption_key = EncryptionKey {
            method: RetrievalMethod::Clear,
            data: Some("encryption_key".to_owned()),
        };
        let expected = "k=clear:encryption_key\r\n";
        let actual = encryption_key.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn display_encryption_key_without_data() {
        let encryption_key = EncryptionKey {
            method: RetrievalMethod::Prompt,
            data: None,
        };
        let expected = "k=prompt\r\n";
        let actual = encryption_key.to_string();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_encryption_key_with_data() {
        let input = Span::new("k=clear:encryption_key\r\n");
        let expected = EncryptionKey {
            method: RetrievalMethod::Clear,
            data: Some("encryption_key".to_owned()),
        };
        let actual = encryption_key(input).unwrap().1;
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_encryption_key_without_data() {
        let input = Span::new("k=prompt\r\n");
        let expected = EncryptionKey {
            method: RetrievalMethod::Prompt,
            data: None,
        };
        let actual = encryption_key(input).unwrap().1;
        assert_eq!(expected, actual);
    }
}
