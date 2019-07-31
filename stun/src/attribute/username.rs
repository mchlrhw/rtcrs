use std::convert::TryInto;

use nom::IResult;

use crate::attribute::{Attribute, Tlv};

#[derive(Debug, PartialEq)]
pub struct Username(String);

impl Username {
    pub fn new(username: &str) -> Self {
        Self(username.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Tlv for Username {
    fn typ(&self) -> u16 {
        0x_0006
    }

    fn length(&self) -> u16 {
        self.0.len().try_into().unwrap()
    }

    fn value(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

pub(crate) fn username(input: &[u8]) -> IResult<&[u8], Attribute> {
    // TODO: check the input length is < 513
    // TODO: return Err here
    let value = String::from_utf8(input.to_vec()).unwrap();

    let inner = Username(value);
    let attribute = Attribute::Username(inner);

    Ok((&[], attribute))
}
