use std::fmt::{Debug, Display, Formatter};
use std::{convert::TryFrom, error::Error, string::FromUtf8Error};

#[derive(Debug, Eq, PartialEq)]
pub struct StreamId(String);

#[derive(Debug, Eq, PartialEq)]
pub enum StreamIdError {
    FromUtf8(FromUtf8Error),
    Length(usize),
}

impl Display for StreamIdError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use StreamIdError::*;
        match self {
            FromUtf8(error) => Display::fmt(error, f),
            Length(len) => write!(
                f,
                "StreamId value length of {} exceeded the limit of 512 bytes",
                len
            ),
        }
    }
}

impl Error for StreamIdError {}

impl TryFrom<Vec<u8>> for StreamId {
    type Error = StreamIdError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > 512 {
            return Err(StreamIdError::Length(value.len()));
        }
        let stream_id = String::from_utf8(value).map_err(StreamIdError::FromUtf8)?;
        Ok(StreamId(stream_id))
    }
}
