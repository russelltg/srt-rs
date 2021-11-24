use std::{convert::TryFrom, string::FromUtf8Error};

#[derive(Debug, Eq, PartialEq)]
pub struct StreamId(String);

#[derive(Debug, Eq, PartialEq)]
pub enum StreamIdError {
    FromUtf8(FromUtf8Error),
    Length(usize),
}

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
