use std::{
    convert::{TryFrom, TryInto},
    error::Error,
    fmt::{Debug, Display, Formatter},
    io::{self, ErrorKind},
    ops::Deref,
    string::FromUtf8Error,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StreamId(String);

impl Deref for StreamId {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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

impl From<StreamIdError> for io::Error {
    fn from(error: StreamIdError) -> Self {
        io::Error::new(ErrorKind::InvalidInput, error)
    }
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

impl TryFrom<String> for StreamId {
    type Error = StreamIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() > 512 {
            return Err(StreamIdError::Length(value.len()));
        }
        Ok(StreamId(value))
    }
}

impl From<&'static str> for StreamId {
    fn from(value: &'static str) -> Self {
        value.try_into().unwrap()
    }
}

impl ToString for StreamId {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}
