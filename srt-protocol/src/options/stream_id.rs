use std::{
    convert::TryFrom,
    error::Error,
    fmt::{Debug, Display, Formatter},
    io::{self, ErrorKind},
    ops::Deref,
    str::FromStr,
    string::FromUtf8Error,
};

// SRTO_STREAMID
/// A string that can be set on the socket prior to connecting. The listener side will be able to
/// retrieve this stream ID from the socket that is returned from srt_accept (for a connected socket
/// with that stream ID). This string can be used completely free-form. However, it's highly
/// recommended to follow the SRT Access Control (Stream ID) Guidlines.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StreamId(String);

impl Deref for StreamId {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
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
                "StreamId value length of {len} exceeded the limit of 512 bytes"
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

impl FromStr for StreamId {
    type Err = StreamIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_string())
    }
}

impl Display for StreamId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
