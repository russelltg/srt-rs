use std::{
    time::Duration,
    {convert::TryFrom, string::FromUtf8Error},
};

pub struct ConnectionOptions {
    /// SRTO_STREAMID
    /// A string that can be set on the socket prior to connecting. The listener side will be able to
    /// retrieve this stream ID from the socket that is returned from srt_accept (for a connected socket
    /// with that stream ID). You usually use SET on the socket used for srt_connect, and GET on the
    /// socket retrieved from srt_accept. This string can be used completely free-form. However, it's
    /// highly recommended to follow the SRT Access Control (Stream ID) Guidlines.
    ///
    /// As this uses internally the std::string type, there are additional functions for it in the
    /// legacy/C++ API (udt.h): srt::setstreamid and srt::getstreamid.
    ///
    /// This option is not useful for a Rendezvous connection, since one side would override the value
    /// from the other side resulting in an arbitrary winner. Also in this connection both peers are
    /// known to one another and both have equivalent roles in the connection.
    ///
    /// IMPORTANT: This option is not derived by the accepted socket from the listener socket, and
    /// setting it on a listener socket (see srt_listen function) doesn't influence anything.
    stream_id: StreamId,

    /// SRTO_CONNTIMEO - Connect timeout - unit: msec, default: 3000, range: 0..
    /// Connect timeout. This option applies to the caller and rendezvous connection modes.
    /// For the rendezvous mode (see SRTO_RENDEZVOUS) the effective connection timeout will be 10 times
    /// the value set with SRTO_CONNTIMEO.
    connect_timeout: Duration,
}

pub struct StreamId(String);

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
