mod connection;
mod encryption;
mod error;
mod receiver;
mod sender;
mod session;
mod stream_id;

pub use connection::*;
pub use encryption::*;
pub use error::*;
pub use receiver::*;
pub use sender::*;
pub use session::*;
pub use stream_id::*;

// see https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md
struct SocketOptions {
    pub negotiation: ConnectionOptions,
    pub session: SessionOptions,
    pub encryption: EncryptionOptions,
    pub sender: SenderOptions,
    pub receiver: ReceiverOptions,
    // SRTO_PACKETFILTER - FEC not supported... yet
}

// TODO: look over these options, they could be useful for statistics
//
// SRTO_EVENT - events? not a configuration option
// SRTO_PEERVERSION - read only, could be helpful as a statistic
// SRTO_RCVDATA - read only, could be helpful as a statistic
// SRTO_RCVKMSTATE - read only, could be helpful as a statistic?
// SRTO_RENDEZVOUS - read only, maybe useful as as a read only setting?
// SRTO_SNDDATA - read only, but useful as a statistic
// Size of the unacknowledged data in send buffer.
// SRTO_SNDKMSTATEE - read only, maybe as a statistic?
// SRTO_VERSION - maybe useful either as a setting or statistic?

// NOTE: will not implement these configuration options
//
// SRTO_IPTOS - socket specific
// SRTO_IPTTL - socket specific
// SRTO_IPV6ONLY - socket specific
// SRTO_LINGER - socket specific
// SRTO_TRANSTYPE - socket specific
// SRTO_BINDTODEVICE - socket only
// SRTO_REUSEADDR - socket specific
// SRTO_STATE - socket specific
// SRTO_RCVSYN - not even relevant for tokio
// SRTO_RCVTIMEO - not even relevant for tokio
// SRTO_SNDSYN - not even relevant for tokio
// SRTO_SNDTIMEO - not even relevant for tokio
// SRTO_KMSTATE - legacy, not supporting
// SRTO_ISN - only good for development scenarios
// SRTO_ENFORCEDENCRYPTION - awkward/arcane - is this actually useful?
// SRTO_UDP_SNDBUF - not really relevant for tokio is it?
// SRTO_UDP_RCVBUF - not really relevant for tokio, is it?
// SRTO_SENDER - always duplex
// SRTO_MESSAGEAPI - only "live" is supported
// SRTO_CONGESTION - only "live" is supported
