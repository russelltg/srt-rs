mod address;
mod bandwidth;
mod bind;
mod caller;
mod connect;
mod encryption;
mod error;
mod listener;
mod receiver;
mod rendezvous;
mod sender;
mod session;
mod socket;
mod srt_version;
mod stream_id;
mod units;
mod uri;
mod validation;

pub use address::*;
pub use bandwidth::*;
pub use bind::*;
pub use caller::*;
pub use connect::*;
pub use encryption::*;
pub use error::*;
pub use listener::*;
pub use receiver::*;
pub use rendezvous::*;
pub use sender::*;
pub use session::*;
pub use socket::*;
pub use srt_version::*;
pub use stream_id::*;
pub use units::*;
pub use uri::url_parse;
pub use validation::*;

// see https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md

// SRTO_PACKETFILTER - FEC not supported... yet

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
// SRTO_UDP_SNDBUF - not really relevant for tokio is it?
// SRTO_UDP_RCVBUF - not really relevant for tokio, is it?
// SRTO_SENDER - always duplex
// SRTO_MESSAGEAPI - only "live" is supported
// SRTO_CONGESTION - only "live" is supported
// SRTO_ENFORCEDENCRYPTION - awkward/arcane - is this actually useful?
