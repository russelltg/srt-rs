#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod builder;
mod channel;
mod congest_ctrl;
mod connection;
mod crypto;
mod loss_compression;
mod modular_num;
mod msg_number;
mod multiplex;
mod packet;
mod pending_connection;
pub mod protocol;
mod receiver;
mod sender;
mod seq_number;
mod sink_send_wrapper;
mod socket;
mod socket_id;
mod srt_congest_ctrl;
mod srt_version;
mod stats;
pub mod tokio;
mod util;

pub use crate::builder::{ConnInitMethod, SrtSocketBuilder, UnderlyingSocket};
pub use crate::congest_ctrl::{CCData, CongestCtrl};
pub use crate::connection::{Connection, ConnectionSettings};
pub use crate::msg_number::MsgNumber;
pub use crate::multiplex::{MultiplexServer, StreamerServer};
pub use crate::packet::{ControlPacket, DataPacket, Packet, PacketCodec};
pub use crate::receiver::Receiver;
// TODO: remove
pub use crate::sender::Sender;
pub use crate::seq_number::SeqNumber;
pub use crate::socket::SrtSocket;
pub use crate::socket_id::SocketID;
pub use crate::srt_congest_ctrl::SrtCongestCtrl;
pub use crate::srt_version::SrtVersion;
pub use crate::stats::Stats;
