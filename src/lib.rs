#![deny(clippy::all)]

mod builder;
mod channel;
mod congest_ctrl;
mod connected;
mod connection_settings;
mod crypto;
mod loss_compression;
mod modular_num;
mod msg_number;
mod multiplex;
mod packet;
mod pending_connection;
mod receiver;
mod sender;
mod seq_number;
mod socket_id;
mod srt_congest_ctrl;
mod srt_version;
mod stats;

// public API
pub use crate::builder::{ConnInitMethod, SrtSocket, SrtSocketBuilder};
pub use crate::congest_ctrl::{CCData, CongestCtrl};
pub use crate::connected::Connected;
pub use crate::connection_settings::ConnectionSettings;
pub use crate::msg_number::MsgNumber;
pub use crate::multiplex::{MultiplexServer, StreamerServer};
pub use crate::packet::{ControlPacket, DataPacket, Packet, PacketCodec};
pub use crate::pending_connection::PendingConnection;
pub use crate::receiver::Receiver;
pub use crate::sender::Sender;
pub use crate::seq_number::SeqNumber;
pub use crate::socket_id::SocketID;
pub use crate::srt_congest_ctrl::SrtCongestCtrl;
pub use crate::srt_version::SrtVersion;
pub use crate::stats::Stats;
