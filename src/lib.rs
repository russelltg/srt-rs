mod builder;
mod congest_ctrl;
mod connected;
mod connection_settings;
mod loss_compression;
mod packet;
mod pending_connection;
mod receiver;
mod sender;
mod srt_congest_ctrl;
mod srt_version;
mod stats;
#[macro_use]
mod modular_num;
mod handshake_responsibiliy;
mod msg_number;
mod seq_number;

// public API
pub use crate::builder::{ConnInitMethod, SrtSocket, SrtSocketBuilder};
pub use crate::congest_ctrl::{CCData, CongestCtrl};
pub use crate::connected::Connected;
pub use crate::connection_settings::ConnectionSettings;
pub use crate::handshake_responsibiliy::HandshakeResponsibility;
pub use crate::msg_number::MsgNumber;
pub use crate::packet::{ControlPacket, DataPacket, Packet};
pub use crate::pending_connection::PendingConnection;
pub use crate::receiver::Receiver;
pub use crate::sender::Sender;
pub use crate::seq_number::SeqNumber;
pub use crate::srt_congest_ctrl::SrtCongestCtrl;
pub use crate::srt_version::SrtVersion;
pub use crate::stats::Stats;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SocketID(pub u32);
