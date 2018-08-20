extern crate bytes;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;
extern crate futures_timer;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_udp;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate failure;

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
pub use builder::{ConnInitMethod, SrtSocket, SrtSocketBuilder};
pub use congest_ctrl::{CCData, CongestCtrl};
pub use connected::Connected;
pub use connection_settings::ConnectionSettings;
pub use handshake_responsibiliy::HandshakeResponsibility;
pub use msg_number::MsgNumber;
pub use packet::{ControlPacket, DataPacket, Packet};
pub use pending_connection::PendingConnection;
pub use receiver::Receiver;
pub use sender::Sender;
pub use seq_number::SeqNumber;
pub use srt_congest_ctrl::SrtCongestCtrl;
pub use srt_version::SrtVersion;
pub use stats::Stats;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SocketID(pub u32);
