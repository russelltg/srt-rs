extern crate byteorder;
extern crate bytes;

#[macro_use]
extern crate futures;
extern crate futures_timer;
#[macro_use]
extern crate log;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_io;
#[macro_use]
extern crate serde_derive;

pub mod builder;
pub mod codec;
pub mod congestion_ctrl;
pub mod connected;
pub mod connection_settings;
pub mod default_congestion_ctrl;
pub mod loss_compression;
pub mod packet;
pub mod pending_connection;
pub mod receiver;
pub mod sender;
pub mod seq_number;
pub mod stats;
pub mod stats_printer;

pub use builder::{ConnInitMethod, SrtSocket, SrtSocketBuilder};
pub use congestion_ctrl::{AckMode, CCData, RecvrCongestionCtrl, SenderCongestionCtrl};
pub use connected::Connected;
pub use connection_settings::ConnectionSettings;
pub use default_congestion_ctrl::{DefaultReceiverCongestionCtrl, DefaultSenderCongestionCtrl};
pub use packet::Packet;
pub use pending_connection::PendingConnection;
pub use receiver::Receiver;
pub use sender::Sender;
pub use seq_number::SeqNumber;
pub use stats::Stats;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SocketID(pub i32);
