extern crate byteorder;
extern crate bytes;

#[macro_use]
extern crate futures;
extern crate futures_timer;
#[macro_use]
extern crate log;
extern crate rand;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_io;

pub mod builder;
pub mod codec;
pub mod congestion_ctrl;
pub mod connected;
pub mod default_congestion_ctrl;
pub mod packet;
pub mod pending_connection;
pub mod receiver;
pub mod sender;
pub mod loss_compression;
pub mod connection_settings;
pub mod seq_number;

pub use builder::{ConnInitMethod, SrtSocket, SrtSocketBuilder};
pub use congestion_ctrl::{AckMode, SenderCongestionCtrl, RecvrCongestionCtrl, CCData};
pub use connected::Connected;
pub use default_congestion_ctrl::{DefaultReceiverCongestionCtrl, DefaultSenderCongestionCtrl};
pub use packet::Packet;
pub use pending_connection::PendingConnection;
pub use receiver::Receiver;
pub use sender::Sender;
pub use connection_settings::ConnectionSettings;
pub use seq_number::SeqNumber;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SocketID(i32);
