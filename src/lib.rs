#![deny(clippy::all)]
#![forbid(unsafe_code)]
#![recursion_limit = "256"]

//! Implementation of [SRT](https://www.haivision.com/products/srt-secure-reliable-transport/) in pure safe rust.
//!
//! Generally used for live video streaming across lossy but high bandwidth connections.
//!
//! # Quick start
//! ```rust
//! use srt::SrtSocketBuilder;
//! use futures::prelude::*;
//! use bytes::Bytes;
//! use std::time::Instant;
//! use failure::Error;
//!
//! #[tokio::main]
//! async fn main()
//!# // keep this to quell `needless_doctest_main` warning
//!# -> ()
//! {
//!     let sender_fut = async {
//!         let mut tx = SrtSocketBuilder::new_listen().local_port(2223).connect().await?;
//!
//!         let iter = ["1", "2", "3"];
//!         
//!         tx.send_all(&mut stream::iter(&iter)
//!             .map(|b| Ok((Instant::now(), Bytes::from(*b))))).await?;
//!         tx.close().await?;
//!
//!         Ok::<_, Error>(())
//!     };
//!
//!     let receiver_fut = async {
//!         let mut rx = SrtSocketBuilder::new_connect("127.0.0.1:2223").connect().await?;
//!
//!         assert_eq!(rx.try_next().await?.map(|(_i, b)| b), Some(b"1"[..].into()));
//!         assert_eq!(rx.try_next().await?.map(|(_i, b)| b), Some(b"2"[..].into()));
//!         assert_eq!(rx.try_next().await?.map(|(_i, b)| b), Some(b"3"[..].into()));
//!         assert_eq!(rx.try_next().await?, None);
//!
//!         Ok::<_, Error>(())
//!     };
//!
//!     futures::try_join!(sender_fut, receiver_fut).unwrap();
//! }
//!
//! ```
//!

mod builder;
mod channel;
mod congest_ctrl;
mod connection;
// mod crypto;
mod loss_compression;
mod modular_num;
mod msg_number;
mod multiplex;
mod packet;
pub mod pending_connection;
mod receiver;
mod sender;
mod seq_number;
mod sink_send_wrapper;
mod socket;
mod socket_id;
mod srt_congest_ctrl;
mod srt_version;
mod stats;
mod util;

pub use crate::builder::{ConnInitMethod, SrtSocketBuilder};
pub use crate::congest_ctrl::{CCData, CongestCtrl};
pub use crate::connection::{Connection, ConnectionSettings};
pub use crate::msg_number::MsgNumber;
pub use crate::multiplex::{multiplex, PackChan, StreamerServer};
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
