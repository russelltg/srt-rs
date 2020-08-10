#![deny(clippy::all)]
#![forbid(unsafe_code)]
#![recursion_limit = "256"]

//! Implementation of [SRT](https://www.haivision.com/products/srt-secure-reliable-transport/) in pure safe rust.
//!
//! Generally used for live video streaming across lossy but high bandwidth connections.
//!
//! # Quick start
//! ```rust
//! use srt_tokio::SrtSocketBuilder;
//! use futures::prelude::*;
//! use bytes::Bytes;
//! use std::time::Instant;
//! use std::io;
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
//!         Ok::<_, io::Error>(())
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
//!         Ok::<_, io::Error>(())
//!     };
//!
//!     futures::try_join!(sender_fut, receiver_fut).unwrap();
//! }
//!
//! ```
//!

mod builder;
mod channel;
mod codec;
mod multiplex;
mod pending_connection;
pub mod tokio;
mod util;

use codec::PacketCodec;

pub use crate::builder::{ConnInitMethod, SrtSocketBuilder};
pub use crate::multiplex::{multiplex, StreamerServer};
pub use crate::tokio::SrtSocket;

use srt_protocol::connection::{Connection, ConnectionSettings};
use srt_protocol::crypto;
use srt_protocol::packet::{self, ControlPacket, Packet, PacketParseError};
use srt_protocol::protocol;
use srt_protocol::SocketID;
