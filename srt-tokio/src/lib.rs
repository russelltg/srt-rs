#![forbid(unsafe_code)]
#![recursion_limit = "256"]

//! Implementation of [SRT](https://www.haivision.com/products/srt-secure-reliable-transport/) in pure safe rust.
//!
//! Generally used for live video streaming across lossy but high bandwidth connections.
//!
//! # Quick start
//! ```rust
//! use srt_tokio::SrtSocket;
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
//!         let mut tx = SrtSocket::builder().listen(2223).await?;
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
//!         let mut rx = SrtSocket::builder().call("127.0.0.1:2223", None).await?;
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
mod listener;
mod multiplex;
mod net;
mod pending_connection;
mod socket;
mod watch;

pub mod options;
pub use srt_protocol::access;

pub use crate::{
    builder::{ConnInitMethod, SrtSocketBuilder},
    listener::{ConnectionRequest, ListenerStatistics, SrtListener},
    multiplex::{multiplex, StreamerServer},
    socket::{SocketStatistics, SrtSocket},
};
