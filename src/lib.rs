#![feature(conservative_impl_trait)]

extern crate byteorder;
extern crate bytes;

#[macro_use]
extern crate futures;
extern crate tokio;
extern crate tokio_io;

pub mod socket;
pub mod packet;
