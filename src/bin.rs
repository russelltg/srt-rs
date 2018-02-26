extern crate bytes;
extern crate srt;

use bytes::{BytesMut, IntoBuf};

use std::net::UdpSocket;
use srt::socket::SrtSocketBuilder;
use std::io::{Cursor, Error};

use futures::prelude::*;

use tokio::executor::current_thread;

struct Peer {
    sock: SrtSocket;
}

impl Future for Peer {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        while let Async::Ready(packet) = self.sock.poll()? {
            println!("{:?}", packet);
        } 
    }
}

fn main() {
    let peer = Peer{sock: SrtSocketBuilder::new("127.0.0.1:8171").build().unwrap()};

    current_thread::run(|_| {
        current_thread::spawn(peer);
    });
}
