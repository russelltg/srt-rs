extern crate bytes;
extern crate srt;

#[macro_use]
extern crate futures;

extern crate tokio;

use std::net::ToSocketAddrs;
use srt::socket::{SrtSocketBuilder, SrtSocket};
use std::io::{Error};

use futures::prelude::*;

use tokio::executor::current_thread;

struct Peer {
    sock: SrtSocket,
}

impl Future for Peer {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        loop {
            let packet = try_ready!(self.sock.poll());
            println!("{:?}", packet);
        }
    }
}

fn main() {

    let peer = Peer{sock: SrtSocketBuilder::new("127.0.0.1:8171".to_socket_addrs().unwrap().next().unwrap()).build().unwrap()};

    current_thread::run(|_| {
        current_thread::spawn(peer.map_err(|e| {
            eprintln!("Error received: {:?}", e);
        }));
    });
}
