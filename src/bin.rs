extern crate bytes;
extern crate srt;

extern crate futures;

extern crate tokio;

use std::net::ToSocketAddrs;
use srt::socket::SrtSocketBuilder;

use futures::prelude::*;

use tokio::executor::current_thread;

fn main() {
    let pending_connection = SrtSocketBuilder::new(
        "127.0.0.1:1231".to_socket_addrs().unwrap().next().unwrap(),
    ).build()
        .unwrap();

    current_thread::run(|_| {
        current_thread::spawn(
            pending_connection
                .map_err(|e| {
                    eprintln!("Error received: {:?}", e);
                })
                .map(|_| {}),
        );
    });
}
