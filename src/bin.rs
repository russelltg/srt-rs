extern crate bytes;
extern crate srt;

#[macro_use]
extern crate futures;

extern crate tokio;

use std::net::ToSocketAddrs;
use srt::socket::{SrtSocket, SrtSocketBuilder};
use srt::receiver::Receiver;
use std::io::Error;

use futures::prelude::*;

use tokio::executor::current_thread;

fn main() {
    let conn = SrtSocketBuilder::new("127.0.0.1:1231".to_socket_addrs().unwrap().next().unwrap())
        .build()
        .unwrap()
        .map(|(sock, addr)| {
            println!("Connected to {:?}", addr);
        });

    current_thread::run(|_| {
        current_thread::spawn(conn.map_err(|e| {
            eprintln!("Error received: {:?}", e);
        }));
    });
}
