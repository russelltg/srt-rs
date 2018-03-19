extern crate srt;

extern crate futures;

extern crate log;
extern crate simple_logger;
extern crate tokio;
extern crate tokio_io;

use log::LevelFilter;

use srt::socket::SrtSocketBuilder;
use srt::connection::Connection;
use tokio::net::UdpSocket;
use tokio::net::UdpFramed;
use tokio_io::codec::BytesCodec;

use futures::prelude::*;

use tokio::executor::current_thread;

fn main() {
    simple_logger::init().unwrap();
    log::set_max_level(LevelFilter::Info);

    let pending_connection = SrtSocketBuilder::new("127.0.0.1:1231".parse().unwrap())
        .build()
        .unwrap();

    current_thread::run(|_| {
        current_thread::spawn(
            pending_connection
                .map_err(|e| eprintln!("Error: {:?}", e))
                .and_then(|c| match c {
                    Connection::Recv(r) => {
                        UdpFramed::new(
                            UdpSocket::bind(&"127.0.0.1:0".parse().unwrap()).unwrap(),
                            BytesCodec::new(),
                        ).send_all(r.map(|buf| (buf, "127.0.0.1:8111".parse().unwrap())))
                            .map_err(|e| println!("{:?}", e))
                    }
                    _ => panic!(),
                })
                .map(|(_, _)| {}),
        );
    });
}
