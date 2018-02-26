extern crate bytes;
extern crate srt;

use bytes::{BytesMut, IntoBuf};

use std::net::UdpSocket;
use srt::packet::Packet;
use std::io::Cursor;

fn main() {
    let sock = UdpSocket::bind("127.0.0.1:8171").unwrap();

    let mut buf: [u8; 65536] = [0; 65536];
    while let Ok((len, addr)) = sock.recv_from(&mut buf) {
        match Packet::parse(Cursor::new(&buf[0..len])) {
            Ok(mut s) => {
                if let Packet::Data(d) = s {
                    println!(
                        "Received data packet; size = {}; message = {}; pos = {:?}",
                        d.payload.len(),
                        d.message_number,
                        d.message_loc
                    );
                    continue;
                }
                println!("{:?}", s);

                let mut out = vec![];
                s.serialize(&mut out);

                sock.send_to(&out[..], addr);
            }
            Err(e) => eprintln!("{:?}", e),
        }
    }
}
