extern crate srt;

extern crate bytes;
extern crate futures;
extern crate futures_timer;
extern crate tokio;

use std::time::Duration;

use bytes::BytesMut;
use futures::prelude::Future;
use futures_timer::Delay;

fn main() {
    let sock = srt::SrtSocketBuilder::new("127.0.0.1:0".parse().unwrap())
        .build_raw()
        .unwrap();

    sock.send_packet(
        &srt::Packet::Control {
            timestamp: 0,
            dest_sockid: 0,
            control_type: srt::packet::ControlTypes::Handshake(srt::packet::HandshakeControlInfo {
                udt_version: 4,
                sock_type: srt::packet::SocketType::Datagram,
                init_seq_num: 1827131,
                max_packet_size: 1500,
                max_flow_size: 25600,
                connection_type: srt::packet::ConnectionType::Regular,
                socket_id: 1238912,
                syn_cookie: 0,
                peer_addr: "127.0.0.1".parse().unwrap(),
            }),
        },
        &"127.0.0.1:1231".parse().unwrap(),
        // get the packet
    ).and_then(|s| s.recv_packet().map_err(|(_, e)| e))
        .and_then(|(sock, addr, pack)| {
            Delay::new(Duration::from_secs(1)).map(move |_| (sock, addr, pack))
        })
        .and_then(|(sock, addr, mut pack)| {
            println!("Handshake from {:?}", addr);

            if let srt::Packet::Control {
                ref mut dest_sockid,
                control_type:
                    srt::packet::ControlTypes::Handshake(srt::packet::HandshakeControlInfo {
                        ref mut connection_type,
                        ..
                    }),
                ..
            } = pack
            {
                *connection_type = srt::packet::ConnectionType::RendezvousRegularSecond;
                *dest_sockid = 0;
            }

            sock.send_packet(&pack, &addr)
        })
        .and_then(|s| s.recv_packet().map_err(|(_, e)| e))
        .and_then(|(sock, addr, pack)| {
            println!("Gotten second handshake");

            // assign sockid
            let sockid = if let srt::Packet::Control {
                control_type:
                    srt::packet::ControlTypes::Handshake(srt::packet::HandshakeControlInfo {
                        socket_id,
                        ..
                    }),
                ..
            } = pack
            {
                socket_id
            } else {
                0
            };

            sock.send_packet(
                &srt::Packet::Data {
                    seq_number: 1827131,
                    message_loc: srt::packet::PacketLocation::Only,
                    in_order_delivery: false,
                    message_number: 1,
                    timestamp: 123131,
                    dest_sockid: sockid,
                    payload: BytesMut::from(&b"1293129083712903712938712937"[..]),
                },
                &addr,
            ).map(move |s| (s, addr, sockid))
        })
        .and_then(|(s, addr, sockid)| {
            Delay::new(Duration::from_secs(1)).map(move |_| (s, addr, sockid))
        })
        .and_then(|(sock, addr, sockid)| {
            sock.send_packet(
                &srt::Packet::Data {
                    seq_number: 1827132,
                    message_loc: srt::packet::PacketLocation::Only,
                    in_order_delivery: false,
                    message_number: 2,
                    timestamp: 212311,
                    dest_sockid: sockid,
                    payload: BytesMut::from(&b"1293129083712903712938712937"[..]),
                },
                &addr,
            )
        })
        .and_then(|s| s.recv_packet().map_err(|(_, e)| e))
        .map(|(_, _, packet)| println!("{:?}", packet))
        .map_err(|e| eprintln!("Error: {:?}", e))
        .wait()
        .unwrap();
}
