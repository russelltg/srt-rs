use std::io::Error;
use std::time::Duration;
use std::iter::repeat;
use std::net::SocketAddr;

use recv_dgram_timeout::RecvDgramTimeout;

use tokio::net::UdpSocket;
use futures::prelude::*;
use packet::Packet;

pub fn recv_packet_timeout(
    sock: &mut UdpSocket,
    timeout: Duration,
) -> Box<Future<Item = (UdpSocket, Option<(SocketAddr, Result<Packet>)>), Error = Error>> {
    let buffer: Vec<_> = repeat(b'\0').take(63356).collect();

    return Box::new(
        RecvDgramTimeout::new(sock, timeout, buffer).map(|(sock, buff, data)| {
            if let Some((size, addr)) = data {
                // data was received, parse it
                return (
                    sock,
                    Some((addr, Packet::parse(Cursor::new(&buff[0..n_bytes])))),
                );
            }

            return (sock, None);
        }),
    );
}
