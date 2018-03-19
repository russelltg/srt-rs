use std::net::SocketAddr;

use tokio_core::net::UdpCodec;

pub struct PacketCodec {}

impl UdpCodec for PacketCodec {
    type In = (Packet, SocketAddr);
    type Out = (Packet, SocketAddr);

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> Result<(Packet, SocketAddr)> {
        (Packet::parse(buf)?, src)
    }

    fn encode(&mut self, msg: (Packet, SocketAddr), buf: &mut Vec<u8>) -> SocketAddr {
        let (packet, addr) = msg;

        packet.serialize(buf);

        addr
    }
}
