use std::io::{Cursor, Error, Result};

use packet::Packet;
use bytes::BytesMut;
use tokio_io::codec::{Decoder, Encoder};

pub struct PacketCodec {}

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Packet>> {
        Packet::parse(Cursor::new(buf)).map(|p| Some(p))
    }
}

impl Encoder for PacketCodec {
    type Item = Packet;
    type Error = Error;

    fn encode(&mut self, packet: Packet, buf: &mut BytesMut) -> Result<()> {
        packet.serialize(buf);

        Ok(())
    }
}
