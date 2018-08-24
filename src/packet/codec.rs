use bytes::BytesMut;
use failure::Error;
use std::io::Cursor;
use tokio_io::codec::{Decoder, Encoder};
use Packet;

pub struct PacketCodec {}

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Packet>, Error> {
        Packet::parse(&mut Cursor::new(buf)).map(Some)
    }
}

impl Encoder for PacketCodec {
    type Item = Packet;
    type Error = Error;

    fn encode(&mut self, packet: Packet, buf: &mut BytesMut) -> Result<(), Error> {
        packet.serialize(buf);

        Ok(())
    }
}
