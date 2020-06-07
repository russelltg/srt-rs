use crate::{Packet, PacketParseError};
use bytes::BytesMut;
use std::io::{self, Cursor};
use tokio_util::codec::{Decoder, Encoder};

pub struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = PacketParseError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Packet>, Self::Error> {
        Packet::parse(&mut Cursor::new(buf)).map(Some)
    }
}

impl Encoder<Packet> for PacketCodec {
    type Error = io::Error;

    fn encode(&mut self, packet: Packet, buf: &mut BytesMut) -> Result<(), Self::Error> {
        packet.serialize(buf);

        Ok(())
    }
}
