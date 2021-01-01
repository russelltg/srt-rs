use crate::{Packet, PacketParseError};
use bytes::{Buf, BytesMut};
use log::debug;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

pub struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = PacketParseError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Packet>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let ret = Packet::parse(buf).map(Some);

        if !buf.is_empty() {
            debug!("Leftover bytes in packet {:?} {:?}", ret, buf.to_vec());
            buf.advance(buf.remaining()); // discard trailing bytes
        }
        ret
    }
}

impl Encoder<Packet> for PacketCodec {
    type Error = io::Error;

    fn encode(&mut self, packet: Packet, buf: &mut BytesMut) -> Result<(), Self::Error> {
        packet.serialize(buf);

        Ok(())
    }
}
