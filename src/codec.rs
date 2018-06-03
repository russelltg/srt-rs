use {
    bytes::BytesMut, std::io::{Cursor, Error, Result}, tokio_io::codec::{Decoder, Encoder}, Packet,
};

pub struct PacketCodec {}

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Packet>> {
        Packet::parse(Cursor::new(buf)).map(Some)
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
