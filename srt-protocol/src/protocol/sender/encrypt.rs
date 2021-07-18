use crate::crypto::CryptoManager;
use crate::packet::DataPacket;
use bytes::BytesMut;

#[derive(Debug)]
pub struct Encrypt(Option<CryptoManager>);

impl Encrypt {
    pub fn new(crypto: Option<CryptoManager>) -> Self {
        Self(crypto)
    }

    pub fn encrypt(&mut self, mut packet: DataPacket) -> (DataPacket, usize) {
        match &mut self.0 {
            Some(cm) => {
                let length = packet.payload.len();
                let mut p = BytesMut::with_capacity(length);
                p.extend_from_slice(&packet.payload[..]);
                let enc = cm.encrypt(packet.seq_number, &mut p[..]);
                packet.encryption = enc;
                packet.payload = p.freeze();
                (packet, length)
            }
            None => (packet, 0),
        }
    }
}
