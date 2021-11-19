use bytes::BytesMut;

use crate::{
    packet::{DataEncryption, DataPacket},
    protocol::crypto::CryptoManager,
};

#[derive(Debug, Eq, PartialEq)]
pub enum DecryptionError {
    UnexpectedUnencryptedPacket(DataPacket),
    UnexpectedEncryptedPacket(DataPacket),
}

#[derive(Debug)]
pub struct Cipher(Option<CryptoManager>);

impl Cipher {
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

    pub fn decrypt(&self, data: DataPacket) -> Result<DataPacket, DecryptionError> {
        use DecryptionError::*;
        let mut data = data;
        match (data.encryption, &self.0) {
            (DataEncryption::None, None) => Ok(data),
            (DataEncryption::None, Some(_)) => Err(UnexpectedUnencryptedPacket(data)),
            (DataEncryption::Even | DataEncryption::Odd, None) => {
                Err(UnexpectedEncryptedPacket(data))
            }
            (_, Some(cm)) => {
                // this requires an extra copy here...maybe DataPacket should have a BytesMut in it instead...
                let mut bm = BytesMut::with_capacity(data.payload.len());
                bm.extend_from_slice(&data.payload[..]);
                cm.decrypt(data.seq_number, data.encryption, &mut bm);
                data.payload = bm.freeze();

                Ok(data)
            }
        }
    }
}
