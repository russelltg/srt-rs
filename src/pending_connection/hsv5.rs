//! Defines HSV5 roles

use crate::{
    crypto::{CryptoError, CryptoManager, CryptoOptions},
    packet::{HandshakeVSInfo, SrtControlPacket, SrtHandshake, SrtShakeFlags},
    SrtVersion,
};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HSV5Responder {
    crypto: Option<CryptoManager>,
    tsbpd_latency: Duration,
}

#[derive(Debug, Clone)]
pub struct HSV5Initiator {
    crypto: Option<CryptoManager>,
    tsbpd_latency: Duration,
}

impl HSV5Responder {
    pub fn new(co: Option<CryptoOptions>, latency: Duration) -> Self {
        HSV5Responder {
            crypto: co.map(|co| CryptoManager::new_empty(co)),
            tsbpd_latency: latency,
        }
    }

    pub fn gen_vs_info(&self, initiator: &HandshakeVSInfo) -> Result<HandshakeVSInfo, CryptoError> {
        todo!()
    }

    pub fn latency(&self) -> Duration {
        todo!()
    }
}

impl HSV5Initiator {
    pub fn new(co: Option<CryptoOptions>, latency: Duration) -> Self {
        HSV5Initiator {
            crypto: match co {
                Some(co) => Some(CryptoManager::new_random(co)),
                None => None,
            },
            tsbpd_latency: latency,
        }
    }

    pub fn latency(&self) -> Duration {
        todo!()
    }

    pub fn take_crypto(&mut self) -> Option<CryptoManager> {
        self.crypto.take()
    }

    pub fn gen_vs_info(&self, peer_crypto_size: u8) -> Result<HandshakeVSInfo, CryptoError> {
        let self_crypto_size = self
            .crypto
            .as_ref()
            .map(CryptoManager::key_length)
            .unwrap_or(0);

        if peer_crypto_size != self_crypto_size {
            unimplemented!("Unimplemted crypto mismatch!");
        }

        let ext_km = if let Some(cm) = &self.crypto {
            Some(SrtControlPacket::KeyManagerRequest(cm.generate_km()?))
        } else {
            None
        };

        Ok(HandshakeVSInfo::V5 {
            crypto_size: self_crypto_size,
            ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                version: SrtVersion::CURRENT,
                flags: SrtShakeFlags::SUPPORTED,
                peer_latency: Duration::from_secs(0),
                latency: self.tsbpd_latency,
            })),
            ext_km,
            ext_config: None,
        })
    }
}
