//! Defines the HSV5 "state machine"

use super::{ConnInitSettings, ConnectError};
use crate::{
    crypto::CryptoManager,
    packet::{
        HSV5Info, HandshakeControlInfo, HandshakeVSInfo, SrtControlPacket, SrtHandshake,
        SrtShakeFlags,
    },
    ConnectionSettings, SrtVersion,
};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

pub fn gen_hsv5_response(
    settings: ConnInitSettings,
    with_hsv5: &HandshakeControlInfo,
    from: SocketAddr,
) -> Result<(HandshakeVSInfo, ConnectionSettings), ConnectError> {
    let incoming = match &with_hsv5.info {
        HandshakeVSInfo::V5(hs) => hs,
        i => return Err(ConnectError::UnsupportedProtocolVersion(i.version())),
    };

    let hs = match incoming.ext_hs {
        Some(SrtControlPacket::HandshakeRequest(hs)) => hs,
        Some(_) => return Err(ConnectError::ExpectedHSReq),
        None => return Err(ConnectError::ExpectedExtFlags),
    };

    // crypto
    let cm = match (&settings.crypto, &incoming.ext_km) {
        // ok, both sizes have crypto
        (Some(co), Some(SrtControlPacket::KeyManagerRequest(km))) => {
            if co.size != incoming.crypto_size {
                unimplemented!("Key size mismatch");
            }

            Some(CryptoManager::new_from_kmreq(co.clone(), km)?)
        }
        // ok, neither have crypto
        (None, None) => None,
        // bad cases
        (Some(_), Some(_)) => unimplemented!("Expected kmreq"),
        (Some(_), None) | (None, Some(_)) => unimplemented!("Crypto mismatch"),
    };
    let outgoing_ext_km = if let Some(cm) = &cm {
        Some(cm.generate_km())
    } else {
        None
    };

    Ok((
        HandshakeVSInfo::V5(HSV5Info {
            crypto_size: cm.as_ref().map(|c| c.key_length()).unwrap_or(0),
            ext_hs: Some(SrtControlPacket::HandshakeResponse(SrtHandshake {
                version: SrtVersion::CURRENT,
                flags: SrtShakeFlags::SUPPORTED,
                send_latency: settings.send_latency,
                recv_latency: settings.recv_latency,
            })),
            ext_km: outgoing_ext_km.map(SrtControlPacket::KeyManagerResponse),
            sid: None,
        }),
        ConnectionSettings {
            remote: from,
            remote_sockid: with_hsv5.socket_id,
            local_sockid: settings.local_sockid,
            socket_start_time: Instant::now(), // xxx?
            init_send_seq_num: settings.starting_send_seqnum,
            init_recv_seq_num: with_hsv5.init_seq_num,
            max_packet_size: 1500, // todo: parameters!
            max_flow_size: 8192,
            send_tsbpd_latency: Duration::max(settings.send_latency, hs.recv_latency),
            recv_tsbpd_latency: Duration::max(settings.recv_latency, hs.send_latency),
            crypto_manager: cm,
        },
    ))
}

#[derive(Debug, Clone)] // i would LOVE for this not to be clone
pub struct StartedInitiator {
    cm: Option<CryptoManager>,
    settings: ConnInitSettings,
}

pub fn start_hsv5_initiation(
    settings: ConnInitSettings,
) -> Result<(HandshakeVSInfo, StartedInitiator), ConnectError> {
    let self_crypto_size = settings.crypto.as_ref().map(|co| co.size).unwrap_or(0);

    // if peer_crypto_size != self_crypto_size {
    //     unimplemented!("Unimplemted crypto mismatch!");
    // }

    let (cm, ext_km) = if let Some(co) = &settings.crypto {
        let cm = CryptoManager::new_random(co.clone());
        let kmreq = SrtControlPacket::KeyManagerRequest(cm.generate_km());
        (Some(cm), Some(kmreq))
    } else {
        (None, None)
    };

    Ok((
        HandshakeVSInfo::V5(HSV5Info {
            crypto_size: self_crypto_size,
            ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                version: SrtVersion::CURRENT,
                flags: SrtShakeFlags::SUPPORTED,
                send_latency: settings.send_latency,
                recv_latency: settings.recv_latency,
            })),
            ext_km,
            sid: None,
        }),
        StartedInitiator { cm, settings },
    ))
}

impl StartedInitiator {
    pub fn finish_hsv5_initiation(
        self,
        response: &HandshakeControlInfo,
        from: SocketAddr,
    ) -> Result<ConnectionSettings, ConnectError> {
        // TODO: factor this out with above...
        let incoming = match &response.info {
            HandshakeVSInfo::V5(hs) => hs,
            i => return Err(ConnectError::UnsupportedProtocolVersion(i.version())),
        };

        let hs = match incoming.ext_hs {
            Some(SrtControlPacket::HandshakeResponse(hs)) => hs,
            Some(_) => return Err(ConnectError::ExpectedHSResp),
            None => return Err(ConnectError::ExpectedExtFlags),
        };

        // todo: validate km!

        // validate response
        Ok(ConnectionSettings {
            remote: from,
            remote_sockid: response.socket_id,
            local_sockid: self.settings.local_sockid,
            socket_start_time: Instant::now(), // xxx?
            init_send_seq_num: self.settings.starting_send_seqnum,
            init_recv_seq_num: response.init_seq_num,
            max_packet_size: 1500, // todo: parameters!
            max_flow_size: 8192,
            send_tsbpd_latency: Duration::max(self.settings.send_latency, hs.recv_latency),
            recv_tsbpd_latency: Duration::max(self.settings.recv_latency, hs.send_latency),
            crypto_manager: self.cm,
        })
    }
}
