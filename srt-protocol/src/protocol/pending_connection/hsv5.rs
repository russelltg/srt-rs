//! Defines the HSV5 "state machine"

use std::{
    cmp::{max, min},
    net::SocketAddr,
    time::Instant,
};

use crate::{connection::ConnectionSettings, options::*, packet::*, settings::*};

use super::{ConnectError, ConnectionReject};

#[allow(clippy::large_enum_variant)]
pub enum GenHsv5Result {
    Accept(HandshakeVsInfo, ConnectionSettings),
    NotHandled(ConnectError),
    Reject(ConnectionReject),
}

pub fn gen_hsv5_response(
    settings: &mut ConnInitSettings,
    with_hsv5: &HandshakeControlInfo,
    from: SocketAddr,
    induction_time: Instant,
    now: Instant,
) -> GenHsv5Result {
    let incoming = match &with_hsv5.info {
        HandshakeVsInfo::V5(hs) => hs,
        _ => {
            return GenHsv5Result::Reject(ConnectionReject::Rejecting(
                ServerRejectReason::Version.into(), // TODO: this error is technically reserved for access control handlers, as the ref impl supports hsv4+5, while we only support 5
            ));
        }
    };

    gen_access_control_response(
        now,
        settings,
        from,
        induction_time,
        with_hsv5.clone(),
        incoming.clone(),
        None,
    )
}

pub fn gen_access_control_response(
    now: Instant,
    settings: &mut ConnInitSettings,
    from: SocketAddr,
    induction_time: Instant,
    with_hsv5: HandshakeControlInfo,
    incoming: HsV5Info,
    key_settings: Option<KeySettings>,
) -> GenHsv5Result {
    // apply parameters generated by acceptor
    if let Some(ks) = key_settings {
        settings.key_settings = Some(ks);
    }

    let hs = match incoming.ext_hs {
        Some(SrtControlPacket::HandshakeRequest(hs)) => hs,
        Some(_) => return GenHsv5Result::NotHandled(ConnectError::ExpectedHsReq),
        None => return GenHsv5Result::NotHandled(ConnectError::ExpectedExtFlags),
    };

    // crypto
    let cipher = match (&settings.key_settings, &incoming.ext_km) {
        // ok, both sizes have crypto
        (Some(key_settings), Some(SrtControlPacket::KeyRefreshRequest(km))) => {
            if key_settings.key_size.as_usize() != incoming.crypto_size as usize {
                unimplemented!("Key size mismatch");
            }

            let cipher = match CipherSettings::new(key_settings, &settings.key_refresh, km) {
                Ok(cm) => cm,
                Err(_) => {
                    return GenHsv5Result::Reject(ConnectionReject::Rejecting(
                        CoreRejectReason::BadSecret.into(),
                    ))
                }
            };
            Some(cipher)
        }
        // ok, neither have crypto
        (None, None) => None,
        // bad cases
        (Some(_), Some(_)) => unimplemented!("Expected kmreq"),
        (Some(_), None) => {
            return GenHsv5Result::Reject(ConnectionReject::Rejecting(
                CoreRejectReason::Unsecure.into(),
            ))
        }
        (None, Some(_)) => unimplemented!("expected no secrets"),
    };

    let outgoing_ext_km = cipher
        .as_ref()
        .and_then(CipherSettings::wrap_keying_material);

    let sid = if let HandshakeVsInfo::V5(info) = &with_hsv5.info {
        info.sid.clone()
    } else {
        None
    };

    let rtt = now - induction_time;

    GenHsv5Result::Accept(
        HandshakeVsInfo::V5(HsV5Info {
            crypto_size: cipher
                .as_ref()
                .map(|c| c.key_settings.key_size.as_usize())
                .unwrap_or(0) as u8,
            ext_hs: Some(SrtControlPacket::HandshakeResponse(SrtHandshake {
                version: SrtVersion::CURRENT,
                flags: SrtShakeFlags::SUPPORTED,
                send_latency: settings.send_latency,
                recv_latency: settings.recv_latency,
            })),
            ext_km: outgoing_ext_km.map(SrtControlPacket::KeyRefreshResponse),
            ext_group: None,
            sid,
        }),
        ConnectionSettings {
            remote: from,
            rtt,
            socket_start_time: now - rtt / 2, // initiate happened 0.5RTT ago
            remote_sockid: with_hsv5.socket_id,
            init_seq_num: with_hsv5.init_seq_num,
            cipher,
            stream_id: incoming.sid,
            max_flow_size: max(settings.max_flow_size, with_hsv5.max_flow_size),
            max_packet_size: min(settings.max_packet_size, with_hsv5.max_packet_size),
            send_tsbpd_latency: max(settings.send_latency, hs.recv_latency),
            recv_tsbpd_latency: max(settings.recv_latency, hs.send_latency),
            bandwidth: settings.bandwidth.clone(),
            local_sockid: settings.local_sockid,
            recv_buffer_size: settings.recv_buffer_size,
            send_buffer_size: settings.send_buffer_size,
            statistics_interval: settings.statistics_interval,
        },
    )
}

#[derive(Debug, Clone)] // TOOD: make not clone
pub struct StartedInitiator {
    cipher: Option<CipherSettings>,
    settings: ConnInitSettings,
    streamid: Option<String>,
    initiate_time: Instant,
}

// TODO: this could check that the responder returns the same initial sequence number that we send
pub fn start_hsv5_initiation(
    settings: ConnInitSettings,
    streamid: Option<String>,
    now: Instant,
) -> (HandshakeVsInfo, StartedInitiator) {
    let self_crypto_size = settings
        .key_settings
        .as_ref()
        .map(|key_settings| key_settings.key_size.as_usize() as u8)
        .unwrap_or(0);

    // if peer_crypto_size != self_crypto_size {
    //     unimplemented!("Unimplemted crypto mismatch!");
    // }

    let (cipher, ext_km) = if let Some(ks) = &settings.key_settings {
        let cipher = CipherSettings::new_random(ks, &settings.key_refresh);
        let keying_material = cipher
            .wrap_keying_material()
            .map(SrtControlPacket::KeyRefreshRequest);
        (Some(cipher), keying_material)
    } else {
        (None, None)
    };

    (
        HandshakeVsInfo::V5(HsV5Info {
            crypto_size: self_crypto_size,
            ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                version: SrtVersion::CURRENT,
                flags: SrtShakeFlags::SUPPORTED,
                send_latency: settings.send_latency,
                recv_latency: settings.recv_latency,
            })),
            ext_km,
            ext_group: None,
            sid: streamid.clone(),
        }),
        StartedInitiator {
            cipher,
            settings,
            streamid,
            initiate_time: now,
        },
    )
}

impl StartedInitiator {
    pub fn finish_hsv5_initiation(
        self,
        response: &HandshakeControlInfo,
        from: SocketAddr,
        now: Instant,
    ) -> Result<ConnectionSettings, ConnectError> {
        // TODO: factor this out with above...
        let incoming = match &response.info {
            HandshakeVsInfo::V5(hs) => hs,
            i => return Err(ConnectError::UnsupportedProtocolVersion(i.version())),
        };

        let hs = match incoming.ext_hs {
            Some(SrtControlPacket::HandshakeResponse(hs)) => hs,
            Some(_) => return Err(ConnectError::ExpectedHsResp),
            None => return Err(ConnectError::ExpectedExtFlags),
        };

        // todo: validate km!

        // validate response
        Ok(ConnectionSettings {
            remote: from,
            rtt: now - self.initiate_time,
            socket_start_time: self.initiate_time,
            init_seq_num: response.init_seq_num,
            remote_sockid: response.socket_id,
            cipher: self.cipher,
            stream_id: self.streamid,
            max_flow_size: max(self.settings.max_flow_size, response.max_flow_size),
            max_packet_size: min(self.settings.max_packet_size, response.max_packet_size),
            send_tsbpd_latency: max(self.settings.send_latency, hs.recv_latency),
            recv_tsbpd_latency: max(self.settings.recv_latency, hs.send_latency),
            bandwidth: self.settings.bandwidth,
            local_sockid: self.settings.local_sockid,
            recv_buffer_size: self.settings.recv_buffer_size,
            send_buffer_size: self.settings.send_buffer_size,
            statistics_interval: self.settings.statistics_interval,
        })
    }
}
