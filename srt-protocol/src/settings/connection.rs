use std::time::Duration;

use rand::random;

use crate::{options, packet::Packet};

use super::*;

#[derive(Debug, Clone)]
pub struct ConnInitSettings {
    pub local_sockid: SocketId,
    pub key_settings: Option<KeySettings>,
    pub key_refresh: KeyMaterialRefreshSettings,
    pub send_latency: Duration,
    pub recv_latency: Duration,
    pub bandwidth: options::LiveBandwidthMode,
    pub statistics_interval: Duration,

    /// Receive buffer size in packets
    pub recv_buffer_size: options::PacketCount,
    /// Size of the send buffer, in packets
    pub send_buffer_size: options::PacketCount,
    pub max_packet_size: options::PacketSize,
    pub max_flow_size: options::PacketCount,
}

impl Default for ConnInitSettings {
    fn default() -> Self {
        options::SocketOptions::default().into()
    }
}

impl ConnInitSettings {
    pub fn copy_randomize(&self) -> ConnInitSettings {
        ConnInitSettings {
            local_sockid: random(),
            ..self.clone()
        }
    }
}

impl From<options::SocketOptions> for ConnInitSettings {
    fn from(options: options::SocketOptions) -> Self {
        Self {
            local_sockid: random(),
            key_settings: options
                .encryption
                .passphrase
                .clone()
                .map(|passphrase| KeySettings {
                    key_size: options.encryption.key_size,
                    passphrase,
                }),
            key_refresh: KeyMaterialRefreshSettings::new(
                options.encryption.km_refresh.period.into(),
                options.encryption.km_refresh.pre_announcement_period.into(),
            )
            .unwrap(),
            send_latency: options.sender.peer_latency,
            recv_latency: options.receiver.latency,
            bandwidth: options.sender.bandwidth,
            statistics_interval: options.session.statistics_interval,
            recv_buffer_size: options.receiver.buffer_size
                / (options.session.max_segment_size - Packet::HEADER_SIZE),
            send_buffer_size: options.sender.buffer_size
                / (options.session.max_segment_size - Packet::HEADER_SIZE),
            max_packet_size: options.sender.max_payload_size,
            max_flow_size: options.sender.flow_control_window_size,
        }
    }
}
