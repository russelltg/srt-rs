use std::{convert::TryInto, time::Duration};

use rand::random;

use crate::options;

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
    pub recv_buffer_size: usize,
}

impl Default for ConnInitSettings {
    fn default() -> Self {
        ConnInitSettings {
            key_settings: None,
            key_refresh: Default::default(),
            send_latency: Duration::from_millis(50),
            recv_latency: Duration::from_micros(50),
            local_sockid: random(),
            bandwidth: Default::default(),
            recv_buffer_size: 8192,
            statistics_interval: Duration::from_secs(1),
        }
    }
}

impl ConnInitSettings {
    pub fn copy_randomize(&self) -> ConnInitSettings {
        ConnInitSettings {
            key_settings: self.key_settings.clone(),
            key_refresh: self.key_refresh.clone(),
            send_latency: self.send_latency,
            recv_latency: self.recv_latency,
            local_sockid: random(),
            bandwidth: Default::default(),
            recv_buffer_size: 8192,
            statistics_interval: self.statistics_interval,
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
                .as_ref()
                .map(|passphrase| KeySettings {
                    key_size: match options.encryption.key_size {
                        options::KeySize::Bytes16 => KeySize::Bytes16,
                        options::KeySize::Bytes24 => KeySize::Bytes24,
                        options::KeySize::Bytes32 => KeySize::Bytes32,
                    },
                    passphrase: passphrase.to_string().try_into().unwrap(),
                }),
            key_refresh: KeyMaterialRefreshSettings::new(
                options.encryption.km_refresh.period,
                options.encryption.km_refresh.pre_announcement_period,
            )
            .unwrap(),
            send_latency: options.sender.peer_latency,
            recv_latency: options.receiver.latency,
            bandwidth: options.sender.bandwidth_mode,
            statistics_interval: options.session.statistics_interval,
            recv_buffer_size: options.receiver.buffer_size,
        }
    }
}
