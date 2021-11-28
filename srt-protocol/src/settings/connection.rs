use std::time::Duration;

use rand::random;

use super::*;

#[derive(Debug, Clone)]
pub struct ConnInitSettings {
    pub local_sockid: SocketId,
    pub key_settings: Option<KeySettings>,
    pub key_refresh: KeyMaterialRefreshSettings,
    pub send_latency: Duration,
    pub recv_latency: Duration,
    pub bandwidth: LiveBandwidthMode,
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
            bandwidth: LiveBandwidthMode::default(),
            recv_buffer_size: 8192,
            statistics_interval: self.statistics_interval,
        }
    }
}
