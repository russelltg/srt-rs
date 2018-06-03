use std::time::Duration;

use SenderCongestionCtrl;

pub struct SrtSenderCongestionCtrl {}

impl SrtSenderCongestionCtrl {
    pub fn new() -> SrtSenderCongestionCtrl {
        SrtSenderCongestionCtrl {}
    }
}

impl SenderCongestionCtrl for SrtSenderCongestionCtrl {
    fn send_interval(&self) -> Duration {
        Duration::from_secs(0)
    }

    fn window_size(&self) -> u32 {
        100000
    }
}
