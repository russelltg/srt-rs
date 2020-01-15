use std::time::Duration;

use crate::CongestCtrl;

pub struct SrtCongestCtrl;

impl CongestCtrl for SrtCongestCtrl {
    fn send_interval(&self) -> Duration {
        Duration::from_secs(0)
    }

    fn window_size(&self) -> u32 {
        10_0000
    }
}

impl SrtCongestCtrl {
    #[allow(non_snake_case)]
    pub fn SDN(&self) -> Duration {
        Duration::from_millis(100)
    }
}
