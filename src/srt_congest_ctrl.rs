use {std::time::Duration, CongestCtrl};

pub struct SrtCongestCtrl;

impl CongestCtrl for SrtCongestCtrl {
    fn send_interval(&self) -> Duration {
        Duration::from_secs(0)
    }

    fn window_size(&self) -> u32 {
        100000
    }
}
