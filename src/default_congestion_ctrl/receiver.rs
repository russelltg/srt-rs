use std::time::Duration;

use {AckMode, CCData, RecvrCongestionCtrl};

pub struct DefaultReceiverCongestionCtrl {}

impl RecvrCongestionCtrl for DefaultReceiverCongestionCtrl {
    fn on_timeout(&mut self, _data: &CCData) {
        unimplemented!()
    }

    fn on_packet_recvd(&mut self, _data: &CCData) {
        unimplemented!()
    }

    fn ack_mode(&self) -> AckMode {
        AckMode::Timer(Duration::from_millis(10)) // SYN
    }
}
