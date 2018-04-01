use std::time::Duration;

use congestion_control::{CCVariables, CCState, CongestionControl};

pub struct DefaultCongestionControl {
    window_size: i32,
    inter_interval: Duration,
    phase: Phase,
}

impl DefaultCongestionControl {
    fn new() -> DefaultCongestionControl {
        DefaultCongestionControl {
            window_size: 16,
            inter_interval: Duration::from_secs(0),
            phase: Phase::SlowStart,
        }
    }
}

enum Phase {
    SlowStart,
    Operation,
}

impl CongestionControl for DefaultCongestionControl {
  
    fn init(&mut self, _state: &CCState, _vars: &mut CCVariables) {}
    fn close(&mut self, state: &CCState, vars: &mut CCVariables) {}
    fn on_ack(&mut self, state: &CCState, vars: &mut CCVariables) {
        // On ACK packet received:
        // 1) If the current status is in the slow start phase, set the
        //     congestion window size to the product of packet arrival rate and
        //     (RTT + SYN). Slow Start ends. Stop.
        if let Phase::SlowStart = self.phase {

        };
        // 2) Set the congestion window size (CWND) to: CWND = A * (RTT + SYN) +
        //     16.
        // 3) The number of sent packets to be increased in the next SYN period
        //     (inc) is calculated as:
        //         if (B <= C)
        //         inc = 1/PS;
        //         else
        //         inc = max(10^(ceil(log10((B-C)*PS*8))) * Beta/PS, 1/PS);
        //     where B is the estimated link capacity and C is the current
        //     sending speed. All are counted as packets per second. PS is the
        //     fixed size of UDT packet counted in bytes. Beta is a constant
        //     value of 0.0000015.
        // 4) The SND period is updated as:
        //         SND = (SND * SYN) / (SND * inc + SYN).

        // These four parameters are used in rate decrease, and their initial
        // values are in the parentheses: AvgNAKNum (1), NAKCount (1),
        // DecCount(1), LastDecSeq (initial sequence number - 1).

        // We define a congestion period as the period between two NAKs in which
        // the first biggest lost packet sequence number is greater than the
        // LastDecSeq, which is the biggest sequence number when last time the
        // packet sending rate is decreased.

        // AvgNAKNum is the average number of NAKs in a congestion period.
        // NAKCount is the current number of NAKs in the current period.
    }
    fn on_nak(state: &CCState, vars: &mut CCVariables) {}
    fn on_timeout(state: &CCState, vars: &mut CCVariables) {}
    fn on_packet_sent(state: &CCState, vars: &mut CCVariables) {}
    fn on_packet_recv(state: &CCState, vars: &mut CCVariables) {}
}
