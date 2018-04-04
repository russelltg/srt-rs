use std::time::Duration;
use std::mem;

use congestion_control::{CCVariables, CongestionControl};
use srt_object::SrtObject;

pub struct DefaultCongestionControl {
    window_size: i32,
    inter_interval: Duration,
    phase: Phase,
    avg_nak_num: i32,
    nak_count: i32,
    dec_count: i32,
    last_dec_seq: i32,
}

impl DefaultCongestionControl {
    fn new() -> DefaultCongestionControl {
        DefaultCongestionControl {
            window_size: 16,
            inter_interval: Duration::from_secs(0),
            phase: Phase::SlowStart,
            avg_nak_num: 1,
            nak_count: 1,
            dec_count: 1,
            last_dec_seq: 0, // TODO: initial seq number - 1
        }
    }
}

enum Phase {
    SlowStart,
    Operation,
}

impl<T> CongestionControl<T> for DefaultCongestionControl
where T: SrtObject {
  
    fn init(&mut self, _srt: &T, _vars: &mut CCVariables) {}
    fn close(&mut self, _srt: &T, vars: &mut CCVariables) {}
    fn on_ack(&mut self, srt: &T, vars: &mut CCVariables) {

        // On ACK packet received:
        // 1) If the current status is in the slow start phase, set the
        //     congestion window size to the product of packet arrival rate and
        //     (RTT + SYN). Slow Start ends. Stop.

        // 2) Set the congestion window size (CWND) to: CWND = A * (RTT + SYN) +
        //     16.
        vars.window_size = (srt.packet_arrival_rate() as f32 * (srt.rtt().as_secs() as f32 + 0.01)) as i32;

        if let Phase::SlowStart = mem::replace(&mut self.phase, Phase::Operation) {

            return;
        };

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
        let inc = {
            let B = srt.estimated_bandwidth();
            let C = srt.packet_send_rate().unwrap_or(0); // on receiver side, this variable isn't even used, so this unwrap doesn't matter
            let PS = srt.max_packet_size();

            if B <= C {
                1.0 / PS as f64
            } else {
                10f64.powf((((B - C) * PS) as f64 * 8.0).log10().ceil()).max(1f64 / PS as f64)
            }
        };

        // 4) The SND period is updated as:
        //         SND = (SND * SYN) / (SND * inc + SYN).
        vars.send_interval = (vars.send_interval * Duration::from_millis(10)) /
            (vars.send_interval * inc + Duration::from_millis(10));


        // We define a congestion period as the period between two NAKs in which
        // the first biggest lost packet sequence number is greater than the
        // LastDecSeq, which is the biggest sequence number when last time the
        // packet sending rate is decreased.

        // TODO: what's a congestion period

        // AvgNAKNum is the average number of NAKs in a congestion period.
        // NAKCount is the current number of NAKs in the current period.
    }
    fn on_nak(&mut self, srt: &T, vars: &mut CCVariables) {}
    fn on_timeout(&mut self, srt: &T, vars: &mut CCVariables) {}
    fn on_packet_sent(&mut self, srt: &T, vars: &mut CCVariables) {}
    fn on_packet_recv(&mut self, srt: &T, vars: &mut CCVariables) {}
}
