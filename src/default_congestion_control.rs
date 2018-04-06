use std::mem;
use std::time::Duration;

use srt_object::SrtObject;
use {AckMode, CongestionControl};

pub struct DefaultCongestionControl {
    inter_interval: Duration,
    phase: Phase,
    avg_nak_num: i32,
    nak_count: i32,
    dec_count: i32,
    last_dec_seq: i32,

    window_size: i32,
    send_interval: Duration,
    inter_ack_duration: Duration,
}

impl DefaultCongestionControl {
    pub fn new() -> DefaultCongestionControl {
        DefaultCongestionControl {
            inter_interval: Duration::from_secs(0),
            phase: Phase::SlowStart,
            avg_nak_num: 1,
            nak_count: 1,
            dec_count: 1,
            last_dec_seq: 0, // TODO: initial seq number - 1

            window_size: 16,
            // TODO: what is the default SND
            send_interval: Duration::from_millis(1),
            inter_ack_duration: Duration::from_millis(10), // SYN
        }
    }
}

enum Phase {
    SlowStart,
    Operation,
}

impl CongestionControl for DefaultCongestionControl {
    fn on_ack(&mut self, srt: &SrtObject) {
        // On ACK packet received:
        // 1) If the current status is in the slow start phase, set the
        //     congestion window size to the product of packet arrival rate and
        //     (RTT + SYN). Slow Start ends. Stop.

        // 2) Set the congestion window size (CWND) to: CWND = A * (RTT + SYN) +
        //     16.
        self.window_size =
            (srt.packet_arrival_rate() as f32 * (srt.rtt().as_secs() as f32 + 0.01)) as i32;

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
                10f64
                    .powf((((B - C) * PS) as f64 * 8.0).log10().ceil())
                    .max(1f64 / PS as f64)
            }
        };

        // 4) The SND period is updated as:
        //         SND = (SND * SYN) / (SND * inc + SYN).
        // I think the units for these are microseconds
        self.send_interval = {
            let snd_total_micros = self.send_interval.as_secs() * 1_000_000
                + self.send_interval.subsec_nanos() as u64 / 1_000;

            let new_snd_total_micros = ((snd_total_micros * 10_000) as f64
                / (snd_total_micros as f64 * inc + 10_000f64))
                as u64;

            Duration::new(
                new_snd_total_micros / 1_000_000,
                (new_snd_total_micros % 1_000_000) as u32 * 1_000,
            )
        };

        // We define a congestion period as the period between two NAKs in which
        // the first biggest lost packet sequence number is greater than the
        // LastDecSeq, which is the biggest sequence number when last time the
        // packet sending rate is decreased.

        // TODO: what's a congestion period

        // AvgNAKNum is the average number of NAKs in a congestion period.
        // NAKCount is the current number of NAKs in the current period.
    }
    fn on_nak(&mut self, srt: &SrtObject) {}
    fn on_timeout(&mut self, srt: &SrtObject) {}
    fn on_packet_sent(&mut self, srt: &SrtObject) {}
    fn on_packet_recvd(&mut self, srt: &SrtObject) {}

    fn send_interval(&self) -> Duration {
        self.send_interval
    }
    fn window_size(&self) -> i32 {
        self.window_size
    }
    fn ack_mode(&self) -> AckMode {
        AckMode::Timer(self.inter_ack_duration)
    }
}
