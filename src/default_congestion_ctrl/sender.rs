use std::mem;
use std::time::Duration;

use {AckMode, CCData, SenderCongestionCtrl, SeqNumber};

use rand::{thread_rng, distributions::{IndependentSample, Normal}};

pub struct DefaultSenderCongestionCtrl {
    inter_interval: Duration,
    phase: Phase,
    avg_nak_num: i32,
    nak_count: i32,
    dec_count: i32,
    last_dec_seq: SeqNumber,
    dec_random: i32,

    window_size: i32,
    send_interval: Duration,
}

impl DefaultSenderCongestionCtrl {
    pub fn new() -> DefaultSenderCongestionCtrl {
        DefaultSenderCongestionCtrl {
            inter_interval: Duration::from_secs(0),
            phase: Phase::SlowStart,
            avg_nak_num: 1,
            nak_count: 1,
            dec_count: 1,
            last_dec_seq: SeqNumber(0), // this is reassigned later
            dec_random: 1,              // TODO: real init size for this

            window_size: 1000,
            // TODO: what is the default SND
            send_interval: Duration::from_millis(1),
        }
    }
}

enum Phase {
    SlowStart,
    Operation,
}

impl SenderCongestionCtrl for DefaultSenderCongestionCtrl {
    fn init(&mut self, init_seq_num: SeqNumber) {
        self.last_dec_seq = init_seq_num - 1;
    }

    fn on_ack(&mut self, data: &CCData) {
        // On ACK packet received:
        // 1) If the current status is in the slow start phase, set the
        //     congestion window size to the product of packet arrival rate and
        //     (RTT + SYN). Slow Start ends. Stop.

        // 2) Set the congestion window size (CWND) to: CWND = A * (RTT + SYN) +
        //     16.
        self.window_size = {
            let rtt_secs = data.rtt.as_secs() as f64 + data.rtt.subsec_nanos() as f64 / 1e9;

            (data.packet_arr_rate as f64 * (rtt_secs + 0.01)) as i32 + 16
        };
        // clamp it between 16 and 1000
        self.window_size = i32::max(self.window_size, 16);
        self.window_size = i32::min(self.window_size, 1000);
        info!("New window size: {}", self.window_size);

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
            let B = data.est_bandwidth as f64;

            let PS = data.max_segment_size as f64;
            // 1/send_interval is packets/second
            // packets/sec * packet_size = bytes/sec
            let C = PS * (1.0 / (self.send_interval.as_secs() as f64
                + self.send_interval.subsec_nanos() as f64 / 1e9));

            if B <= C {
                // 1.0 / PS as f64
                0.01
            } else {
                10f64
                    .powf((((B - C) * PS) * 8.0).log10().ceil())
                    .max(1.0 / PS)
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
    fn on_nak(&mut self, largest_seq_in_ll: SeqNumber, data: &CCData) {
        // 1) If it is in slow start phase, set inter-packet interval to
        // 1/recvrate. Slow start ends. Stop.

        match mem::replace(&mut self.phase, Phase::Operation) {
            Phase::SlowStart => {
                self.send_interval =
                    Duration::new(0, ((1.0 / data.packet_arr_rate as f64) * 1e9) as u32);
                return;
            }
            Phase::Operation => {}
        }

        // 2) If this NAK starts a new congestion period, increase inter-packet
        // interval (snd) to snd = snd * 1.125; Update AvgNAKNum, reset
        // NAKCount to 1, and compute DecRandom to a random (average
        // distribution) number between 1 and AvgNAKNum. Update LastDecSeq.
        //   Stop.
        if largest_seq_in_ll > self.last_dec_seq {
            self.send_interval += self.send_interval / 8;

            self.avg_nak_num = self.avg_nak_num * 7 / 8 + self.nak_count / 8;
            self.nak_count = 1;
            self.dec_count = 1;
            self.dec_random = {
                // TODO: what should the stddev be? This seems reasonable
                let dist = Normal::new(
                    (1 + self.avg_nak_num) as f64 / 2.0,
                    ((self.avg_nak_num - 1) as f64 / 3.0).abs(),
                );

                dist.ind_sample(&mut thread_rng()) as i32
            }
        }

        // 3) If DecCount <= 5, and NAKCount == DecCount * DecRandom:
        //    a. Update SND period: SND = SND * 1.125;
        //    b. Increase DecCount by 1;
        //    c. Record the current largest sent sequence number (LastDecSeq).
        if self.dec_count <= 5 && self.nak_count == self.dec_count * self.dec_random {
            self.send_interval += self.send_interval / 8;
            self.dec_count += 1;

            self.last_dec_seq = data.latest_seq_num.unwrap();
        }
    }

    fn send_interval(&self) -> Duration {
        self.send_interval
    }
    fn window_size(&self) -> i32 {
        self.window_size
    }
}
