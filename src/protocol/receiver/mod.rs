use std::cmp::Ordering;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::iter::Iterator;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use log::{debug, info, trace, warn};

use super::{TimeSpan, Timer};
use crate::loss_compression::compress_loss_list;
use crate::packet::{
    ControlPacket, ControlTypes, DataPacket, HandshakeControlInfo, Packet, SrtControlPacket,
};
use crate::protocol::handshake::Handshake;
use crate::protocol::TimeStamp;
use crate::{seq_number::seq_num_range, ConnectionSettings, SeqNumber};

mod buffer;
mod time;

use buffer::RecvBuffer;

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ReceiverAlgorithmAction {
    TimeBoundedReceive(Instant),
    SendControl(ControlPacket, SocketAddr),
    OutputData((Instant, Bytes)),
    Close,
}

struct ReceiveTimers {
    syn: Timer,
    ack: Timer,
    nak: Timer,
}

impl ReceiveTimers {
    pub fn new(now: Instant) -> ReceiveTimers {
        let syn = Duration::from_millis(10);
        ReceiveTimers {
            syn: Timer::new(syn, now),
            ack: Timer::new(syn, now),
            nak: Timer::new(syn, now),
        }
    }

    pub fn update_rtt(&mut self, rtt: TimeSpan, rtt_var: TimeSpan) {
        let rtt = Duration::from_micros(rtt.as_micros() as u64);
        let rtt_var = Duration::from_micros(rtt_var.as_micros() as u64);
        self.nak.set_period(4 * rtt + rtt_var + self.syn.period());
        self.ack.set_period(4 * rtt + rtt_var + self.syn.period());
    }

    pub fn next_timer(&self) -> Instant {
        min(self.ack.next_instant(), self.nak.next_instant())
    }
}

struct LossListEntry {
    seq_num: SeqNumber,

    // last time it was feed into NAK
    feedback_time: TimeStamp,

    // the number of times this entry has been fed back into NAK
    k: i32,
}

struct AckHistoryEntry {
    /// the highest packet sequence number received that this ACK packet ACKs + 1
    ack_number: SeqNumber,

    /// the ack sequence number
    ack_seq_num: i32,

    /// timestamp that it was sent at
    timestamp: TimeStamp,
}

pub struct Receiver {
    settings: ConnectionSettings,

    handshake: Handshake,

    timers: ReceiveTimers,

    control_packets: VecDeque<Packet>,

    data_release: VecDeque<(Instant, Bytes)>,

    /// the round trip time, in microseconds
    /// is calculated each ACK2
    rtt: TimeSpan,

    /// the round trip time variance, in microseconds
    /// is calculated each ACK2
    rtt_variance: TimeSpan,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// Receiver's Loss List: It is a list of tuples whose values include:
    /// the sequence numbers of detected lost data packets, the latest
    /// feedback time of each tuple, and a parameter k that is the number
    /// of times each one has been fed back in NAK. Values are stored in
    /// the increasing order of packet sequence numbers.
    loss_list: Vec<LossListEntry>,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// ACK History Window: A circular array of each sent ACK and the time
    /// it is sent out. The most recent value will overwrite the oldest
    /// one if no more free space in the array.
    ack_history_window: Vec<AckHistoryEntry>,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// PKT History Window: A circular array that records the arrival time
    /// of each data packet.
    ///
    /// First is sequence number, second is timestamp
    packet_history_window: Vec<(SeqNumber, TimeStamp)>,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// Packet Pair Window: A circular array that records the time
    /// interval between each probing packet pair.
    ///
    /// First is seq num, second is time
    packet_pair_window: Vec<(SeqNumber, TimeSpan)>,

    /// the highest received packet sequence number + 1
    lrsn: SeqNumber,

    /// The ID of the next ack packet
    next_ack: i32,

    /// The timestamp of the probe time
    /// Used to see duration between packets
    probe_time: Option<TimeStamp>,

    /// The ACK sequence number of the largest ACK2 received, and the ack number
    lr_ack_acked: (i32, SeqNumber),

    /// The buffer
    receive_buffer: RecvBuffer,

    /// Shutdown flag. This is set so when the buffer is flushed, it returns Async::Ready(None)
    shutdown_flag: bool,
}

impl Receiver {
    pub fn new(settings: ConnectionSettings, handshake: Handshake) -> Self {
        let init_seq_num = settings.init_seq_num;

        info!(
            "Receiving started from {:?}, with latency={:?}",
            settings.remote, settings.tsbpd_latency
        );

        Receiver {
            settings,
            timers: ReceiveTimers::new(settings.socket_start_time),
            control_packets: VecDeque::new(),
            data_release: VecDeque::new(),
            handshake,
            rtt: TimeSpan::from_micros(10_000),
            rtt_variance: TimeSpan::from_micros(1_000),
            loss_list: Vec::new(),
            ack_history_window: Vec::new(),
            packet_history_window: Vec::new(),
            packet_pair_window: Vec::new(),
            lrsn: init_seq_num, // at start, we have received everything until the first packet, exclusive (aka nothing)
            next_ack: 1,
            probe_time: None,
            lr_ack_acked: (0, init_seq_num),
            receive_buffer: RecvBuffer::with(&settings),
            shutdown_flag: false,
        }
    }

    pub fn handle_shutdown(&mut self) {
        self.shutdown_flag = true;
    }

    // handles an incoming a packet
    pub fn handle_packet(&mut self, now: Instant, (packet, from): (Packet, SocketAddr)) {
        // We don't care about packets from elsewhere
        if from != self.settings.remote {
            info!("Packet received from unknown address: {:?}", from);
            return;
        }

        if self.settings.local_sockid != packet.dest_sockid() {
            // packet isn't applicable
            info!(
                "Packet send to socket id ({}) that does not match local ({})",
                packet.dest_sockid().0,
                self.settings.local_sockid.0
            );
            return;
        }

        trace!("Received packet: {:?}", packet);

        match packet {
            Packet::Control(ctrl) => {
                self.receive_buffer.synchronize_clock(now, ctrl.timestamp);

                // handle the control packet
                match ctrl.control_type {
                    ControlTypes::Ack { .. } => warn!("Receiver received ACK packet, unusual"),
                    ControlTypes::Ack2(seq_num) => self.handle_ack2(seq_num, now),
                    ControlTypes::DropRequest { .. } => unimplemented!(),
                    ControlTypes::Handshake(shake) => self.handle_handshake_packet(now, shake),
                    ControlTypes::KeepAlive => {} // TODO: actually reset EXP etc
                    ControlTypes::Nak { .. } => warn!("Receiver received NAK packet, unusual"),
                    ControlTypes::Shutdown => {
                        info!("Shutdown packet received, flushing receiver...");
                        self.shutdown_flag = true;
                    } // end of stream
                    ControlTypes::Srt(srt_packet) => {
                        self.handle_srt_control_packet(srt_packet);
                    }
                }
            }
            Packet::Data(data) => self.handle_data_packet(&data, now),
        };
    }

    /// 6.2 The Receiver's Algorithm
    pub fn next_algorithm_action(&mut self, now: Instant) -> ReceiverAlgorithmAction {
        use ReceiverAlgorithmAction::*;

        //   Data Sending Algorithm:
        //   1) Query the system time to check if ACK, NAK, or EXP timer has
        //      expired. If there is any, process the event (as described below
        //      in this section) and reset the associated time variables. For
        //      ACK, also check the ACK packet interval.
        if self.timers.ack.check_expired(now).is_some() {
            self.on_ack_event(now);
        }
        if self.timers.nak.check_expired(now).is_some() {
            self.on_nak_event(now);
        }

        if let Some(data) = self.pop_data(now) {
            OutputData(data)
        } else if let Some(Packet::Control(packet)) = self.pop_conotrol_packet() {
            SendControl(packet, self.settings.remote)
        } else if self.shutdown_flag && self.is_flushed() {
            Close
        } else {
            // 2) Start time bounded UDP receiving. If no packet arrives, go to 1).
            TimeBoundedReceive(self.next_timer(now))
        }
    }

    pub fn is_flushed(&self) -> bool {
        self.receive_buffer.next_msg_ready().is_none()
    }

    fn on_ack_event(&mut self, now: Instant) {
        trace!("Ack event hit {:?}", self.settings.local_sockid);
        // get largest inclusive received packet number
        let ack_number = match self.loss_list.first() {
            // There is an element in the loss list
            Some(i) => i.seq_num,
            // No elements, use lrsn, as it's already exclusive
            None => self.lrsn,
        };

        // 2) If (a) the ACK number equals to the largest ACK number ever
        //    acknowledged by ACK2
        if ack_number == self.lr_ack_acked.1 {
            // stop (do not send this ACK).
            return;
        }

        // make sure this ACK number is greater or equal to a one sent previously
        if let Some(w) = self.ack_history_window.last() {
            assert!(w.ack_number <= ack_number);
        }

        trace!(
            "Sending ACK; ack_num={:?}, lr_ack_acked={:?}",
            ack_number,
            self.lr_ack_acked.1
        );

        if let Some(&AckHistoryEntry {
            ack_number: last_ack_number,
            timestamp: last_timestamp,
            ..
        }) = self.ack_history_window.first()
        {
            // or, (b) it is equal to the ACK number in the
            // last ACK
            if last_ack_number == ack_number &&
                // and the time interval between this two ACK packets is
                // less than 2 RTTs,
                (self.receive_buffer.timestamp_from(now) - last_timestamp) < (self.rtt * 2)
            {
                // stop (do not send this ACK).
                return;
            }
        }

        // 3) Assign this ACK a unique increasing ACK sequence number.
        let ack_seq_num = self.next_ack;
        self.next_ack += 1;

        // 4) Calculate the packet arrival speed according to the following
        // algorithm:
        let packet_recv_rate = if self.packet_history_window.len() < 16 {
            0
        } else {
            // Calculate the median value of the last 16 packet arrival
            // intervals (AI) using the values stored in PKT History Window.
            let mut last_16: Vec<_> = self.packet_history_window
                [self.packet_history_window.len() - 16..]
                .windows(2)
                .map(|w| w[1].1 - w[0].1) // delta time
                .collect();
            last_16.sort();

            // the median AI
            let ai = last_16[last_16.len() / 2];

            // In these 16 values, remove those either greater than AI*8 or
            // less than AI/8.
            let filtered: Vec<TimeSpan> = last_16
                .iter()
                .filter(|&&n| n / 8 < ai && n > ai / 8)
                .cloned()
                .collect();

            // If more than 8 values are left, calculate the
            // average of the left values AI', and the packet arrival speed is
            // 1/AI' (number of packets per second). Otherwise, return 0.
            if filtered.len() > 8 {
                // 1e6 / (sum / len) = len * 1e6 / sum
                (1_000_000 * filtered.len()) as u64
                    / filtered
                        .iter()
                        .map(|dt| i64::from(dt.as_micros()))
                        .sum::<i64>() as u64 // all these dts are garunteed to be positive
            } else {
                0
            }
        } as u32;

        // 5) Calculate the estimated link capacity according to the following algorithm:
        let est_link_cap = {
            if self.packet_pair_window.len() < 16 {
                0
            } else {
                //  Calculate the median value of the last 16 packet pair
                //  intervals (PI) using the values in Packet Pair Window, and the
                //  link capacity is 1/PI (number of packets per second).
                let pi = {
                    let mut last_16: Vec<_> = self.packet_pair_window
                        [self.packet_pair_window.len() - 16..]
                        .iter()
                        .map(|&(_, time)| time)
                        .collect();
                    last_16.sort_unstable();

                    last_16[last_16.len() / 2]
                };

                (1. / (pi.as_secs_f64())) as i32
            }
        };

        // Pack the ACK packet with RTT, RTT Variance, and flow window size (available
        // receiver buffer size).

        self.send_control(
            now,
            ControlTypes::Ack {
                ack_seq_num,
                ack_number,
                rtt: Some(self.rtt),
                rtt_variance: Some(self.rtt_variance),
                buffer_available: None, // TODO: add this
                packet_recv_rate: Some(packet_recv_rate),
                est_link_cap: Some(est_link_cap),
            },
        );

        // add it to the ack history
        let ts_now = self.receive_buffer.timestamp_from(now);
        self.ack_history_window.push(AckHistoryEntry {
            ack_number,
            ack_seq_num,
            timestamp: ts_now,
        });
    }

    fn on_nak_event(&mut self, now: Instant) {
        // reset NAK timer, rtt and variance are in us, so convert to ns

        // NAK is used to trigger a negative acknowledgement (NAK). Its period
        // is dynamically updated to 4 * RTT_+ RTTVar + SYN, where RTTVar is the
        // variance of RTT samples.
        self.timers.update_rtt(self.rtt, self.rtt_variance);

        // Search the receiver's loss list, find out all those sequence numbers
        // whose last feedback time is k*RTT before, where k is initialized as 2
        // and increased by 1 each time the number is fed back. Compress
        // (according to section 6.4) and send these numbers back to the sender
        // in an NAK packet.

        let ts_now = self.receive_buffer.timestamp_from(now);

        // increment k and change feedback time, returning sequence numbers
        let seq_nums = {
            let mut ret = Vec::new();

            let rtt = self.rtt;
            for pak in self
                .loss_list
                .iter_mut()
                .filter(|lle| lle.feedback_time < ts_now - rtt * lle.k)
            {
                pak.k += 1;
                pak.feedback_time = ts_now;

                ret.push(pak.seq_num);
            }

            ret
        };

        if seq_nums.is_empty() {
            return;
        }

        // send the nak
        self.send_nak(now, seq_nums.into_iter());
    }

    fn handle_handshake_packet(&mut self, now: Instant, control_info: HandshakeControlInfo) {
        if let Some(c) = self.handshake.handle_handshake(control_info) {
            self.send_control(now, c)
        }
    }

    // handles a SRT control packet
    fn handle_srt_control_packet(&mut self, pack: SrtControlPacket) {
        use self::SrtControlPacket::*;
        match pack {
            HandshakeRequest(_) | HandshakeResponse(_) => {
                warn!("Received handshake SRT packet, HSv5 expected");
            }
            _ => unimplemented!(),
        }
    }

    fn handle_ack2(&mut self, seq_num: i32, now: Instant) {
        // 1) Locate the related ACK in the ACK History Window according to the
        //    ACK sequence number in this ACK2.
        let id_in_wnd = match self
            .ack_history_window
            .as_slice()
            .binary_search_by(|entry| entry.ack_seq_num.cmp(&seq_num))
        {
            Ok(i) => Some(i),
            Err(_) => None,
        };

        if let Some(id) = id_in_wnd {
            let AckHistoryEntry {
                timestamp: send_timestamp,
                ack_number,
                ..
            } = self.ack_history_window[id];

            // 2) Update the largest ACK number ever been acknowledged.
            self.lr_ack_acked = (seq_num, ack_number);

            // 3) Calculate new rtt according to the ACK2 arrival time and the ACK
            //    departure time, and update the RTT value as: RTT = (RTT * 7 +
            //    rtt) / 8
            let immediate_rtt = self.receive_buffer.timestamp_from(now) - send_timestamp;
            self.rtt = (self.rtt * 7 + immediate_rtt) / 8;

            // 4) Update RTTVar by: RTTVar = (RTTVar * 3 + abs(RTT - rtt)) / 4.
            self.rtt_variance =
                (self.rtt_variance * 3 + (self.rtt_variance - immediate_rtt).abs()) / 4;

            // 5) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
            self.timers.update_rtt(self.rtt, self.rtt_variance);
        } else {
            warn!(
                "ACK sequence number in ACK2 packet not found in ACK history: {}",
                seq_num
            );
        }
    }

    fn handle_data_packet(&mut self, data: &DataPacket, now: Instant) {
        let ts_now = self.receive_buffer.timestamp_from(now);

        // 2&3 don't apply

        // 4) If the sequence number of the current data packet is 16n + 1,
        //     where n is an integer, record the time interval between this
        if data.seq_number % 16 == 0 {
            self.probe_time = Some(ts_now)
        } else if data.seq_number % 16 == 1 {
            // if there is an entry
            if let Some(pt) = self.probe_time {
                // calculate and insert
                self.packet_pair_window.push((data.seq_number, ts_now - pt));

                // reset
                self.probe_time = None
            }
        }
        // 5) Record the packet arrival time in PKT History Window.
        self.packet_history_window.push((data.seq_number, ts_now));

        // 6)
        // a. If the sequence number of the current data packet is greater
        //    than LRSN, put all the sequence numbers between (but
        //    excluding) these two values into the receiver's loss list and
        //    send them to the sender in an NAK packet.
        match data.seq_number.cmp(&self.lrsn) {
            Ordering::Greater => {
                // lrsn is the latest packet received, so nak the one after that
                for i in seq_num_range(self.lrsn, data.seq_number) {
                    self.loss_list.push(LossListEntry {
                        seq_num: i,
                        feedback_time: ts_now,
                        // k is initialized at 2, as stated on page 12 (very end)
                        k: 2,
                    })
                }

                self.send_nak(now, seq_num_range(self.lrsn, data.seq_number));
            }
            // b. If the sequence number is less than LRSN, remove it from the
            //    receiver's loss list.
            Ordering::Less => {
                match self.loss_list[..].binary_search_by(|ll| ll.seq_num.cmp(&data.seq_number)) {
                    Ok(i) => {
                        self.loss_list.remove(i);
                    }
                    Err(_) => {
                        debug!(
                            "Packet received that's not in the loss list: {:?}, loss_list={:?}",
                            data.seq_number,
                            self.loss_list
                                .iter()
                                .map(|ll| ll.seq_num.as_raw())
                                .collect::<Vec<_>>()
                        );
                    }
                };
            }
            Ordering::Equal => {}
        }

        // record that we got this packet
        self.lrsn = max(data.seq_number + 1, self.lrsn);

        // we've already gotten this packet, drop it
        if self.receive_buffer.next_release() > data.seq_number {
            debug!("Received packet {:?} twice", data.seq_number);
            return;
        }

        self.receive_buffer.add(data.clone());
    }

    // send a NAK, and return the future
    fn send_nak(&mut self, now: Instant, lost_seq_nums: impl Iterator<Item = SeqNumber>) {
        let vec: Vec<_> = lost_seq_nums.collect();
        debug!("Sending NAK for={:?}", vec);

        self.send_control(
            now,
            ControlTypes::Nak(compress_loss_list(vec.iter().cloned()).collect()),
        );
    }

    fn pop_data(&mut self, now: Instant) -> Option<(Instant, Bytes)> {
        // try to release packets
        while let Some(d) = self.receive_buffer.next_msg_tsbpd(now) {
            self.data_release.push_back(d);
        }

        // drop packets
        // TODO: do something with this
        let _dropped = self.receive_buffer.drop_too_late_packets(now);

        self.data_release.pop_front()
    }

    fn pop_conotrol_packet(&mut self) -> Option<Packet> {
        self.control_packets.pop_front()
    }

    fn next_timer(&self, now: Instant) -> Instant {
        std::cmp::min(
            self.timers.next_timer(),
            self.receive_buffer
                .next_message_release_time(now)
                .unwrap_or(now),
        )
    }

    fn send_control(&mut self, now: Instant, control: ControlTypes) {
        self.control_packets
            .push_back(Packet::Control(ControlPacket {
                timestamp: self.receive_buffer.timestamp_from(now),
                dest_sockid: self.settings.remote_sockid,
                control_type: control,
            }));
    }
}
