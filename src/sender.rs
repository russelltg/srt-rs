use SeqNumber;
use bytes::Bytes;
use futures::prelude::*;
use futures_timer::Delay;
use packet::{ControlTypes, Packet, PacketLocation};
use std::{collections::VecDeque, io::{Error, ErrorKind, Result}, net::SocketAddr, time::Duration};

use {CCData, ConnectionSettings, SenderCongestionCtrl};

use loss_compression::decompress_loss_list;

pub struct Sender<T, CC> {
    sock: T,

    /// The congestion control
    congest_ctrl: CC,

    /// The settings, including remote sockid and address
    settings: ConnectionSettings,

    /// The list of pending packets
    pending_packets: VecDeque<Bytes>,

    /// The sequence number for the next data packet
    next_seq_number: SeqNumber,

    /// The messag number for the next message
    next_message_number: i32,

    // 1) Sender's Loss List: The sender's loss list is used to store the
    //    sequence numbers of the lost packets fed back by the receiver
    //    through NAK packets or inserted in a timeout event. The numbers
    //    are stored in increasing order.
    loss_list: VecDeque<Packet>,

    /// The buffer to store packets for retransmision
    buffer: VecDeque<Packet>,

    /// The first sequence number in buffer, so seq number i would be found at
    /// buffer[i - first_seq]
    first_seq: SeqNumber,

    /// The sequence number of the largest acknowledged packet + 1
    lr_acked_packet: SeqNumber,

    /// Round trip time, in microseconds
    rtt: i32,

    /// Round trip time variance
    rtt_var: i32,

    /// packet arrival rate
    pkt_arr_rate: i32,

    /// estimated link capacity
    est_link_cap: i32,

    /// The send timer
    snd_timer: Delay,
}

impl<T, CC> Sender<T, CC>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
    CC: SenderCongestionCtrl,
{
    pub fn new(sock: T, congest_ctrl: CC, settings: ConnectionSettings) -> Sender<T, CC> {
        info!("Sending started to {:?}", settings.remote);

        Sender {
            sock,
            congest_ctrl,
            settings,
            pending_packets: VecDeque::new(),
            next_seq_number: settings.init_seq_num,
            next_message_number: 0,
            loss_list: VecDeque::new(),
            buffer: VecDeque::new(),
            first_seq: settings.init_seq_num,
            lr_acked_packet: settings.init_seq_num,
            rtt: 10_000,
            rtt_var: 0,
            pkt_arr_rate: 0,
            est_link_cap: 0,
            snd_timer: Delay::new(Duration::from_millis(1)),
        }
    }

    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    pub fn remote(&self) -> SocketAddr {
        self.settings.remote
    }

    fn make_cc_info(&self) -> CCData {
        CCData {
            est_bandwidth: self.est_link_cap,
            max_segment_size: self.settings.max_packet_size,
            latest_seq_num: Some(self.next_seq_number - 1),
            packet_arr_rate: self.pkt_arr_rate,
            rtt: Duration::new(0, (self.rtt * 1_000) as u32), // TODO: may be better to not use just nanos to avoid overflow
        }
    }

    fn handle_packet(&mut self, pack: Packet) -> Result<()> {
        match pack {
            Packet::Control {
                control_type,
                .. // Use dst sockid
            } => {
                match control_type {
                    ControlTypes::Ack(seq_num, data) => {
                        // 1) Update the largest acknowledged sequence number, which is the ACK number
                        self.lr_acked_packet = data.ack_number;

                        // 2) Send back an ACK2 with the same ACK sequence number in this ACK.
                        let now = self.get_timestamp();
                        self.sock.start_send((Packet::Control {
                            timestamp: now,
                            dest_sockid: self.settings.remote_sockid,
                            control_type: ControlTypes::Ack2(seq_num),
                        }, self.settings.remote))?;

                        // 3) Update RTT and RTTVar.
                        self.rtt = data.rtt.unwrap_or(0);
                        self.rtt_var = data.rtt_variance.unwrap_or(0);

                        // 4) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
                        // TODO: figure out why this makes sense, the sender shouldn't send ACK or NAK packets.

                        // 5) Update flow window size.
                        {
                            let cc_info = self.make_cc_info();
                            self.congest_ctrl.on_ack(&cc_info);
                        }

                        // 6) If this is a Light ACK, stop.
                        // TODO: wat

                        // 7) Update packet arrival rate: A = (A * 7 + a) / 8, where a is the
                        //    value carried in the ACK.
                        self.pkt_arr_rate =
                            self.pkt_arr_rate / 8 * 7 + data.packet_recv_rate.unwrap_or(0) / 8;

                        // 8) Update estimated link capacity: B = (B * 7 + b) / 8, where b is
                        //    the value carried in the ACK.
                        self.est_link_cap =
                            (self.est_link_cap * 7 + data.est_link_cap.unwrap_or(0)) / 8;

                        // 9) Update sender's buffer (by releasing the buffer that has been
                        //    acknowledged).
                        while data.ack_number > self.first_seq {
                            self.buffer.pop_front();
                            self.first_seq += 1;
                        }

                        // 10) Update sender's loss list (by removing all those that has been
                        //     acknowledged).
                        // TODO: this isn't the most effiecnet algorithm, it checks the beginning of the array many times
                        while let Some(id) =
                            self.loss_list
                                .iter()
                                .position(|x| data.ack_number > x.seq_number().unwrap()) {

                            self.loss_list.remove(id);
                        }
                    }
                    ControlTypes::Ack2(_) => warn!("Sender received ACK2, unusual"),
                    ControlTypes::DropRequest(_msg_id, _info) => unimplemented!(),
                    ControlTypes::Handshake(_shake) => unimplemented!(),
                    // TODO: reset EXP-ish
                    ControlTypes::KeepAlive => {}
                    ControlTypes::Nak(info) => {
                        // 1) Add all sequence numbers carried in the NAK into the sender's loss list.
                        // 2) Update the SND period by rate control (see section 3.6).
                        // 3) Reset the EXP time variable.

                        for lost in decompress_loss_list(info.loss_info.iter().cloned()) {
                            let packet = match self.buffer
                                .iter()
                                .find(|pack| pack.seq_number().unwrap() == lost)
                            {
                                Some(p) => p,
                                None => {warn!("NAK received for packet that's not in the buffer, maybe it's already been ACKed"); continue }
                            };

                            self.loss_list.push_back(packet.clone());
                        }

                        // update CC
                        if !self.loss_list.is_empty() {
                            let cc_info = self.make_cc_info();
                            self.congest_ctrl.on_nak(
                                self.loss_list.back().unwrap().seq_number().unwrap(),
                                &cc_info);
                        }

                        trace!("Loss list={:?}", self.loss_list.iter().map(|ll| ll.seq_number().unwrap().0).collect::<Vec<_>>());

                        // TODO: reset EXP
                    }
                    ControlTypes::Shutdown => unimplemented!(),
                }
            }
            Packet::Data { .. } => warn!("Sender received data packet"),
        }

        Ok(())
    }

    fn send_packet(&mut self, payload: Bytes) -> Result<()> {
        debug!("Sending packet with length={}", payload.len());

        let pack = Packet::Data {
            dest_sockid: self.settings.remote_sockid,
            in_order_delivery: false, // TODO: research this
            message_loc: PacketLocation::Only,
            message_number: {
                self.next_message_number += 1;
                self.next_message_number = self.next_message_number << 1 >> 1; // loop around

                self.next_message_number - 1
            },
            seq_number: {
                // this does looping for us
                self.next_seq_number += 1;

                self.next_seq_number - 1
            },
            timestamp: self.get_timestamp(),
            payload,
        };
        // add it to the buffer
        self.buffer.push_back(pack.clone());

        self.sock.start_send((pack, self.settings.remote))?;

        Ok(())
    }

    fn get_timestamp(&self) -> i32 {
        self.settings.get_timestamp()
    }
}

impl<T, CC> Sink for Sender<T, CC>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
    CC: SenderCongestionCtrl,
{
    type SinkItem = Bytes;
    type SinkError = Error;

    fn start_send(&mut self, item: Bytes) -> StartSend<Bytes, Error> {
        self.pending_packets.push_back(item);

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        // we need to poll_complete this until completion
        // this poll_complete could have come from a wakeup of that, so call it
        if let Async::Ready(_) = self.sock.poll_complete()? {
            // if everything is flushed, return Ok
            if self.loss_list.is_empty() && self.pending_packets.is_empty()
                && self.lr_acked_packet == self.next_seq_number
                && self.buffer.is_empty()
            {
                // TODO: this is wrong for KeepAlive
                debug!("Returning ready");
                return Ok(Async::Ready(()));
            }
        }

        loop {
            // do we have any packets to handle?
            while let Async::Ready(a) = self.sock.poll()? {
                match a {
                    Some((pack, addr)) => {
                        debug!("Got packet: {:?}", pack);
                        // ignore the packet if it isn't from the right address
                        if addr == self.settings.remote {
                            self.handle_packet(pack)?;
                        }
                    }
                    // stream has ended, this is weird
                    None => {
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "Unexpected EOF of underlying stream",
                        ));
                    }
                }
            }
            // if we're here, we are guaranteed to have a NotReady, so returning NotReady is OK

            // wait for the SND timer to timeout
            try_ready!(self.snd_timer.poll());

            // 6) Wait (SND - t) time, where SND is the inter-packet interval
            //     updated by congestion control and t is the total time used by step
            //     1 to step 5. Go to 1).
            {
                let cc_info = self.make_cc_info();
                self.congest_ctrl.on_packet_sent(&cc_info);
            }

            // reset the timer
            self.snd_timer.reset(self.congest_ctrl.send_interval());

            // 1) If the sender's loss list is not empty, send all the packets it in
            if let Some(pack) = self.loss_list.pop_front() {
                debug!(
                    "Sending packet in loss list, seq={:?}",
                    pack.seq_number().unwrap()
                );
                self.sock.start_send((pack, self.settings.remote))?;
            } else {
                // 2) In messaging mode, if the packets has been the loss list for a
                //    time more than the application specified TTL (time-to-live), send
                //    a message drop request and remove all related packets from the
                //    loss list. Go to 1).

                // TODO: I honestly don't know what this means

                // 3) Wait until there is application data to be sent.

                // a. If the number of unacknowledged packets exceeds the
                //    flow/congestion window size, wait until an ACK comes. Go to
                //    1).
                // TODO: account for looping here
                if self.lr_acked_packet < self.next_seq_number - self.congest_ctrl.window_size() {
                    // flow window exceeded, wait for ACK
                    trace!("Flow window exceeded lr_acked={:?}, next_seq={:?}, window_size={}, next_seq-window={:?}", 
                        self.lr_acked_packet,
                        self.next_seq_number,
                        self.congest_ctrl.window_size(),
                        self.next_seq_number - self.congest_ctrl.window_size());

                    continue;
                }

                // b. Pack a new data packet and send it out.
                {
                    let payload = match self.pending_packets.pop_front() {
                        Some(p) => p,
                        // All packets have been flushed
                        None => continue,
                    };
                    debug!(
                        "Sending packet: {}; pending.len={}; SND={:?}",
                        self.next_seq_number.0,
                        self.pending_packets.len(),
                        self.congest_ctrl.send_interval(),
                    );
                    self.send_packet(payload)?;
                }

                // 5) If the sequence number of the current packet is 16n, where n is an
                //     integer, go to 2) (which is send another packet).
                if (self.next_seq_number - 1) % 16 == 0 {
                    let payload = match self.pending_packets.pop_front() {
                        Some(p) => p,
                        // All packets have been flushed
                        None => continue,
                    };
                    self.send_packet(payload)?;
                }
            }
            self.sock.poll_complete()?;
        }
    }

    fn close(&mut self) -> Poll<(), Error> {
        try_ready!(self.poll_complete());

        // once it's all flushed, send a Shutdown
        let ts = self.get_timestamp();
        self.sock.start_send((
            Packet::Control {
                dest_sockid: self.settings.remote_sockid,
                timestamp: ts,
                control_type: ControlTypes::Shutdown,
            },
            self.settings.remote,
        ))?;

        return Ok(Async::Ready(()));
    }
}
