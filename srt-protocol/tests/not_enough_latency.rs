use bytes::Bytes;
use helpers::{Action, Direction, SyncLossyConn};
use log::{debug, info};
use rand::{prelude::StdRng, Rng, SeedableRng};
use srt_protocol::{
    accesscontrol::AllowAllStreamAcceptor,
    pending_connection::{connect::Connect, listen::Listen, ConnInitSettings, ConnectionResult},
    protocol::{
        receiver::{Receiver, ReceiverAlgorithmAction},
        sender::{Sender, SenderAlgorithmAction},
    },
    Packet, SeqNumber,
};
use std::{
    net::SocketAddr,
    str,
    time::{Duration, Instant},
};

mod helpers;

#[test]
fn not_enough_latency() {
    let _ = pretty_env_logger::try_init();
    let seed = 1934;

    const PACKETS: u32 = 1_000;

    let start = Instant::now();

    let mut rng = StdRng::seed_from_u64(seed);

    let r_sa = ([127, 0, 0, 1], 2222).into();
    let s_sa: SocketAddr = ([127, 0, 0, 1], 2224).into();

    let r_sid = rng.gen();
    let s_sid = rng.gen();
    let seqno = SeqNumber::new_truncate(0); // rng.gen();

    let packet_spacing = Duration::from_millis(10);

    let mut send = ConnSend::Conn(
        Connect::new(
            r_sa,
            s_sa.ip(),
            ConnInitSettings {
                starting_send_seqnum: seqno,
                local_sockid: s_sid,
                crypto: None,
                send_latency: Duration::from_millis(2000),
                recv_latency: Duration::from_millis(20),
            },
            None,
        ),
        start,
    );

    let mut recv = ListRecv::List(Listen::new(ConnInitSettings {
        starting_send_seqnum: seqno,
        local_sockid: r_sid,
        crypto: None,
        send_latency: Duration::from_millis(20),
        recv_latency: Duration::from_millis(20),
    }));

    // 4% packet loss, 4 sec latency with 0.2 s variance
    let mut conn = SyncLossyConn::new(
        Duration::from_millis(1500),
        Duration::from_millis(0),
        0.01,
        rng,
    );

    let mut packets_sent = 0;
    let mut next_packet_send_time = Some(start);

    let mut current_time = start;
    let mut total_recvd = 0;
    let mut last_index = 0;

    loop {
        if let Some(rel_time) = &mut next_packet_send_time {
            if *rel_time <= current_time {
                *rel_time += packet_spacing;

                if let ConnSend::Send(sendr) = &mut send {
                    packets_sent += 1;

                    debug!("Sending {} at {:?}", packets_sent, current_time - start);

                    sendr.handle_data(
                        (current_time, Bytes::from(format!("{}", packets_sent))),
                        current_time,
                    );
                    if packets_sent == PACKETS {
                        sendr.handle_close();
                        next_packet_send_time = None;
                    }
                }
            }
        }

        let conn_next_time = loop {
            match conn.action(current_time) {
                Action::Wait(when) => break when,
                Action::Release(pack, Direction::A2B) => {
                    recv.handle_packet(pack, current_time, s_sa, &mut conn)
                }
                Action::Release(pack, Direction::B2A) => {
                    send.handle_packet(pack, current_time, r_sa, &mut conn)
                }
            }
        };

        // handle recv
        let recv_wakeup_time = recv.tick(current_time, &mut conn, |ts, by| {
            total_recvd += 1;

            // they don't have to be sequential, but they should be increasing
            let this_idx = str::from_utf8(&by[..]).unwrap().parse().unwrap();
            debug!("received {} at {:?}", this_idx, ts - start);
            assert!(this_idx > last_index, "Sequence numbers aren't increasing");
            if this_idx - last_index > 1 {
                debug!("{} messages dropped", this_idx - last_index - 1)
            }
            last_index = this_idx;

            // make sure the timings are still decent
            let diff = current_time - ts;
            assert!(
                diff > Duration::from_millis(1900) && diff < Duration::from_millis(3000),
                "Time difference {:?} not within 1.9 sec and 3 sec",
                diff
            );
        });

        // handle send
        let send_wakeup_time = send.tick(current_time, &mut conn);

        let new_current = [
            next_packet_send_time,
            recv_wakeup_time,
            send_wakeup_time,
            conn_next_time,
        ]
        .iter()
        .copied()
        .flatten()
        .min();

        if let Some(nc) = new_current {
            current_time = nc
        } else {
            break;
        }
    }

    assert!(total_recvd > PACKETS / 3 * 2);
    assert!(total_recvd < PACKETS);
}

#[allow(clippy::large_enum_variant)]
pub enum ConnSend {
    Conn(Connect, Instant),
    Send(Sender),
}

#[allow(clippy::large_enum_variant)]
pub enum ListRecv {
    List(Listen),
    Recv(Receiver),
}

impl ConnSend {
    pub fn handle_packet(
        &mut self,
        pack: Packet,
        now: Instant,
        recvr_sa: SocketAddr,
        conn: &mut SyncLossyConn,
    ) {
        match self {
            ConnSend::Conn(connect, _) => {
                let res = connect.handle_packet((pack, recvr_sa), now);
                self.handle_connection_result(res, now, conn)
            }
            ConnSend::Send(sendr) => sendr.handle_packet((pack, recvr_sa), now),
        }
    }

    pub fn tick(&mut self, now: Instant, conn: &mut SyncLossyConn) -> Option<Instant> {
        match self {
            ConnSend::Conn(connect, next_time) => {
                let next_time_deref = *next_time;
                if now >= *next_time {
                    *next_time += Duration::from_millis(100);
                    let res = connect.handle_tick(now);
                    self.handle_connection_result(res, now, conn);
                }
                Some(next_time_deref)
            }
            ConnSend::Send(sendr) => {
                let next_time = match sendr.next_action(now) {
                    SenderAlgorithmAction::WaitUntilAck => None,
                    SenderAlgorithmAction::WaitForData => None,
                    SenderAlgorithmAction::WaitUntil(until) => Some(until),
                    SenderAlgorithmAction::Close => None, // xxx
                };

                while let Some((pack, _)) = sendr.pop_output() {
                    conn.push_s2r(pack, now);
                }

                next_time
            }
        }
    }

    fn handle_connection_result(
        &mut self,
        res: ConnectionResult,
        now: Instant,
        conn: &mut SyncLossyConn,
    ) {
        match res {
            ConnectionResult::Reject(_, _) => panic!("Rejected?"),
            ConnectionResult::SendPacket((pack, _)) => conn.push_s2r(pack, now),
            ConnectionResult::Connected(hs, connection) => {
                if let Some((pack, _)) = hs {
                    conn.push_s2r(pack, now);
                }

                *self = ConnSend::Send(Sender::new(connection.settings, connection.handshake));
                info!("Sender connected");
            }
            ConnectionResult::NotHandled(_) | ConnectionResult::NoAction => {}
        }
    }
}

impl ListRecv {
    pub fn handle_packet(
        &mut self,
        pack: Packet,
        now: Instant,
        send_sa: SocketAddr,
        conn: &mut SyncLossyConn,
    ) {
        match self {
            ListRecv::List(listen) => {
                match listen.handle_packet(
                    (pack, send_sa),
                    Instant::now(),
                    &mut AllowAllStreamAcceptor::default(),
                ) {
                    ConnectionResult::Reject(_, _) => {
                        panic!("Rejected?")
                    }
                    ConnectionResult::SendPacket((pack, _)) => conn.push_r2s(pack, now),
                    ConnectionResult::Connected(hs, connection) => {
                        if let Some((pack, _)) = hs {
                            conn.push_r2s(pack, now);
                        }

                        *self = ListRecv::Recv(Receiver::new(
                            connection.settings,
                            connection.handshake,
                        ));
                        info!("Listener connected");
                    }
                    ConnectionResult::NoAction | ConnectionResult::NotHandled(_) => {}
                }
            }

            ListRecv::Recv(recv) => {
                recv.handle_packet(now, (pack, send_sa));
            }
        }
    }

    pub fn tick(
        &mut self,
        now: Instant,
        conn: &mut SyncLossyConn,
        mut on_pack: impl FnMut(Instant, Bytes),
    ) -> Option<Instant> {
        match self {
            ListRecv::List(_) => None, // listener needs no tick
            ListRecv::Recv(recv) => loop {
                match recv.next_algorithm_action(now) {
                    ReceiverAlgorithmAction::TimeBoundedReceive(wakeup) => break Some(wakeup),
                    ReceiverAlgorithmAction::SendControl(cp, _) => conn.push_r2s(cp.into(), now),
                    ReceiverAlgorithmAction::OutputData((ts, by)) => on_pack(ts, by),
                    ReceiverAlgorithmAction::Close => break None,
                }
            },
        }
    }
}
