use bytes::Bytes;
use log::{debug, info};
use lossy_conn::Action;
use rand::{prelude::StdRng, Rng, SeedableRng};
use srt_protocol::{
    accesscontrol::AllowAllStreamAcceptor,
    pending_connection::{
        connect::Connect,
        listen::Listen,
        ConnInitSettings,
        ConnectionResult::{Connected, NoAction, NotHandled, Reject, SendPacket},
    },
    protocol::{
        receiver::{Receiver, ReceiverAlgorithmAction},
        sender::{Sender, SenderAlgorithmAction},
    },
    SeqNumber,
};
use std::{
    net::SocketAddr,
    str,
    time::{Duration, Instant},
};

mod lossy_conn;

#[allow(clippy::large_enum_variant)]
enum ConnSend {
    Conn(Connect, Instant),
    Send(Sender),
}

#[allow(clippy::large_enum_variant)]
enum ListRecv {
    List(Listen),
    Recv(Receiver),
}

#[test]
fn not_enough_latency() {
    let _ = pretty_env_logger::try_init();
    let seed = 1934;

    const PACKETS: u32 = 10_000;

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
    let mut conn = lossy_conn::SyncLossyConn::new(
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
                Action::S2R(pack) => match &mut recv {
                    ListRecv::List(listen) => {
                        match listen.handle_packet(
                            (pack, s_sa),
                            Instant::now(),
                            &mut AllowAllStreamAcceptor::default(),
                        ) {
                            Reject(_, _) => panic!("Rejected?"),
                            SendPacket((pack, _)) => conn.push_r2s(pack, current_time),
                            Connected(hs, connection) => {
                                if let Some((pack, _)) = hs {
                                    conn.push_r2s(pack, current_time);
                                }

                                recv = ListRecv::Recv(Receiver::new(
                                    connection.settings,
                                    connection.handshake,
                                ));
                                info!("Listener connected");
                            }
                            NoAction | NotHandled(_) => {}
                        }
                    }

                    ListRecv::Recv(recv) => {
                        recv.handle_packet(current_time, (pack, s_sa));
                    }
                },
                Action::R2S(pack) => match &mut send {
                    ConnSend::Conn(connect, _) => {
                        match connect.handle_packet((pack, r_sa), current_time) {
                            Reject(_, _) => panic!("Rejected?"),
                            SendPacket((pack, _)) => conn.push_s2r(pack, current_time),
                            Connected(hs, connection) => {
                                if let Some((pack, _)) = hs {
                                    conn.push_s2r(pack, current_time);
                                }

                                send = ConnSend::Send(Sender::new(
                                    connection.settings,
                                    connection.handshake,
                                ));
                                info!("Sender connected");
                            }
                            NotHandled(_) | NoAction => {}
                        }
                    }
                    ConnSend::Send(sendr) => sendr.handle_packet((pack, r_sa), current_time),
                },
            }
        };

        // handle recv
        let recv_wakeup_time = match &mut recv {
            ListRecv::List(_) => None, // listener needs no tick
            ListRecv::Recv(recv) => {
                loop {
                    match recv.next_algorithm_action(current_time) {
                        ReceiverAlgorithmAction::TimeBoundedReceive(wakeup) => break Some(wakeup),
                        ReceiverAlgorithmAction::SendControl(cp, _) => {
                            conn.push_r2s(cp.into(), current_time)
                        }
                        ReceiverAlgorithmAction::OutputData((ts, by)) => {
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
                                diff > Duration::from_millis(1900)
                                    && diff < Duration::from_millis(3000),
                                "Time difference {:?} not within 1.9 sec and 3 sec",
                                diff
                            );
                        }
                        ReceiverAlgorithmAction::Close => break None,
                    }
                }
            }
        };

        // handle send
        let send_wakeup_time = loop {
            match &mut send {
                ConnSend::Conn(connect, next_time) => {
                    if current_time >= *next_time {
                        *next_time += Duration::from_millis(100);
                        match connect.handle_tick(current_time) {
                            Reject(_, _) => panic!("Rejected?"),
                            SendPacket((pack, _)) => conn.push_s2r(pack, current_time),
                            Connected(hs, connection) => {
                                if let Some((pack, _)) = hs {
                                    conn.push_s2r(pack, current_time);
                                }

                                send = ConnSend::Send(Sender::new(
                                    connection.settings,
                                    connection.handshake,
                                ));
                                info!("Sender connected");
                                continue;
                            }
                            NotHandled(_) | NoAction => {}
                        }
                    }
                    break Some(*next_time);
                }
                ConnSend::Send(sendr) => {
                    let next_time = match sendr.next_action(current_time) {
                        SenderAlgorithmAction::WaitUntilAck => None,
                        SenderAlgorithmAction::WaitForData => None,
                        SenderAlgorithmAction::WaitUntil(until) => Some(until),
                        SenderAlgorithmAction::Close => None, // xxx
                    };

                    while let Some((pack, _)) = sendr.pop_output() {
                        conn.push_s2r(pack, current_time);
                    }

                    break next_time;
                }
            }
        };

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
            assert_ne!(nc, current_time);
            current_time = nc
        } else {
            break;
        }
    }

    assert!(total_recvd > PACKETS / 3 * 2);
}
