use bytes::Bytes;
use helpers::{Action, ConnSend, Direction, ListRecv, SyncLossyConn};
use log::debug;
use rand::{prelude::StdRng, Rng, SeedableRng};
use srt_protocol::{
    pending_connection::{connect::Connect, listen::Listen, ConnInitSettings},
    SeqNumber,
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
