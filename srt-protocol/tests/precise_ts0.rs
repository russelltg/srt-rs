use std::{
    cmp::max,
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, Instant},
};

use srt_protocol::{
    accesscontrol::AllowAllStreamAcceptor,
    pending_connection::{connect::Connect, listen::Listen, ConnInitSettings, ConnectionResult},
    Connection, SeqNumber, SocketId,
};

enum Direction {
    S2R,
    R2S,
}

enum Conn<T> {
    Pending(T),
    Done(Connection),
}

#[test]
fn precise_ts0() {
    let r_sa = ([127, 0, 0, 1], 2222).into();
    let s_sa: SocketAddr = ([127, 0, 0, 1], 2224).into();

    let seqno = SeqNumber::new_truncate(0);
    let s_sid = SocketId(1234);
    let r_sid = SocketId(5678);

    let conn_tick_time = Duration::from_millis(100);
    let rtt2 = Duration::from_millis(500);

    let start = Instant::now();

    let mut send = Conn::Pending(Connect::new(
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
    ));
    let mut next_connect_tick = start + conn_tick_time;

    let mut recv = Conn::Pending(Listen::new(ConnInitSettings {
        starting_send_seqnum: seqno,
        local_sockid: r_sid,
        crypto: None,
        send_latency: Duration::from_millis(20),
        recv_latency: Duration::from_millis(20),
    }));

    let mut queue = VecDeque::new();
    let mut current_time = start;

    let (a, b) = loop {
        if queue
            .front()
            .as_ref()
            .map(|(ts, _, _)| *ts <= current_time)
            .unwrap_or(false)
        {
            let (_, dir, packet) = queue.pop_front().unwrap();
            match (dir, &mut recv, &mut send) {
                (Direction::S2R, Conn::Pending(r), _) => match r.handle_packet(
                    (packet, s_sa),
                    current_time,
                    &mut AllowAllStreamAcceptor::default(),
                ) {
                    ConnectionResult::Reject(_, _) => panic!("Reject?"),
                    ConnectionResult::SendPacket((pack, _)) => {
                        queue.push_back((current_time + rtt2, Direction::R2S, pack))
                    }
                    ConnectionResult::Connected(Some((pack, _)), conn) => {
                        queue.push_back((current_time + rtt2, Direction::R2S, pack));
                        recv = Conn::Done(conn);
                    }
                    ConnectionResult::Connected(None, conn) => recv = Conn::Done(conn),
                    ConnectionResult::NotHandled(_) | ConnectionResult::NoAction => {}
                },
                (Direction::R2S, _, Conn::Pending(s)) => {
                    match s.handle_packet((packet, r_sa), current_time) {
                        ConnectionResult::Reject(_, _) => panic!("Reject?"),
                        ConnectionResult::SendPacket((pack, _)) => {
                            queue.push_back((current_time + rtt2, Direction::S2R, pack))
                        }
                        ConnectionResult::Connected(Some((pack, _)), conn) => {
                            queue.push_back((current_time + rtt2, Direction::S2R, pack));
                            send = Conn::Done(conn)
                        }
                        ConnectionResult::Connected(None, conn) => send = Conn::Done(conn),
                        ConnectionResult::NotHandled(_) | ConnectionResult::NoAction => {}
                    }
                }
                _ => {} // ignore, already connected
            }
        }

        if current_time >= next_connect_tick {
            next_connect_tick += conn_tick_time;
            if let Conn::Pending(conn) = &mut send {
                match conn.handle_tick(current_time) {
                    ConnectionResult::Reject(_, _) => panic!("Reject?"),
                    ConnectionResult::SendPacket((pack, _)) => {
                        queue.push_back((current_time + rtt2, Direction::S2R, pack))
                    }
                    ConnectionResult::Connected(Some((pack, _)), conn) => {
                        queue.push_back((current_time + rtt2, Direction::S2R, pack));
                        send = Conn::Done(conn);
                    }
                    ConnectionResult::Connected(None, conn) => send = Conn::Done(conn),
                    ConnectionResult::NotHandled(_) | ConnectionResult::NoAction => {}
                }
            }
        }

        if let (Conn::Done(a), Conn::Done(b)) = (&mut send, &mut recv) {
            break (a, b);
        }

        let next_time = max(
            queue
                .front()
                .map(|(inst, _, _)| *inst)
                .unwrap_or(next_connect_tick),
            next_connect_tick,
        );

        current_time = next_time;
    };

    assert_eq!(a.settings.socket_start_time, b.settings.socket_start_time);
    assert_eq!(a.settings.rtt, rtt2 * 2);
    assert_eq!(b.settings.rtt, rtt2 * 2);
}
