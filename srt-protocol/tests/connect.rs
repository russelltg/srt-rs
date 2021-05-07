use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use rand::{prelude::StdRng, SeedableRng};
use srt_protocol::{
    accesscontrol::AllowAllStreamAcceptor,
    packet::ControlTypes,
    pending_connection::{
        connect::Connect, listen::Listen, rendezvous::Rendezvous, ConnInitSettings,
        ConnectionResult,
    },
    Connection, ControlPacket, Packet, SeqNumber, SocketId,
};

pub mod helpers;

use helpers::{Action, Direction, SyncLossyConn};

const CONN_TICK_TIME: Duration = Duration::from_millis(100);

#[allow(clippy::large_enum_variant)]
enum Conn {
    PendingL(Direction, Listen),
    PendingC(Direction, Connect, Instant),
    PendingR(Direction, Rendezvous, Instant),
    Done(Direction, Connection),
}

impl Conn {
    pub fn handle_packet(
        &mut self,
        packet: Packet,
        now: Instant,
        remote_sa: SocketAddr,
        conn: &mut SyncLossyConn,
    ) {
        let (d, res) = match self {
            Conn::PendingL(d, l) => (
                *d,
                l.handle_packet(
                    (packet, remote_sa),
                    now,
                    &mut AllowAllStreamAcceptor::default(),
                ),
            ),
            Conn::PendingC(d, c, _) => (*d, c.handle_packet((packet, remote_sa), now)),
            Conn::PendingR(d, r, _) => (*d, r.handle_packet((packet, remote_sa), now)),
            Conn::Done(d, c) => {
                if let Packet::Control(ControlPacket {
                    control_type: ControlTypes::Handshake(hs),
                    ..
                }) = &packet
                {
                    match c.handshake.handle_handshake(hs) {
                        Some(control_type) => (
                            *d,
                            ConnectionResult::SendPacket((
                                Packet::Control(ControlPacket {
                                    control_type,
                                    ..packet.control().unwrap().clone() // this is chekced in the pattern, but can't be @'d
                                }),
                                remote_sa,
                            )),
                        ),
                        None => (*d, ConnectionResult::NoAction),
                    }
                } else {
                    (*d, ConnectionResult::NoAction)
                }
            }
        };
        match res {
            ConnectionResult::Reject(_, _) => panic!("Reject?"),
            ConnectionResult::SendPacket((pack, _)) => {
                conn.push(pack, now, d);
            }
            ConnectionResult::Connected(Some((pack, _)), c) => {
                conn.push(pack, now, d);
                *self = Conn::Done(d, c);
            }
            ConnectionResult::Connected(None, conn) => *self = Conn::Done(d, conn),
            ConnectionResult::NotHandled(_) | ConnectionResult::NoAction => {}
        }
    }

    fn handle_tick(&mut self, now: Instant, conn: &mut SyncLossyConn) {
        let nct = match self {
            Conn::PendingL(_, _) | Conn::Done(_, _) => return,
            Conn::PendingC(_, _, nct) | Conn::PendingR(_, _, nct) => nct,
        };
        if now >= *nct {
            *nct += CONN_TICK_TIME;
            let (d, res) = match self {
                Conn::PendingC(d, c, _) => (*d, c.handle_tick(now)),
                Conn::PendingR(d, r, _) => (*d, r.handle_tick(now)),
                _ => unreachable!(),
            };
            match res {
                ConnectionResult::Reject(_, _) => panic!("Reject?"),
                ConnectionResult::SendPacket((pack, _)) => {
                    conn.push(pack, now, d);
                }
                ConnectionResult::Connected(Some((pack, _)), c) => {
                    conn.push(pack, now, d);
                    *self = Conn::Done(d, c);
                }
                ConnectionResult::Connected(None, conn) => *self = Conn::Done(d, conn),
                ConnectionResult::NotHandled(_) | ConnectionResult::NoAction => {}
            }
        }
    }

    fn next_tick_time(&self) -> Option<Instant> {
        match self {
            Conn::Done(_, _) | Conn::PendingL(_, _) => None,
            Conn::PendingC(_, _, ntt) | Conn::PendingR(_, _, ntt) => Some(*ntt),
        }
    }
}

#[test]
fn precise_ts0() {
    let r_sa = ([127, 0, 0, 1], 2222).into();
    let s_sa: SocketAddr = ([127, 0, 0, 1], 2224).into();

    let seqno = SeqNumber::new_truncate(0);
    let s_sid = SocketId(1234);
    let r_sid = SocketId(5678);

    let rtt2 = Duration::from_millis(500);

    let start = Instant::now();

    let send = Conn::PendingC(
        Direction::A2B,
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

    let recv = Conn::PendingL(
        Direction::B2A,
        Listen::new(ConnInitSettings {
            starting_send_seqnum: seqno,
            local_sockid: r_sid,
            crypto: None,
            send_latency: Duration::from_millis(20),
            recv_latency: Duration::from_millis(20),
        }),
    );

    let mut conn = SyncLossyConn::new(rtt2, Duration::from_millis(0), 0., StdRng::seed_from_u64(0));

    let (a, b) = complete(send, recv, s_sa, r_sa, start, &mut conn);

    assert_eq!(a.settings.socket_start_time, b.settings.socket_start_time);
    assert_eq!(a.settings.rtt, rtt2 * 2);
    assert_eq!(b.settings.rtt, rtt2 * 2);
}

#[test]
fn lossy_connect() {
    for _ in 0..100 {
        let seed = rand::random();
        println!("Seed is {}", seed);
        do_lossy_connect(seed);
    }
}

fn do_lossy_connect(seed: u64) {
    let _ = pretty_env_logger::try_init();

    let c_sa: SocketAddr = ([127, 0, 0, 1], 2222).into();
    let l_sa: SocketAddr = ([127, 0, 0, 1], 2224).into();

    let start_seqno = SeqNumber::new_truncate(0);

    let r_sid = SocketId(1234);
    let s_sid = SocketId(2234);

    let start = Instant::now();

    let mut conn = helpers::SyncLossyConn::new(
        Duration::from_millis(20),
        Duration::from_millis(20),
        0.70,
        StdRng::seed_from_u64(seed),
    );

    let c = Conn::PendingC(
        Direction::A2B,
        Connect::new(
            l_sa,
            c_sa.ip(),
            ConnInitSettings {
                starting_send_seqnum: start_seqno,
                local_sockid: s_sid,
                crypto: None,
                send_latency: Duration::from_millis(20),
                recv_latency: Duration::from_millis(20),
            },
            None,
        ),
        start,
    );

    let l = Conn::PendingL(
        Direction::B2A,
        Listen::new(ConnInitSettings {
            starting_send_seqnum: start_seqno,
            local_sockid: r_sid,
            crypto: None,
            send_latency: Duration::from_millis(20),
            recv_latency: Duration::from_millis(20),
        }),
    );

    complete(c, l, c_sa, l_sa, start, &mut conn);
}

#[test]
fn lossy_rendezvous() {
    for _ in 0..100 {
        let seed = rand::random();
        println!("Seed is {}", seed);
        do_lossy_rendezvous(seed);
    }
}

fn do_lossy_rendezvous(seed: u64) {
    let _ = pretty_env_logger::try_init();

    let a_sa: SocketAddr = ([127, 0, 0, 1], 2222).into();
    let b_sa: SocketAddr = ([127, 0, 0, 1], 2224).into();

    let start_seqno = SeqNumber::new_truncate(0);

    let r_sid = SocketId(1234);
    let s_sid = SocketId(2234);

    let start = Instant::now();

    let mut conn = helpers::SyncLossyConn::new(
        Duration::from_millis(20),
        Duration::from_millis(20),
        0.70,
        StdRng::seed_from_u64(seed),
    );

    let a = Conn::PendingR(
        Direction::A2B,
        Rendezvous::new(
            a_sa,
            b_sa,
            ConnInitSettings {
                starting_send_seqnum: start_seqno,
                local_sockid: s_sid,
                crypto: None,
                send_latency: Duration::from_millis(20),
                recv_latency: Duration::from_millis(20),
            },
        ),
        start,
    );

    let b = Conn::PendingR(
        Direction::B2A,
        Rendezvous::new(
            b_sa,
            a_sa,
            ConnInitSettings {
                starting_send_seqnum: start_seqno,
                local_sockid: r_sid,
                crypto: None,
                send_latency: Duration::from_millis(20),
                recv_latency: Duration::from_millis(20),
            },
        ),
        start,
    );

    complete(a, b, a_sa, b_sa, start, &mut conn);
}

fn complete(
    mut a: Conn,
    mut b: Conn,
    a_sa: SocketAddr,
    b_sa: SocketAddr,
    mut current_time: Instant,
    conn: &mut SyncLossyConn,
) -> (Connection, Connection) {
    loop {
        let conn_time = loop {
            match conn.action(current_time) {
                Action::Release(packet, direction) => match direction {
                    Direction::A2B => b.handle_packet(packet, current_time, a_sa, conn),
                    Direction::B2A => a.handle_packet(packet, current_time, b_sa, conn),
                },
                Action::Wait(until) => break until,
            }
        };

        a.handle_tick(current_time, conn);
        b.handle_tick(current_time, conn);

        if let (Conn::Done(_, a), Conn::Done(_, b)) = (&mut a, &mut b) {
            break (a.clone(), b.clone());
        }

        let next_time = [conn_time, a.next_tick_time(), b.next_tick_time()]
            .iter()
            .copied()
            .flatten()
            .min()
            .unwrap();

        current_time = next_time;
    }
}
