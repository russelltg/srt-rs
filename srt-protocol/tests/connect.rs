use std::{
    cmp::min,
    net::SocketAddr,
    time::{Duration, Instant},
};

use log::debug;
use rand::{prelude::StdRng, SeedableRng};

use rand_distr::{Bernoulli, Normal};
use simulator::*;
use srt_protocol::{
    accesscontrol::AllowAllStreamAcceptor,
    connection::Input,
    packet::ControlTypes,
    pending_connection::{
        connect::Connect, listen::Listen, rendezvous::Rendezvous, ConnInitSettings,
        ConnectionResult,
    },
    Connection, ControlPacket, Packet, SeqNumber, SocketId,
};

pub mod simulator;

const CONN_TICK_TIME: Duration = Duration::from_millis(100);

#[allow(clippy::large_enum_variant)]
enum ConnectEntity {
    PendingL(Listen),
    PendingC(Connect, Instant),
    PendingR(Rendezvous, Instant),
    Done(Connection),
}

struct Conn {
    a: ConnectEntity,
    b: ConnectEntity,
    conn: NetworkSimulator,
    sim: RandomLossSimulation,
}

impl ConnectEntity {
    pub fn handle_packet(
        &mut self,
        packet: Packet,
        now: Instant,
        remote_sa: SocketAddr,
        conn: &mut NetworkSimulator,
        sim: &mut RandomLossSimulation,
    ) {
        let res = match self {
            ConnectEntity::PendingL(l) => l.handle_packet(
                (packet, remote_sa),
                now,
                &mut AllowAllStreamAcceptor::default(),
            ),
            ConnectEntity::PendingC(c, _) => c.handle_packet((packet, remote_sa), now),
            ConnectEntity::PendingR(r, _) => r.handle_packet((packet, remote_sa), now),
            ConnectEntity::Done(c) => {
                if let Packet::Control(ControlPacket {
                    control_type: ControlTypes::Handshake(hs),
                    ..
                }) = &packet
                {
                    match c.handshake.handle_handshake(hs.clone()) {
                        Some(control_type) => ConnectionResult::SendPacket((
                            Packet::Control(ControlPacket {
                                control_type,
                                ..packet.control().unwrap().clone() // this is chekced in the pattern, but can't be @'d
                            }),
                            remote_sa,
                        )),
                        None => ConnectionResult::NoAction,
                    }
                } else {
                    ConnectionResult::NoAction
                }
            }
        };
        match res {
            ConnectionResult::Reject(_, _) => panic!("Reject?"),
            ConnectionResult::SendPacket(pack) => conn.send_lossy(sim, now, pack),
            ConnectionResult::Connected(Some(pack), c) => {
                conn.send_lossy(sim, now, pack);
                *self = ConnectEntity::Done(c);
            }
            ConnectionResult::Connected(None, conn) => *self = ConnectEntity::Done(conn),
            ConnectionResult::NotHandled(_) | ConnectionResult::NoAction => {}
        }
    }

    fn handle_tick(
        &mut self,
        now: Instant,
        sim: &mut RandomLossSimulation,
        conn: &mut NetworkSimulator,
    ) {
        let nct = match self {
            ConnectEntity::PendingL(_) | ConnectEntity::Done(_) => return,
            ConnectEntity::PendingC(_, nct) | ConnectEntity::PendingR(_, nct) => nct,
        };

        if now >= *nct {
            *nct += CONN_TICK_TIME;
            let res = match self {
                ConnectEntity::PendingC(c, _) => c.handle_tick(now),
                ConnectEntity::PendingR(r, _) => r.handle_tick(now),
                _ => unreachable!(),
            };
            match res {
                ConnectionResult::Reject(_, _) => panic!("Reject?"),
                ConnectionResult::SendPacket(pack) => {
                    conn.send_lossy(sim, now, pack);
                }
                ConnectionResult::Connected(Some(pack), c) => {
                    conn.send_lossy(sim, now, pack);
                    *self = ConnectEntity::Done(c);
                }
                ConnectionResult::Connected(None, conn) => *self = ConnectEntity::Done(conn),
                ConnectionResult::NotHandled(_) | ConnectionResult::NoAction => {}
            }
        }
    }

    fn next_tick_time(&self) -> Option<Instant> {
        match self {
            ConnectEntity::Done(_) | ConnectEntity::PendingL(_) => None,
            ConnectEntity::PendingC(_, ntt) | ConnectEntity::PendingR(_, ntt) => Some(*ntt),
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

    let send = ConnectEntity::PendingC(
        Connect::new(
            r_sa,
            s_sa.ip(),
            ConnInitSettings {
                local_sockid: s_sid,
                crypto: None,
                send_latency: Duration::from_millis(2000),
                recv_latency: Duration::from_millis(20),
            },
            None,
            seqno,
        ),
        start,
    );

    let recv = ConnectEntity::PendingL(Listen::new(ConnInitSettings {
        local_sockid: r_sid,
        crypto: None,
        send_latency: Duration::from_millis(20),
        recv_latency: Duration::from_millis(20),
    }));

    let conn = NetworkSimulator::new(s_sa, r_sa);

    let sim = RandomLossSimulation {
        rng: StdRng::seed_from_u64(0),
        delay_dist: Normal::new(rtt2.as_secs_f64(), 0.0).unwrap(),
        drop_dist: Bernoulli::new(0.).unwrap(),
    };

    let (a, b) = complete(
        Conn {
            a: send,
            b: recv,
            conn,
            sim,
        },
        start,
    );

    assert_eq!(
        a.settings.socket_start_time,
        b.settings.socket_start_time,
        "{:?}!={:?}",
        a.settings.socket_start_time - start,
        b.settings.socket_start_time - start
    );
    assert_eq!(a.settings.rtt, rtt2 * 2);
    assert_eq!(b.settings.rtt, rtt2 * 2);
}

#[test]
fn lossy_connect() {
    for _ in 0..100 {
        let seed = rand::random();
        println!("Connect seed is {}", seed);
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

    let conn = NetworkSimulator::new(c_sa, l_sa);

    let sim = RandomLossSimulation {
        rng: StdRng::seed_from_u64(seed),
        delay_dist: Normal::new(0.02, 0.02).unwrap(),
        drop_dist: Bernoulli::new(0.7).unwrap(),
    };

    let c = ConnectEntity::PendingC(
        Connect::new(
            l_sa,
            c_sa.ip(),
            ConnInitSettings {
                local_sockid: s_sid,
                crypto: None,
                send_latency: Duration::from_millis(20),
                recv_latency: Duration::from_millis(20),
            },
            None,
            start_seqno,
        ),
        start,
    );

    let l = ConnectEntity::PendingL(Listen::new(ConnInitSettings {
        local_sockid: r_sid,
        crypto: None,
        send_latency: Duration::from_millis(20),
        recv_latency: Duration::from_millis(20),
    }));

    complete(
        Conn {
            a: c,
            b: l,
            conn,
            sim,
        },
        start,
    );
}

#[test]
fn lossy_rendezvous() {
    let _ = pretty_env_logger::try_init();

    // run once failing seeds
    do_lossy_rendezvous(1104041222010949432);
    do_lossy_rendezvous(16693786644192575166);

    for _ in 0..100 {
        let seed = rand::random();
        do_lossy_rendezvous(seed);
    }
}

fn do_lossy_rendezvous(seed: u64) {
    println!("Rendezvous seed is {}", seed);

    let a_sa: SocketAddr = ([127, 0, 0, 1], 2222).into();
    let b_sa: SocketAddr = ([127, 0, 0, 1], 2224).into();

    let start_seqno = SeqNumber::new_truncate(0);

    let r_sid = SocketId(1234);
    let s_sid = SocketId(2234);

    let start = Instant::now();

    let conn = NetworkSimulator::new(a_sa, b_sa);

    let sim = RandomLossSimulation {
        rng: StdRng::seed_from_u64(seed),
        delay_dist: Normal::new(0.02, 0.02).unwrap(),
        drop_dist: Bernoulli::new(0.70).unwrap(),
    };

    let a = ConnectEntity::PendingR(
        Rendezvous::new(
            a_sa,
            b_sa,
            ConnInitSettings {
                local_sockid: s_sid,
                crypto: None,
                send_latency: Duration::from_millis(20),
                recv_latency: Duration::from_millis(20),
            },
            start_seqno,
        ),
        start,
    );

    let b = ConnectEntity::PendingR(
        Rendezvous::new(
            b_sa,
            a_sa,
            ConnInitSettings {
                local_sockid: r_sid,
                crypto: None,
                send_latency: Duration::from_millis(20),
                recv_latency: Duration::from_millis(20),
            },
            start_seqno,
        ),
        start,
    );

    complete(Conn { a, b, conn, sim }, start);
}

fn complete(mut conn: Conn, start: Instant) -> (Connection, Connection) {
    const TIME_LIMIT: Duration = Duration::from_secs(10);

    let mut current_time = start;

    loop {
        // assert!(current_time - start < TIME_LIMIT);
        if current_time - start > TIME_LIMIT {
            println!("Hi")
        }

        let sender_time = loop {
            match conn.conn.sender.select_next_input(
                current_time,
                conn.a
                    .next_tick_time()
                    .unwrap_or(current_time + Duration::from_secs(1)),
            ) {
                (time, Input::Packet(Some((packet, sa)))) => {
                    debug!("b->a {:?}", packet);
                    conn.a
                        .handle_packet(packet, time, sa, &mut conn.conn, &mut conn.sim)
                }
                (time, Input::Timer) => break time,
                _ => unreachable!(),
            }
        };
        let recvr_time = loop {
            match conn.conn.receiver.select_next_input(
                current_time,
                conn.b
                    .next_tick_time()
                    .unwrap_or(current_time + Duration::from_secs(1)),
            ) {
                (time, Input::Packet(Some((packet, sa)))) => {
                    debug!("a->b {:?}", packet);
                    conn.b
                        .handle_packet(packet, time, sa, &mut conn.conn, &mut conn.sim)
                }
                (time, Input::Timer) => break time,
                _ => unreachable!(),
            }
        };

        conn.a
            .handle_tick(current_time, &mut conn.sim, &mut conn.conn);
        conn.b
            .handle_tick(current_time, &mut conn.sim, &mut conn.conn);

        if let (ConnectEntity::Done(a), ConnectEntity::Done(b)) = (&mut conn.a, &mut conn.b) {
            break (a.clone(), b.clone());
        }

        let next_time = min(sender_time, recvr_time);

        current_time = next_time;
    }
}
