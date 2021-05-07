use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use log::info;
use srt_protocol::{
    accesscontrol::AllowAllStreamAcceptor,
    pending_connection::{connect::Connect, listen::Listen, ConnectionResult},
    protocol::{
        receiver::{Receiver, ReceiverAlgorithmAction},
        sender::{Sender, SenderAlgorithmAction},
    },
    Packet,
};

use super::SyncLossyConn;

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
        loop {
            match self {
                ConnSend::Conn(connect, next_time) => {
                    let next_time_deref = *next_time;
                    if now >= *next_time {
                        *next_time += Duration::from_millis(100);
                        let res = connect.handle_tick(now);
                        self.handle_connection_result(res, now, conn);
                    }
                    break Some(next_time_deref);
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

                    break next_time;
                }
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
        mut on_pack: impl FnMut(Instant, Bytes) -> (),
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
