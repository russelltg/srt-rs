use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use futures::{channel::mpsc, future::Fuse, prelude::*, select, FutureExt, SinkExt};
use srt_protocol::{connection::Connection, listener::*, packet::*, settings::ConnInitSettings};
use tokio::sync::oneshot;

use crate::{net::PacketSocket, watch};

use super::session::*;

pub struct SrtListenerState {
    local_address: SocketAddr,
    listener: MultiplexListener,
    socket: PacketSocket,
    request_sender: mpsc::Sender<ConnectionRequest>,
    response_sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
    response_receiver: mpsc::Receiver<(SessionId, AccessControlResponse)>,
    statistics_sender: watch::Sender<ListenerStatistics>,
    pending_connections: HashMap<SessionId, PendingConnection>,
    open_connections: HashMap<SessionId, OpenConnection>,
    close_recvr: Fuse<oneshot::Receiver<()>>,
}

impl SrtListenerState {
    pub fn new(
        socket: PacketSocket,
        local_address: SocketAddr,
        settings: ConnInitSettings,
        request_sender: mpsc::Sender<ConnectionRequest>,
        statistics_sender: watch::Sender<ListenerStatistics>,
        close_recvr: oneshot::Receiver<()>,
    ) -> Self {
        let listener = MultiplexListener::new(Instant::now(), local_address, settings);
        let (response_sender, response_receiver) = mpsc::channel(100);
        Self {
            local_address,
            listener,
            socket,
            request_sender,
            response_sender,
            response_receiver,
            statistics_sender,
            pending_connections: Default::default(),
            open_connections: Default::default(),
            close_recvr: close_recvr.fuse(),
        }
    }

    pub async fn run_loop(mut self) {
        use Action::*;
        let mut input = Input::Timer;
        let mut timer_interval = tokio::time::interval(Duration::from_millis(100));
        let start = Instant::now();
        let elapsed = |now: Instant| TimeSpan::from_interval(start, now);
        loop {
            let now = Instant::now();
            log::debug!(
                "{:?}|listener:{}|input - {:?}",
                elapsed(now),
                self.local_address,
                input
            );

            let action = self.listener.handle_input(now, input);
            let next = NextInputContext::for_action(&action);

            log::debug!(
                "{:?}|listener:{}|action - {:?}",
                elapsed(now),
                self.local_address,
                action
            );

            input = match action {
                SendPacket(packet) => next.input_from(self.socket.send(packet).await),
                RequestAccess(session_id, request) => {
                    next.input_from(self.request_access(session_id, request).await)
                }
                RejectConnection(session_id, packet) => {
                    next.input_from(self.reject_connection(session_id, packet).await)
                }
                OpenConnection(session_id, connection) => {
                    next.input_from(self.open_connection(session_id, connection).await)
                }
                DelegatePacket(session_id, packet) => {
                    next.input_from(self.delegate_packet(session_id, packet).await)
                }
                DropConnection(session_id) => {
                    next.input_from(self.drop_connection(session_id).await)
                }
                UpdateStatistics(statistics) => {
                    next.input_from(self.statistics_sender.send(statistics.clone()))
                }
                WaitForInput => select! {
                    packet = self.socket.receive().fuse() => Input::Packet(packet),
                    response = self.response_receiver.next() => Input::AccessResponse(response),
                    _ = timer_interval.tick().fuse() => Input::Timer,
                    _ = &mut self.close_recvr => break,
                },
                Close => break,
            }
        }

        for conn in self.open_connections.values_mut() {
            let _ = conn.close().await;
        }
    }

    async fn request_access(
        &mut self,
        session_id: SessionId,
        request: AccessControlRequest,
    ) -> Result<(), ()> {
        let request_sender = &mut self.request_sender;
        let response_sender = self.response_sender.clone();
        let (pending, request) =
            PendingConnection::start_approval(session_id, request, response_sender);
        request_sender.send(request).await.ok().ok_or(())?;
        let _ = self.pending_connections.insert(session_id, pending);
        Ok(())
    }

    async fn reject_connection(
        &mut self,
        session_id: SessionId,
        packet: Option<(Packet, SocketAddr)>,
    ) -> Result<usize, ()> {
        let _ = self.pending_connections.remove(&session_id);
        if let Some(packet) = packet {
            self.socket.send(packet).await.ok().ok_or(())
        } else {
            Ok(0)
        }
    }

    async fn open_connection(
        &mut self,
        session_id: SessionId,
        connection: Box<(Option<(Packet, SocketAddr)>, Connection)>,
    ) -> Result<usize, ()> {
        let (packet, connection) = *connection;
        let pending = self.pending_connections.remove(&session_id).ok_or(())?;
        let active = pending.transition_to_open(&self.socket, connection)?;
        let _ = self.open_connections.insert(session_id, active);
        match packet {
            Some(packet) => self.socket.send(packet).await.ok().ok_or(()),
            None => Ok(0),
        }
    }

    async fn delegate_packet(
        &mut self,
        session_id: SessionId,
        packet: (Packet, SocketAddr),
    ) -> Result<(), ()> {
        match self.open_connections.get_mut(&session_id) {
            Some(connection) => connection.send(packet).await,
            None => Ok(()),
        }
    }

    async fn drop_connection(&mut self, session_id: SessionId) -> Result<(), ()> {
        match self.open_connections.remove(&session_id) {
            Some(mut connection) => connection.close().await,
            None => Ok(()),
        }
    }
}
