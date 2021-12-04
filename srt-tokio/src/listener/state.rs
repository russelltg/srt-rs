use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use futures::{channel::mpsc, prelude::*, select, SinkExt};
use log::debug;
use srt_protocol::{connection::Connection, listener::*, packet::*, settings::ConnInitSettings};
use tokio::time::sleep_until;

use crate::{net::PacketSocket, watch};

use super::session::*;

pub struct SrtListenerState {
    listener: MultiplexListener,
    socket: PacketSocket,
    request_sender: mpsc::Sender<ConnectionRequest>,
    response_sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
    response_receiver: mpsc::Receiver<(SessionId, AccessControlResponse)>,
    statistics_sender: watch::Sender<ListenerStatistics>,
    pending_connections: HashMap<SessionId, PendingConnection>,
    open_connections: HashMap<SessionId, OpenConnection>,
}

// TODO: allow configuring using options module
impl SrtListenerState {
    pub fn new(
        socket: PacketSocket,
        request_sender: mpsc::Sender<ConnectionRequest>,
        statistics_sender: watch::Sender<ListenerStatistics>,
    ) -> Self {
        let settings = ConnInitSettings::default();
        let listener = MultiplexListener::new(Instant::now(), settings);
        let (response_sender, response_receiver) = mpsc::channel(100);
        Self {
            listener,
            socket,
            request_sender,
            response_sender,
            response_receiver,
            statistics_sender,
            pending_connections: Default::default(),
            open_connections: Default::default(),
        }
    }

    pub async fn run_loop(mut self) {
        use Action::*;
        let mut input = Input::Timer;
        loop {
            let now = Instant::now();
            let timeout = now + Duration::from_millis(100);
            debug!("{:?}", input);
            let action = self.listener.handle_input(now, input);
            debug!("{:?}", action);
            let next = NextInputContext::for_action(&action);
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
                DropConnection(session_id) => next.input_from(self.drop_connection(session_id)),
                UpdateStatistics(statistics) => {
                    next.input_from(self.statistics_sender.send(statistics.clone()))
                }
                WaitForInput => select! {
                    packet = self.socket.receive().fuse() => Input::Packet(packet),
                    response = self.response_receiver.next() => Input::AccessResponse(response),
                    _ = sleep_until(timeout.into()).fuse() => Input::Timer,
                },
                Close => break,
            }
        }
    }

    async fn request_access(
        &mut self,
        session_id: SessionId,
        request: AccessControlRequest,
    ) -> Result<(), ()> {
        assert!(!self.pending_connections.contains_key(&session_id));
        let request_sender = &mut self.request_sender;
        let response_sender = self.response_sender.clone();
        let (pending, request) =
            PendingConnection::start_approval(session_id, request, response_sender);
        let _ = request_sender.send(request).await.ok().ok_or(())?;
        let _ = self.pending_connections.insert(session_id, pending);
        Ok(())
    }

    async fn reject_connection(
        &mut self,
        session_id: SessionId,
        packet: Option<(Packet, SocketAddr)>,
    ) -> Result<usize, ()> {
        assert!(!self.pending_connections.contains_key(&session_id));
        let _ = self.pending_connections.remove(&session_id);
        let packet = packet.ok_or(())?;
        self.socket.send(packet).await.ok().ok_or(())
    }

    async fn open_connection(
        &mut self,
        session_id: SessionId,
        connection: Box<(Option<(Packet, SocketAddr)>, Connection)>,
    ) -> Result<usize, ()> {
        assert!(!self.open_connections.contains_key(&session_id));
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
        let conn = self.open_connections.get_mut(&session_id).ok_or(())?;
        conn.send(packet).await
    }

    fn drop_connection(&mut self, session_id: SessionId) -> Result<(), ()> {
        match self.open_connections.remove(&session_id) {
            Some(_) => Ok(()),
            None => Err(()),
        }
    }
}
