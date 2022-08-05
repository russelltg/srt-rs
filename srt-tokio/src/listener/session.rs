use std::{io::ErrorKind, net::SocketAddr};

use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use srt_protocol::{
    connection::{Connection, ConnectionSettings},
    listener::*,
    options::*,
    packet::*,
    settings::*,
};
use tokio::task::JoinHandle;

use crate::{
    net::PacketSocket,
    socket::factory::{self, SrtSocketFactory, SrtSocketTaskFactory},
    SrtSocket,
};

#[derive(Debug)]
pub struct ConnectionRequest {
    response_sender: ResponseSender,
    request: AccessControlRequest,
    settings_receiver: oneshot::Receiver<(ConnectionSettings, JoinHandle<()>)>,
    socket_factory: SrtSocketFactory,
}

impl ConnectionRequest {
    pub fn local_socket_id(&self) -> SocketId {
        self.request.local_socket_id
    }
    pub fn remote_socket_id(&self) -> SocketId {
        self.request.remote_socket_id
    }
    pub fn remote(&self) -> SocketAddr {
        self.request.remote
    }
    pub fn stream_id(&self) -> Option<&StreamId> {
        self.request.stream_id.as_ref()
    }

    pub async fn accept(
        self,
        key_settings: Option<KeySettings>,
    ) -> Result<SrtSocket, std::io::Error> {
        self.response_sender
            .send(AccessControlResponse::Accepted(key_settings))
            .await?;

        let (settings, jh) = self
            .settings_receiver
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::NotConnected, e))?;

        Ok(self.socket_factory.create_socket(settings, jh))
    }

    pub async fn reject(self, reason: RejectReason) -> Result<(), std::io::Error> {
        self
            .response_sender
            .send(AccessControlResponse::Rejected(reason))
            .await
    }
}

#[derive(Debug)]
pub struct PendingConnection {
    settings_sender: oneshot::Sender<(ConnectionSettings, JoinHandle<()>)>,
    task_factory: SrtSocketTaskFactory,
}

impl PendingConnection {
    pub fn start_approval(
        session_id: SessionId,
        request: AccessControlRequest,
        response_sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
    ) -> (PendingConnection, ConnectionRequest) {
        let (socket_factory, task_factory) = factory::split_new();

        let (settings_sender, settings_receiver) = oneshot::channel();
        let response_sender = ResponseSender(session_id, response_sender);

        let state = PendingConnection {
            settings_sender,
            task_factory,
        };

        let request = ConnectionRequest {
            request,
            response_sender,
            settings_receiver,
            socket_factory,
        };

        (state, request)
    }

    pub fn transition_to_open(
        self,
        socket: &PacketSocket,
        connection: Connection,
    ) -> Result<OpenConnection, ()> {
        let (packet_sender, socket) = socket.clone_channel(100);
        let (handle, settings) = self.task_factory.spawn_task(socket, connection);
        let _ = self
            .settings_sender
            .send((settings, handle))
            .ok()
            .ok_or(())?;
        Ok(OpenConnection { packet_sender })
    }
}

#[derive(Debug)]
pub struct OpenConnection {
    packet_sender: mpsc::Sender<ReceivePacketResult>,
}

impl OpenConnection {
    pub async fn send(&mut self, packet: (Packet, SocketAddr)) -> Result<(), ()> {
        match self.packet_sender.try_send(Ok(packet)) {
            Err(e) if e.is_full() => self.packet_sender.send(e.into_inner()).await.ok().ok_or(()),
            r => r.ok().ok_or(()),
        }
    }

    pub async fn close(&mut self) -> Result<(), ()> {
        self.packet_sender.close().await.ok().ok_or(())
    }
}

#[derive(Debug)]
struct ResponseSender(SessionId, mpsc::Sender<(SessionId, AccessControlResponse)>);

impl ResponseSender {
    async fn send(mut self, response: AccessControlResponse) -> Result<(), std::io::Error> {
        self.1
            .send((self.0, response))
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::NotConnected, e))
    }
}
