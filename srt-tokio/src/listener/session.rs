use std::{io::ErrorKind, net::SocketAddr, time::Instant};

use bytes::Bytes;
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

use crate::{net::PacketSocket, watch, SocketStatistics, SrtSocket};

#[derive(Debug)]
pub struct ConnectionRequest {
    response_sender: ResponseSender,
    request: AccessControlRequest,
    settings_receiver: oneshot::Receiver<ConnectionSettings>,
    input_data_sender: mpsc::Sender<(Instant, Bytes)>,
    output_data_receiver: mpsc::Receiver<(Instant, Bytes)>,
    statistics_receiver: watch::Receiver<SocketStatistics>,
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

        let settings = self
            .settings_receiver
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::NotConnected, e))?;

        Ok(SrtSocket::create(
            settings,
            self.input_data_sender,
            self.output_data_receiver,
            self.statistics_receiver,
        ))
    }

    pub async fn reject(self, reason: i32) -> Result<(), std::io::Error> {
        Ok(self
            .response_sender
            .send(AccessControlResponse::Rejected(RejectReason::User(reason)))
            .await?)
    }
}

pub struct PendingConnection {
    settings_sender: oneshot::Sender<ConnectionSettings>,
    input_data_receiver: mpsc::Receiver<(Instant, Bytes)>,
    output_data_sender: mpsc::Sender<(Instant, Bytes)>,
    statistics_sender: watch::Sender<SocketStatistics>,
}

impl PendingConnection {
    pub fn start_approval(
        session_id: SessionId,
        request: AccessControlRequest,
        response_sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
    ) -> (PendingConnection, ConnectionRequest) {
        let (settings_sender, settings_receiver) = oneshot::channel();
        let (output_data_sender, output_data_receiver) = mpsc::channel(128);
        let (input_data_sender, input_data_receiver) = mpsc::channel(128);
        let (statistics_sender, statistics_receiver) = watch::channel();
        let response_sender = ResponseSender(session_id, response_sender);

        let state = PendingConnection {
            settings_sender,
            output_data_sender,
            input_data_receiver,
            statistics_sender,
        };

        let request = ConnectionRequest {
            request,
            response_sender,
            settings_receiver,
            input_data_sender,
            output_data_receiver,
            statistics_receiver,
        };

        (state, request)
    }

    pub fn transition_to_open(
        self,
        socket: &PacketSocket,
        connection: Connection,
    ) -> Result<OpenConnection, ()> {
        let (packet_sender, socket) = socket.clone_channel(100);
        let (handle, settings) = SrtSocket::spawn(
            connection,
            socket,
            self.input_data_receiver,
            self.output_data_sender,
            self.statistics_sender,
        );
        let _ = self.settings_sender.send(settings).ok().ok_or(())?;
        Ok(OpenConnection {
            _handle: handle,
            packet_sender,
        })
    }
}

pub struct OpenConnection {
    _handle: JoinHandle<()>,
    packet_sender: mpsc::Sender<ReceivePacketResult>,
}

impl OpenConnection {
    pub async fn send(&mut self, packet: (Packet, SocketAddr)) -> Result<(), ()> {
        self.packet_sender.send(Ok(packet)).await.ok().ok_or(())
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
