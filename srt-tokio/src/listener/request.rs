use std::{io::ErrorKind, net::SocketAddr, time::Instant};

use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use srt_protocol::options::StreamId;
use srt_protocol::{connection::ConnectionSettings, listener::*, packet::*, settings::KeySettings};

use crate::{watch, SocketStatistics, SrtSocket};

#[derive(Debug)]
pub struct ConnectionRequest {
    response_sender: ResponseSender,
    request: AccessControlRequest,
    settings: oneshot::Receiver<ConnectionSettings>,
    input_data: mpsc::Sender<(Instant, Bytes)>,
    output_data: mpsc::Receiver<(Instant, Bytes)>,
    statistics: watch::Receiver<SocketStatistics>,
}

impl ConnectionRequest {
    pub(crate) fn new(
        session_id: SessionId,
        response_sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
        request: AccessControlRequest,
        settings: oneshot::Receiver<ConnectionSettings>,
        input_data: mpsc::Sender<(Instant, Bytes)>,
        output_data: mpsc::Receiver<(Instant, Bytes)>,
        statistics: watch::Receiver<SocketStatistics>,
    ) -> Self {
        Self {
            response_sender: ResponseSender(session_id, response_sender),
            request,
            settings,
            output_data,
            input_data,
            statistics,
        }
    }

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
            .settings
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::NotConnected, e))?;

        Ok(SrtSocket::create(
            settings,
            self.input_data,
            self.output_data,
            self.statistics,
        ))
    }

    pub async fn reject(self, reason: i32) -> Result<(), std::io::Error> {
        Ok(self
            .response_sender
            .send(AccessControlResponse::Rejected(RejectReason::User(reason)))
            .await?)
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
