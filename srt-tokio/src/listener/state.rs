use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    prelude::*,
    select, SinkExt,
};
use log::debug;
use srt_protocol::settings::ConnInitSettings;
use srt_protocol::{
    connection::{Connection, ConnectionSettings},
    listener::*,
    packet::*,
};
use tokio::{task::JoinHandle, time::sleep_until};

use crate::{net::PacketSocket, watch, SocketStatistics, SrtSocket};

use super::ConnectionRequest;

pub struct SrtListenerState {
    listener: MultiplexListener,
    socket: PacketSocket,
    request_sender: mpsc::Sender<ConnectionRequest>,
    response_sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
    response_receiver: mpsc::Receiver<(SessionId, AccessControlResponse)>,
    statistics_sender: watch::Sender<ListenerStatistics>,
    pending_connections: HashMap<SessionId, PendingApproval>,
    active_connections: HashMap<SessionId, ActiveConnection>,
}

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
            pending_connections: HashMap::new(),
            active_connections: HashMap::new(),
        }
    }

    pub async fn run_loop(mut self) {
        let mut input = Input::Timer;
        use Action::*;
        loop {
            let now = Instant::now();
            let timeout = now + Duration::from_millis(100);
            debug!("{:?}", input);
            let action = self.listener.handle_input(now, input);
            debug!("{:?}", action);
            input = match action {
                SendPacket(packet) => match self.socket.send(packet).await {
                    Ok(size) => Input::PacketSent(size),
                    Err(_) => Input::Failure(ActionError::SendPacketFailed),
                },
                UpdateStatistics(statistics) => {
                    match self.statistics_sender.send(statistics.clone()) {
                        Ok(()) => Input::StatisticsUpdated,
                        Err(_) => Input::Failure(ActionError::SendStatistics),
                    }
                }
                RequestAccess(session_id, request) => {
                    assert!(!self.pending_connections.contains_key(&session_id));

                    let result = PendingApproval::new_request(
                        &mut self.request_sender,
                        session_id.clone(),
                        request,
                        self.response_sender.clone(),
                    )
                    .await;

                    match result {
                        Ok(pending) => {
                            let _ = self.pending_connections.insert(session_id.clone(), pending);
                            Input::AccessRequested(session_id)
                        }
                        Err(_) => Input::Failure(ActionError::RequestAccessFailed(session_id)),
                    }
                }
                RejectConnection(session_id, packet) => {
                    let _ = self.pending_connections.remove(&session_id);
                    match packet {
                        Some(packet) => match self.socket.send(packet).await {
                            Ok(size) => Input::PacketSent(size),
                            Err(_) => Input::Failure(ActionError::SendPacketFailed),
                        },
                        None => Input::ConnectionRejected(session_id),
                    }
                }
                OpenConnection(session_id, connection) => {
                    assert!(!self.active_connections.contains_key(&session_id));
                    let (packet, c) = *connection;
                    match self.pending_connections.remove(&session_id) {
                        Some(pending) => match pending.open_connection(&self.socket, c) {
                            Ok(active) => {
                                self.active_connections.insert(session_id.clone(), active);
                                match packet {
                                    Some(packet) => match self.socket.send(packet).await {
                                        Ok(size) => Input::PacketSent(size),
                                        Err(_) => Input::Failure(ActionError::SendPacketFailed),
                                    },
                                    None => Input::ConnectionOpened(session_id),
                                }
                            }
                            Err(_) => Input::Failure(ActionError::OpenConnectionFailed(session_id)),
                        },
                        None => Input::Failure(ActionError::PendingConnectionMissing(session_id)),
                    }
                }
                DelegatePacket(session_id, packet) => {
                    match self.active_connections.get_mut(&session_id) {
                        Some(connection) => match connection.packet_sender.send(Ok(packet)).await {
                            Ok(()) => Input::PacketDelegated(session_id),
                            Err(_) => Input::Failure(ActionError::DelegatePacketFailed(session_id)),
                        },
                        None => Input::Failure(ActionError::ActiveConnectionMissing(session_id)),
                    }
                }
                DropConnection(session_id) => match self.active_connections.remove(&session_id) {
                    Some(_) => Input::ConnectionDropped(session_id),
                    None => Input::Failure(ActionError::ActiveConnectionMissing(session_id)),
                },
                WaitForInput => select! {
                    packet = self.socket.receive().fuse() => Input::Packet(packet),
                    response = self.response_receiver.next() => Input::AccessResponse(response),
                    _ = sleep_until(timeout.into()).fuse() => Input::Timer,
                },
                Close => break,
            }
        }
    }
}

struct PendingApproval {
    settings_sender: oneshot::Sender<ConnectionSettings>,
    input_data_receiver: mpsc::Receiver<(Instant, Bytes)>,
    output_data_sender: mpsc::Sender<(Instant, Bytes)>,
    statistics_sender: watch::Sender<SocketStatistics>,
}

struct ActiveConnection {
    _handle: JoinHandle<()>,
    packet_sender: mpsc::Sender<ReceivePacketResult>,
}

impl PendingApproval {
    async fn new_request(
        request_sender: &mut mpsc::Sender<ConnectionRequest>,
        session_id: SessionId,
        request: AccessControlRequest,
        response_sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
    ) -> Result<PendingApproval, mpsc::SendError> {
        let (settings_sender, settings_receiver) = oneshot::channel();
        let (output_data_sender, output_data_receiver) = mpsc::channel(128);
        let (input_data_sender, input_data_receiver) = mpsc::channel(128);
        let (statistics_sender, statistics_receiver) = watch::channel();

        let state = PendingApproval {
            settings_sender,
            output_data_sender,
            input_data_receiver,
            statistics_sender,
        };

        let settings = settings_receiver;
        let input_data = input_data_sender;
        let output_data = output_data_receiver;
        let statistics = statistics_receiver;
        let request = ConnectionRequest::new(
            session_id,
            response_sender,
            request,
            settings,
            input_data,
            output_data,
            statistics,
        );

        let _ = request_sender.send(request).await?;

        Ok(state)
    }

    fn open_connection(
        self,
        socket: &PacketSocket,
        connection: Connection,
    ) -> Result<ActiveConnection, ConnectionSettings> {
        let (packet_sender, socket) = socket.clone_channel(100);
        let (handle, settings) = SrtSocket::spawn(
            connection,
            socket,
            self.input_data_receiver,
            self.output_data_sender,
            self.statistics_sender,
        );
        let _ = self.settings_sender.send(settings)?;
        Ok(ActiveConnection {
            _handle: handle,
            packet_sender,
        })
    }
}
