use std::time::Instant;

use bytes::Bytes;
use futures::{channel::mpsc, prelude::*, select};
use log::{error, trace};
use srt_protocol::{
    connection::{Action, DuplexConnection, Input},
    packet::TimeSpan,
};
use tokio::{task::JoinHandle, time::sleep_until};

use crate::{net::PacketSocket, watch, SocketStatistics, SrtSocket};

pub struct SrtSocketState {
    socket: PacketSocket,
    connection: DuplexConnection,
    statistics_sender: watch::Sender<SocketStatistics>,
    output_data_sender: mpsc::Sender<(Instant, Bytes)>,
    input_data_receiver: mpsc::Receiver<(Instant, Bytes)>,
}

impl SrtSocketState {
    pub fn spawn_socket(
        socket: PacketSocket,
        connection: DuplexConnection,
    ) -> (JoinHandle<()>, SrtSocket) {
        let (output_data_sender, output_data_receiver) = mpsc::channel(128);
        let (input_data_sender, input_data_receiver) = mpsc::channel(128);
        let (statistics_sender, statistics_receiver) = watch::channel();
        let settings = connection.settings().clone();

        let state = SrtSocketState {
            socket,
            connection,
            statistics_sender,
            output_data_sender,
            input_data_receiver,
        };

        let handle = tokio::spawn(async move { state.run_loop().await });

        let socket = SrtSocket {
            settings,
            output_data_receiver,
            input_data_sender,
            statistics_receiver,
        };

        (handle, socket)
    }

    pub async fn run_loop(self) {
        // Using run_input_loop breaks a couple of the stransmit_interop tests.
        // Both stransmit_decrypt and stransmit_server run indefinitely. For now,
        // run_handler_loop exclusively, until a fix is found or an API decision
        // is reached.
        if Instant::now().elapsed().as_nanos() != 0 {
            self.run_handler_loop().await;
        } else {
            self.run_input_loop().await;
        }
    }

    async fn run_handler_loop(self) {
        let local_sockid = self.connection.settings().local_sockid;
        let mut socket = self.socket;
        let mut input_data = self.input_data_receiver.fuse();
        let mut output_data = self.output_data_sender;
        let mut connection = self.connection;
        let statistics_sender = self.statistics_sender;
        while connection.is_open() {
            if connection.should_update_statistics(Instant::now()) {
                let _ = statistics_sender.send(connection.statistics().clone());
            }

            while let Some(packet) = connection.next_packet(Instant::now()) {
                if let Err(e) = socket.send(packet).await {
                    error!("Error while sending packet: {:?}", e); // TODO: real error handling
                }
            }

            while let Some(data) = connection.next_data(Instant::now()) {
                if output_data.is_closed() {
                    continue;
                }
                if let Err(e) = output_data.send(data).await {
                    error!("Error while releasing packet {:?}", e);
                }
            }

            let timeout = connection.check_timers(Instant::now());
            let timeout_fut = async {
                let now = Instant::now();
                trace!(
                    "{:?} scheduling wakeup at {:?}",
                    local_sockid,
                    TimeSpan::from_interval(timeout, now),
                );
                sleep_until(timeout.into()).await
            };

            let input = select! {
                // one of the entities requested wakeup
                _ = timeout_fut.fuse() => Input::Timer,
                // new packet received
                packet = socket.receive().fuse() =>
                    Input::Packet(packet),
                // new packet queued
                data = input_data.next() => {
                    Input::Data(data)
                }
            };

            match input {
                Input::Packet(packet) => connection.handle_packet_input(Instant::now(), packet),
                Input::Data(data) => connection.handle_data_input(Instant::now(), data),
                _ => {}
            }
        }
        if let Err(e) = output_data.close().await {
            error!("Error while closing data output stream {:?}", e);
        }
    }

    async fn run_input_loop(self) {
        let mut socket = self.socket;
        let mut input_data = self.input_data_receiver.fuse();
        let mut output_data = self.output_data_sender;
        let mut connection = self.connection;
        let statistics_sender = self.statistics_sender;
        let mut input = Input::Timer;
        loop {
            let now = Instant::now();
            input = match connection.handle_input(now, input) {
                Action::Close => break,
                Action::ReleaseData(data) => {
                    if !output_data.is_closed() {
                        if let Err(e) = output_data.send(data).await {
                            error!("Error while releasing data {:?}", e);
                        }
                    }
                    Input::DataReleased
                }
                Action::SendPacket(packet) => {
                    if let Err(e) = socket.send(packet).await {
                        error!("Error while seding packet: {:?}", e); // TODO: real error handling
                    }
                    Input::PacketSent
                }
                Action::UpdateStatistics(statistics) => {
                    let _ = statistics_sender.send(statistics.clone());
                    Input::StatisticsUpdated
                }
                Action::WaitForData(wait) => {
                    let timeout = now + wait;
                    select! {
                        _ = sleep_until(timeout.into()).fuse() => Input::Timer,
                        packet = socket.receive().fuse() =>
                            Input::Packet(packet),
                        res = input_data.next() => {
                            Input::Data(res)
                        }
                    }
                }
            }
        }
        if let Err(e) = output_data.close().await {
            error!("Error while closing data output stream {:?}", e);
        }
    }
}
