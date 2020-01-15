use crate::packet::PacketCodec;
use crate::protocol::sender::{Sender, SenderAlgorithmAction};
use crate::protocol::Handshake;
use crate::{SrtCongestCtrl, ControlPacket, DataPacket, Packet};
use bytes::Bytes;
use failure::Error;
use futures::channel::{mpsc, oneshot};
use futures::future::Fuse;
use futures::select;
use futures::{FutureExt, SinkExt, StreamExt};
use log::debug;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::delay_until;
use tokio_util::udp::UdpFramed;

pub struct SrtCaller {
    close_tx: Option<oneshot::Sender<()>>,
    srt_send_tx: mpsc::Sender<(Bytes, Instant)>,
    _task: tokio::task::JoinHandle<()>,
}

impl SrtCaller {
    pub async fn connect(remote: SocketAddr) -> Result<SrtCaller, Error> {
        // TODO: unify errors and remove panics

        let local = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let latency = Duration::from_millis(50);

        let mut socket = UdpFramed::new(UdpSocket::bind(local).await.unwrap(), PacketCodec {});
        let connect = crate::pending_connection::connect(
            &mut socket,
            remote,
            rand::random(),
            local.ip(),
            latency,
            None,
        )
        .await
        .unwrap();

        let (close_tx, close_rx) = oneshot::channel();
        let (srt_send_tx, srt_send_rx) = mpsc::channel::<(Bytes, Instant)>(10);

        let sender = Sender::new(
            connect.settings,
            // TODO: use handshake method from sender
            Handshake::Caller,
            SrtCongestCtrl,
        );

        let mut state = SrtConnectionState {
            // this needs to be fused here so it actually doesn't get polled after
            // completion
            // the streams don't need this as we construct a new futures each time[
            close_rx: close_rx.fuse(),
            srt_send_rx,
            socket,
            sender,
        };

        let task = tokio::spawn(async move {
            state.run().await;
        });

        Ok(SrtCaller {
            close_tx: Some(close_tx),
            srt_send_tx: srt_send_tx,
            _task: task,
        })
    }

    pub async fn send(&mut self, data: Bytes) -> Result<(), mpsc::SendError> {
        self.srt_send_tx.send((data, Instant::now())).await
    }

    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.close_tx = None;
        Ok(())
    }
}

struct SrtConnectionState {
    close_rx: Fuse<oneshot::Receiver<()>>,
    srt_send_rx: mpsc::Receiver<(Bytes, Instant)>,
    socket: UdpFramed<PacketCodec>,
    sender: Sender,
}

impl SrtConnectionState {
    async fn send_control(&mut self, packet: ControlPacket, to: SocketAddr) {
        let result = self.socket.send((Packet::Control(packet), to)).await;
        let _ = result.map_err(|error| eprintln!("{:?}", error));
    }

    async fn send_data(&mut self, packet: DataPacket, to: SocketAddr) {
        let result = self.socket.send((Packet::Data(packet), to)).await;
        let _ = result.map_err(|error| eprintln!("{:?}", error));
    }

    async fn wait(&mut self) {
        // TODO: rethink magic number
        self.wait_until(Instant::now() + Duration::from_millis(10))
            .await
    }

    async fn wait_until(&mut self, t: Instant) {
        // TODO: get rid of the panics with legit error handling, e.g. an error channel on SrtCaller
        let result = select! {
            _ = &mut self.close_rx => self.sender.handle_close(Instant::now()),
            _ = delay_until(t.into()).fuse() => self.sender.handle_timer(Instant::now()),
            packet = crate::util::get_packet(&mut self.socket).fuse() => self.sender.handle_packet(packet.unwrap(), Instant::now()),
            data = self.srt_send_rx.next().fuse() => self.sender.handle_send_rx(data.unwrap(), Instant::now()),
        };
        let _ = result.map_err(|error| eprintln!("{:?}", error));
    }

    pub async fn run(&mut self) {
        use SenderAlgorithmAction::*;
        loop {
            let (current_step, next_action) = self.sender.next_algorithm_action(|| Instant::now());
            debug!("{:?}: {:?}", current_step, next_action);
            match next_action {
                Continue => {}
                SendControl((packet, to)) => self.send_control(packet, to).await,
                SendData((packet, to)) => self.send_data(packet, to).await,
                WaitUnitlAck => self.wait().await,
                WaitUntilData => self.wait().await,
                WaitUntil(t) => self.wait_until(t).await,
                Close => break,
            }
        }
    }
}
