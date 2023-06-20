use std::time::{Duration, Instant};

use log::info;

use crate::settings::SocketId;

#[derive(Debug, Clone, Eq, PartialEq)]
enum Status {
    Open(Duration), // (flush_timeout)
    Shutdown(Instant), // (flush_deadline)
    Drain(Instant), // (drain_deadline)
    Closed,
}

#[derive(Debug)]
pub struct ConnectionStatus {
    connection: Status,
    sender: Status,
    receiver: Status,
}

impl ConnectionStatus {
    pub fn new(flush_timeout: Duration) -> Self {
        Self {
            connection: Status::Open(flush_timeout),
            receiver: Status::Open(flush_timeout),
            sender: Status::Open(flush_timeout),
        }
    }

    pub fn is_open(&self) -> bool {
        !self.is_closed()
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.connection, Status::Closed)
    }

    pub fn should_drain_send_buffer(&self) -> bool {
        use Status::*;
        matches!(self.sender, Shutdown(_) | Drain(_))
    }

    pub fn on_data_stream_closed(&mut self, now: Instant) {
        use Status::*;
        if let Open(timeout) = self.sender {
            info!("data stream closed, sender is in shutdown");
            self.sender = Shutdown(now + timeout);
        }
    }

    pub fn on_socket_closed(&mut self, now: Instant) {
        use Status::*;
        if let Open(timeout) = self.receiver {
            info!("socket closed, receiver is draining");
            self.receiver = Drain(now + timeout);
        }
    }

    pub fn on_peer_idle_timeout(&mut self, now: Instant) {
        use Status::*;
        if let Open(timeout) = self.receiver {
            info!("peer idle timeout, receiver is draining");
            self.receiver = Drain(now + timeout);
        }
    }

    pub fn handle_shutdown_packet(&mut self, now: Instant, log_sockid: SocketId) {
        use Status::*;
        if let Open(timeout) = self.receiver {
            info!("{log_sockid:?} received shutdown packet, draining for {timeout:?}");
            self.receiver = Drain(now + timeout);
        }
    }

    pub fn check_sender_shutdown(
        &mut self,
        now: Instant,
        send_buffer_flushed: bool,
        receive_buffer_flushed: bool,
        output_empty: bool,
    ) -> bool {
        use Status::*;
        let result = match self.sender {
            Shutdown(timeout) if send_buffer_flushed && output_empty || now > timeout => {
                info!("sender Shutdown -> Drain");
                self.sender = Drain(timeout);
                true
            }
            Drain(timeout) if send_buffer_flushed && output_empty || now > timeout => {
                info!("sender Drain -> Closed");
                self.sender = Closed;
                false
            }
            _ => false,
        };
        if matches!(self.sender, Closed) && receive_buffer_flushed && output_empty {
            info!("sender closed and receiver flushed, socket is closed");
            self.connection = Closed;
        }
        result
    }

    pub fn check_receive_close_timeout(
        &mut self,
        now: Instant,
        receive_buffer_flushed: bool,
        log_sockid: SocketId,
    ) -> bool {
        use Status::*;
        match self.receiver {
            Shutdown(_) | Drain(_) if receive_buffer_flushed => {
                self.receiver = Closed;
                self.connection = Closed;
                info!("{log_sockid:?} reciever closed and flushed, connection is closed");
                false
            }
            Shutdown(timeout) | Drain(timeout) if now > timeout => {
                self.receiver = Closed;
                self.connection = Closed;
                info!("{log_sockid:?} reciever timed out flushing ({:?} too late), connection is closed", now - timeout);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_close() {
        let timeout = Duration::from_secs(10);
        let mut status = ConnectionStatus::new(timeout);

        assert!(status.is_open());
        assert!(!status.is_closed());
        assert!(!status.should_drain_send_buffer());

        let now = Instant::now();
        status.on_socket_closed(now);

        assert!(status.is_open());
        assert!(!status.is_closed());
        assert!(!status.should_drain_send_buffer());
    }
}
