use std::time::{Duration, Instant};

#[derive(Debug, Clone, Eq, PartialEq)]
enum Status {
    Open(Duration),
    Shutdown(Instant),
    Drain(Instant),
    Closed,
}

#[derive(Debug)]
pub struct ConnectionStatus {
    connection: Status,
    sender: Status,
    receiver: Status,
}

impl ConnectionStatus {
    pub fn new(timeout: Duration) -> Self {
        Self {
            connection: Status::Open(timeout),
            receiver: Status::Open(timeout),
            sender: Status::Open(timeout),
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
            self.sender = Shutdown(now + timeout);
        }
    }

    pub fn on_socket_closed(&mut self, now: Instant) {
        use Status::*;
        if let Open(timeout) = self.receiver {
            self.receiver = Drain(now + timeout);
        }
    }

    pub fn on_peer_idle_timeout(&mut self, now: Instant) {
        use Status::*;
        if let Open(timeout) = self.receiver {
            self.receiver = Drain(now + timeout);
        }
    }

    pub fn handle_shutdown_packet(&mut self, now: Instant) {
        use Status::*;
        if let Open(timeout) = self.receiver {
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
                self.sender = Drain(timeout);
                true
            }
            Drain(timeout) if send_buffer_flushed && output_empty || now > timeout => {
                self.sender = Closed;
                false
            }
            _ => false,
        };
        if matches!(self.sender, Closed) && receive_buffer_flushed && output_empty {
            self.connection = Closed;
        }
        result
    }

    pub fn check_receive_close_timeout(
        &mut self,
        now: Instant,
        receive_buffer_flushed: bool,
    ) -> bool {
        use Status::*;
        match self.receiver {
            Shutdown(timeout) | Drain(timeout) if now > timeout => {
                self.receiver = Closed;
                self.connection = Closed;
                true
            }
            Shutdown(_) | Drain(_) if receive_buffer_flushed => {
                self.receiver = Closed;
                self.connection = Closed;
                false
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
