use crate::packet::{HandshakeControlInfo, ShakeType};
use crate::ControlPacket;
use std::net::SocketAddr;
use std::time::Instant;

pub mod sender;

pub enum Handshake {
    Caller,
    Listener(ControlPacket),
    Rendezvous(ControlPacket),
}

impl Handshake {
    pub fn handle_handshake<E>(
        &self,
        from: SocketAddr,
        handshake: HandshakeControlInfo,
    ) -> Result<Option<(ControlPacket, SocketAddr)>, E> {
        match (self, handshake.shake_type) {
            (Handshake::Rendezvous(packet), ShakeType::Conclusion) => {
                Ok(Some((packet.clone(), from)))
            }
            (Handshake::Listener(packet), _) => Ok(Some((packet.clone(), from))),
            (Handshake::Caller, _) | (Handshake::Rendezvous(_), _) => Ok(None),
        }
    }
}

/// Timestamp in us
pub type TimeStamp = i32;

#[derive(Copy, Clone, Debug)]
pub struct TimeBase(Instant);
impl TimeBase {
    pub fn new() -> Self {
        Self(Instant::now())
    }

    pub fn from_raw(start_time: Instant) -> Self {
        let _ = Self::new();
        Self(start_time)
    }

    pub fn timestamp_from(&self, at: Instant) -> TimeStamp {
        let elapsed = at - self.0;
        elapsed.as_micros() as i32 // TODO: handle overflow here
    }

    pub fn timestamp_now(&self) -> TimeStamp {
        self.timestamp_from(Instant::now())
    }
}
