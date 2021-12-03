use std::convert::TryInto;
use std::net::{SocketAddr, ToSocketAddrs};

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerOptions {
    pub remote: SocketAddr,
    pub stream_id: StreamId,
    pub socket: SocketOptions,
}

impl CallerOptions {
    pub fn new(
        remote: impl ToSocketAddrs,
        stream_id: impl Into<String>,
    ) -> Result<Valid<Self>, OptionsError> {
        let remote = remote
            .to_socket_addrs()
            .map_err(|_| OptionsError::InvalidRemoteAddress)?
            .next()
            .ok_or(OptionsError::InvalidRemoteAddress)?;
        let stream_id = stream_id
            .into()
            .try_into()
            .map_err(OptionsError::InvalidStreamId)?;
        Self {
            remote,
            stream_id,
            socket: Default::default(),
        }
        .try_validate()
    }
}

impl Validation for CallerOptions {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        let local_ip = self.socket.connect.local_ip;
        if self.remote.ip().is_ipv4() != local_ip.is_ipv4() {
            return Err(OptionsError::MismatchedAddressFamilies(
                self.remote,
                local_ip,
            ));
        }
        self.socket.is_valid()?;
        self.is_valid_composite()
    }
}

impl CompositeValidation for CallerOptions {
    fn is_valid_composite(&self) -> Result<(), <Self as Validation>::Error> {
        Ok(())
    }
}

impl OptionsOf<SocketOptions> for CallerOptions {
    fn set_options(&mut self, value: SocketOptions) {
        self.socket = value;
    }
}

impl OptionsOf<Connect> for CallerOptions {
    fn set_options(&mut self, value: Connect) {
        self.socket.connect = value;
    }
}

impl OptionsOf<Session> for CallerOptions {
    fn set_options(&mut self, value: Session) {
        self.socket.session = value;
    }
}

impl OptionsOf<Encryption> for CallerOptions {
    fn set_options(&mut self, value: Encryption) {
        self.socket.encryption = value;
    }
}

impl OptionsOf<Sender> for CallerOptions {
    fn set_options(&mut self, value: Sender) {
        self.socket.sender = value;
    }
}

impl OptionsOf<Receiver> for CallerOptions {
    fn set_options(&mut self, value: Receiver) {
        self.socket.receiver = value;
    }
}
