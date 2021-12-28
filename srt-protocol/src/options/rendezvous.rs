use std::convert::TryInto;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RendezvousOptions {
    pub remote: SocketAddress,
    pub socket: SocketOptions,
}

impl RendezvousOptions {
    pub fn new(remote: impl TryInto<SocketAddress>) -> Result<Valid<Self>, OptionsError> {
        let socket = Default::default();
        Self::with(remote, socket)
    }

    pub fn with(
        remote: impl TryInto<SocketAddress>,
        socket: SocketOptions,
    ) -> Result<Valid<RendezvousOptions>, OptionsError> {
        let remote = remote
            .try_into()
            .map_err(|_| OptionsError::InvalidRemoteAddress)?;
        Self { remote, socket }.try_validate()
    }
}

impl Validation for RendezvousOptions {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        let local = &self.socket.connect.local;
        use SocketHost::*;
        let mismatch = match (&self.remote.host, local.ip().is_ipv4()) {
            (Ipv4(ipv4), false) => Some((*ipv4).into()),
            (Ipv6(ipv6), true) => Some((*ipv6).into()),
            _ => None,
        };
        if let Some(remote_ip) = mismatch {
            return Err(OptionsError::MismatchedAddressFamilies(
                remote_ip,
                local.ip(),
            ));
        }
        self.socket.is_valid()?;
        self.is_valid_composite()
    }
}

impl CompositeValidation for RendezvousOptions {
    fn is_valid_composite(&self) -> Result<(), <Self as Validation>::Error> {
        Ok(())
    }
}

impl OptionsOf<SocketOptions> for RendezvousOptions {
    fn set_options(&mut self, value: SocketOptions) {
        self.socket = value;
    }
}

impl OptionsOf<Connect> for RendezvousOptions {
    fn set_options(&mut self, value: Connect) {
        self.socket.connect = value;
    }
}

impl OptionsOf<Session> for RendezvousOptions {
    fn set_options(&mut self, value: Session) {
        self.socket.session = value;
    }
}

impl OptionsOf<Encryption> for RendezvousOptions {
    fn set_options(&mut self, value: Encryption) {
        self.socket.encryption = value;
    }
}

impl OptionsOf<Sender> for RendezvousOptions {
    fn set_options(&mut self, value: Sender) {
        self.socket.sender = value;
    }
}

impl OptionsOf<Receiver> for RendezvousOptions {
    fn set_options(&mut self, value: Receiver) {
        self.socket.receiver = value;
    }
}
