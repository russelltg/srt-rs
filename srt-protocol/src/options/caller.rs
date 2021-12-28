use std::{
    convert::TryInto,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerOptions {
    pub remote: SocketAddress,
    pub stream_id: Option<StreamId>,
    pub socket: SocketOptions,
}

impl CallerOptions {
    pub fn new(
        remote: impl TryInto<SocketAddress>,
        stream_id: Option<&str>,
    ) -> Result<Valid<Self>, OptionsError> {
        let socket = Default::default();
        Self::with(remote, stream_id, socket)
    }

    pub fn with(
        remote: impl TryInto<SocketAddress>,
        stream_id: Option<&str>,
        socket: SocketOptions,
    ) -> Result<Valid<CallerOptions>, OptionsError> {
        let remote = remote
            .try_into()
            .map_err(|_| OptionsError::InvalidRemoteAddress)?;

        let stream_id = match stream_id {
            Some(s) => Some(
                s.to_string()
                    .try_into()
                    .map_err(OptionsError::InvalidStreamId)?,
            ),
            None => None,
        };

        use SocketHost::*;
        let local_ip = socket.connect.local.ip();
        let local_ip = match (local_ip.is_ipv6(), &remote.host) {
            (false, &Ipv6(_)) if local_ip == Ipv4Addr::UNSPECIFIED => Ipv6Addr::UNSPECIFIED.into(),
            (true, &Ipv4(_)) if local_ip == Ipv6Addr::UNSPECIFIED => Ipv4Addr::UNSPECIFIED.into(),
            _ => local_ip,
        };

        let mut options = Self {
            remote,
            stream_id,
            socket,
        };

        options.socket.connect.local.set_ip(local_ip);

        options.try_validate()
    }
}

impl Validation for CallerOptions {
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
