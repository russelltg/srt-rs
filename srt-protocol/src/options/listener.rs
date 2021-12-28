use std::{
    convert::TryInto,
    net::{Ipv4Addr, SocketAddr},
};

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerOptions {
    pub socket: SocketOptions,
}

impl ListenerOptions {
    pub fn new(local: impl TryInto<SocketAddress>) -> Result<Valid<Self>, OptionsError> {
        Self::with(local, Default::default())
    }

    pub fn with(
        local: impl TryInto<SocketAddress>,
        socket: SocketOptions,
    ) -> Result<Valid<ListenerOptions>, OptionsError> {
        let local_address = local
            .try_into()
            .map_err(|_| OptionsError::InvalidLocalAddress)?;

        use SocketHost::*;
        let local = match local_address.host {
            Ipv4(ipv4) => SocketAddr::new(ipv4.into(), local_address.port),
            Ipv6(ipv6) => SocketAddr::new(ipv6.into(), local_address.port),
            Domain(_) => return Err(OptionsError::InvalidLocalAddress),
        };

        let mut options = Self { socket };
        options.socket.connect.local.set_port(local.port());
        if local.ip() != Ipv4Addr::UNSPECIFIED {
            options.socket.connect.local.set_ip(local.ip());
        }

        options.try_validate()
    }
}

impl Validation for ListenerOptions {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        self.socket.is_valid()?;
        if self.socket.connect.local.port() == 0 {
            Err(OptionsError::LocalPortRequiredToListen)
        } else {
            self.is_valid_composite()
        }
    }
}

impl CompositeValidation for ListenerOptions {
    fn is_valid_composite(&self) -> Result<(), <Self as Validation>::Error> {
        Ok(())
    }
}

impl OptionsOf<SocketOptions> for ListenerOptions {
    fn set_options(&mut self, value: SocketOptions) {
        self.socket = value;
    }
}

impl OptionsOf<Connect> for ListenerOptions {
    fn set_options(&mut self, value: Connect) {
        self.socket.connect = value;
    }
}

impl OptionsOf<Session> for ListenerOptions {
    fn set_options(&mut self, value: Session) {
        self.socket.session = value;
    }
}

impl OptionsOf<Encryption> for ListenerOptions {
    fn set_options(&mut self, value: Encryption) {
        self.socket.encryption = value;
    }
}

impl OptionsOf<Sender> for ListenerOptions {
    fn set_options(&mut self, value: Sender) {
        self.socket.sender = value;
    }
}

impl OptionsOf<Receiver> for ListenerOptions {
    fn set_options(&mut self, value: Receiver) {
        self.socket.receiver = value;
    }
}
