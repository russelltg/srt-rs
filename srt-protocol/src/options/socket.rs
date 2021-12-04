use super::*;
use std::net::SocketAddr;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SocketOptions {
    pub connect: Connect,
    pub session: Session,
    pub encryption: Encryption,
    pub sender: Sender,
    pub receiver: Receiver,
}

impl SocketOptions {
    pub fn new() -> Valid<Self> {
        Self::default().try_validate().unwrap()
    }

    pub fn local_address(&self) -> SocketAddr {
        SocketAddr::new(self.connect.local_ip, self.connect.local_port)
    }
}

impl Validation for SocketOptions {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        self.connect.is_valid()?;
        self.session.is_valid()?;
        self.encryption.is_valid()?;
        self.sender.is_valid()?;
        self.receiver.is_valid()?;
        self.is_valid_composite()
    }
}

impl CompositeValidation for SocketOptions {
    fn is_valid_composite(&self) -> Result<(), <Self as Validation>::Error> {
        // There is a restriction that the receiver buffer size (SRTO_RCVBUF) must not be greater than
        // SRTO_FC (#700). Therefore, it is recommended to set the value of SRTO_FC first, and then the
        // value of SRTO_RCVBUF.
        if self.receiver.buffer_size
            > self.sender.flow_control_window_size * self.session.max_segment_size
        {
            Err(OptionsError::ReceiveBufferTooLarge {
                buffer: self.receiver.buffer_size,
                max_segment: self.session.max_segment_size,
                flow_control_window: self.sender.flow_control_window_size,
            })
        } else {
            Ok(())
        }
    }
}

impl OptionsOf<Connect> for SocketOptions {
    fn set_options(&mut self, value: Connect) {
        self.connect = value;
    }
}

impl OptionsOf<Session> for SocketOptions {
    fn set_options(&mut self, value: Session) {
        self.session = value;
    }
}

impl OptionsOf<Encryption> for SocketOptions {
    fn set_options(&mut self, value: Encryption) {
        self.encryption = value;
    }
}

impl OptionsOf<Sender> for SocketOptions {
    fn set_options(&mut self, value: Sender) {
        self.sender = value;
    }
}

impl OptionsOf<Receiver> for SocketOptions {
    fn set_options(&mut self, value: Receiver) {
        self.receiver = value;
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;
    use std::time::Duration;

    use super::*;

    #[test]
    fn test() -> Result<(), OptionsError> {
        let _ = SocketOptions::new()
            .with(Connect {
                timeout: Duration::from_secs(1),
                ..Default::default()
            })?
            .with(Session {
                peer_idle_timeout: Duration::from_secs(20),
                ..Default::default()
            })?
            .with(Encryption {
                key_size: KeySize::AES192,
                passphrase: "this is a passphrase".try_into().ok(),
                ..Default::default()
            })?
            .with(Sender {
                buffer_size: 1000000,
                ..Default::default()
            })?
            .with(Receiver {
                buffer_size: 1000000,
                ..Default::default()
            })?;

        let _ = SocketOptions {
            connect: Connect {
                timeout: Duration::from_secs(1),
                ..Default::default()
            },
            session: Session {
                peer_idle_timeout: Duration::from_secs(20),
                ..Default::default()
            },
            encryption: Encryption {
                key_size: KeySize::AES192,
                passphrase: "this is a passphrase".try_into().ok(),
                ..Default::default()
            },
            sender: Sender {
                buffer_size: 1000000,
                ..Default::default()
            },
            receiver: Receiver {
                buffer_size: 1000000,
                ..Default::default()
            },
        }
        .try_validate()?;

        Ok(())
    }
}
