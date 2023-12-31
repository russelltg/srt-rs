use super::*;

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
            return Err(OptionsError::ReceiveBufferTooLarge {
                buffer: self.receiver.buffer_size,
                max_segment: self.session.max_segment_size,
                flow_control_window: self.sender.flow_control_window_size,
            });
        }

        if self.connect.udp_recv_buffer_size
            > self.sender.flow_control_window_size * self.session.max_segment_size
        {
            return Err(OptionsError::UdpReceiveBufferTooLarge {
                udp_buffer: self.connect.udp_recv_buffer_size,
                max_segment: self.session.max_segment_size,
                flow_control_window: self.sender.flow_control_window_size,
            });
        }

        if self.connect.udp_send_buffer_size
            > self.sender.flow_control_window_size * self.session.max_segment_size
        {
            return Err(OptionsError::UdpSenderBufferTooLarge {
                udp_buffer: self.connect.udp_send_buffer_size,
                max_segment: self.session.max_segment_size,
                flow_control_window: self.sender.flow_control_window_size,
            });
        }

        Ok(())
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
    use std::time::Duration;

    use super::*;

    use assert_matches::assert_matches;

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
                passphrase: Some("this is a passphrase".into()),
                ..Default::default()
            })?
            .with(Sender {
                buffer_size: ByteCount(1000000),
                ..Default::default()
            })?
            .with(Receiver {
                buffer_size: ByteCount(1000000),
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
                passphrase: Some("this is a passphrase".into()),
                ..Default::default()
            },
            sender: Sender {
                buffer_size: ByteCount(1000000),
                ..Default::default()
            },
            receiver: Receiver {
                buffer_size: ByteCount(1000000),
                ..Default::default()
            },
        }
        .try_validate()?;

        assert_eq!(
            SocketOptions::new().set(|op| {
                op.connect.udp_recv_buffer_size = ByteCount(1500 * 10_000 + 1);
                op.session.max_segment_size = PacketSize(1500);
                op.sender.flow_control_window_size = PacketCount(10_000);
            }),
            Err(OptionsError::UdpReceiveBufferTooLarge {
                udp_buffer: ByteCount(1500 * 10_000 + 1),
                max_segment: PacketSize(1500),
                flow_control_window: PacketCount(10_000),
            })
        );
        assert_matches!(
            SocketOptions::new().set(|op| {
                op.connect.udp_recv_buffer_size = ByteCount(1500 * 10_000);
                op.session.max_segment_size = PacketSize(1500);
                op.sender.flow_control_window_size = PacketCount(10_000);
            }),
            Ok(_)
        );

        assert_eq!(
            SocketOptions::new().set(|op| {
                op.connect.udp_send_buffer_size = ByteCount(1500 * 10_000 + 1);
                op.session.max_segment_size = PacketSize(1500);
                op.sender.flow_control_window_size = PacketCount(10_000);
            }),
            Err(OptionsError::UdpSenderBufferTooLarge {
                udp_buffer: ByteCount(1500 * 10_000 + 1),
                max_segment: PacketSize(1500),
                flow_control_window: PacketCount(10_000),
            })
        );
        assert_matches!(
            SocketOptions::new().set(|op| {
                op.connect.udp_send_buffer_size = ByteCount(1500 * 10_000);
                op.session.max_segment_size = PacketSize(1500);
                op.sender.flow_control_window_size = PacketCount(10_000);
            }),
            Ok(_)
        );

        Ok(())
    }
}
