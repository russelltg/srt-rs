use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Connect {
    pub local: SocketAddr,

    /// Connect timeout. This option applies to the caller and rendezvous connection modes.
    /// For the rendezvous mode (see SRTO_RENDEZVOUS) the effective connection timeout will be 10 times
    /// the value set with SRTO_CONNTIMEO.
    ///
    /// Default is 3 seconds.
    pub timeout: Duration,

    /// SRTO_MINVERSION
    /// The minimum SRT version that is required from the peer. A connection to a peer that does not
    /// satisfy the minimum version requirement will be rejected. See SRTO_VERSION for the version
    /// format.
    ///
    /// The default value is 0x010000 (SRT v1.0.0).
    pub min_version: SrtVersion,

    /// SRTO_UDP_RCVBUF
    ///
    /// UDP Socket Receive Buffer Size. Configured in bytes, maintained in packets based on MSS value.
    /// Receive buffer must not be greater than FC size.
    ///
    /// Default is 64k
    pub udp_recv_buffer_size: ByteCount,

    /// SRT_UDP_SNDBUF
    ///
    /// UDP Socket Send Buffer Size. Configured in bytes, maintained in packets based on SRTO_MSS value.
    ///
    /// Default is 64k
    pub udp_send_buffer_size: ByteCount,

    /// SRTO_IPTTL
    ///
    /// IPv4 Time To Live (see IP_TTL option for IP) or IPv6 unicast hops (see IPV6_UNICAST_HOPS for IPv6) depending on socket address family. Applies to sender only.
    ///
    /// When getting, the returned value is the user preset for non-connected sockets and the actual value for connected sockets.
    /// Sender: user configurable, default: 64
    pub ip_ttl: u8,

    /// Linger time on close (see [SO_LINGER](http://man7.org/linux/man-pages/man7/socket.7.html)).
    /// Set to None to disable linger
    ///
    /// Default is 180s
    pub linger: Option<Duration>,
}

impl Connect {}
impl Default for Connect {
    fn default() -> Self {
        Self {
            local: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            timeout: Duration::from_secs(3),
            min_version: SrtVersion::new(1, 0, 0),
            udp_recv_buffer_size: ByteCount(65536),
            udp_send_buffer_size: ByteCount(65536),
            ip_ttl: 64,
            linger: Some(Duration::from_secs(180)),
        }
    }
}

impl Validation for Connect {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        if self.ip_ttl == 0 {
            return Err(OptionsError::InvalidIpTtl);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ttl_validate() {
        assert_eq!(
            Connect {
                ip_ttl: 0,
                ..Default::default()
            }
            .is_valid(),
            Err(OptionsError::InvalidIpTtl)
        );
    }
}
