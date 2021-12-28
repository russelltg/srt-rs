use std::{
    convert::{TryFrom, TryInto},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    str::FromStr,
};

use thiserror::Error;
use url::Host;

// A simple wrapper for SocketAddr. This is used to support scenarios where using ToSocketAddrs in
// function parameters is undesirable or impossible, yet still support similar use of ergonomic
// static string configuration for addresses when desired.
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SocketAddress {
    pub host: SocketHost,
    pub port: u16,
}

impl TryFrom<&str> for SocketAddress {
    type Error = SocketAddressParseError;

    fn try_from(address: &str) -> Result<Self, Self::Error> {
        let mut split = address.split(':');
        match (split.next(), split.next(), split.next()) {
            (Some(""), Some(port), None) => Ok(Self {
                host: SocketHost::Ipv4(Ipv4Addr::UNSPECIFIED),
                port: u16::from_str(port)?,
            }),
            (Some(host), port, None) => Ok(Self {
                host: match url::Host::parse(host)? {
                    Host::Domain(domain) => SocketHost::Domain(domain),
                    Host::Ipv4(ipv4) => SocketHost::Ipv4(ipv4),
                    Host::Ipv6(ipv6) => SocketHost::Ipv6(ipv6),
                },
                port: port.map(u16::from_str).unwrap_or(Ok(0))?,
            }),
            _ => Err(SocketAddressParseError::Invalid(address.to_string())),
        }
    }
}

impl From<u16> for SocketAddress {
    fn from(port: u16) -> Self {
        Self {
            host: SocketHost::Ipv4(Ipv4Addr::UNSPECIFIED),
            port,
        }
    }
}

impl From<SocketAddr> for SocketAddress {
    fn from(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().into(),
            port: addr.port(),
        }
    }
}

impl TryInto<SocketAddr> for SocketAddress {
    type Error = ();

    fn try_into(self) -> Result<SocketAddr, Self::Error> {
        Ok(SocketAddr::new(self.host.try_into()?, self.port))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SocketHost {
    /// A DNS domain name, as '.' dot-separated labels.
    Domain(String),

    /// An IPv4 address.
    Ipv4(Ipv4Addr),

    /// An IPv6 address.
    Ipv6(Ipv6Addr),
}

impl From<IpAddr> for SocketHost {
    fn from(addr: IpAddr) -> Self {
        use SocketHost::*;
        match addr {
            IpAddr::V4(v4) => Ipv4(v4),
            IpAddr::V6(v6) => Ipv6(v6),
        }
    }
}

impl TryInto<IpAddr> for SocketHost {
    type Error = ();

    fn try_into(self) -> Result<IpAddr, Self::Error> {
        use SocketHost::*;
        match self {
            Ipv4(ipv4) => Ok(ipv4.into()),
            Ipv6(ipv6) => Ok(ipv6.into()),
            _ => Err(()),
        }
    }
}

impl From<Ipv4Addr> for SocketHost {
    fn from(ipv4: Ipv4Addr) -> SocketHost {
        SocketHost::Ipv4(ipv4)
    }
}

impl From<Ipv6Addr> for SocketHost {
    fn from(ipv6: Ipv6Addr) -> SocketHost {
        SocketHost::Ipv6(ipv6)
    }
}

impl Default for SocketHost {
    fn default() -> Self {
        SocketHost::Ipv4(Ipv4Addr::UNSPECIFIED)
    }
}

#[derive(Error, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SocketAddressParseError {
    #[error("Invalid address: {0}")]
    Invalid(String),
    #[error("Invalid host: {0}")]
    InvalidHost(String),
    #[error("Invalid port: {0}")]
    InvalidPort(String),
}

impl From<ParseIntError> for SocketAddressParseError {
    fn from(error: ParseIntError) -> Self {
        SocketAddressParseError::InvalidPort(error.to_string())
    }
}

impl From<url::ParseError> for SocketAddressParseError {
    fn from(error: url::ParseError) -> Self {
        SocketAddressParseError::InvalidHost(error.to_string())
    }
}
