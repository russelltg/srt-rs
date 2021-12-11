use std::{
    convert::TryFrom,
    net::{AddrParseError, SocketAddr},
    net::{IpAddr, Ipv4Addr},
};

use derive_more::*;

// A simple wrapper for SocketAddr. This is used to support scenarios where using ToSocketAddrs in
// function parameters is undesirable or impossible, yet still support similar use of ergonomic
// static string configuration for addresses when desired.
#[derive(Clone, Debug, Deref, Into, From, Eq, PartialEq)]
pub struct SocketAddress(SocketAddr);

impl TryFrom<&str> for SocketAddress {
    type Error = AddrParseError;

    fn try_from(address: &str) -> Result<Self, Self::Error> {
        let address = if address.starts_with(':') {
            (String::from("0.0.0.0") + address).parse()?
        } else {
            address.parse()?
        };
        Ok(Self(address))
    }
}

impl TryFrom<u16> for SocketAddress {
    type Error = AddrParseError;

    fn try_from(port: u16) -> Result<Self, Self::Error> {
        Ok(Self(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port,
        )))
    }
}
