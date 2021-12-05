use std::{
    convert::TryFrom,
    net::{AddrParseError, SocketAddr},
    ops::Deref,
};

// A simple wrapper for SocketAddr. This is used to support scenarios where using ToSocketAddrs in
// function parameters is undesirable or in possible, yet similar ergonomic static string
// configuration use for addresses is desired.
#[derive(Clone, Debug, Eq, PartialEq)]
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

impl From<SocketAddr> for SocketAddress {
    fn from(address: SocketAddr) -> Self {
        Self(address)
    }
}

impl From<SocketAddress> for SocketAddr {
    fn from(address: SocketAddress) -> Self {
        address.0
    }
}

impl Deref for SocketAddress {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
