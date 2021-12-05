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
}

impl Connect {}
impl Default for Connect {
    fn default() -> Self {
        Self {
            local: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            timeout: Duration::from_secs(3),
        }
    }
}

impl Validation for Connect {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
