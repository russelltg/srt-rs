use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Connect {
    pub local_ip: IpAddr,

    pub local_port: u16,

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
            local_ip: Ipv4Addr::UNSPECIFIED.into(),
            local_port: 0,
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
