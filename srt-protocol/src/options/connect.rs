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
}

impl Connect {}
impl Default for Connect {
    fn default() -> Self {
        Self {
            local: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            timeout: Duration::from_secs(3),
            min_version: SrtVersion::new(1, 0, 0),
        }
    }
}

impl Validation for Connect {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
