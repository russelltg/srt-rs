use rand::distributions::{Distribution, Standard};
use rand::Rng;

use std::fmt;

/// A newtype wrapper for strongly-typed SocketIDs
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct SocketID(pub u32);

impl Distribution<SocketID> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SocketID {
        SocketID(rng.sample(self))
    }
}

impl fmt::Debug for SocketID {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "SRT#{:08X}", self.0)
    }
}
