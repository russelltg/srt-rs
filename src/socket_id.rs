use rand::distributions::{Distribution, Standard};
use rand::Rng;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SocketID(pub u32);

impl Distribution<SocketID> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SocketID {
        SocketID(rng.sample(self))
    }
}
