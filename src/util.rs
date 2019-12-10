use failure::{bail, Error};
use futures::prelude::*;
use log::warn;
use std::net::SocketAddr;

use crate::Packet;

pub async fn get_packet<T: Stream<Item = Result<(Packet, SocketAddr), Error>> + Unpin>(
    sock: &mut T,
) -> Result<(Packet, SocketAddr), Error> {
    loop {
        match sock.next().await {
            None => bail!("Failed to listen, connection closed"),
            Some(Ok(t)) => break Ok(t),
            Some(Err(e)) => warn!("Failed to parse packet: {:?}", e),
        }
    }
}
