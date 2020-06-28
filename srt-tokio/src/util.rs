use futures::prelude::*;
use log::warn;
use std::{io, net::SocketAddr};

use crate::{Packet, PacketParseError};

pub async fn get_packet<
    T: Stream<Item = Result<(Packet, SocketAddr), PacketParseError>> + Unpin,
>(
    sock: &mut T,
) -> Result<(Packet, SocketAddr), io::Error> {
    loop {
        match sock.next().await {
            None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "")),
            Some(Ok(t)) => break Ok(t),
            Some(Err(e)) => warn!("Failed to parse packet: {}", e),
        }
    }
}
