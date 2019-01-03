mod streamer_server;

pub use self::streamer_server::StreamerServer;

use std::net::SocketAddr;
use std::time::Duration;

use futures::future::Future;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::try_ready;
use futures::{Async, Poll};

use log::{info, warn};

use failure::{bail, Error};

use tokio_udp::{UdpFramed, UdpSocket};

use crate::channel::Channel;
use crate::packet::{ControlPacket, ControlTypes};
use crate::pending_connection::Listen;
use crate::{Connected, Packet, PacketCodec, SocketID};

type PackChan = Channel<(Packet, SocketAddr)>;

pub struct MultiplexServer {
    sock: UdpFramed<PacketCodec>,
    // (channel to talk to listener on, listener, socketid that is connecting here)
    initiators: Vec<(PackChan, Listen<PackChan>, SocketID)>,
    connections: Vec<(PackChan, SocketID)>,
    latency: Duration,
}

impl MultiplexServer {
    pub fn bind(addr: &SocketAddr, latency: Duration) -> Result<Self, Error> {
        Ok(MultiplexServer {
            sock: UdpFramed::new(UdpSocket::bind(addr)?, PacketCodec),
            initiators: vec![],
            connections: vec![],
            latency,
        })
    }
}

impl Stream for MultiplexServer {
    type Item = Connected<PackChan>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        'whole_poll: loop {
            self.sock.poll_complete()?;
            for chan in self
                .initiators
                .iter_mut()
                .map(|(c, _, _)| c)
                .chain(self.connections.iter_mut().map(|(c, _)| c))
            {
                chan.poll_complete()?;
            }

            // see if any are ready
            for i in 0..self.initiators.len() {
                let (ref mut channel, ref mut listener, _) = self.initiators[i];

                // poll before checking the channel, listener is allowed to start_send and return in the same poll
                let listener_poll = listener.poll()?;

                // poll the channel, send any packets it has
                if let Async::Ready(Some((pack, addr))) = channel.poll()? {
                    self.sock.start_send((pack, addr))?;
                    self.sock.poll_complete()?;
                }

                if let Async::Ready(conn) = listener_poll {
                    let (mut chan, _, _) = self.initiators.remove(i);

                    let _ = chan.poll()?;

                    self.connections.push((chan, conn.settings().local_sockid));

                    info!("Multiplexed connection to {} ready", conn.settings().remote);
                    return Ok(Async::Ready(Some(conn)));
                }
            }

            // send out outgoing packets
            for (ref mut chan, _) in &mut self.connections {
                while let Async::Ready(Some((pack, addr))) = chan.poll()? {
                    self.sock.start_send((pack, addr))?;
                    self.sock.poll_complete()?;
                }
            }

            // deal with incomming packets
            'outer: loop {
                let (pack, addr) = match try_ready!(self.sock.poll()) {
                    Some(pa) => pa,
                    None => bail!("Underlying socket ended"),
                };

                let dest_sockid = pack.dest_sockid();

                // is this an initator?
                for (ref mut chan, ref listener, ref remote_sockid) in &mut self.initiators {
                    let same_src = if let Packet::Control(ControlPacket {
                        control_type: ControlTypes::Handshake(info),
                        ..
                    }) = &pack
                    {
                        info.socket_id == *remote_sockid
                    } else {
                        false
                    };

                    if dest_sockid == listener.sockid() || same_src {
                        // forward it on
                        chan.start_send((pack, addr))?;
                        chan.poll_complete()?;

                        continue 'outer;
                    }
                }

                // is this an already made connection?
                for (ref mut chan, sockid) in &mut self.connections {
                    if dest_sockid == *sockid {
                        // forward it
                        chan.start_send((pack, addr))?;
                        chan.poll_complete()?;

                        continue 'outer;
                    }
                }

                // if it is neither of these, then it is a new connection
                if let Packet::Control(ControlPacket {
                    control_type: ControlTypes::Handshake(info),
                    ..
                }) = &pack
                {
                    info!(
                        "Got packet from an unrecognized socketid, starting new connection from {}",
                        addr
                    );

                    let socket_id = info.socket_id; // cache so we can move out of pack

                    let (mut chan_a, chan_b) = PackChan::channel(1000); // TODO: what should this size be?

                    let listener = Listen::new(chan_b, rand::random(), self.latency);

                    chan_a.start_send((pack, addr))?;
                    chan_a.poll_complete()?;

                    self.initiators.push((chan_a, listener, socket_id));

                    continue 'whole_poll; // listen needs to be polled now, so just go back to the beginning of the function
                } else {
                    warn!("Non-handshake packet received that was not associed with a known socket ID: {}. Discarding", dest_sockid.0);
                }
            }
        }
    }
}
