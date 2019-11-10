mod streamer_server;

pub use self::streamer_server::StreamerServer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::future::BoxFuture;
use futures::ready;
use futures::sink::Sink;
use futures::stream::Stream;

use log::{info, warn};

use failure::{format_err, Error};

use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

use crate::channel::Channel;
use crate::packet::{ControlPacket, ControlTypes};
use crate::{pending_connection, ConnectionSettings, Packet, PacketCodec, SocketID};

type PackChan = Channel<(Packet, SocketAddr)>;

pub struct MultiplexServer {
    sock: UdpFramed<PacketCodec>,

    // the socketid here is the remote socketid of the connecting party
    initiators: HashMap<SocketID, InitMd>,

    // the socketid here is the local socketid
    connections: HashMap<SocketID, PackChan>,

    latency: Duration,
}

struct InitMd {
    chan: PackChan,
    future: BoxFuture<'static, Result<(ConnectionSettings, PackChan), Error>>,
}

impl MultiplexServer {
    pub async fn bind(addr: &SocketAddr, latency: Duration) -> Result<Self, Error> {
        Ok(MultiplexServer {
            sock: UdpFramed::new(UdpSocket::bind(addr).await?, PacketCodec),
            initiators: HashMap::new(),
            connections: HashMap::new(),
            latency,
        })
    }

    fn sock(&mut self) -> Pin<&mut UdpFramed<PacketCodec>> {
        Pin::new(&mut self.sock)
    }

    fn check_for_complete_connections(
        &mut self,
        cx: &mut Context,
    ) -> Result<Option<(ConnectionSettings, PackChan)>, Error> {
        // see if any are ready
        let keys = self.initiators.keys().copied().collect::<Vec<_>>(); // TODO: is there a better way to do this?
        for sockid in keys {
            let md = self.initiators.get_mut(&sockid).unwrap();
            // poll before checking the channel, listener is allowed to start_send and return in the same poll
            let listener_poll = md.future.as_mut().poll(cx);

            // poll the channel, send any packets it has
            let mut pin_chan = Pin::new(&mut md.chan);
            while let Poll::Ready(Some(Ok((pack, addr)))) = pin_chan.as_mut().poll_next(cx) {
                // TODO: this probably isn't technically correct, as we need to make sure there's space first. Ideally, this would .await, but that ain't a thing.
                Pin::new(&mut self.sock).start_send((pack, addr))?;
                // ok to discard; will be called every poll
                let _ = Pin::new(&mut self.sock).poll_flush(cx)?;
            }

            if let Poll::Ready(conn) = listener_poll {
                let conn = conn?;
                // let _ = chan.poll_next(cx)?;

                let md = self.initiators.remove(&sockid).unwrap();
                self.connections.insert(conn.0.local_sockid, md.chan);

                info!("Multiplexed connection to {} ready", conn.0.remote);
                return Ok(Some(conn));
            }
        }

        Ok(None)
    }
}

impl Stream for MultiplexServer {
    type Item = Result<(ConnectionSettings, PackChan), Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();
        'whole_poll: loop {
            // ok to discard, as we don't really care if it's finished or not
            let _ = pin.sock().poll_flush(cx)?;

            // poll send sides of channels
            for chan in pin
                .initiators
                .values_mut()
                .map(|md| &mut md.chan)
                .chain(pin.connections.values_mut())
            {
                if let Poll::Ready(Err(e)) = Pin::new(chan).poll_flush(cx) {
                    return Poll::Ready(Some(Err(format_err!(
                        "Failed to poll underlying channel: {}",
                        e
                    ))));
                }
            }

            if let Some(conn) = pin.check_for_complete_connections(cx)? {
                return Poll::Ready(Some(Ok(conn)));
            }

            let mut to_remove = vec![];
            // send out outgoing packets
            for (sockid, chan) in &mut pin.connections {
                let mut pin_chan = Pin::new(chan);
                while let Poll::Ready(opt) = pin_chan.as_mut().poll_next(cx)? {
                    if let Some(pa) = opt {
                        ready!(Pin::new(&mut pin.sock).poll_ready(cx))?;
                        Pin::new(&mut pin.sock).start_send(pa)?;
                        let _ = Pin::new(&mut pin.sock).poll_flush(cx)?;
                    } else {
                        // stream returned None, remove it from connections
                        to_remove.push(*sockid);
                        break;
                    }
                }
            }
            for r in to_remove {
                pin.connections.remove(&r);
            }

            // deal with incomming packets
            'outer: loop {
                let (pack, addr) = match ready!(pin.sock().poll_next(cx)) {
                    Some(Ok(pa)) => pa,
                    _ => {
                        return Poll::Ready(Some(Err(format_err!(
                            "Underlying socket ended or errored"
                        ))))
                    }
                };

                let dest_sockid = pack.dest_sockid();

                // is this an initator?
                for (remote_sockid, md) in &mut pin.initiators {
                    let same_src = if let Packet::Control(ControlPacket {
                        control_type: ControlTypes::Handshake(info),
                        ..
                    }) = &pack
                    {
                        info.socket_id == *remote_sockid
                    } else {
                        false
                    };

                    if same_src {
                        // forward it on
                        let mut pin_chan = Pin::new(&mut md.chan);
                        ready!(pin_chan.as_mut().poll_ready(cx)?); // TODO: this will drop the packet
                        pin_chan.as_mut().start_send((pack, addr))?;
                        let _ = pin_chan.as_mut().poll_flush(cx)?;

                        continue 'outer;
                    }
                }

                // is this an already made connection?
                for (sockid, ref mut chan) in &mut pin.connections {
                    if dest_sockid == *sockid {
                        // forward it
                        let mut pin_chan = Pin::new(chan);
                        ready!(pin_chan.as_mut().poll_ready(cx)?); // TODO: this will drop the packet
                        pin_chan.as_mut().start_send((pack, addr))?;
                        let _ = pin_chan.as_mut().poll_flush(cx)?;

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

                    let (mut chan_a, mut chan_b) = PackChan::channel(1000); // TODO: what should this size be?

                    let listener = {
                        let latency = pin.latency;
                        Box::pin(async move {
                            Ok((
                                pending_connection::listen(&mut chan_b, rand::random(), latency)
                                    .await?,
                                chan_b,
                            ))
                        })
                    };

                    let mut pin_chan_a = Pin::new(&mut chan_a);
                    pin_chan_a.as_mut().start_send((pack, addr))?;
                    let _ = pin_chan_a.as_mut().poll_flush(cx)?;

                    pin.initiators.insert(
                        socket_id,
                        InitMd {
                            chan: chan_a,
                            future: listener,
                        },
                    );

                    continue 'whole_poll; // listen needs to be polled now, so just go back to the beginning of the function
                } else {
                    warn!("Non-handshake packet received that was not associed with a known socket ID: {}. Discarding", dest_sockid.0);
                }
            }
        }
    }
}
