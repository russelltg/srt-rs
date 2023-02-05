use std::{
    io,
    time::{Duration, Instant},
};

use futures::{prelude::*, select};
use log::{debug, info, trace, warn};
use tokio::time::interval;

use srt_protocol::{
    connection::Connection,
    options::*,
    protocol::pending_connection::{connect::Connect, ConnectionResult},
};

use crate::net::{lookup_remote_host, PacketSocket};

pub async fn bind_with(
    mut socket: PacketSocket,
    options: Valid<CallerOptions>,
) -> Result<(PacketSocket, Connection), io::Error> {
    let stream_id = options.stream_id.as_ref().map(|s| s.to_string());
    let remote = lookup_remote_host(&options.remote).await?;

    let mut tick_interval = interval(Duration::from_millis(100));
    let mut connect = Connect::new(
        remote,
        options.socket.connect.local.ip(),
        options.socket.clone().into(),
        stream_id.clone(),
        rand::random(),
    );

    let start_time = Instant::now();

    loop {
        if start_time.elapsed() > options.socket.connect.timeout {
            return Err(io::Error::new(io::ErrorKind::TimedOut, ""));
        }

        let result = select! {
            now = tick_interval.tick().fuse() => {
                trace!("caller interval elapsed, passing tick");
                connect.handle_tick(now.into())
            }
            packet = socket.receive().fuse() => {
                trace!("caller got packet {packet:?}");
                connect.handle_packet(packet, Instant::now())
            }
        };

        debug!("{:?}:connect - {:?}", stream_id, result);
        use ConnectionResult::*;
        match result {
            SendPacket(packet) => {
                let _ = socket.send(packet.clone()).await?;
            }
            NotHandled(e) => {
                warn!("{:?}", e);
            }
            Reject(rp, rr) => {
                if let Some(packet) = rp {
                    let _ = socket.send(packet).await?;
                }
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, rr));
            }
            Connected(p, connection) => {
                if let Some(packet) = p {
                    let _ = socket.send(packet).await?;
                }
                return Ok((socket, connection));
            }
            NoAction => {}
            RequestAccess(_) => {}
            Failure(error) => {
                info!("Connection failure: {error}");
                return Err(error);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        io,
        time::{Duration, Instant},
    };

    use crate::SrtSocket;
    use assert_matches::assert_matches;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn conntimeo() {
        let _ = pretty_env_logger::try_init();

        // bind a socket because otherwise on windows this will fail immediately with "ConnectionReset"
        let _sock = UdpSocket::bind("127.0.0.1:11111").await.unwrap();

        // default-3s
        let start = Instant::now();
        let ret = SrtSocket::builder().call("127.0.0.1:11111", None).await;
        assert_matches!(ret, Err(e) if e.kind() == io::ErrorKind::TimedOut);
        assert!(start.elapsed() > Duration::from_millis(3000));
        assert!(start.elapsed() < Duration::from_millis(3500));

        // try non-default: 5s
        let start = Instant::now();
        let ret = SrtSocket::builder()
            .set(|o| o.connect.timeout = Duration::from_secs(5))
            .call("127.0.0.1:11111", None)
            .await;
        assert_matches!(ret, Err(e) if e.kind() == io::ErrorKind::TimedOut);
        assert!(start.elapsed() > Duration::from_millis(5000));
        assert!(start.elapsed() < Duration::from_millis(5500));
    }
}
