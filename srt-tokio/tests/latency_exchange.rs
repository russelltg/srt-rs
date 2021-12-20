use anyhow::Result;
use srt_tokio::SrtSocket;
use std::time::Duration;
use tokio::time::sleep;

use futures::prelude::*;

async fn test_latency_exchange(
    connector_send_latency: Duration,
    connector_rec_latency: Duration,
    listener_send_latency: Duration,
    listener_recv_latency: Duration,
) -> Result<()> {
    let connector = SrtSocket::builder()
        .send_latency(connector_send_latency)
        .receive_latency(connector_rec_latency)
        .call("127.0.0.1:4200", None);

    let listener = SrtSocket::builder()
        .send_latency(listener_send_latency)
        .receive_latency(listener_recv_latency)
        .listen(":4200");

    let ((l2c1, c2l1), (l2c2, c2l2)) = futures::join!(
        async move {
            let mut c = connector.await.unwrap();
            let c2l = c.settings().send_tsbpd_latency;
            let l2c = c.settings().recv_tsbpd_latency;
            c.close().await.unwrap();
            (l2c, c2l)
        },
        async move {
            let mut c = listener.await.unwrap();
            let l2c = c.settings().send_tsbpd_latency;
            let c2l = c.settings().recv_tsbpd_latency;
            c.close().await.unwrap();
            (l2c, c2l)
        },
    );

    let expected_l2c = Duration::max(connector_rec_latency, listener_send_latency);
    let expected_c2l = Duration::max(connector_send_latency, listener_recv_latency);

    assert_eq!(l2c1, expected_l2c);
    assert_eq!(l2c2, expected_l2c);
    assert_eq!(c2l1, expected_c2l);
    assert_eq!(c2l2, expected_c2l);

    Ok(())
}

#[tokio::test]
async fn latency_exchange() -> Result<()> {
    let from_secs = Duration::from_secs;

    let _ = pretty_env_logger::try_init();

    test_latency_exchange(from_secs(3), from_secs(4), from_secs(5), from_secs(4)).await?;
    sleep(from_secs(2)).await;
    test_latency_exchange(from_secs(4), from_secs(5), from_secs(5), from_secs(3)).await?;

    Ok(())
}
