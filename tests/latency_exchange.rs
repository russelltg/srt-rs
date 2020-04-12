use failure::Error;
use srt::{ConnInitMethod, SrtSocketBuilder};
use std::time::Duration;
use tokio::time::delay_for;

use futures::prelude::*;

async fn test_latency_exchange(
    connecter_latency: Duration,
    listener_latency: Duration,
) -> Result<(), Error> {
    let connecter = SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:4000".parse()?))
        .latency(connecter_latency)
        .connect();

    let listener = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(4000)
        .latency(listener_latency)
        .connect();

    let (l1, l2) = futures::join!(
        async move {
            let mut c = connecter.await.unwrap();
            let latency = c.settings().tsbpd_latency;
            c.close().await.unwrap();
            latency
        },
        async move {
            let mut c = listener.await.unwrap();
            let latency = c.settings().tsbpd_latency;
            c.close().await.unwrap();
            latency
        },
    );

    let expected = Duration::max(connecter_latency, listener_latency);

    assert_eq!(l1, expected);
    assert_eq!(l2, expected);

    Ok(())
}

#[tokio::test]
async fn latency_exchange() -> Result<(), Error> {
    env_logger::init();

    test_latency_exchange(Duration::from_secs(3), Duration::from_secs(4)).await?;
    delay_for(Duration::from_secs(2)).await;
    test_latency_exchange(Duration::from_secs(4), Duration::from_secs(3)).await?;

    Ok(())
}
