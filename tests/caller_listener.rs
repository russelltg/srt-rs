use bytes::Bytes;
use failure::Error;
use futures::stream::StreamExt;
use srt::tokio::SrtCaller;
use srt::{ConnInitMethod, SrtSocketBuilder};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::delay_for;

#[tokio::test]
async fn caller() -> Result<(), Error> {
    env_logger::init();

    let _local = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
    let latency = Duration::from_millis(50);
    let remote = "127.0.0.1:11124".parse::<SocketAddr>().unwrap();

    let caller = SrtCaller::connect(remote);

    let recvr = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(11124)
        .latency(latency)
        .connect();

    let (mut caller, recvr) = futures::try_join!(caller, recvr)?;

    println!("Connected!");

    let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    // send a really really long packet
    let long_message = Bytes::copy_from_slice(data.as_ref());

    let (_, data_vec) = futures::join!(
        async {
            caller.send(long_message.clone()).await?;
            delay_for(Duration::from_millis(50)).await;
            caller.shutdown().await?;
            Ok(()) as Result<_, Error>
        },
        recvr.collect::<Vec<_>>()
    );

    assert_eq!(
        &data_vec
            .iter()
            .map(|r| r.as_ref().unwrap())
            .map(|(_, b)| b)
            .collect::<Vec<_>>(),
        &[&Bytes::copy_from_slice(data.as_ref())]
    );

    Ok(())
}
