use bytes::Bytes;
use futures::stream;
use futures::{SinkExt, StreamExt};
use srt_tokio::SrtSocket;
use std::io::Error;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut srt_socket = SrtSocket::builder().listen_on(":3333").await?;

    let mut stream = stream::unfold(0, |count| async move {
        print!("\rSent {count:?} packets");
        sleep(Duration::from_millis(10)).await;
        Some((Ok((Instant::now(), Bytes::from(vec![0; 8000]))), count + 1))
    })
    .boxed();

    srt_socket.send_all(&mut stream).await?;
    Ok(())
}
