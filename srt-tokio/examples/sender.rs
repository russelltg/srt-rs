use bytes::Bytes;
use futures::stream;
use futures::{SinkExt, StreamExt};
use tokio::time::sleep;

use srt_tokio::SrtSocketBuilder;
use std::io::Error;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut srt_socket = SrtSocketBuilder::new_listen()
        .local_port(3333)
        .connect()
        .await?;

    let mut stream = stream::unfold(0, |count| async move {
        print!("\rSent {:?} packets", count);
        sleep(Duration::from_millis(10)).await;
        Some((Ok((Instant::now(), Bytes::from(vec![0; 8000]))), count + 1))
    })
    .boxed();

    srt_socket.send_all(&mut stream).await?;
    Ok(())
}
