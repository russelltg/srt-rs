use srt_tokio::SrtSocketBuilder;
use std::io::Error;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut srt_socket = SrtSocketBuilder::new_connect("127.0.0.1:3333")
        .connect()
        .await?;
    let mut count = 0;

    while let Some((_instant, _bytes)) = srt_socket.try_next().await? {
        count += 1;
        print!("\rReceived {:?} packets", count);
    }

    println!("\nConnection closed");

    Ok(())
}
