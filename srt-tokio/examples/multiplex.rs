use bytes::Bytes;
use futures::stream;
use futures::{SinkExt, StreamExt};
use tokio::time::sleep;

use srt_tokio::SrtSocketBuilder;
use std::io::Error;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let port = 3333;
    let binding = SrtSocketBuilder::new_listen()
        .local_port(port)
        .build_multiplexed()
        .await?;

    tokio::pin!(binding);

    println!("SRT Multiplex Server is listening on port: {}", port);

    while let Some(Ok(mut srt_socket)) = binding.next().await {
        tokio::spawn(async move {
            let client_desc = format!(
                "(ip_port: {}, sockid: {})",
                srt_socket.settings().remote,
                srt_socket.settings().remote_sockid.0
            );

            println!("\nNew client connected: {}", client_desc);

            let mut stream = stream::unfold(
                (0, client_desc.clone()),
                |(count, client_desc)| async move {
                    if count % 100 == 0 {
                        println!("Sent to client: {} {:?} packets", client_desc, count);
                    }
                    sleep(Duration::from_millis(10)).await;
                    Some((
                        Ok((Instant::now(), Bytes::from(vec![0; 8000]))),
                        (count + 1, client_desc),
                    ))
                },
            )
            .boxed();

            if let Err(e) = srt_socket.send_all(&mut stream).await {
                println!("\nSend to client: {} error: {:?}", client_desc, e);
            }
            println!("\nClient {} disconnected", client_desc);
        });
    }
    Ok(())
}
