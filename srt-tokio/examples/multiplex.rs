use std::{
    io::Error,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::{stream, SinkExt, StreamExt};
use tokio::time::sleep;

use srt_tokio::SrtListener;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let port = 3333;
    let (_binding, mut incoming) = SrtListener::builder().bind(port).await?;

    println!("SRT Multiplex Server is listening on port: {port}");

    while let Some(request) = incoming.incoming().next().await {
        let mut srt_socket = request.accept(None).await.unwrap();
        tokio::spawn(async move {
            let client_desc = format!(
                "(ip_port: {}, sockid: {})",
                srt_socket.settings().remote,
                srt_socket.settings().remote_sockid.0
            );

            println!("\nNew client connected: {client_desc}");

            let mut stream = stream::unfold(
                (0, client_desc.clone()),
                |(count, client_desc)| async move {
                    if count % 100 == 0 {
                        println!("Sent to client: {client_desc} {count:?} packets");
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
                println!("\nSend to client: {client_desc} error: {e:?}");
            }
            println!("\nClient {client_desc} disconnected");
        });
    }
    Ok(())
}
