use bytes::Bytes;
use futures::stream;
use futures::{SinkExt, StreamExt};
use tokio::time::delay_for;

use srt_protocol::NullEventReceiver;
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

    while let Some(Ok((conn, pack_chan))) = binding.next().await {
        let mut srt_socket =
            srt_tokio::tokio::create_bidrectional_srt::<NullEventReceiver, _>(pack_chan, conn);

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
                    delay_for(Duration::from_millis(10)).await;
                    return Some((
                        Ok((Instant::now(), Bytes::from(vec![0; 8000]))),
                        (count + 1, client_desc),
                    ));
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
