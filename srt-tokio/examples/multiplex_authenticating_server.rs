use bytes::Bytes;
use futures::{stream, SinkExt, StreamExt};
use log::info;
use srt_protocol::access::RejectReason;
use srt_protocol::options::KeySize;
use srt_protocol::packet::ServerRejectReason;
use srt_protocol::settings::{KeySettings, Passphrase};
use srt_tokio::{ConnectionRequest, SrtListener};
use std::io;
use std::time::Instant;

#[tokio::main]
async fn main() -> io::Result<()> {
    let _ = pretty_env_logger::try_init();

    let (_server, mut incoming) = SrtListener::builder().bind(3333).await.unwrap();

    while let Some(request) = incoming.incoming().next().await {
        tokio::spawn(async move { handle_request(request).await });
    }

    Ok(())
}

async fn handle_request(request: ConnectionRequest) {
    info!("received connection request");

    if request.key_size() != KeySize::AES256 {
        info!("rejecting, key size is not AES256");
        request
            .reject(RejectReason::Server(ServerRejectReason::BadRequest))
            .await
            .unwrap();
        return;
    }

    let key_settings = KeySettings {
        key_size: KeySize::AES256,
        passphrase: Passphrase::try_from("password128").unwrap(),
    };
    let mut sender = request.accept(Some(key_settings)).await.unwrap();
    let mut stream = stream::iter(
        Some(Ok((Instant::now(), Bytes::from("Hello authenticated user!!")))).into_iter(),
    );

    sender.send_all(&mut stream).await.unwrap();
    sender.close().await.unwrap();
    info!("finished sending bytes to caller");
}
