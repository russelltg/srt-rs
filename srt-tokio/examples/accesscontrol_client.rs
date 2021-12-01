use std::{env::args, io::Error, process::exit};

use srt_protocol::access::*;
use tokio_stream::StreamExt;

use srt_tokio::SrtSocketBuilder;

#[tokio::main]
async fn main() -> Result<(), Error> {
    if args().len() != 2 {
        eprintln!("Usage: cargo run --example=connect_streamid <username>");
        exit(1);
    }

    let mut srt_socket = SrtSocketBuilder::new_connect_with_streamid(
        "127.0.0.1:3333",
        format!(
            "{}",
            AccessControlList(vec![StandardAccessControlEntry::UserName(
                args().nth(1).unwrap()
            )
            .into(),])
        ),
    )
    .connect()
    .await?;

    while let Some((_instant, bytes)) = srt_socket.try_next().await? {
        println!("{}", std::str::from_utf8(&bytes[..]).unwrap());
    }

    println!("Connection closed");

    Ok(())
}
