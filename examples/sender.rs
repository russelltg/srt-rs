use bytes::Bytes;
use futures_util::sink::SinkExt;
use srt::SrtSocketBuilder;
use std::io::Error;
use std::time::Instant;
use std::{thread, time};

#[tokio::main]
async fn main() -> Result<(), Error> {
  let mut srt_socket = SrtSocketBuilder::new_listen().local_port(3333).connect().await?;
  let mut count = 0;

  loop {
    srt_socket.send((Instant::now(), Bytes::from(vec![0; 1000]))).await?;
    print!("\rSended {:?} packets", count);
    count += 1;

    let ten_millis = time::Duration::from_millis(10);
    thread::sleep(ten_millis);
  }
}
