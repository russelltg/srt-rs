#[cfg(feature = "ac-ffmpeg")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::{
        env::args,
        fs::File,
        io,
        time::{Duration, Instant},
    };

    use ac_ffmpeg::{
        format::{demuxer::Demuxer, io::IO},
        time::Timestamp,
    };
    use bytes::Bytes;
    use futures::SinkExt;
    use srt_tokio::SrtSocket;
    use tokio::{sync::mpsc::channel, time::sleep_until};
    use tokio_stream::StreamExt;

    pretty_env_logger::init();

    let args = args().collect::<Vec<_>>();
    let input = File::open(&args[1])?; // validate file before connecting

    let mut socket = SrtSocket::builder()
        .latency(Duration::from_millis(1000))
        .listen(":1234")
        .await?;

    let io = IO::from_seekable_read_stream(input);

    let mut demuxer = Demuxer::builder()
        .build(io)?
        .find_stream_info(None)
        .map_err(|(_, err)| err)?;

    let mut last_pts_inst: Option<(Timestamp, Instant)> = None;

    let (chan_send, chan_recv) = channel(1024);

    let demuxer_task = tokio::spawn(async move {
        while let Some(packet) = demuxer.take().unwrap() {
            let pts = packet.pts();
            let inst = match last_pts_inst {
                Some((last_pts, last_inst)) => {
                    if pts < last_pts {
                        last_inst
                    } else {
                        let d_t = pts - last_pts;
                        let deadline = last_inst + d_t;
                        sleep_until(deadline.into()).await;
                        last_pts_inst = Some((pts, deadline));
                        deadline
                    }
                }
                None => {
                    let now = Instant::now();
                    last_pts_inst = Some((pts, now));
                    now
                }
            };
            println!("Sending packet {:?}", packet.pts());
            if chan_send
                .send((inst, Bytes::copy_from_slice(packet.data())))
                .await
                .is_err()
            {
                println!("Channel closed, quitting...");
                break;
            }
        }
    });

    let mut stream = tokio_stream::wrappers::ReceiverStream::new(chan_recv).map(Ok::<_, io::Error>);
    socket.send_all(&mut stream).await?;
    socket.close().await?;

    demuxer_task.await?;

    Ok(())
}

#[cfg(not(feature = "ac-ffmpeg"))]
fn main() {
    println!("Enable the ac-ffmpeg feature to run this example")
}
