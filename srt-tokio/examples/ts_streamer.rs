#[cfg(feature = "ac-ffmpeg")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::{
        env::args,
        fs::File,
        io::{self, Write},
        time::{Duration, Instant},
    };

    use ac_ffmpeg::{
        format::{
            demuxer::Demuxer,
            io::IO,
            muxer::{Muxer, OutputFormat},
        },
        time::Timestamp,
    };
    use bytes::Bytes;
    use futures::SinkExt;
    use srt_tokio::SrtSocket;
    use tokio::{
        runtime::Handle,
        sync::mpsc::{channel, Sender},
        time::sleep_until,
    };
    use tokio_stream::StreamExt;

    struct WriteBridge(Sender<(Instant, Bytes)>);
    impl Write for WriteBridge {
        fn write(&mut self, w: &[u8]) -> Result<usize, std::io::Error> {
            for chunk in w.chunks(1316) {
                // NOTE: Instant::now() is not ideal
                // This should be directly derived from the PTS of the packet, which is not availabe here,
                // it would require some refactoring
                if self
                    .0
                    .try_send((Instant::now(), Bytes::copy_from_slice(chunk)))
                    .is_err()
                {
                    println!("Sender was throttled and buffer exausted, dropping packet");
                }
            }
            Ok(w.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Handle::current().block_on(async { Ok(()) })
        }
    }

    pretty_env_logger::init();

    let args = args().collect::<Vec<_>>();
    let input = File::open(&args[1])?; // validate file before connecting
    let io = IO::from_seekable_read_stream(input);

    let mut demuxer = Demuxer::builder()
        .build(io)?
        .find_stream_info(None)
        .map_err(|(_, err)| err)?;

    for (index, stream) in demuxer.streams().iter().enumerate() {
        let params = stream.codec_parameters();

        println!("Stream #{}:", index);
        println!("  duration: {}", stream.duration().as_f64().unwrap_or(0f64));

        if let Some(params) = params.as_audio_codec_parameters() {
            println!("  type: audio");
            println!("  codec: {}", params.decoder_name().unwrap_or("N/A"));
            println!("  sample format: {}", params.sample_format().name());
            println!("  sample rate: {}", params.sample_rate());
            println!("  channels: {}", params.channel_layout().channels());
        } else if let Some(params) = params.as_video_codec_parameters() {
            println!("  type: video");
            println!("  codec: {}", params.decoder_name().unwrap_or("N/A"));
            println!("  width: {}", params.width());
            println!("  height: {}", params.height());
            println!("  pixel format: {}", params.pixel_format().name());
        } else {
            println!("  type: unknown");
        }
    }

    println!("Waiting for a connection to start streaming...");

    let mut socket = SrtSocket::builder()
        .latency(Duration::from_millis(1000))
        .listen(":1234")
        .await?;

    println!("Connection established");

    let mut last_pts_inst: Option<(Timestamp, Instant)> = None;

    let (chan_send, chan_recv) = channel(1024);

    let demuxer_task = tokio::spawn(async move {
        let streams = demuxer
            .streams()
            .iter()
            .map(|stream| stream.codec_parameters())
            .collect::<Vec<_>>();

        let io = IO::from_write_stream(WriteBridge(chan_send));

        let mut muxer_builder = Muxer::builder();
        for codec_parameters in streams {
            muxer_builder.add_stream(&codec_parameters).unwrap();
        }

        let mut muxer = muxer_builder
            .build(io, OutputFormat::find_by_name("mpegts").unwrap())
            .unwrap();

        while let Some(packet) = demuxer.take().unwrap() {
            let pts = packet.pts();
            let _inst = match last_pts_inst {
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
            println!(
                "Sending packet {:?} len={}",
                packet.pts(),
                packet.data().len()
            );

            muxer.push(packet).unwrap();
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
