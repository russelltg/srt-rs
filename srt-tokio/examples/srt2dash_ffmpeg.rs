// Run with
// ffmpeg -re -stream_loop -1 -i ~/Videos/test.ts -c:v copy -c:a copy -f mpegts 'srt://127.0.0.1:1234'
// cargo run --example=srt2dash_ffmpeg --features ac-ffmpeg
// python3 -m http.server
// ffplay http://localhost:8000/segments/dash.mpd

#[cfg(feature = "ac-ffmpeg")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use ac_ffmpeg::{
        codec::{CodecParameters, VideoCodecParametersBuilder},
        format::{
            demuxer::{Demuxer, InputFormat},
            io::IO,
            muxer::{Muxer, OutputFormat},
        },
        Error,
    };
    use anyhow::{Context, Result};
    use bytes::Bytes;
    use futures::Stream;
    use srt_tokio::SrtListener;
    use std::{
        fs::{self, File},
        io::{self, Read},
        sync::mpsc::{channel, Receiver, Sender},
        time::Instant,
    };
    use tokio_stream::StreamExt;

    fn open_output(
        path: &str,
        elementary_streams: &[CodecParameters],
    ) -> Result<Muxer<File>, Error> {
        let output_format = OutputFormat::find_by_name("dash").ok_or_else(|| {
            Error::new(format!("unable to guess output format for file: {}", path))
        })?;

        let output = File::create(path)
            .map_err(|err| Error::new(format!("unable to create output file {}: {}", path, err)))?;

        let io = IO::from_seekable_write_stream(output);

        let mut muxer_builder = Muxer::builder()
            .set_option("url", path)
            .set_option("use_timeline", "1")
            .set_option("use_template", "1")
            .set_option("hls_playlist", "1")
            .set_option("streaming", "1")
            .set_option("remove_at_exit", "1")
            .set_option("window_size", "5")
            .set_option("seg_duration", "6")
            .set_option("adaptation_sets", "id=0,streams=v id=1,streams=a");

        for codec_parameters in elementary_streams {
            muxer_builder.add_stream(codec_parameters)?;
        }

        muxer_builder.build(io, output_format)
    }

    struct ByteReceiver {
        rx: Receiver<bytes::Bytes>,
        prev: Option<(bytes::Bytes, usize)>,
    }

    impl ByteReceiver {
        fn new(rx: Receiver<bytes::Bytes>) -> Self {
            Self { rx, prev: None }
        }
    }

    impl Read for ByteReceiver {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some(ref mut prev) = self.prev {
                let limit = std::cmp::min(prev.0.len() - prev.1, buf.len());
                buf[..limit].copy_from_slice(&prev.0[prev.1..prev.1 + limit]);
                if prev.1 + limit < prev.0.len() {
                    prev.1 += limit;
                } else {
                    self.prev = None
                }
                Ok(limit)
            } else if let Ok(bytes) = self.rx.recv() {
                let limit = std::cmp::min(bytes.len(), buf.len());
                buf[..limit].copy_from_slice(&bytes[..limit]);
                if buf.len() < bytes.len() {
                    self.prev = Some((bytes, buf.len()));
                }
                Ok(limit)
            } else {
                Ok(0)
            }
        }
    }

    fn handle_input(rx: impl Read) -> Result<()> {
        let io = IO::from_read_stream(rx);
        let format = InputFormat::find_by_name("mpegts").context("mpegts input format")?;
        let mut demuxer = Demuxer::builder()
            .input_format(Some(format))
            .build(io)?
            .find_stream_info(None)
            .map_err(|(_, err)| err)?;

        for (index, stream) in demuxer.streams().iter().enumerate() {
            let params = stream.codec_parameters();

            println!("Stream #{}:", index);
            println!("  duration: {:?}", stream.duration().as_f64());
            let tb = stream.time_base();
            println!("  time base: {} / {}", tb.num(), tb.den());

            if let Some(params) = params.as_audio_codec_parameters() {
                println!("  type: audio");
                println!("  codec: {}", params.decoder_name().unwrap_or("N/A"));
                println!("  sample format: {}", params.sample_format().name());
                println!("  sample rate: {}", params.sample_rate());
                println!("  channels: {}", params.channel_layout().channels());
                println!("  bitrate: {}", params.bit_rate());
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

        let mut codec_parameters = demuxer
            .streams()
            .iter()
            .map(|stream| stream.codec_parameters())
            .collect::<Vec<_>>();

        for cp in &mut codec_parameters {
            if let Some(vcp) = cp.as_video_codec_parameters() {
                *cp = VideoCodecParametersBuilder::from(vcp.clone())
                    .bit_rate(10_000_000)
                    .build()
                    .into();
            }
        }

        let mut muxer = open_output("segments/dash.mpd", &codec_parameters)?;

        while let Some(packet) = demuxer.take()? {
            if let Err(e) = muxer.push(packet) {
                println!("Err: {}", e);
            }
        }

        println!("Flushing muxer...");

        muxer.flush()?;

        println!("Muxer flushed.");

        Ok(())
    }

    async fn handle_socket(
        mut socket: impl Stream<Item = io::Result<(Instant, Bytes)>> + Unpin,
        tx: Sender<bytes::Bytes>,
    ) -> Result<usize> {
        let mut count = 0;

        while let Some((_inst, bytes)) = socket.try_next().await? {
            tx.send(bytes)?;
            count += 1;
        }

        Ok(count)
    }

    fs::create_dir_all("segments")?;

    let (binding, mut incoming) = SrtListener::builder().bind(1234).await?;

    while let Some(request) = incoming.incoming().next().await {
        let socket = request.accept(None).await?;
        tokio::spawn(async move {
            let socket_id = socket.settings().remote_sockid.0;
            let (tx, rx) = channel();
            let f1 = tokio::task::spawn_blocking(move || handle_input(ByteReceiver::new(rx)));
            let f2 = async {
                let client_desc = format!(
                    "(ip_port: {}, sockid: {}, stream_id: {:?})",
                    socket.settings().remote,
                    socket_id,
                    socket.settings().stream_id,
                );
                println!("New client connected: {}", client_desc);
                let count = handle_socket(socket, tx).await?;
                println!(
                    "Client {} disconnected, received {:?} packets",
                    client_desc, count
                );
                Ok::<_, anyhow::Error>(())
            };
            let (r1, r2) = tokio::join!(f1, f2);

            if let Err(e) = r1 {
                println!("Error in input handler: {}", e);
            }
            if let Err(e) = r2 {
                println!("Error in socket handler: {}", e);
            }
        });
    }

    println!("\nServer closed");

    Ok(())
}

#[cfg(not(feature = "ac-ffmpeg"))]
fn main() {
    println!("Enable the ac-ffmpeg feature to run this example")
}
