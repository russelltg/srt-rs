#![recursion_limit = "256"]
use std::{
    env,
    ffi::{CStr, CString},
    intrinsics::transmute,
    io::ErrorKind,
    mem::size_of,
    net::{SocketAddr, SocketAddrV4},
    os::raw::{c_char, c_int},
    process::Command,
    ptr::null,
    thread,
    time::{Duration, Instant},
};

use anyhow::Error;
use bytes::Bytes;
use futures::{future::try_join, join, stream, SinkExt, Stream, StreamExt};
use libc::sockaddr;
use libloading::{Library, Symbol};
use log::{debug, info};
use srt_protocol::options::PacketCount;
use tokio::{
    net::UdpSocket,
    task::spawn_blocking,
    time::{self, sleep},
};
use tokio_util::{codec::BytesCodec, udp::UdpFramed};

use srt_tokio::SrtSocket;

macro_rules! allow_not_found {
    ($x:expr) => {
        match $x {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if std::env::var("SRT_ALLOW_NO_INTEROP_TESTS").is_ok() {
                    log::error!("could not find executable, skipping");
                    return Ok(());
                } else {
                    return Err(e.into());
                }
            }
            Err(e) => return Err(e.into()),
            Ok(s) => s,
        }
    };
}

fn counting_stream(packets: u32, delay: Duration) -> impl Stream<Item = Bytes> {
    tokio_stream::StreamExt::throttle(
        stream::iter(0..packets).map(|i| Bytes::from(i.to_string())),
        delay,
    )
    .boxed()
}

async fn udp_recvr(packets: u32, port: u16) -> Result<(), Error> {
    // start udp listener
    let socket = UdpFramed::new(
        UdpSocket::bind(&SocketAddr::V4(SocketAddrV4::new(
            "127.0.0.1".parse().unwrap(),
            port,
        )))
        .await
        .unwrap(),
        BytesCodec::new(),
    );

    receiver(packets, socket.map(|i| i.unwrap().0.freeze())).await
}

async fn receiver(
    packets: u32,
    mut stream: impl Stream<Item = Bytes> + Unpin,
) -> Result<(), Error> {
    let mut i = 0;
    while let Some(a) = stream.next().await {
        assert_eq!(&a, &i.to_string());

        i += 1;

        info!("Got pack {i}!");

        // stransmit does not totally care if it sends 100% of it's packets
        // (which is prob fair), just make sure that we got at least 2/3s of it
        if i >= packets * 2 / 3 {
            info!("Got enough packs! Exiting!");
            break;
        }
    }
    assert!(i >= packets * 2 / 3);

    Ok(())
}

async fn udp_sender(packets: u32, port: u16) -> Result<(), Error> {
    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    for i in 0..packets {
        sock.send_to(i.to_string().as_bytes(), ("127.0.0.1", port))
            .await?;

        sleep(Duration::from_millis(1)).await;
    }

    Ok(())
}

#[tokio::test]
async fn stransmit_client() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    const PACKETS: u32 = 1_000;

    // stranmsit process
    let mut stransmit = allow_not_found!(Command::new("srt-live-transmit")
        .arg("udp://:2452")
        .arg("srt://127.0.0.1:2453?latency=182")
        .arg("-a:no") // don't reconnect
        .spawn());

    let listener = async {
        // connect to process
        let mut conn = SrtSocket::builder()
            .latency(Duration::from_millis(827))
            .listen_on(2453)
            .await
            .unwrap();
        assert_eq!(
            conn.settings().send_tsbpd_latency,
            Duration::from_millis(827)
        );
        assert_eq!(
            conn.settings().recv_tsbpd_latency,
            Duration::from_millis(827)
        );

        let mut i = 0;

        // start the data generation process
        join!(async { udp_sender(PACKETS, 2452).await.unwrap() }, async {
            // receive
            while let Some(p) = conn.next().await {
                let (_, b) = p.unwrap();

                assert_eq!(&i.to_string(), &b);

                i += 1;

                if i > PACKETS * 2 / 3 {
                    break;
                }
            }
            assert!(i > PACKETS * 2 / 3);
        });
    };

    listener.await;
    stransmit.wait()?;

    if time::Instant::now().elapsed() > Duration::MAX {
        haivision_echo(
            1,
            0,
            HaiSettings {
                km_refreshrate: None,
                km_preannounce: None,
                passphrase: None,
                pbkeylen: None,
            },
        );
    }

    Ok(())
}

// srt-rs connects to stransmit and sends to stransmit
#[tokio::test]
async fn stransmit_server() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    const PACKETS: u32 = 1_000;

    // start SRT connector
    let serv = async {
        let mut sender = SrtSocket::builder()
            .latency(Duration::from_millis(99))
            .call("127.0.0.1:2340", None)
            .await
            .unwrap();

        assert_eq!(
            sender.settings().send_tsbpd_latency,
            Duration::from_millis(123)
        );
        assert_eq!(
            sender.settings().recv_tsbpd_latency,
            Duration::from_millis(123)
        );

        let mut stream =
            counting_stream(PACKETS, Duration::from_millis(1)).map(|b| Ok((Instant::now(), b)));
        sender.send_all(&mut stream).await.unwrap();
        sender.close().await.unwrap();
    };

    let udp_recv = async { udp_recvr(PACKETS, 2341).await.unwrap() };

    // start stransmit process
    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("srt://:2340?latency=123?blocking=true")
        .arg("udp://127.0.0.1:2341")
        .arg("-a:no") // don't auto-reconnect
        .spawn());

    join!(serv, udp_recv);

    child.wait()?;

    Ok(())
}

#[tokio::test]
#[ignore]
async fn stransmit_rendezvous() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    const PACKETS: u32 = 1_000;

    let sender_fut = async move {
        let mut sender = SrtSocket::builder()
            .local_port(2545)
            .rendezvous("127.0.0.1:2544")
            .await
            .unwrap();

        sender
            .send_all(
                &mut counting_stream(PACKETS, Duration::from_millis(1))
                    .map(|b| Ok((Instant::now(), b))),
            )
            .await
            .unwrap();

        sender.close().await.unwrap();
    };

    let udp_recvr = async { udp_recvr(PACKETS, 2546).await.unwrap() };

    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("srt://127.0.0.1:2545?adapter=127.0.0.1&port=2544&mode=rendezvous")
        .arg("udp://127.0.0.1:2546")
        .arg("-a:no") // don't auto-reconnect
        .spawn());

    join!(sender_fut, udp_recvr);

    child.wait()?;

    Ok(())
}

#[tokio::test]
async fn stransmit_encrypt() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    const PACKETS: u32 = 1_000;

    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("udp://:2677")
        .arg("srt://:2678?passphrase=password123&pbkeylen=16")
        .arg("-a:no")
        .arg("-loglevel:debug")
        .spawn());

    let recvr_fut = async move {
        let recv = SrtSocket::builder()
            .encryption(16, "password123")
            .call("127.0.0.1:2678", None)
            .await
            .unwrap();

        try_join(
            receiver(PACKETS, recv.map(|f| f.unwrap().1)),
            udp_sender(PACKETS, 2677),
        )
        .await
        .unwrap();
    };

    recvr_fut.await;
    child.wait().unwrap();

    Ok(())
}

#[tokio::test]
async fn stransmit_decrypt() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    const PACKETS: u32 = 1_000;

    let sender_fut = async move {
        let mut snd = SrtSocket::builder()
            .encryption(16, "password123")
            .listen_on(2909)
            .await
            .unwrap();

        snd.send_all(
            &mut counting_stream(PACKETS, Duration::from_millis(1))
                .map(|b| Ok((Instant::now(), b))),
        )
        .await
        .unwrap();
        info!("Send finished!");
        snd.close().await.unwrap();
        info!("Closed!");
    };

    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("srt://127.0.0.1:2909?passphrase=password123&pbkeylen=16")
        .arg("udp://127.0.0.1:2910")
        .arg("-a:no")
        .arg("-loglevel:debug")
        .spawn());

    join!(sender_fut, async {
        udp_recvr(PACKETS, 2910).await.unwrap()
    });
    info!("Futures finished!");
    child.wait().unwrap();

    Ok(())
}

#[tokio::test]
async fn stransmit_encrypt_rekey() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    const PACKETS: u32 = 1_000;

    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("udp://:2011")
        .arg("srt://:2012?passphrase=password123&pbkeylen=16&kmrefreshrate=128&kmpreannounce=60")
        .arg("-a:no")
        .arg("-loglevel:debug")
        .spawn());

    let recvr_fut = async move {
        let recv = SrtSocket::builder()
            .encryption(16, "password123")
            .call("127.0.0.1:2012", None)
            .await
            .unwrap();

        try_join(
            receiver(PACKETS, recv.map(|f| f.unwrap().1)),
            udp_sender(PACKETS, 2011),
        )
        .await
        .unwrap();
    };

    recvr_fut.await;
    child.wait().unwrap();

    Ok(())
}

// reported by @ian-spoonradio
#[tokio::test]
#[cfg(not(target_os = "windows"))]
async fn test_c_client_interop() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    let srt_rs_side = async move {
        let mut sock = SrtSocket::builder().listen_on(2811).await.unwrap();

        for _ in 0..100 {
            let (_, msg) = sock.next().await.unwrap().unwrap();
            assert_eq!(msg, TEST_C_CLIENT_MESSAGE);
            debug!("Got packet");
        }

        debug!("Closing");

        sock.close().await.unwrap();

        debug!("Closed");

        Ok(())
    };

    let jh = spawn_blocking(move || test_c_client(2811));

    try_join(srt_rs_side, jh).await.unwrap();

    Ok(())
}

#[tokio::test]
#[cfg(not(target_os = "windows"))]
async fn bidirectional_interop() -> Result<(), Error> {
    #[cfg(target_os = "macos")]
    if Instant::now().elapsed() < Duration::MAX {
        return Ok(());
    }

    let _ = pretty_env_logger::try_init();

    let srt_rs_side = async move {
        let mut sock = SrtSocket::builder().listen_on(2812).await.unwrap();

        time::sleep(Duration::from_millis(500)).await;

        for _ in 0..10 {
            debug!("Sending...");
            sock.send((Instant::now(), Bytes::from_static(b"1234")))
                .await
                .unwrap();
            debug!("Sent");

            let (_, buf) = sock.next().await.unwrap().unwrap();
            debug!("Recvd");
            assert_eq!(&*buf, b"1234");
        }

        Ok(())
    };

    let jh = spawn_blocking(move || haivision_echo(2812, 10, HaiSettings::default()));

    try_join(srt_rs_side, jh).await.unwrap();

    Ok(())
}

#[tokio::test]
#[cfg(not(target_os = "windows"))]
async fn bidirectional_interop_encrypt_rekey() -> Result<(), Error> {
    use tokio::time::sleep;

    #[cfg(target_os = "macos")]
    if Instant::now().elapsed() < Duration::MAX {
        return Ok(());
    }

    let _ = pretty_env_logger::try_init();

    let srt_rs_side = async move {
        let sock = SrtSocket::builder()
            .encryption(16, "password123")
            .set(|options| {
                options.encryption.km_refresh.period = PacketCount(128);
                options.encryption.km_refresh.pre_announcement_period = PacketCount(60);
            })
            .listen_on(2813)
            .await
            .unwrap();

        time::sleep(Duration::from_millis(500)).await;

        let (mut s, mut r) = sock.split();

        let s = async move {
            for _ in 0..1024 {
                debug!("Sending...");
                s.send((Instant::now(), Bytes::from_static(b"1234")))
                    .await
                    .unwrap();
                debug!("Sent");
                sleep(Duration::from_millis(10)).await;
            }
        };
        let r = async move {
            for _ in 0..1024 {
                let (_, buf) = r.next().await.unwrap().unwrap();
                debug!("Recvd");
                assert_eq!(&*buf, b"1234");
            }
        };
        join!(s, r);

        Ok(())
    };

    let jh = spawn_blocking(move || {
        haivision_echo(
            2813,
            1024,
            HaiSettings {
                km_preannounce: Some(60),
                km_refreshrate: Some(128),
                passphrase: Some("password123".into()),
                pbkeylen: Some(16),
            },
        )
    });

    try_join(srt_rs_side, jh).await.unwrap();

    Ok(())
}

#[tokio::test]
#[cfg(not(target_os = "windows"))]
async fn key_size_mismatch_rust_caller() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    const PACKETS: u32 = 1_000;

    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("udp://:2814")
        .arg("srt://:2815?passphrase=password123&pbkeylen=24")
        .arg("-a:no")
        .arg("-loglevel:debug")
        .spawn());

    let recvr_fut = async move {
        let recv = SrtSocket::builder()
            .encryption(16, "password123")
            .call("127.0.0.1:2815", None)
            .await
            .unwrap();

        try_join(
            receiver(PACKETS, recv.map(|f| f.unwrap().1)),
            udp_sender(PACKETS, 2814),
        )
        .await
        .unwrap();
    };

    recvr_fut.await;
    child.wait().unwrap();

    Ok(())
}

#[tokio::test]
#[cfg(not(target_os = "windows"))]
async fn key_size_mismatch_rust_listener() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    const PACKETS: u32 = 1_000;

    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("srt://127.0.0.1:2816?passphrase=password123&pbkeylen=24")
        .arg("udp://:2817")
        .arg("-a:no")
        .arg("-loglevel:debug")
        .spawn());

    let sendr = async move {
        let mut sender = SrtSocket::builder()
            .encryption(16, "password123")
            .local_port(2816)
            .listen()
            .await
            .unwrap();

        let mut stream =
            counting_stream(PACKETS, Duration::from_millis(1)).map(|b| Ok((Instant::now(), b)));
        sender.send_all(&mut stream).await.unwrap();
        sender.close().await.unwrap();

        Ok(())
    };

    try_join(sendr, udp_recvr(PACKETS, 2817)).await.unwrap();

    child.wait().unwrap();

    Ok(())
}

type HaiSocket = i32;

const SRTO_SENDER: c_int = 21;
const SRTO_KMREFRESHRATE: c_int = 51;
const SRTO_KMPREANNOUNCE: c_int = 52;
const SRTO_PASSPHRASE: c_int = 26;
const SRTO_PBKEYLEN: c_int = 27;

const LOG_DEBUG: c_int = 7;

struct HaivisionSrt<'l> {
    create_socket: Symbol<'l, unsafe extern "C" fn() -> HaiSocket>,
    setsockflag: Symbol<'l, unsafe extern "C" fn(HaiSocket, c_int, *const (), c_int) -> c_int>,
    connect: Symbol<'l, unsafe extern "C" fn(HaiSocket, *const sockaddr, c_int) -> c_int>,
    sendmsg2: Symbol<'l, unsafe extern "C" fn(HaiSocket, *const u8, c_int, *const ()) -> c_int>,
    recvmsg2: Symbol<'l, unsafe extern "C" fn(HaiSocket, *const u8, c_int, *const ()) -> c_int>,
    close: Symbol<'l, unsafe extern "C" fn(HaiSocket) -> c_int>,
    startup: Symbol<'l, unsafe extern "C" fn() -> c_int>,
    // cleanup: Symbol<'l, unsafe extern "C" fn() -> c_int>,
    getlasterror_str: Symbol<'l, unsafe extern "C" fn() -> *const c_char>,
    setloglevel: Symbol<'l, unsafe extern "C" fn(c_int) -> ()>,
}

impl<'l> HaivisionSrt<'l> {
    unsafe fn new(lib: &'l Library) -> HaivisionSrt<'l> {
        HaivisionSrt {
            create_socket: lib.get(b"srt_create_socket").unwrap(),
            setsockflag: lib.get(b"srt_setsockflag").unwrap(),
            connect: lib.get(b"srt_connect").unwrap(),
            sendmsg2: lib.get(b"srt_sendmsg2").unwrap(),
            recvmsg2: lib.get(b"srt_recvmsg2").unwrap(),
            close: lib.get(b"srt_close").unwrap(),
            startup: lib.get(b"srt_startup").unwrap(),
            // cleanup: lib.get(b"srt_cleanup").unwrap(),
            getlasterror_str: lib.get(b"srt_getlasterror_str").unwrap(),
            setloglevel: lib.get(b"srt_setloglevel").unwrap(),
        }
    }
}

const TEST_C_CLIENT_MESSAGE: &[u8] = b"This message should be sent to the other side";

#[cfg(target_os = "linux")]
fn make_sockaddr(port: u16) -> sockaddr {
    use libc::{in_addr, sockaddr_in, AF_INET};
    unsafe {
        transmute(sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: in_addr {
                s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
            },
            sin_zero: [0; 8],
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn make_sockaddr(port: u16) -> sockaddr {
    use libc::{in_addr, sockaddr_in, AF_INET};
    unsafe {
        transmute(sockaddr_in {
            sin_family: AF_INET as u8,
            sin_port: port.to_be(),
            sin_addr: in_addr {
                s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
            },
            sin_zero: [0; 8],
            sin_len: size_of::<sockaddr_in>() as u8,
        })
    }
}

#[cfg(target_os = "windows")]
fn make_sockaddr(port: u16) -> sockaddr {
    unimplemented!()
}

fn open_libsrt() -> Option<Library> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let possible_names = ["libsrt-gnutls.so.1.4", "libsrt.so", "libsrt.so.1"];

    #[cfg(target_os = "windows")]
    let possible_names = ["srt.dll"];

    #[cfg(target_os = "macos")]
    let possible_names = ["libsrt.dylib"];

    // first the environment variable
    if let Ok(path) = env::var("LIBSRT_PATH") {
        info!("LIBSRT_PATH={}, trying...", path);
        if let Ok(lib) = unsafe { Library::new(path) } {
            return Some(lib);
        }
    }

    for name in &possible_names {
        match unsafe { Library::new(*name) } {
            Ok(lib) => return Some(lib),
            Err(e) => println!("Failed to load from {name}: {e}"),
        }
    }
    None
}

#[derive(Default)]
struct HaiSettings {
    km_refreshrate: Option<i32>,
    km_preannounce: Option<i32>,
    passphrase: Option<String>,
    pbkeylen: Option<i32>,
}

lazy_static::lazy_static! {
    static ref LIBSRT: Library = open_libsrt().unwrap();
    static ref SRT: HaivisionSrt<'static> = unsafe {
        let srt = HaivisionSrt::new(&LIBSRT);
        (srt.startup)();
        (srt.setloglevel)(LOG_DEBUG);
        srt
    };
}

// this mimics test_c_client from the repository
fn test_c_client(port: u16) {
    unsafe {
        let ss = (SRT.create_socket)();
        if ss == -1 {
            panic!("Failed to create socket");
        }

        let sa = make_sockaddr(port);

        let yes: c_int = 1;
        (SRT.setsockflag)(
            ss,
            SRTO_SENDER,
            &yes as *const i32 as *const (),
            size_of::<c_int>() as c_int,
        );

        let st = (SRT.connect)(ss, &sa, size_of::<sockaddr>() as c_int);
        if st == -1 {
            panic!(
                "Failed to connect {:?}",
                CStr::from_ptr((SRT.getlasterror_str)())
            );
        }

        for _ in 0..100 {
            let st = (SRT.sendmsg2)(
                ss,
                TEST_C_CLIENT_MESSAGE.as_ptr(),
                TEST_C_CLIENT_MESSAGE.len() as c_int,
                null(),
            );
            if st == -1 {
                panic!();
            }

            thread::sleep(Duration::from_millis(1))
        }

        thread::sleep(Duration::from_millis(100));

        if (SRT.close)(ss) == -1 {
            panic!();
        }

        // (SRT.cleanup)();
    }
}

fn haivision_echo(port: u16, packets: usize, settings: HaiSettings) {
    unsafe {
        let ss = (SRT.create_socket)();
        if ss == -1 {
            panic!("Failed to create socket");
        }

        let sa = make_sockaddr(port);

        if let Some(kmrr) = settings.km_refreshrate {
            (SRT.setsockflag)(
                ss,
                SRTO_KMREFRESHRATE,
                &kmrr as *const i32 as *const (),
                size_of::<c_int>() as c_int,
            );
        }
        if let Some(kmpa) = settings.km_preannounce {
            (SRT.setsockflag)(
                ss,
                SRTO_KMPREANNOUNCE,
                &kmpa as *const i32 as *const (),
                size_of::<c_int>() as c_int,
            );
        }
        if let Some(passphrase) = settings.passphrase {
            let cstr = CString::new(passphrase).unwrap();
            (SRT.setsockflag)(
                ss,
                SRTO_PASSPHRASE,
                cstr.as_ptr() as *const (),
                cstr.as_bytes().len() as i32,
            );
        }
        if let Some(pbkeylen) = settings.pbkeylen {
            (SRT.setsockflag)(
                ss,
                SRTO_PBKEYLEN,
                &pbkeylen as *const i32 as *const (),
                size_of::<c_int>() as c_int,
            );
        }

        let st = (SRT.connect)(ss, &sa, size_of::<sockaddr>() as c_int);

        if st == -1 {
            panic!(
                "Failed to connect {:?}",
                CStr::from_ptr((SRT.getlasterror_str)())
            );
        }

        let mut buffer = [0; 1316];

        // receive + send n packets
        for _ in 0..packets {
            let size = (SRT.recvmsg2)(ss, buffer.as_mut_ptr(), buffer.len() as c_int, null());
            if size == -1 {
                panic!()
            }

            let st = (SRT.sendmsg2)(ss, buffer.as_ptr(), size, null());

            if st == -1 {
                panic!()
            }
        }

        thread::sleep(Duration::from_secs(2)); // make sure the receiver gets the last message before closing

        if (SRT.close)(ss) == -1 {
            panic!();
        }
    }
}
