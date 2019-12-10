use srt::{ConnInitMethod, SrtSocketBuilder};

use futures::try_join;

#[tokio::test]
async fn rendezvous() {
    let a = SrtSocketBuilder::new(ConnInitMethod::Rendezvous(
        "127.0.0.1:5000".parse().unwrap(),
    ))
    .local_port(5001)
    .connect();

    let b = SrtSocketBuilder::new(ConnInitMethod::Rendezvous(
        "127.0.0.1:5001".parse().unwrap(),
    ))
    .local_port(5000)
    .connect();

    let _ = try_join!(a, b).unwrap();
}
