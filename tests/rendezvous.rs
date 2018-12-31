use srt::{ConnInitMethod, SrtSocketBuilder};

use futures::Future;

#[test]
fn rendezvous() {
    let a = SrtSocketBuilder::new(ConnInitMethod::Rendezvous(
        "127.0.0.1:5000".parse().unwrap(),
    ))
    .local_port(5001)
    .build()
    .unwrap();

    let b = SrtSocketBuilder::new(ConnInitMethod::Rendezvous(
        "127.0.0.1:5001".parse().unwrap(),
    ))
    .local_port(5000)
    .build()
    .unwrap();

    let _ = a.join(b).wait().unwrap();
}
