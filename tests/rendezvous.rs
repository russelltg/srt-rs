use srt::SrtSocketBuilder;

use futures::try_join;

#[tokio::test]
async fn rendezvous() {
    let a = SrtSocketBuilder::new_rendezvous("127.0.0.1:5000")
        .local_port(5001)
        .connect();

    let b = SrtSocketBuilder::new_rendezvous("127.0.0.1:5001")
        .local_port(5000)
        .connect();

    let _ = try_join!(a, b).unwrap();
}
