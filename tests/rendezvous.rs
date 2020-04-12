use srt::SrtSocketBuilder;

use futures::join;
use futures::prelude::*;

#[tokio::test]
async fn rendezvous() {
    let a = SrtSocketBuilder::new_rendezvous("127.0.0.1:5000")
        .local_port(5001)
        .connect();

    let b = SrtSocketBuilder::new_rendezvous("127.0.0.1:5001")
        .local_port(5000)
        .connect();

    join!(
        async move {
            a.await.unwrap().close().await.unwrap();
        },
        async move {
            b.await.unwrap().close().await.unwrap();
        }
    );
}
