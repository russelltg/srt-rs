use futures::prelude::*;

use std::io::Error;

use bytes::Bytes;

pub struct Sender {}

impl Sender {
    fn new(socket: SrtSocket) -> Sender {}
}

// impl Sink for Sender {
//     type SinkItem = Bytes;
//     type SinkError = Error;

//     fn start_send(&mut self, item: Bytes) -> StartSend<Bytes, Error> {}

//     fn poll_complete(&mut self) -> Poll<(), Error> {}

//     fn close(&mut self) -> Poll<(), Error> {}
// }
