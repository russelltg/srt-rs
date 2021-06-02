#![no_main]
use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};

use srt_protocol::{
    pending_connection::{connect::Connect, ConnInitSettings},
    Packet,
};

use std::time::Instant;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let mut uns = Unstructured::new(data);
    let mut connect = Connect::new(
        ([127, 0, 0, 1], 2221).into(),
        [127, 0, 0, 1].into(),
        ConnInitSettings::default(),
        None,
    );
    if let Ok(packet) = Packet::arbitrary(&mut uns) {
        connect.handle_packet((packet, ([127, 0, 0, 1], 2221).into()), Instant::now());
    }
    if let Ok(packet) = Packet::arbitrary(&mut uns) {
        connect.handle_packet((packet, ([127, 0, 0, 1], 2221).into()), Instant::now());
    }
    if let Ok(packet) = Packet::arbitrary(&mut uns) {
        connect.handle_packet((packet, ([127, 0, 0, 1], 2221).into()), Instant::now());
    }
});
