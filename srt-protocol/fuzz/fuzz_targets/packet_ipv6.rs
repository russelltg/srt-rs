#![no_main]
use libfuzzer_sys::fuzz_target;

use srt_protocol::Packet;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::parse(&mut Cursor::new(data), true);
});
