use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn gen_cookie(saddr: &SocketAddr) -> i32 {
    let time_mins = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time was before the the unix epoch!!!")
        .as_secs()
        * 60;

    let mut hasher = DefaultHasher::new();
    saddr.hash(&mut hasher);
    time_mins.hash(&mut hasher);

    hasher.finish() as u32 as i32
}
