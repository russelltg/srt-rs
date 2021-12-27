use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=tests/test_connection_timeout.cpp");
    println!("cargo:rerun-if-changed=tests/test_many_connections.cpp");

    cc::Build::new()
        // .file("tests/test_connection_timeout.cpp")
        .file("tests/test_many_connections.cpp")
        .include("../srt-c")
        .compile("units");

    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=gtest");
    println!("cargo:rustc-link-lib=gtest_main");

    // println!("cargo:rustc-link-search={}", env::var("OUT_DIR").unwrap());
    let mut path = PathBuf::from(env::var("OUT_DIR").unwrap());
    path.pop();
    path.pop();
    path.pop();
    println!("cargo:rustc-link-arg-bins={}/libsrt_c.so", path.display());
}
