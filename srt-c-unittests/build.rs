use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=tests/test_connection_timeout.cpp");
    println!("cargo:rerun-if-changed=tests/test_enforced_encryption.cpp");
    println!("cargo:rerun-if-changed=tests/test_file_transmission.cpp");
    println!("cargo:rerun-if-changed=tests/test_ipv6.cpp");
    println!("cargo:rerun-if-changed=tests/test_listen_callback.cpp");
    println!("cargo:rerun-if-changed=tests/test_many_connections.cpp");
    println!("cargo:rerun-if-changed=tests/test_muxer.cpp");
    println!("cargo:rerun-if-changed=tests/test_reuseaddr.cpp");
    println!("cargo:rerun-if-changed=tests/test_socket_options.cpp");

    cc::Build::new()
        .file("tests/test_connection_timeout.cpp")
        .file("tests/test_enforced_encryption.cpp")
        .file("tests/test_file_transmission.cpp")
        .file("tests/test_ipv6.cpp")
        .file("tests/test_listen_callback.cpp")
        .file("tests/test_many_connections.cpp")
        .file("tests/test_muxer.cpp")
        .file("tests/test_reuseaddr.cpp")
        .file("tests/test_socket_options.cpp")
        .include("../srt-c")
        .compile("units");

    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=gtest");
    println!("cargo:rustc-link-lib=gtest_main");
    println!("cargo:rustc-link-lib=m");

    let mut path = PathBuf::from(env::var("OUT_DIR").unwrap());
    path.pop();
    path.pop();
    path.pop();
    println!("cargo:rustc-link-search={}", path.display());
    println!("cargo:rustc-link-lib=srt_c");
}
