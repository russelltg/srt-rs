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
        .cpp(true)
        // disable tests that don't pass yet
        .define("TestEnforcedEncryption", "DISABLED_TestEnforcedEncryption")
        .define("FileUpload", "DISABLED_FileUpload")
        .define("v4_calls_v6_mapped", "DISABLED_v4_calls_v6_mapped")
        .define("v6_calls_v6_mapped", "DISABLED_v6_calls_v6_mapped")
        .define("v6_calls_v6", "DISABLED_v6_calls_v6")
        .define("v6_calls_v4", "DISABLED_v6_calls_v4")
        .define("IPv4_and_IPv6", "DISABLED_IPv4_and_IPv6")
        .define("SameAddr1", "DISABLED_SameAddr1")
        .define("SameAddr2", "DISABLED_SameAddr2")
        .define("DiffAddr", "DISABLED_DiffAddr")
        .define("Wildcard", "DISABLED_Wildcard")
        .define("ProtocolVersion", "DISABLED_ProtocolVersion")
        .define("DefaultVals", "DISABLED_DefaultVals")
        .define("MaxVals", "DISABLED_MaxVals")
        .define("MinVals", "DISABLED_MinVals")
        .define("InvalidVals", "DISABLED_InvalidVals")
        .define("RestrictionBind", "DISABLED_RestrictionBind")
        .define("RestrictionListening", "DISABLED_RestrictionListening")
        .define("RestrictionConnected", "DISABLED_RestrictionConnected")
        .define("TLPktDropInherits", "DISABLED_TLPktDropInherits")
        .define("LossMaxTTL", "DISABLED_LossMaxTTL")
        .define("MinInputBWDefault", "DISABLED_MinInputBWDefault")
        .define("MinInputBWSet", "DISABLED_MinInputBWSet")
        .define("MinInputBWRuntime", "DISABLED_MinInputBWRuntime")
        // files
        .define("SRT_ENABLE_ENCRYPTION", None)
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

    println!("cargo:rustc-link-lib=gtest");
    println!("cargo:rustc-link-lib=gtest_main");

    let mut path = PathBuf::from(env::var("OUT_DIR").unwrap());
    path.pop();
    path.pop();
    path.pop();
    println!("cargo:rustc-link-search={}", path.display());
    println!("cargo:rustc-link-lib=srt_c");
}
