fn main() {
    println!("cargo:rerun-if-changed=src/catch.cpp");
    cc::Build::new()
        .cpp(true)
        .file("src/catch.cpp")
        .flag("-std=c++11")
        .compile("catch");
}
