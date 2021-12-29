fn main() {
    println!("cargo:rerun-if-changed=src/catch.cpp");
    cc::Build::new().file("src/catch.cpp").compile("catch");
}
