use std::env;
use std::path::PathBuf;

// https://rust-lang.github.io/rust-bindgen/tutorial-3.html
// target/mbedtls/library -lmbedtls -lmbedx509 -lmbedcrypto
fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search=target/mbedtls/library");

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    println!("cargo:rustc-link-lib=mbedtls");
    println!("cargo:rustc-link-lib=mbedx509");
    println!("cargo:rustc-link-lib=mbedcrypto");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    // println!("cargo:rerun-if-changed=wrapper.h");
}
