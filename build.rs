use std::env;
use std::path::PathBuf;

// https://rust-lang.github.io/rust-bindgen/tutorial-3.html
fn main() {
    // tell cargo to look for libraries in the specified directory
    println!("cargo:rustc-link-search=target/mbedtls/library");

    // tell cargo to tell rustc to link the library.
    println!("cargo:rustc-link-lib=mbedtlsmono");

    // tell cargo to invalidate the built crate whenever the wrapper changes
    // println!("cargo:rerun-if-changed=wrapper.h");
}
