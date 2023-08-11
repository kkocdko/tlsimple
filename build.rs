use std::fs;
fn main() {
    // https://rust-lang.github.io/rust-bindgen/tutorial-3.html
    // let excludes = "base64|aria|camellia|ccm|chacha|poly1305|lmots|lms|des|dhm|ecjpake|cmac|threading|hkdf|md5|net_sockets|mps_|psa_|ssl_tls13_";
    let files = fs::read_dir("3rdparty/mbedtls/library")
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|e| e.extension() == Some(std::ffi::OsStr::new("c")))
        .collect::<Vec<_>>();
    cc::Build::new()
        .include("3rdparty/mbedtls/include")
        .include("src")
        .define("MBEDTLS_CONFIG_FILE", "<mbedtls_config_custom.h>")
        .files(files)
        .compile("mbedtlsmono");
    // tell cargo to look for libraries in the specified directory
    // println!("cargo:rustc-link-search=target/mbedtls/library");

    // // tell cargo to tell rustc to link the library.
    // println!("cargo:rustc-link-lib=mbedtlsmono");

    // tell cargo to invalidate the built crate whenever the wrapper changes
    // println!("cargo:rerun-if-changed=wrapper.h");
}
