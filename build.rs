use std::ffi::OsStr;
use std::fs;

fn main() {
    // https://rust-lang.github.io/rust-bindgen/tutorial-3.html
    // let excludes = "base64|aria|camellia|ccm|chacha|poly1305|lmots|lms|des|dhm|ecjpake|cmac|threading|hkdf|md5|net_sockets|mps_|psa_|ssl_tls13_";
    let cc_files = fs::read_dir("3rdparty/mbedtls/library")
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|e| e.extension() == Some(OsStr::new("c")));
    cc::Build::new()
        .include("3rdparty/mbedtls/include")
        .include("src")
        .define("MBEDTLS_CONFIG_FILE", "<mbedtls_config_custom.h>")
        .files(cc_files)
        .compile("mbedtlsmono"); // however, in official guide, it should be spilted into 3 files
}
