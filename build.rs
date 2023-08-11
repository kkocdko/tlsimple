use std::ffi::OsStr;
use std::fmt::Write;
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
        .compile("mbedtlsmono");

    let mut match_block = "pub fn err_name(code:i32)->&'static str{match code{\n".to_string();
    let err_files = fs::read_dir("3rdparty/mbedtls/include/mbedtls")
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|e| e.extension() == Some(OsStr::new("h")));
    for file in err_files {
        let data = fs::read_to_string(file).unwrap();
        let lines = data
            .split('\n')
            .filter(|e| e.starts_with("#define MBEDTLS_ERR_"))
            .map(|e| e.split_whitespace());
        for mut parts in lines {
            parts.next();
            let k = parts.next().unwrap();
            let v = parts.next().unwrap();
            write!(&mut match_block, "{v} => \"{k}\",\n").unwrap();
        }
    }
    match_block += "_=>\"unknown\"}}";
    fs::write("src/mbedtls_err.rs", match_block).unwrap();
    // for header
    //     .map(|e| fs::read_to_string(e).unwrap())
    //     .collect::<Vec<_>>();
    // ~/misc/apps/rg '#define MBEDTLS_ERR_'

    // tell cargo to look for libraries in the specified directory
    // println!("cargo:rustc-link-search=target/mbedtls/library");

    // // tell cargo to tell rustc to link the library.
    // println!("cargo:rustc-link-lib=mbedtlsmono");

    // tell cargo to invalidate the built crate whenever the wrapper changes
    // println!("cargo:rerun-if-changed=wrapper.h");
}
