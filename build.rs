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
        .define("MBEDTLS_CONFIG_FILE", "<stddef.h>")
        .files(cc_files)
        .compile("mbedtlsmono"); // however, in official guide, it should be spilted into 3 files

    let mut mbedtls_err_rs = "pub fn err_name(code:i32)->&'static str{match code{\n".to_string();
    let err_files = fs::read_dir("3rdparty/mbedtls/include/mbedtls")
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|e| e.extension() == Some(OsStr::new("h")));
    for file in err_files {
        let data = fs::read_to_string(file).unwrap();
        let err_def_lines = data
            .split('\n')
            .filter(|e| e.starts_with("#define MBEDTLS_ERR_"))
            .map(|e| e.split_whitespace());
        for mut parts in err_def_lines {
            parts.next();
            let k = parts.next().unwrap();
            let v = parts.next().unwrap();
            writeln!(&mut mbedtls_err_rs, "{v} => \"{k}\",").unwrap();
        }
    }
    mbedtls_err_rs += "_=>\"unknown\"}}";
    fs::write("src/mbedtls_err.rs", mbedtls_err_rs).unwrap();
}
