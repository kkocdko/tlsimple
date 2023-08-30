use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::process::Command;
use std::str;

fn main() {
    if fs::metadata("3rdparty/mbedtls").is_err() {
        fs::create_dir_all("3rdparty/mbedtls").unwrap();
        if fs::metadata("3rdparty/mbedtls.tar.gz").is_err() {
            Command::new("curl")
                .args([
                    "-o",
                    "3rdparty/mbedtls.tar.gz",
                    "-L",
                    // "https://github.com/Mbed-TLS/mbedtls/archive/41d689f389a51e078e4de0fba20391d9de5d83e6.tar.gz",
                    "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz",
                ])
                .status()
                .unwrap();
        }
        let tar_prefix = Command::new("tar")
            .args(["--exclude=*/*/*", "-tf", "3rdparty/mbedtls.tar.gz"])
            .output()
            .unwrap()
            .stdout;
        let tar_prefix = str::from_utf8(tar_prefix.split(|&c| c == b'/').next().unwrap()).unwrap();
        Command::new("tar")
            .args([
                "--strip-components",
                "1",
                "-xf",
                "3rdparty/mbedtls.tar.gz",
                "-C",
                "3rdparty/mbedtls",
            ])
            .arg(format!("{tar_prefix}/include"))
            .arg(format!("{tar_prefix}/library"))
            .status()
            .unwrap();

        let mut ffi_rs = File::create("src/ffi.rs").unwrap();
        ffi_rs.write_all(b"#![allow(warnings)]\n").unwrap();
        Command::new("bindgen") // cargo install bindgen-cli ; dnf install clang-devel
            .args([
                "src/mbedtls.h",
                "--default-macro-constant-type",
                "signed",
                "--",
                "-I3rdparty/mbedtls/include",
            ])
            .stdout(ffi_rs)
            .status()
            .unwrap();

        let mut err_rs = File::create("src/err.rs").unwrap();
        err_rs
            .write_all(b"pub fn err_name(code:i32)->&'static str{match code{\n")
            .unwrap();
        let err_files = fs::read_dir("3rdparty/mbedtls/include/mbedtls")
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|e| e.extension() == Some(OsStr::new("h")));
        for file in err_files {
            let data = fs::read_to_string(file).unwrap();
            let def_lines = data
                .split('\n')
                .filter(|e| e.starts_with("#define MBEDTLS_ERR_"))
                .map(|e| e.split_whitespace());
            for mut parts in def_lines {
                parts.next();
                let k = parts.next().unwrap();
                let v = parts.next().unwrap();
                writeln!(&mut err_rs, "{v} => \"{k}\",").unwrap();
            }
        }
        err_rs.write_all(b"_=>\"unknown\"}}").unwrap();

        println!("cargo:warning=Mbed-TLS not found, inited now.");
    }

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
