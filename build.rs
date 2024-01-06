use std::ffi::OsStr;
use std::fs;
use std::process::Command;

fn main() {
    let binding_src = Command::new("bindgen") // cargo install bindgen-cli ; dnf install clang-devel
        .args([
            "src/mbedtls.h",
            "--default-macro-constant-type",
            "signed",
            "--",
            "-I3rdparty/mbedtls/include",
        ])
        .output()
        .unwrap()
        .stdout;
    let mut binding_src =
        "#![allow(warnings)]\n".to_string() + std::str::from_utf8(&binding_src).unwrap();
    binding_src += "\npub fn err_name(code:i32)->&'static str{match code{\n";
    let err_defs: Vec<_> = binding_src
        .split('\n')
        .filter(|e| e.contains("pub const MBEDTLS_ERR_"))
        .map(|e| {
            let mut splited = e.split(&[' ', ':', ';']);
            splited.find(|&p| p == "const").unwrap();
            let name = splited.next().unwrap();
            splited.find(|&p| p == "=").unwrap();
            let code = splited.next().unwrap();
            (name.to_string(), code.to_string())
        })
        .collect();
    for (name, code) in err_defs {
        binding_src += &code;
        binding_src += " => \"";
        binding_src += &name;
        binding_src += "\",\n";
    }
    binding_src += "_=>\"unknown\"}}\n";
    fs::write("src/ffi.rs", binding_src).unwrap();

    let cc_files = fs::read_dir("3rdparty/mbedtls/library")
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|e| e.extension() == Some(OsStr::new("c")))
        // .filter(|e| {
        //     let file_name = e.file_name().unwrap().to_str().unwrap();
        //     !["net_sockets", "mps_", "psa_"]
        //         .iter()
        //         .any(|p| file_name.starts_with(p))
        // })
         ;
    cc::Build::new()
        .include("3rdparty/mbedtls/include")
        .include("src")
        .define("MBEDTLS_CONFIG_FILE", "<mbedtls_config_custom.h>")
        // .ar_flag("-no_warning_for_no_symbols")
        .files(cc_files)
        .compile("mbedtlsmono"); // however, in official guide, it should be spilted into 3 files
}
