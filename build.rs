use std::env;
use std::path::PathBuf;

// https://rust-lang.github.io/rust-bindgen/tutorial-3.html
fn main() {
    let list="aes aesce aesni asn1parse asn1write bignum bignum_core bignum_mod bignum_mod_raw cipher cipher_wrap constant_time ctr_drbg debug ecdh ecdsa ecp ecp_curves entropy entropy_poll error gcm hash_info hmac_drbg md memory_buffer_alloc nist_kw oid padlock pem pk pk_wrap pkcs12 pkcs5 pkcs7 pkparse pkwrite platform platform_util ripemd160 rsa rsa_alt_helpers sha1 sha256 sha512 ssl_cache ssl_ciphersuites ssl_client ssl_cookie ssl_debug_helpers_generated ssl_msg ssl_ticket ssl_tls ssl_tls12_client ssl_tls12_server timing version version_features x509 x509_create x509_crl x509_crt x509_csr x509write_crt x509write_csr";
    cc::Build::new()
        .include("3rdparty/mbedtls/include")
        .include("src")
        .define("MBEDTLS_CONFIG_FILE", "<mbedtls_config_custom.h>")
        .files(
            list.split(' ')
                .map(|v| format!("3rdparty/mbedtls/library/{v}.c")),
        )
        .compile("mbedtlsmono");
    // // tell cargo to look for libraries in the specified directory
    // println!("cargo:rustc-link-search=target/mbedtls/library");

    // // tell cargo to tell rustc to link the library.
    // println!("cargo:rustc-link-lib=mbedtlsmono");

    // tell cargo to invalidate the built crate whenever the wrapper changes
    // println!("cargo:rerun-if-changed=wrapper.h");
}
