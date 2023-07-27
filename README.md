# tlsimple

Some kkocdko's crazy ideas about TLS & HTTPS supports in Rust.

## Goals

- Async support. Provide `TlsStream` (for tokio) and `HttpsConnector` (for hyper).

- Single crate, less dependencies.

- Easy to build, without install Perl, autoconf, automake etc.

## Roadmap

- [x] Run OpenSSL demo
- [x] Run wolfSSL demo
- [x] Run Mbed TLS demo
- [x] Use Mbed TLS BIO
- [x] Try to figure out if Mbed TLS is easy to strip
- [ ] Bind to Rust.
- [ ] Bind to Rust with async.
- [ ] Bench OpenSSL and Mbed TLS.
- [ ] Strip
- [ ] Deploy
- [ ] Publish & Announce
- [ ] Provide blocking API

https://openwrt.org/releases/23.05/notes-23.05.0-rc2#switch_from_wolfssl_to_mbedtls_as_default

https://dev.mysql.com/blog-archive/mysql-is-openssl-only-now/

https://curl.se/docs/ssl-compared.html

<!--
cargo install bindgen-cli
sudo dnf install clang-devel
bindgen src/mbedtls.h -o src/mbedtls.h.rs -- -Itarget/mbedtls/include
https://rust-lang.github.io/rust-bindgen/allowlisting.html
-->

<!--
https://stackoverflow.com/questions/50887018/cmake-generate-single-header-file
https://github.com/rust-lang/cc-rs/issues/242
https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html
先尝试 bindgen 或者其他方案
crate “cc”
绑定代码？询问

cargo install bindgen-cli

-->

<!--
# openssl
mkdir -p target
cd target
curl -o openssl.tar.gz -L https://github.com/openssl/openssl/releases/download/openssl-3.1.1/openssl-3.1.1.tar.gz
rm -rf openssl
mkdir openssl
tar -xf openssl.tar.gz --strip-components 1 -C openssl
cd openssl
rm -rf test doc demos CHANGES.md
tar -cJf openssl.tar.xz openssl
-->
