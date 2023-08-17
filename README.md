# tlsimple

Simple and tiny TLS supports for Rust (Async FFI of Mbed TLS).

## Goals

- In a word: Async Rust binding, use cc crate, needs only a c compiler, supports multi platform.

- Async support. Provide `TlsStream` (for tokio) and `HttpsConnector` (for hyper).

- Single crate, less dependencies.

- Easy to build, without install Perl, autoconf, automake etc.

## Roadmap

- [x] Run OpenSSL demo.
- [x] Run wolfSSL demo.
- [x] Run Mbed TLS demo.
- [x] Use Mbed TLS BIO (I/O abstraction).
- [x] Try to figure out if Mbed TLS is easy to strip.
- [x] Build Mbed TLS with AddressSanitizer.
- [x] Build Rust executable with AddressSanitizer.
- [x] Rust binding prototype worked.
- [x] Fully control the build progress, use only gcc / ar command.
- [ ] TLS 1.3.
- [x] Fix LeakSanitizer.
- [ ] Test if C demo works in Windows.
- [x] Compile with the Rust cc crate.
- [x] Bind to Rust.
- [x] Bind to Rust with async.
- [ ] Miri, Loom, ThreadSanitizer and more.
- [x] Set ALPN to use HTTP 2.
- [x] Client mode.
- [ ] Client mode cert vertify.
- [x] Client with Hyper.
- [x] Deploy on Tokio current-thread runtime.
- [ ] Fix crach on Tokio multi-thread runtime.
- [ ] Bench OpenSSL and Mbed TLS.
- [x] Strip more.
- [ ] Use mbedtls_ssl_cache_context to speed up.
- [ ] Kernel TLS offload?
- [ ] Deploy.
- [ ] Publish & Announce.

https://github.com/monoio-rs/monoio-tls

https://github.com/Mbed-TLS/mbedtls/pull/5969

https://openwrt.org/releases/23.05/notes-23.05.0-rc2#switch_from_wolfssl_to_mbedtls_as_default

https://dev.mysql.com/blog-archive/mysql-is-openssl-only-now/

https://curl.se/docs/ssl-compared.html

https://wiki.mozilla.org/Security/Server_Side_TLS

<!--
cargo install bindgen-cli
sudo dnf install clang-devel
bindgen src/mbedtls.h -o src/mbedtls_h.rs --default-macro-constant-type signed -- -I3rdparty/mbedtls/include
https://rust-lang.github.io/rust-bindgen/allowlisting.html
-->

<!--
curl -vvvk --tlsv1.3 https://127.0.0.1:11111
https://stackoverflow.com/questions/50887018/cmake-generate-single-header-file
https://github.com/rust-lang/cc-rs/issues/242
https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html
先尝试 bindgen 或者其他方案
crate “cc”
绑定代码？询问

https://doc.rust-lang.org/cargo/reference/manifest.html#the-exclude-and-include-fields


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
