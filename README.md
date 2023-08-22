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
- [x] Fix crach on Tokio multi-thread runtime.
- [x] Bench OpenSSL and Mbed TLS.
- [x] Strip more.
- [ ] TLS 1.3.
- [ ] Use mbedtls_ssl_cache_context to speed up.
- [ ] Improve multi-thread performance.
- [x] Bench OpenSSL and Mbed TLS.
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
cargo run --example exname -- --exoption exarg1 exarg2

cargo install bindgen-cli
sudo dnf install clang-devel
bindgen src/mbedtls.h --default-macro-constant-type signed -- -I3rdparty/mbedtls/include >src/ffi.rs
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

tlsimple (174 deps)  =  5783792 Aug 17 19:52 ksite
rustls (183 deps)    =  6479280 Aug 17 20:10 ksite


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

<!--
https://mbed-tls.readthedocs.io/projects/api/en/development/api/file/net__sockets_8h/#net__sockets_8h_1a4841afd0e14f1fd44b82c3a850961ab7
https://github.com/Mbed-TLS/mbedtls/tree/development/programs/ssl
https://github.com/Mbed-TLS/mbedtls/blob/963513dba56991e2c741290841e2f33b9398ea52/programs/ssl/ssl_server2.c#L2855
https://github.com/Mbed-TLS/mbedtls/blob/development/programs/ssl/mini_client.c
https://github.com/sfackler/hyper-openssl/blob/master/src/lib.rs
-->
