# tlsimple

Simple and tiny TLS support for Rust, using [Mbed-TLS](https://github.com/Mbed-TLS/mbedtls).

## Features

- With async and blocking support, server and client mode. Also provide `HttpsConnector` for Hyper client.

- Lightweight, as a thin layer (< 2K Lines). Few dependencies.

- Easy to build, only a C compiler is required. Unlike OpenSSL (require perl + autoconf + automake + many more).

## Roadmap

- [x] Run Mbed-TLS demo.
- [x] Use Mbed-TLS BIO (I/O abstraction).
- [x] Try to figure out if Mbed-TLS is easy to strip.
- [x] Build Mbed-TLS with AddressSanitizer.
- [x] Build Rust executable with AddressSanitizer.
- [x] Rust binding prototype worked.
- [x] Fully control the build progress, use only gcc / ar command.
- [x] Fix LeakSanitizer.
- [x] Compile with the Rust cc crate.
- [x] Bind to Rust.
- [x] Bind to Rust with async.
- [ ] Miri, Loom, ThreadSanitizer and more.
- [x] Set ALPN to use HTTP 2.
- [x] Client mode.
- [x] Implement Client mode cert vetify.
- [ ] Test client mode cert vetify works.
- [x] Client with Hyper 0.14.
- [ ] Client with Hyper 1.0 rc.
- [x] Deploy on Tokio current-thread runtime.
- [x] Fix crach on Tokio multi-thread runtime.
- [x] Bench OpenSSL and Mbed-TLS.
- [x] Strip more.
- [ ] Test if works in Windows.
- [ ] TLS 1.3.
- [ ] ~~Use mbedtls_ssl_cache_context to speed up.~~
- [x] Use context pool to improve performance.
- [x] Improve multi-thread performance.
- [x] Bench and compare with OpenSSL / Rustls.
- [ ] Better error code to name convert.
- [x] CI by GitHub Actions.
- [ ] Handle underlying io errors.
- [ ] Port init script to build.rs.
- [ ] ~~Kernel TLS offload~~.
- [x] Deploy on ksite.
- [ ] Publish & Announce.

## Build

<!-- To reduce the repo size, we use fetched -->

## Thanks

- https://github.com/Mbed-TLS/mbedtls

- https://github.com/tokio-rs/tokio-openssl

- https://github.com/fortanix/rust-mbedtls

- https://curl.se/docs/ssl-compared.html

<!--

tlsimple (174 deps)  =  5783792 Aug 17 19:52 ksite
rustls (183 deps)    =  6479280 Aug 17 20:10 ksite

./bombardier -a -d 4s -c 96 https://127.0.0.1:9304/

https://frippery.org/files/busybox/busybox-w32-FRP-5181-g5c1a3b00e.exe

https://github.com/rmyorston/busybox-w32

https://github.com/monoio-rs/monoio-tls

https://github.com/Mbed-TLS/mbedtls/pull/5969

https://openwrt.org/releases/23.05/notes-23.05.0-rc2#switch_from_wolfssl_to_mbedtls_as_default

https://dev.mysql.com/blog-archive/mysql-is-openssl-only-now/

https://curl.se/docs/ssl-compared.html

https://wiki.mozilla.org/Security/Server_Side_TLS

https://github.com/rust-lang/cc-rs/issues/242

https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html

https://doc.rust-lang.org/cargo/reference/manifest.html#the-exclude-and-include-fields

https://mbed-tls.readthedocs.io/projects/api/en/development/api/file/net__sockets_8h/#net__sockets_8h_1a4841afd0e14f1fd44b82c3a850961ab7

https://github.com/Mbed-TLS/mbedtls/tree/development/programs/ssl

https://github.com/Mbed-TLS/mbedtls/blob/963513dba56991e2c741290841e2f33b9398ea52/programs/ssl/ssl_server2.c#L2855

https://github.com/Mbed-TLS/mbedtls/blob/development/programs/ssl/mini_client.c

https://github.com/sfackler/hyper-openssl/blob/master/src/lib.rs

https://mbed-tls.readthedocs.io/projects/api/en/development/api/file/x509__crt_8h/#:~:text=int%20mbedtls_x509_crt_verify(mbedtls_x509_crt

https://github.com/travis-ci/travis-ci/issues/4704#issuecomment-348435959

-->
