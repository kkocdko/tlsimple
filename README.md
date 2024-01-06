# tlsimple

TLS for async Rust, with [Mbed-TLS](https://github.com/Mbed-TLS/mbedtls).

## Features

- Out of the box. Only a C compiler is required (unlike OpenSSL which needs perl + autoconf + automake + many more).

- Async and blocking support, server and client mode. Also provide `HttpsConnector` for Hyper (0.14) client.

- Lightweight. As a thin layer (< 2K Lines) with few dependencies. Binary size about 700 KiB smaller than rustls, 2 MiB smaller than rust-openssl.

## Performance

WIP

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
- [x] Client with Hyper 1.0.
- [x] Deploy on Tokio current-thread runtime.
- [x] Fix crach on Tokio multi-thread runtime.
- [x] Bench OpenSSL and Mbed-TLS.
- [x] Strip more.
- [x] Test if works in Windows.
- [x] TLS 1.3 in C.
- [x] TLS 1.3 in Rust.
- [ ] ~~Use mbedtls_ssl_cache_context to speed up.~~
- [x] Use context pool to improve performance.
- [x] Improve multi-thread performance.
- [x] Bench and compare with OpenSSL / Rustls.
- [ ] Better error code to name convert.
- [x] CI by GitHub Actions.
- [x] Handle underlying io errors.
- [ ] More about close notify?
- [x] Port init script to build.rs.
- [ ] ~~Kernel TLS offload~~.
- [x] Deploy on ksite.
- [ ] Publish & Announce.

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

<details>
<summary>简体中文</summary>

> tlsimple

为 Rust 提供轻巧的 TLS 支持，基于 [Mbed-TLS](https://github.com/Mbed-TLS/mbedtls)。

## 特性

- 支持异步与同步，服务端与客户端模式。同时为 Hyper 客户端提供 `HttpsConnector`。

> 翻译仍在进行中...

</details>
