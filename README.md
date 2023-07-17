# tlsimple

Some kkocdko's crazy ideas about TLS & HTTPS supports in async Rust.

## Goals

- TlsStream (tokio).

- HttpsConnector (hyper).

- Single crate, less dependencies.

wolfssl / openssl backend

https://openwrt.org/releases/23.05/notes-23.05.0-rc2#switch_from_wolfssl_to_mbedtls_as_default

https://dev.mysql.com/blog-archive/mysql-is-openssl-only-now/

https://curl.se/docs/ssl-compared.html

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
