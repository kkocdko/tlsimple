#!/bin/sh

cd $(dirname $(realpath $0))
mkdir -p target

if [ "$1" = "init-wolfssl" ]; then
  cd target
  if [ ! -e wolfssl.tar.gz ]; then
    curl -o wolfssl.tar.gz -L https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.6.3-stable.tar.gz
    # curl -o wolfssl.tar.gz -L https://github.com/wolfSSL/wolfssl/archive/refs/heads/master.tar.gz
  fi
  rm -rf wolfssl
  mkdir wolfssl
  tar -xf wolfssl.tar.gz --strip-components 1 -C wolfssl
  cd wolfssl
  rm -rf build
  ./autogen.sh
  ./configure --disable-oldtls --disable-tlsv12 --enable-tls13 --disable-examples --disable-oldnames --disable-crypttests --disable-md5 --disable-aescbc --enable-alpn --disable-base64encode --disable-filesystem --disable-shared
  make -j`nproc`
  ls -lh src/.libs/libwolfssl.a
  # --disable-errorstrings
  # https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#build-options
  # sudo dnf install autoconf automake libtool
fi

if [ "$1" = "run-wolfssl" ]; then
  ~/misc/apps/mold -run g++ src/main.cc -o target/main -I target/wolfssl -L target/wolfssl/src/.libs -lwolfssl -Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer
  target/main
fi

if [ "$1" = "init-openssl" ]; then
  cd target
  if [ ! -e openssl.tar.gz ]; then
    # curl -o openssl.tar.gz -L https://github.com/openssl/openssl/releases/download/openssl-3.1.1/openssl-3.1.1.tar.gz
    curl -o openssl.tar.gz -L https://github.com/openssl/openssl/archive/0c85bcbaeabe3a695831bec44ab87964725a51a6.tar.gz
  fi
  rm -rf openssl
  mkdir openssl
  tar -xf openssl.tar.gz --strip-components 1 -C openssl
  cd openssl
  # rm -rf test doc demos CHANGES.md
  perl Configure \
    no-deprecated no-legacy \
    no-filenames no-autoerrinit no-autoload-config \
    no-egd no-pic no-dso no-tests no-quic no-apps no-docs no-cmp no-comp no-cms no-ct no-dgram no-http no-module no-ocsp no-ts no-srp no-srtp no-ssl-trace no-engine no-threads no-thread-pool \
    no-dtls \
    no-aria no-bf no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dh no-dsa no-ecdh no-ecdsa no-idea no-md2 no-md4 no-mdc2 no-ocb no-poly1305 no-rc2 no-rc4 no-rc5 no-rmd160 no-scrypt no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool \
    no-shared no-asm
    # no-asm no-async no-err no-weak-ssl-ciphers
  
  # no-ssl no-ssl3 no-tls no-tls1 no-tls1_1 no-tls1_2 no-dtls no-dtls1 no-dtls1_2 \
  # no-ssl3-method no-tls1-method no-tls1_1-method no-tls1_2-method no-dtls1-method no-dtls1_2-method \
  # no-filenames
  # no-{aria|bf|blake2|camellia|cast|chacha|cmac|des|dh|dsa|ecdh|ecdsa|idea|md4|mdc2|ocb|poly1305|rc2|rc4|rmd160|scrypt|seed|siphash|siv|sm2|sm3|sm4|whirlpool}
  # dnf install perl
  # [...new Set(a.split(' ').sort())].join(' ')
  make -j`nproc`
  ls -l libcrypto.a libssl.a
  # https://github.com/openssl/openssl/blob/master/INSTALL.md
fi

if [ "$1" = "run-openssl" ]; then
  # ~/misc/apps/mold -run g++ src/main.cc -o target/main -I target/wolfssl -L target/wolfssl/src/.libs -lwolfssl -Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer
  # -g -fsanitize=address,undefined -fno-omit-frame-pointer
  ~/misc/apps/mold -run g++ src/main.cc -o target/main -I target/openssl/include -L target/openssl -lssl -lcrypto -Wall -Wextra -Wl,--gc-sections
  strip --strip-all target/main
  ls -l target/main
  target/main $2 $3
fi

MBEDTLS_CFLAGS='-Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer'
# MBEDTLS_CFLAGS='-Os -flto'

if [ "$1" = "mbedtls" ]; then
  if [ "$2" = "init" ]; then
    cd target
    if [ ! -e mbedtls.tar.gz ]; then
      curl -o mbedtls.tar.gz -L https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.0.tar.gz
      # curl -o mbedtls.tar.gz -L https://github.com/Mbed-TLS/mbedtls/archive/refs/heads/development.tar.gz
    fi
    rm -rf mbedtls
    mkdir mbedtls
    tar_prefix=`tar -tf mbedtls.tar.gz | head -n1 | sed -e 's/\///g'`
    tar --strip-components 1 -xf mbedtls.tar.gz -C mbedtls $tar_prefix/include $tar_prefix/library
    cd mbedtls
    # tar -cJf ../mbedtls.tar.xz -C .. mbedtls
    # ~/misc/apps/dua

    cd library
    list=`find -name '*.c' | grep -Ev 'base64|aria|camellia|ccm|chacha|poly1305|lmots|lms|des|dhm|ecjpake|cmac|threading|hkdf|md5|net_sockets|mps_|psa_|ssl_tls13_'`
    echo $list
    for n in $list; do
      gcc -c $n -I../include -DMBEDTLS_CONFIG_FILE='<../../../src/mbedtls_config_custom.h>' -fPIE $MBEDTLS_CFLAGS &
    done
    wait
    ar r libmbedtlsmono.a *.o
    find -name '*.o' -delete
    # https://stackoverflow.com/q/3821916
  fi
  if [ "$2" = "run" ]; then
    ~/misc/apps/mold -run g++ src/main.cc -o target/main -I target/mbedtls/include -L target/mbedtls/library -lmbedtlsmono $MBEDTLS_CFLAGS
    strip --strip-all target/main
    ls -l target/main
    target/main
  fi
fi

if [ "$1" = "run-rust" ]; then
  export RUST_BACKTRACE=1
  export RUSTFLAGS=-Zsanitizer=address
  ~/misc/apps/mold -run cargo run
  # cargo run
  # https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html
fi

# curl https://127.0.0.1:11111/
