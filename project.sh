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
    curl -o openssl.tar.gz -L https://github.com/openssl/openssl/archive/refs/heads/master.tar.gz
  fi
  rm -rf openssl
  mkdir openssl
  tar -xf openssl.tar.gz --strip-components 1 -C openssl
  cd openssl
  # rm -rf test doc demos CHANGES.md
  perl Configure no-deprecated no-comp no-legacy no-shared no-tests no-quic no-apps no-docs no-dgram
  # perl Configure no-deprecated no-comp no-legacy no-shared no-tests no-quic no-ssl no-tls no-dtls no-docs no-apps no-srtp no-srp no-dgram no-sctp \
  #   no-aria no-bf no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dh no-dsa no-ecdh no-ecdsa no-idea no-md4 no-mdc2 no-ocb no-poly1305 no-rc2 no-rc4 no-rmd160 no-scrypt no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool
  # dnf install perl
  make -j`nproc`
  ls -l libcrypto.a libssl.a
  # https://github.com/openssl/openssl/blob/master/INSTALL.md
fi

if [ "$1" = "run-openssl" ]; then
  # ~/misc/apps/mold -run g++ src/main.cc -o target/main -I target/wolfssl -L target/wolfssl/src/.libs -lwolfssl -Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer
  ~/misc/apps/mold -run g++ src/main.cc -o target/main -I target/openssl/include -L target/openssl -lssl -lcrypto -Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer
  target/main $2 $3
fi

# curl https://127.0.0.1:11111/
