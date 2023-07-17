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
  # cmake -B build -G Ninja -D CMAKE_BUILD_TYPE=MinSizeRel
  # cmake -B build -G Ninja -D WOLFSSL_OLD_TLS=no -D WOLFSSL_BASE64_ENCODE=no -D WOLFSSL_MD5=no -D WOLFSSL_EXAMPLES=no -D WOLFSSL_DTLS=no -D WOLFSSL_ECC=no -D CMAKE_BUILD_TYPE=MinSizeRel
  # cmake --build build
  # ls -lh /home/kkocdko/misc/code/wolfssl-util/target/wolfssl/build/libwolfssl.so.35.5.1
  ./autogen.sh
  # --disable-filesystem
  ./configure --disable-oldtls --disable-tlsv12 --enable-tls13 --disable-examples --disable-md5 --disable-aescbc --disable-sp --enable-alpn --disable-base64encode --disable-filesystem --disable-shared
  make -j`nproc`
  ls -lh src/.libs/libwolfssl.a
  # ls -lh /home/kkocdko/misc/code/wolfssl-util/target/wolfssl/src/.libs/libwolfssl.so.35.5.1
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
    curl -o openssl.tar.gz -L https://github.com/openssl/openssl/releases/download/openssl-3.1.1/openssl-3.1.1.tar.gz
  fi
  rm -rf openssl
  mkdir openssl
  tar -xf openssl.tar.gz --strip-components 1 -C openssl
  cd openssl
  rm -rf test doc demos CHANGES.md
fi

if [ "$1" = "run-openssl" ]; then
  ~/misc/apps/mold -run g++ src/main.cc -o target/main -I target/wolfssl -L target/wolfssl/src/.libs -lwolfssl -Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer
  target/main
fi

# curl https://127.0.0.1:11111/
