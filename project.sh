#!/bin/sh

if [ "$1" = "init" ]; then
  mkdir -p 3rdparty
  cd 3rdparty
  if [ ! -e mbedtls.tar.gz ]; then
    curl -o mbedtls.tar.gz -L https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz
    # curl -o mbedtls.tar.gz -L https://github.com/Mbed-TLS/mbedtls/archive/refs/heads/development.tar.gz
  fi
  rm -rf mbedtls
  mkdir mbedtls
  tar_prefix=`tar -tf mbedtls.tar.gz | head -n1 | sed -e 's/\///g'`
  tar --strip-components 1 -xf mbedtls.tar.gz -C mbedtls $tar_prefix/include $tar_prefix/library
fi

if [ "$1" = "run-rust" ]; then
  export RUST_BACKTRACE=1
  export RUSTC_BOOTSTRAP=1
  export RUSTFLAGS=-Zsanitizer=address
  # ~/misc/apps/mold -run \
  cargo run --target=x86_64-unknown-linux-gnu
  # cargo run
  # https://doc.rust-lang.org/stable/unstable-book/compiler-flags/sanitizer.html#build-scripts-and-procedural-macros
fi

exit

cd $(dirname $(realpath $0))
mkdir -p target

MBEDTLS_CFLAGS='-Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer'
# MBEDTLS_CFLAGS='-Os -flto'

if [ "$1" = "mbedtls" ]; then
  if [ "$2" = "init" ]; then
    mkdir -p 3rdparty
    cd 3rdparty
    if [ ! -e mbedtls.tar.gz ]; then
      curl -o mbedtls.tar.gz -L https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz
      # curl -o mbedtls.tar.gz -L https://github.com/Mbed-TLS/mbedtls/archive/refs/heads/development.tar.gz
    fi
    rm -rf mbedtls
    mkdir mbedtls
    tar_prefix=`tar -tf mbedtls.tar.gz | head -n1 | sed -e 's/\///g'`
    tar --strip-components 1 -xf mbedtls.tar.gz -C mbedtls $tar_prefix/include $tar_prefix/library
    exit
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


# curl https://127.0.0.1:11111/

exit
