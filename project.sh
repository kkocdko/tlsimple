#!/bin/sh

# https://frippery.org/files/busybox/busybox-w32-FRP-5181-g5c1a3b00e.exe
# https://github.com/rmyorston/busybox-w32

cd $(dirname $(realpath $0))

if [ "$1" = "init" ]; then
  mkdir -p 3rdparty/mbedtls
  cd 3rdparty
  if [ ! -e mbedtls.tar.gz ]; then
    curl -o mbedtls.tar.gz -L https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz # https://github.com/Mbed-TLS/mbedtls/archive/refs/heads/development.tar.gz
  fi
  tar_prefix=`tar -tf mbedtls.tar.gz | head -n1 | sed -e 's/\///g'`
  tar --strip-components 1 -xf mbedtls.tar.gz -C mbedtls $tar_prefix/include $tar_prefix/library
fi

if [ "$1" = "run-cpp" ]; then
  mkdir -p target
  cd target
  ccflags='-Wall -Wextra -g -fno-omit-frame-pointer -fsanitize=address,undefined'
  # ccflags='-flto=auto -Os'
  # rm libmbedtlsmono.a
  if [ ! -e libmbedtlsmono.a ]; then
    for n in `find ../3rdparty/mbedtls/library -name '*.c' | grep -Ev 'net_sockets|mps_|psa_'`; do
      gcc -c $n -I../3rdparty/mbedtls/include -I../src -DMBEDTLS_CONFIG_FILE='<mbedtls_config_custom.h>' -fPIE $ccflags &
    done
    wait
    ar r libmbedtlsmono.a *.o
    rm -rf *.o
  fi
  ~/misc/apps/mold -run \
  g++ ../examples/main.cc -o main -I../3rdparty/mbedtls/include -L. -lmbedtlsmono $ccflags
  # strip --strip-all main
  ls -l main
  ./main
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
