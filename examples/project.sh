#!/bin/sh

cd $(dirname $(realpath $0)) ; cd ..

if [ "$1" = "run-cpp" ]; then
  mkdir -p target
  cd target
  ccflags='-Wall -Wextra -g -fno-omit-frame-pointer -fsanitize=address,undefined'
  # ccflags='-flto=auto -Os'
  # rm libmbedtlsmono.a
  if [ ! -e libmbedtlsmono.a ]; then
    for n in $(find ../3rdparty/mbedtls/library -name '*.c' | grep -Ev 'net_sockets|mps_|psa_'); do
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
  export RUSTFLAGS=-Zsanitizer=address # -Zsanitizer=leak # https://doc.rust-lang.org/stable/unstable-book/compiler-flags/sanitizer.html
  op="$2"
  [ "$op" = "" ] && op=run
  ~/misc/apps/mold -run \
  cargo $op --example demo --target=x86_64-unknown-linux-gnu
fi

if [ "$1" = "run-rust-bench" ]; then
  ~/misc/apps/mold -run \
  cargo build --example demo --target=x86_64-unknown-linux-gnu --release
  exe_path=target/x86_64-unknown-linux-gnu/release/examples/demo
  # $exe_path
  rm -rf perf.data && perf record -g $exe_path
  # perf report
  # curl -vvvk --tlsv1.3 https://127.0.0.1:11111
  # ./bombardier --disableKeepAlives --connections=64 https://127.0.0.1:9304/
fi
