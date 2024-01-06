#!/bin/sh

cd $(dirname $0)

if [ "$1" = "init" ]; then
  rm -rf 3rdparty
  mkdir -p 3rdparty
  cd 3rdparty
  curl -o mbedtls.tar.gz -L https://github.com/Mbed-TLS/mbedtls/archive/a021d63bf7f5b33fc2e4b567a8db99de049318f2.tar.gz # current commit. stable is https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.5.1.tar.gz
  rm -rf mbedtls
  mkdir mbedtls
  tar_prefix="$(tar "--exclude=*/*/*" -tf mbedtls.tar.gz | head -n1 | cut -d "/" -f 1)"
  tar -xf mbedtls.tar.gz --strip-components 1 -C mbedtls $tar_prefix/include $tar_prefix/library $tar_prefix/scripts
  cd mbedtls
  python -m venv venv
  source venv/bin/activate
  unset all_proxy ALL_PROXY # pip have not socks support by default, unset these to use transparent proxy instead
  pip install jinja2==3.1.2 jsonschema==4.20.0
  mkdir programs tests # to fit the detection in ./scripts/mbedtls_dev/build_tree.py
  ./scripts/generate_ssl_debug_helpers.py
  ./scripts/generate_driver_wrappers.py
  deactivate
  rm -rf venv
  du -sh *
  exit
fi

if [ "$1" = "run-cpp" ]; then
  mkdir -p target
  cd target
  ccflags='-Wall -Wextra -g -fno-omit-frame-pointer -fsanitize=address,undefined'
  # ccflags='-flto=auto -Os'
  rm -f libmbedtlsmono.a
  if [ ! -e libmbedtlsmono.a ]; then
    # for n in $(find ../3rdparty/mbedtls/library -name '*.c' | grep -Ev 'net_sockets|mps_|psa_'); do
    for n in $(find ../3rdparty/mbedtls/library -name '*.c'); do
      gcc -c $n -I../3rdparty/mbedtls/include -I../src -DMBEDTLS_CONFIG_FILE='<mbedtls_config_custom.h>' -fPIE $ccflags &
    done
    wait
    ar r libmbedtlsmono.a *.o
    rm -rf *.o
  fi
  mold -run \
  g++ ../examples/main.cc -o main -I../3rdparty/mbedtls/include -L. -lmbedtlsmono $ccflags
  # strip --strip-all main
  ls -l main
  ./main
fi

if [ "$1" = "run-rust" ]; then
  export RUST_BACKTRACE="full"
  export RUSTC_BOOTSTRAP="1"
  export RUSTFLAGS=-Zsanitizer=address # -Zsanitizer=leak # https://doc.rust-lang.org/stable/unstable-book/compiler-flags/sanitizer.html
  mold -run \
  cargo run --example demo --target=x86_64-unknown-linux-gnu
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
