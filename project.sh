#!/bin/sh

cd $(dirname $(realpath $0))

if [ "$1" = "init" ]; then
  mkdir -p 3rdparty/mbedtls
  cd 3rdparty
  if [ ! -e mbedtls.tar.gz ]; then
    curl -o mbedtls.tar.gz -L https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz
    # https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz
    # https://github.com/Mbed-TLS/mbedtls/archive/refs/heads/development.tar.gz
    # https://github.com/Mbed-TLS/mbedtls/archive/41d689f389a51e078e4de0fba20391d9de5d83e6.tar.gz
  fi
  tar_prefix=`tar -tf mbedtls.tar.gz | head -n1 | sed -e 's/\///g'`
  tar --strip-components 1 -xf mbedtls.tar.gz -C mbedtls $tar_prefix/include $tar_prefix/library
  cd ..
  # cargo install bindgen-cli ; sudo dnf install clang-devel
  echo "#![allow(warnings)]" >src/ffi.rs
  bindgen src/mbedtls.h --default-macro-constant-type signed -- -I3rdparty/mbedtls/include >>src/ffi.rs
  echo "pub fn err_name(code:i32)->&'static str{match code{" >src/err.rs
  grep -rh '#define MBEDTLS_ERR_' 3rdparty/mbedtls/include | awk '{print $3"=>\""$2"\","}' >>src/err.rs
  echo '_=>"unknown"}}' >>src/err.rs
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
  # export RUSTFLAGS=-Zsanitizer=leak
  op=$2
  [ "$op" == "" ] && op=run
  ~/misc/apps/mold -run \
  cargo $op --example demo --target=x86_64-unknown-linux-gnu
fi

if [ "$1" = "run-rust-bench" ]; then
  export RUST_BACKTRACE=1
  export RUSTC_BOOTSTRAP=1
  ~/misc/apps/mold -run \
  cargo build --example demo --target=x86_64-unknown-linux-gnu --release
  exe_path=target/x86_64-unknown-linux-gnu/release/examples/demo
  # $exe_path
  rm -rf perf.data && perf record -g $exe_path
  # perf report
  # https://doc.rust-lang.org/stable/unstable-book/compiler-flags/sanitizer.html#build-scripts-and-procedural-macros
  # curl -vvvk --tlsv1.3 https://127.0.0.1:11111
  # ./bombardier --disableKeepAlives --connections=64 https://127.0.0.1:9304/
fi
