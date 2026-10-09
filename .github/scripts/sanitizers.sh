#!/usr/bin/env bash
set -euo pipefail

# Build in a fresh directory so cached, uninstrumented objects cannot be reused.
cd "$(dirname "$0")/../.."
root="$PWD"
mkdir -p tmp
build="$(mktemp -d "$root/tmp/sanitizers.XXXXXX")"
export CC=gcc
export CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all'
export LDFLAGS='-fsanitize=address,undefined'
export ASAN_OPTIONS='detect_leaks=0:halt_on_error=1'
export UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'

# Ruby itself is not instrumented. Preload GCC's matching ASan runtime when
# executing Ruby tests; leak checking remains the separate Valgrind job's job.
asan="$(gcc -print-file-name=libasan.so)"
test -f "$asan"
echo "Sanitizer build: $build"
cd "$build"
bundle exec ruby "$root/ext/rbsecp256k1/extconf.rb" --with-cflags="$CFLAGS" --with-ldflags="$LDFLAGS"
make -j2
mkdir -p rbsecp256k1
cp rbsecp256k1.so rbsecp256k1/
cd "$root"
LD_PRELOAD="$asan" bundle exec ruby -I "$build" -I "$root/lib" -S rspec \
  --seed "${SANITIZER_SEED:-10010}"
