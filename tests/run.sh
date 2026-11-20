#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts
cargo build --locked --release --bins
cp "${CARGO_TARGET_DIR:-target}/release/"{aidbg,aidbg-server} artifacts/
cc -Wall -Wextra -Werror -O2 -g -fomit-frame-pointer -fno-optimize-sibling-calls \
  -fPIC -shared tests/shared.c -o artifacts/libfixture.so
cc -Wall -Wextra -Werror -O2 -g -fomit-frame-pointer -fno-optimize-sibling-calls \
  -fPIE -pie tests/fixture.c -pthread -Lartifacts -lfixture \
  '-Wl,-rpath,$ORIGIN' -o artifacts/fixture
python3 tests/run.py
