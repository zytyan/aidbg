#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

profile=${AIDBG_TEST_PROFILE:-debug}
if [[ $profile == release ]]; then
  cargo build --locked --release --bins
else
  cargo build --locked --bins
fi
binaries="${CARGO_TARGET_DIR:-target}/${CARGO_BUILD_TARGET:+$CARGO_BUILD_TARGET/}$profile"
fixtures=$(mktemp -d)
trap 'rm -rf -- "$fixtures"' EXIT

flags=(-Wall -Wextra -Werror -g -O0 -fno-omit-frame-pointer)
"${CC:-gcc}" "${flags[@]}" -gdwarf-4 tests/session_fixture.c -o "$fixtures/gcc-fixture"
"${CC:-gcc}" -O0 -fno-pic -c tests/session_link.c -o "$fixtures/link.o"
targets=("$fixtures/gcc-fixture")
if command -v clang >/dev/null; then
  clang "${flags[@]}" -gdwarf-5 tests/session_fixture.c -o "$fixtures/clang-fixture"
  targets+=("$fixtures/clang-fixture")
fi
python3 tests/session.py "$binaries/aidbg" "$binaries/aidbg-server" \
  "${targets[@]}" --object "$fixtures/link.o" "$@"
