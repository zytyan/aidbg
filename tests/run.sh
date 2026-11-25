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

flags=(-Wall -Wextra -Werror -g -O0 -fno-omit-frame-pointer -pthread)
"${CC:-gcc}" "${flags[@]}" -gdwarf-4 tests/session_fixture.c -ldl -o "$fixtures/gcc-fixture"
"${CC:-gcc}" -Wall -Wextra -Werror -pthread -gdwarf-4 -O1 -fomit-frame-pointer \
  -fasynchronous-unwind-tables -rdynamic tests/session_fixture.c -ldl -o "$fixtures/stripped-fixture"
objcopy --only-keep-debug "$fixtures/stripped-fixture" "$fixtures/manual.debug"
strip --strip-all "$fixtures/stripped-fixture"
"${CC:-gcc}" -O0 -fno-pic -c tests/session_link.c -o "$fixtures/link.o"
"${CC:-gcc}" -O0 -g -shared -fPIC tests/session_link.c -o "$fixtures/session-test.so"
targets=("$fixtures/gcc-fixture")
make -C tests/debug-cases OUT="$fixtures/cases" "$fixtures/cases"/{D02,D04,D05,D06,D08,D09,D10}
if command -v clang >/dev/null; then
  clang "${flags[@]}" -gdwarf-5 tests/session_fixture.c -ldl -o "$fixtures/clang-fixture"
  targets+=("$fixtures/clang-fixture")
fi
python3 tests/session.py "$binaries/aidbg" "$binaries/aidbg-server" \
  "${targets[@]}" --object "$fixtures/link.o" --cases "$fixtures/cases" --library "$fixtures/session-test.so" \
  --stripped "$fixtures/stripped-fixture" --debug-image "$fixtures/manual.debug" "$@"
