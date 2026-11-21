#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts

case ${1:-} in
  --pi)
    if (( $# > 2 )); then
      echo "Usage: $0 [--pi [ssh-host]]" >&2
      exit 2
    fi
    ssh_host=${2:-pi}
    rust_target=aarch64-unknown-linux-musl
    cc=aarch64-linux-gnu-gcc
    cxx=aarch64-linux-gnu-g++
    objcopy=aarch64-linux-gnu-objcopy
    for tool in zig "$cc" "$cxx" "$objcopy"; do
      if ! command -v "$tool" >/dev/null; then
        echo "Missing local cross-build tool: $tool" >&2
        exit 1
      fi
    done
    run_dir=$(mktemp -d "$PWD/artifacts/pi.XXXXXXXX")
    out="$run_dir/artifacts"
    mkdir -p "$out" "$run_dir/tests"
    cargo build --locked --release --bins --target "$rust_target"
    release_dir="${CARGO_TARGET_DIR:-target}/$rust_target/release"
    ;;
  '')
    out=artifacts
    cc=cc
    cxx=c++
    objcopy=objcopy
    cargo build --locked --release --bins
    release_dir="${CARGO_TARGET_DIR:-target}/${CARGO_BUILD_TARGET:+$CARGO_BUILD_TARGET/}release"
    ;;
  *)
    echo "Usage: $0 [--pi [ssh-host]]" >&2
    exit 2
    ;;
esac

cp "$release_dir/"{aidbg,aidbg-server} "$out/"
for bin in "$out/"{aidbg,aidbg-server}; do
  needed=$(readelf -dW "$bin" | awk '/\(NEEDED\)/ {print $NF}')
  if [[ ${1:-} == --pi || ${CARGO_BUILD_TARGET:-} == *-linux-musl ]]; then
    if [[ -n $needed ]] || readelf -lW "$bin" | grep 'INTERP' >/dev/null; then
      echo "Expected a fully static ELF: $bin" >&2
      exit 1
    fi
  elif [[ -n $needed ]] && grep -Ev '^\[(libc\.so\.6|libm\.so\.6|libgcc_s\.so\.1|libpthread\.so\.0|libdl\.so\.2|librt\.so\.1|ld-linux-[a-zA-Z0-9_.-]+\.so\.[0-9]+)\]$' <<<"$needed"; then
    echo "Unexpected dynamic dependencies: $bin" >&2
    exit 1
  fi
done
fixture_flags=(-Wall -Wextra -Werror -O2 -g)
unwind_flags=(-fomit-frame-pointer -fno-optimize-sibling-calls)
"$cc" "${fixture_flags[@]}" "${unwind_flags[@]}" \
  -fPIC -shared tests/shared.c -o "$out/libfixture.so"
"$cc" "${fixture_flags[@]}" -fPIC -shared tests/step_watch_fixture.c -o "$out/libstep_watch.so"
"$cc" "${fixture_flags[@]}" -g0 -fomit-frame-pointer -fno-unwind-tables \
  -fno-asynchronous-unwind-tables -nostartfiles -fPIC -shared tests/unwind_gap.c \
  -o "$out/libunwind_gap.so"
"$cc" "${fixture_flags[@]}" -g0 -DKEEP_FRAME_POINTER -fno-omit-frame-pointer \
  -mno-omit-leaf-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -nostartfiles -fPIC -shared tests/unwind_gap.c -Wl,--build-id=none -o "$out/libunwind_fp.so"
"$cc" "${fixture_flags[@]}" "${unwind_flags[@]}" \
  -fPIE -pie tests/fixture.c -pthread -L"$out" -lfixture \
  '-Wl,-rpath,$ORIGIN' -o "$out/fixture"
"$cc" -Wall -Wextra -Werror -O0 -g -DBUILD_DSO -fPIC -shared tests/coredump_fixture.c \
  -o "$out/libcoredump_fixture.so"
"$cc" -Wall -Wextra -Werror -O0 -g -fPIC -pie tests/coredump_fixture.c \
  -pthread -L"$out" -lcoredump_fixture '-Wl,-rpath,$ORIGIN' -o "$out/coredump_fixture"
"$cc" "${fixture_flags[@]}" -fPIE -pie tests/breakpoint_fixture.c -pthread -ldl \
  -o "$out/breakpoint_fixture"
"$cc" "${fixture_flags[@]}" -fno-pie -no-pie tests/breakpoint_fixture.c -pthread -ldl \
  -o "$out/breakpoint_fixture_nopie"
"$cxx" "${fixture_flags[@]}" -fPIC -shared tests/cpp_symbols.cc -o "$out/libcppsymbols.so"
"$cxx" "${fixture_flags[@]}" -fPIC -shared tests/target_call_fixture.cc -o "$out/libtarget_call.so"
"$cxx" -Wall -Wextra -Werror -O0 -gdwarf-4 -fPIC -shared tests/variables.cc -o "$out/libvariables-gcc-o0.so"
"$cxx" -Wall -Wextra -Werror -O2 -gdwarf-5 -fPIC -shared tests/variables.cc -o "$out/libvariables-gcc-o2.so"
if command -v clang++ >/dev/null; then
  clang_target=()
  if [[ ${1:-} == --pi ]]; then
    clang_target=(--target=aarch64-linux-gnu --gcc-toolchain=/usr)
  fi
  clang++ "${clang_target[@]}" -Wall -Wextra -Werror -O0 -gdwarf-5 -fPIC -shared \
    tests/variables.cc -o "$out/libvariables-clang-o0.so"
  clang++ "${clang_target[@]}" -Wall -Wextra -Werror -O2 -gdwarf-4 -fPIC -shared \
    tests/variables.cc -o "$out/libvariables-clang-o2.so"
fi
cp "$out/libfixture.so" "$out/libstripped.so"
"$objcopy" --only-keep-debug "$out/libstripped.so" "$out/libstripped.so.debug"
"$objcopy" --strip-all "--add-gnu-debuglink=$out/libstripped.so.debug" "$out/libstripped.so"

if [[ ${1:-} != --pi ]]; then
  python3 tests/run.py
  python3 tests/breakpoints.py
  python3 tests/advanced.py
  if command -v zstd >/dev/null; then
    python3 tests/coredump.py
  else
    echo 'SKIP coredump integration test (zstd unavailable)'
  fi
  exit
fi

cp tests/{run,breakpoints,advanced,coredump}.py "$run_dir/tests/"
echo "Pi integration log: $run_dir/integration.log"
tar -C "$run_dir" -czf - artifacts tests | ssh -T -o BatchMode=yes -- "$ssh_host" '
  set -eu
  if [ "$(uname -sm)" != "Linux aarch64" ]; then
    echo "Expected Linux aarch64, got $(uname -sm)" >&2
    exit 1
  fi
  work=$(mktemp -d /tmp/aidbg-pi.XXXXXXXX)
  trap '\''rm -rf -- "$work"'\'' EXIT
  trap '\''exit 1'\'' HUP INT TERM
  cd "$work"
  tar -xzf -
  if [ -r /proc/device-tree/model ]; then
    tr -d "\000" </proc/device-tree/model
    printf "\n"
  fi
  uname -smr
  if [ -r /etc/os-release ]; then
    ( . /etc/os-release; printf "%s\n" "$PRETTY_NAME" )
  fi
  python3 -u tests/run.py
  python3 -u tests/breakpoints.py
  python3 -u tests/advanced.py
  if command -v zstd >/dev/null; then
    python3 -u tests/coredump.py
  else
    echo "SKIP coredump integration test (zstd unavailable)"
  fi
' 2>&1 | tee "$run_dir/integration.log"
