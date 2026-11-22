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
    run_dir=$(mktemp -d "$PWD/artifacts/pi.XXXXXXXX")
    mkdir -p "$run_dir/artifacts"
    cargo build --locked --release --bins --target "$rust_target"
    release_dir="${CARGO_TARGET_DIR:-target}/$rust_target/release"
    cp "$release_dir/"{aidbg,aidbg-server} "$run_dir/artifacts/"
    cp -R tests "$run_dir/"
    ssh_config=()
    if [[ -f $HOME/.ssh/config ]]; then
      ssh_config=(-F "$HOME/.ssh/config")
    fi
    echo "Pi integration log: $run_dir/integration.log"
    tar -C "$run_dir" -czf - artifacts tests | ssh -T "${ssh_config[@]}" -o BatchMode=yes -- "$ssh_host" '
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
      bash tests/run.sh --pi-fixtures
    ' 2>&1 | tee "$run_dir/integration.log"
    exit
    ;;
  --pi-fixtures)
    # The Pi bundle contains the Rust binaries. Build the C/C++ fixtures here.
    ;;
  '')
    cargo build --locked --release --bins
    release_dir="${CARGO_TARGET_DIR:-target}/${CARGO_BUILD_TARGET:+$CARGO_BUILD_TARGET/}release"
    cp "$release_dir/"{aidbg,aidbg-server} artifacts/
    ;;
  *)
    echo "Usage: $0 [--pi [ssh-host]]" >&2
    exit 2
    ;;
esac

out=artifacts
cc=cc
cxx=c++
objcopy=objcopy
for bin in "$out/"{aidbg,aidbg-server}; do
  needed=$(readelf -dW "$bin" | awk '/\(NEEDED\)/ {print $NF}')
  if [[ ${1:-} == --pi-fixtures || ${CARGO_BUILD_TARGET:-} == *-linux-musl ]]; then
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
"$cc" -Wall -Wextra -Werror -O0 -g -pthread tests/run_target_fixture.c \
  -o "$out/run_target_fixture"
"$cxx" "${fixture_flags[@]}" -fPIC -shared tests/cpp_symbols.cc -o "$out/libcppsymbols.so"
"$cxx" "${fixture_flags[@]}" -fPIC -shared tests/target_call_fixture.cc -o "$out/libtarget_call.so"
"$cxx" -Wall -Wextra -Werror -O0 -gdwarf-4 -fPIC -shared tests/variables.cc -o "$out/libvariables-gcc-o0.so"
"$cxx" -Wall -Wextra -Werror -O2 -gdwarf-5 -fPIC -shared tests/variables.cc -o "$out/libvariables-gcc-o2.so"
if command -v clang++ >/dev/null; then
  clang++ -Wall -Wextra -Werror -O0 -gdwarf-5 -fPIC -shared \
    tests/variables.cc -o "$out/libvariables-clang-o0.so"
  clang++ -Wall -Wextra -Werror -O2 -gdwarf-4 -fPIC -shared \
    tests/variables.cc -o "$out/libvariables-clang-o2.so"
fi
cp "$out/libfixture.so" "$out/libstripped.so"
"$objcopy" --only-keep-debug "$out/libstripped.so" "$out/libstripped.so.debug"
"$objcopy" --strip-all "--add-gnu-debuglink=$out/libstripped.so.debug" "$out/libstripped.so"

case_out="$PWD/$out/breakpoint-cases"
make -C tests/debug-cases OUT="$case_out" "$case_out/D01" "$case_out/D02" "$case_out/D04" "$case_out/D06" "$case_out/D07" "$case_out/D08" "$case_out/D09" "$case_out/D10"

python3 -u tests/run.py
python3 -u tests/breakpoints.py
python3 -u tests/breakpoint_cases.py
python3 -u tests/run_target.py "$out/aidbg" "$out/aidbg-server" "$out/run_target_fixture"
python3 -u tests/advanced.py
if command -v zstd >/dev/null; then
  python3 -u tests/coredump.py
else
  echo 'SKIP coredump integration test (zstd unavailable)'
fi
