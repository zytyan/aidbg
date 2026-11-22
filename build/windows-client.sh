#!/usr/bin/env sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"
if ! command -v x86_64-w64-mingw32-gcc >/dev/null &&
    command -v x86_64-w64-mingw32-gcc-posix >/dev/null; then
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc-posix
fi
exec cargo build --locked --release --target x86_64-pc-windows-gnu --bin aidbg "$@"
