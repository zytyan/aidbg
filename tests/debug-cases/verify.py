#!/usr/bin/env python3
"""Check that the debugging exercises still reproduce their stated symptoms."""

import argparse
import ctypes
import mmap
import platform
import os
from pathlib import Path
import resource
import select
import shutil
import signal
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent


def run(*args, cwd, env=None):
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=30)


def require_success(*args, cwd):
    result = run(*args, cwd=cwd)
    if result.returncode:
        raise RuntimeError(f"{args} failed:\n{result.stdout}{result.stderr}")
    return result.stdout


def expect(actual, expected):
    if actual != expected:
        raise AssertionError(f"expected {expected!r}, got {actual!r}")


def check_runtime(work, output):

    crash = run(output / "D01", cwd=work)
    expect(crash.returncode, -signal.SIGSEGV)
    expect(crash.stdout, "account=7 quota=64\n")

    try:
        subprocess.run([output / "D04"], cwd=work, capture_output=True, timeout=2)
    except subprocess.TimeoutExpired as stalled:
        expect(sorted((stalled.stdout or b"").splitlines()),
               [b"reconcile started", b"refresh started"])
    else:
        raise AssertionError("D04 exited before the timeout")

    expected = {
        "D02": "10 20 30 10\n",
        "D03": "total=10\n",
        "D05": "bytes=70000 blocks=2\n",
        "D06": "before=5\nafter=2\n",
        "D07": "10\n",
        "D08": "samples=0,0,0,0 markers=0,202\n",
        "D09": "fetch=0\nparse=1\nsave=0\n",
        "D10": "south south\n",
    }
    for case, stdout in expected.items():
        expect(require_success(output / case, cwd=work), stdout)

    session = subprocess.run(
        [output / "D02"], cwd=work, input="\n", text=True, capture_output=True,
        timeout=5, check=True, env={**os.environ, "AIDBG_WAIT": "1"},
    )
    banner, stdout = session.stdout.split("\n", 1)
    expect(banner.startswith("pid=") and banner.endswith("; press Enter to start"), True)
    expect(stdout, expected["D02"])
    for release in ("signal:SIGUSR1", f"file:{work / 'release'}"):
        with subprocess.Popen(
            [output / "D02"], cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env={**os.environ, "AIDBG_WAIT_RELEASE": release},
        ) as target:
            try:
                ready, _, _ = select.select([target.stdout], [], [], 5)
                if not ready:
                    raise AssertionError(f"D02 did not block at {release}")
                banner = target.stdout.readline()
                expect(banner.startswith(f"pid={target.pid}; waiting for "), True)
                expect(target.poll(), None)
                if release == "signal:SIGUSR1":
                    target.send_signal(signal.SIGUSR1)
                else:
                    (work / "release").touch()
                stdout, stderr = target.communicate(timeout=5)
                expect(target.returncode, 0)
                expect(stdout, expected["D02"])
                expect(stderr, "")
            finally:
                if target.poll() is None:
                    target.kill()


def can_map_high_va():
    if platform.machine() != "aarch64":
        return True
    libc = ctypes.CDLL(None)
    libc.mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long)
    libc.mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    wanted = 0x500000000000
    result = libc.mmap(wanted, mmap.PAGESIZE, 0, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
    if result != ctypes.c_void_p(-1).value:
        libc.munmap(result, mmap.PAGESIZE)
    return result == wanted


def select_asan(work, output, env):
    high_va = can_map_high_va()
    regular = output / "asan" if (output / "asan").is_dir() else output
    candidates = [output / "asan39", regular] if not high_va else [regular, output / "asan39"]
    startup_errors = []
    for directory in candidates:
        if not all((directory / case).is_file() for case in ("D13", "D14", "D15")):
            continue
        probe_executable = directory / "asan-probe"
        dedicated_probe = probe_executable.is_file()
        if not dedicated_probe:
            probe_executable = directory / "D13"  # Older prebuilt bundles.
        probe = run(probe_executable, cwd=work, env=env)
        if (dedicated_probe and probe.returncode == 0) or "ERROR: AddressSanitizer: heap-use-after-free" in probe.stderr:
            return directory
        if not dedicated_probe and probe.returncode == 0:
            continue
        if not high_va and ("ReserveShadowMemoryRange failed" in probe.stderr
                            or "Failed to mmap" in probe.stderr
                            or "((kSpaceBeg))" in probe.stderr
                            or "out of memory" in probe.stderr.lower()):
            startup_errors.append(probe.stderr)
            continue
        raise AssertionError(f"ASan runtime probe failed for {directory}:\n{probe.stderr}")
    if startup_errors:
        print("The available ASan build cannot initialize on this VA layout.")
        return None
    return None


def find_memcheck(output):
    bundled = output.parent / "tools" / "bin" / "valgrind"
    return os.environ.get("VALGRIND") or (bundled if os.access(bundled, os.X_OK) else shutil.which("valgrind"))


def check_memory(work, output, memcheck, build_missing=False):
    env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=0"}
    if not memcheck:
        asan = select_asan(work, output, env)
        if asan is None:
            memcheck = find_memcheck(output)
            if not memcheck:
                print("SKIP D13–D15: build asan39 or provide Valgrind with --memcheck.")
                return False
            if build_missing:
                require_success("make", f"OUT={output}", "memcheck", cwd=HERE)
            print(f"D13–D15: using Memcheck ({memcheck}).")
        else:
            output = asan
    if memcheck:
        prefix = [memcheck, "--tool=memcheck", "--error-exitcode=86"]
        output /= "memcheck"
        expected = {
            "D13": ("Invalid read of size", "free'd"),
            "D14": ("Invalid write of size", "after a block of size 6"),
            "D15": ("Invalid free()", "free'd"),
        }
    else:
        prefix = []
        expected = {
            "D13": ("heap-use-after-free", "READ of size"),
            "D14": ("heap-buffer-overflow", "WRITE of size"),
            "D15": ("attempting double-free",),
        }
    for case, diagnostics in expected.items():
        result = run(*prefix, output / case, cwd=work, env=env)
        correct_exit = result.returncode == 86 if memcheck else result.returncode != 0
        if not correct_exit or not all(message in result.stderr for message in diagnostics):
            raise AssertionError(f"{case} did not reproduce {diagnostics}:\n{result.stderr}")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path,
                        help="use prebuilt runtime fixtures")
    parser.add_argument("--memcheck", metavar="VALGRIND", help="use this Valgrind for D13–D15")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for variable in ("AIDBG_WAIT", "AIDBG_WAIT_RELEASE", "AIDBG_TRACER_PID"):
        os.environ.pop(variable, None)
    with tempfile.TemporaryDirectory(prefix="aidbg-debug-cases-") as directory:
        work = Path(directory)
        output = args.bin_dir.resolve() if args.bin_dir else work / "bin"
        if args.bin_dir is None:
            memory_target = "memcheck" if args.memcheck else "asan"
            require_success("make", f"OUT={output}", "all", memory_target, cwd=HERE)
            if not args.memcheck and not can_map_high_va() and os.environ.get("ASAN39_CC"):
                alternate = run("make", f"OUT={output}", "asan39", cwd=HERE)
                if alternate.returncode:
                    print(f"asan39 build unavailable:\n{alternate.stderr.strip()}")
        check_runtime(work, output)
        memory_checked = check_memory(work, output, args.memcheck, build_missing=args.bin_dir is None)
    print("All expected symptoms reproduced" if memory_checked else "D01–D10: all expected symptoms reproduced")
