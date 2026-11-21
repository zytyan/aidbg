#!/usr/bin/env python3
"""Validate Linux core bytes through the CLI, the Zstd decoder and GDB."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
import resource
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import tempfile
import time

from run import ARTIFACTS, check_detach, server, status

MODES = ("lite", "stack-4k", "stack", "standard", "extended", "full")
STREAM_CUT_BYTES = 2 * 1024**2


def unpack_core(data):
    assert data[:7] == b"\x7fELF\x02\x01\x01"
    assert struct.unpack_from("<H", data, 16) == (4,), "expected ET_CORE"
    machine, = struct.unpack_from("<H", data, 18)
    assert machine in (62, 183)
    phoff, = struct.unpack_from("<Q", data, 32)
    phsize, phnum = struct.unpack_from("<HH", data, 54)
    loads, registers = [], {}
    metadata = None
    for index in range(phnum):
        kind, flags, offset, addr, _, filesz, memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + phsize * index)
        assert offset + filesz <= len(data)
        if kind == 1:
            loads.append((addr, addr + filesz, offset))
        if kind != 4:
            continue
        cursor = offset
        while cursor < offset + filesz:
            namesz, descsz, note = struct.unpack_from("<III", data, cursor)
            cursor += 12
            owner = data[cursor:cursor + namesz].rstrip(b"\0")
            cursor += (namesz + 3) & ~3
            desc = data[cursor:cursor + descsz]
            cursor += (descsz + 3) & ~3
            if (owner, note) == (b"CORE", 1):
                tid, = struct.unpack_from("<I", desc, 32)
                sp, = struct.unpack_from("<Q", desc, 112 + (19 if machine == 62 else 31) * 8)
                registers[tid] = sp
            if (owner, note) == (b"AIDBG", 1):
                metadata = json.loads(desc)
    assert metadata is not None
    assert len(registers) == 2, registers
    return loads, registers, metadata


def capture(cli, path, fixture, mode=None, extra=(), expected=0):
    args = ["coredump", "--pid", str(fixture.pid), "--output", path, *extra]
    if mode is not None:
        args += ["--mode", mode]
    result = subprocess.run([*cli, *args], capture_output=True, timeout=75)
    if expected != 0:
        assert result.returncode != 0, (args, result.stdout)
        return result
    assert result.returncode == 0, result.stderr.decode()
    summary = json.loads(result.stdout)
    assert summary["mode"] == (mode or "stack") and summary["threads"] == 2, summary
    assert summary["path"] == str(path) and path.stat().st_mode & 0o777 == 0o600
    assert summary["compressed_bytes"] == path.stat().st_size
    assert 0 <= summary["staged_bytes"] <= summary["captured_bytes"]
    if not summary["parallel_compression"]:
        assert summary["staged_bytes"] == summary["captured_bytes"]
    assert all(status(fixture.pid, tid.name)["TracerPid"] == "0"
               for tid in Path(f"/proc/{fixture.pid}/task").iterdir())
    return summary


def verify_mode(cli, work, fixture, mode, addresses, workload):
    path = work / f"{mode}.core.zst"
    start = time.monotonic()
    summary = capture(cli, path, fixture, mode if mode != "stack" else None)
    elapsed_ms = round((time.monotonic() - start) * 1000)
    assert summary["pause_us"] // 1000 == summary["pause_ms"]
    assert summary["timing_us"]["staging"] <= summary["timing_us"]["buffering"]
    assert summary["image_cache_hits"] > 0
    if mode in ("lite", "full"):
        assert summary["timing_us"]["images"] == 0
    data = subprocess.check_output(["zstd", "-qdc", path], timeout=30)
    loads, registers, meta = unpack_core(data)
    assert sum(end - start for start, end, _ in loads) == summary["captured_bytes"]
    assert meta["mode"] == mode
    assert any(row["build_id"] for row in meta["modules"] if row["path"].endswith("coredump_fixture"))

    def read(addr):
        for start, end, offset in loads:
            if start <= addr < end:
                return data[offset + addr - start]
        return None

    level = MODES.index(mode)
    assert (read(addresses["code"]) is not None) == (mode == "full")
    markers = [
        ("stack", 0x73, "stack"), ("main_data", 0x3c, "standard"),
        ("dso_data", 0x45, "standard"), ("dso_bss", 0x69, "standard"),
        ("cow", 0x61, "standard"), ("cow_end", 0x62, "standard"),
        ("clean", 0, "full"), ("ipc", 0x64, "extended"), ("anonymous", 0x68, "extended"),
        ("anonymous_end", 0x6a, "extended"),
    ]
    if workload == "typical":
        markers.extend([
            ("objects", ord("/"), "extended"), ("text", ord("r"), "extended"),
            ("sparse", 0x6b, "extended"), ("short", 0, "full"),
        ])
    for name, value, minimum in markers:
        wanted = value if level >= MODES.index(minimum) else None
        assert read(addresses[name]) == wanted, (mode, name, wanted, read(addresses[name]), summary)
    if summary["conservative_shared_mappings"] and level >= MODES.index("standard") and mode != "full":
        assert read(addresses["shared"]) == 0x63
    if mode == "full":
        assert read(addresses["shared"]) == 0x63
    if workload == "stress" and level >= MODES.index("standard"):
        assert read(addresses["short"]) is None
        assert any(gap["start"] <= addresses["short"] < gap["end"]
                   for gap in meta["coverage"]["missing"]), (mode, meta["coverage"])
    if mode in ("lite", "stack-4k"):
        assert not summary["missing_bytes"]
    if mode == "lite":
        assert summary["captured_bytes"] == 0 and summary["status"] == "complete", meta["coverage"]
    if mode == "stack-4k":
        for sp in registers.values():
            mapping = next(row for row in meta["mappings"] if row["start"] <= sp < row["end"])
            assert any((start, end) == (sp, min(sp + 4096, mapping["end"]))
                       for start, end, _ in loads), (sp, mapping, loads)
        vdso = next(row for row in meta["mappings"] if row["path"] == "[vdso]")
        assert read(vdso["start"]) == 0x7f
    if workload == "stress" and mode == "extended":
        assert summary["compressed_bytes"] > 16 * 1024**2, summary
    if mode in ("stack", "standard") and shutil.which("gdb"):
        core = work / "debug.core"
        core.write_bytes(data)
        vector = "xmm0" if data[18] == 62 else "v0"
        args = ["-ex", "info threads", "-ex", "thread apply all bt", "-ex", f"info registers {vector}"]
        if mode == "standard":
            args += ["-ex", "p/x core_main_data", "-ex", "p/x core_dso_bss[131072]"]
        output = subprocess.check_output(
            ["gdb", "-nx", "-batch", "-iex", "set debuginfod enabled off",
             ARTIFACTS / "coredump_fixture", core, *args], text=True, stderr=subprocess.STDOUT, timeout=30)
        assert "await_dump" in output and "idle_worker" in output, output
        assert vector in output, output
        if mode == "standard":
            assert "$1 = 0x3c" in output and "$2 = 0x69" in output, output
    pipeline = "parallel" if summary["parallel_compression"] else "serial"
    print(f"PASS {workload}/{mode}: {summary['captured_bytes']} B captured, {summary['compressed_bytes']} B compressed,"
          f" {summary['staged_bytes']} B staged, {summary['pause_ms']} ms pause,"
          f" {elapsed_ms} ms ready ({pipeline})")


def compare_compression(workload, core_path):
    raw = subprocess.check_output(["zstd", "-qdc", core_path], timeout=30)
    for level in (1, 3, 5):
        compress_ms = []
        decompress_ms = []
        for _ in range(3):
            start = time.monotonic()
            encoded = subprocess.check_output(["zstd", f"-{level}", "-qc"], input=raw, timeout=30)
            compress_ms.append((time.monotonic() - start) * 1000)
            start = time.monotonic()
            decoded = subprocess.check_output(["zstd", "-qdc"], input=encoded, timeout=30)
            decompress_ms.append((time.monotonic() - start) * 1000)
            assert decoded == raw, (workload, level)
        print(f"BENCH {workload}/full zstd-{level}: {len(raw)} -> {len(encoded)} B"
              f" ({len(raw) / len(encoded):.2f}x), encode {statistics.median(compress_ms):.0f} ms,"
              f" decode {statistics.median(decompress_ms):.0f} ms")


def relay(listener, backend, pid, cut):
    client, _ = listener.accept()
    with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
        upstream.settimeout(10)
        client.settimeout(10)
        upstream.connect(str(backend))
        forwarded = 0
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if cut == "capture" and status(pid)["TracerPid"] != "0":
                return forwarded
            ready, _, _ = select.select([client, upstream], [], [], 0.001 if cut == "capture" else 0.05)
            for source in ready:
                data = source.recv(64 * 1024)
                if not data:
                    assert cut is None, f"connection closed before {cut} cut"
                    return forwarded
                if source is client:
                    upstream.sendall(data)
                    continue
                if cut == "stream":
                    data = data[:STREAM_CUT_BYTES - forwarded]
                client.sendall(data)
                forwarded += len(data)
                if cut == "stream" and forwarded == STREAM_CUT_BYTES:
                    return forwarded
        raise RuntimeError("coredump connection test timed out")


def verify_disconnect(cli, work, fixture):
    endpoint = work / "proxy.sock"
    proxy_cli = [*cli[:-1], endpoint]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, ThreadPoolExecutor(1) as pool:
        listener.bind(str(endpoint))
        listener.listen()
        listener.settimeout(10)
        for cut in ("capture", "stream"):
            output = work / f"recovered-{cut}.core.zst"
            first = pool.submit(relay, listener, cli[-1], fixture.pid, cut)
            failure = capture(proxy_cli, output, fixture, "full", expected=1)
            forwarded = first.result(timeout=10)
            if cut == "stream":
                assert forwarded == STREAM_CUT_BYTES, forwarded
            assert not failure.stdout and not output.exists() and not list(work.glob(".tmp*"))
            deadline = time.monotonic() + 10
            while any(status(fixture.pid, tid.name)["TracerPid"] != "0"
                      for tid in Path(f"/proc/{fixture.pid}/task").iterdir()):
                assert time.monotonic() < deadline, "link loss left a thread traced"
                time.sleep(0.01)

            reconnect = pool.submit(relay, listener, cli[-1], fixture.pid, None)
            summary = capture(proxy_cli, output, fixture, "full")
            assert reconnect.result(timeout=10) >= summary["compressed_bytes"]
            subprocess.check_call(["zstd", "-qt", output], timeout=30)
            assert not list(work.glob(".tmp*"))
            print(f"PASS connection cut during {cut}, cleanup and fresh capture on the same socket")


def verify_mcp(cli, work, fixture):
    output = work / "mcp.core.zst"
    with subprocess.Popen([*cli, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as mcp:
        def send(method, params=None, ident=None):
            request = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                request["params"] = params
            if ident is not None:
                request["id"] = ident
            mcp.stdin.write(json.dumps(request).encode() + b"\n")
            mcp.stdin.flush()
            if ident is not None:
                assert select.select([mcp.stdout], [], [], 15)[0], request
                reply = json.loads(mcp.stdout.readline())
                assert reply.get("id") == ident and "error" not in reply, reply
                return reply["result"]
        try:
            send("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                "clientInfo": {"name": "coredump-test", "version": "1"}}, 1)
            send("notifications/initialized")
            result = send("tools/call", {"name": "coredump", "arguments": {
                "pid": fixture.pid, "mode": "lite", "output": str(output)}}, 2)
            assert not result.get("isError") and result["structuredContent"]["status"] == "complete", result
            assert output.is_file()
        finally:
            mcp.stdin.close()
            mcp.wait(timeout=10)


def verify_cancel(cli, work, fixture):
    output = work / "cancel.core.zst"
    with subprocess.Popen([*cli, "coredump", "--pid", str(fixture.pid), "--mode", "full",
                           "--output", output], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        deadline = time.monotonic() + 10
        while status(fixture.pid)["TracerPid"] == "0" and proc.poll() is None:
            assert time.monotonic() < deadline, "capture never attached"
            time.sleep(0.001)
        assert proc.poll() is None, "capture completed before cancellation"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 143
    while status(fixture.pid)["TracerPid"] != "0":
        assert time.monotonic() < deadline, "cancelled capture left the target traced"
        time.sleep(0.01)
    assert not output.exists() and not list(work.glob(".tmp*"))


def verify_write_failure(cli, work, fixture):
    def limit_file_size():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))

    output = work / "write-failure.core.zst"
    result = subprocess.run([*cli, "coredump", "--pid", str(fixture.pid), "--mode", "extended",
                             "--output", output], preexec_fn=limit_file_size,
                            capture_output=True, timeout=30)
    assert result.returncode != 0 and b"File too large" in result.stderr, result
    assert not output.exists() and not list(work.glob(".tmp*"))
    assert status(fixture.pid)["TracerPid"] == "0"


def verify_breakpoint_conflict(cli, work, fixture, address):
    command = [*cli, "breakpoint"]
    capabilities = json.loads(subprocess.check_output([*command, "capabilities"], timeout=15))
    if not capabilities["software_execution"]:
        print("SKIP coredump breakpoint conflict (software breakpoints unavailable)")
        return
    rule = json.loads(subprocess.check_output([
        *command, "set", "--kind", "software", "--address", hex(address), "--pid", str(fixture.pid),
    ], timeout=15))
    try:
        output = work / "conflict.core.zst"
        result = capture(cli, output, fixture, "lite", expected=1)
        assert b"an active breakpoint session owns this PID" in result.stderr, result
        assert not output.exists()
    finally:
        subprocess.check_call([
            *command, "remove", "--pid", str(fixture.pid), "--breakpoint-id", str(rule["breakpoint_id"]),
        ], stdout=subprocess.DEVNULL, timeout=15)


@contextmanager
def start_fixture(work, workload):
    work.mkdir()
    with subprocess.Popen(
        [ARTIFACTS / "coredump_fixture", work, workload],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0,
    ) as fixture:
        try:
            addresses = {}
            while True:
                assert select.select([fixture.stdout], [], [], 10)[0]
                line = fixture.stdout.readline().decode().strip()
                if line == "READY":
                    break
                name, address = line.split()
                addresses[name] = int(address, 16)
            yield fixture, addresses
            check_detach(fixture, [int(tid.name) for tid in Path(f"/proc/{fixture.pid}/task").iterdir()])
        finally:
            if fixture.poll() is None:
                fixture.kill()


def sweep_pause(work, bin_dir, baseline, repeats):
    import run

    endpoint = work / "debug.sock"
    state = work / "state"
    state.mkdir(mode=0o700)
    profiles = [(bin_dir, buffer_mib, block_kib) for buffer_mib, block_kib in (
        (0, 1024), (4, 1024), (8, 1024), (16, 1024), (32, 1024),
        (16, 256), (16, 4096), (32, 256), (32, 4096),
    )]
    for workload in ("typical", "stress"):
        case = work / workload
        with start_fixture(case, workload) as (fixture, _):
            for mode in ("stack-4k", "stack", "standard", "full"):
                if mode == "full":
                    cases = profiles
                elif mode == "stack-4k":
                    cases = [(bin_dir, 2, 1024)]
                else:
                    cases = [(bin_dir, 8, 1024), (bin_dir, 16, 1024)]
                if baseline is not None:
                    cases = [(baseline, None, None), *cases]
                for binaries, budget, block in cases:
                    run.SERVER = binaries / "aidbg-server"
                    cli = [binaries / "aidbg", "--socket", endpoint]
                    extra = () if budget is None else ("--buffer-mib", str(budget), "--block-kib", str(block))
                    output = case / "sweep.core.zst"
                    samples = []
                    with server(endpoint, state) as process:
                        for iteration in range(repeats + 1):
                            started = time.monotonic_ns()
                            summary = capture(cli, output, fixture, mode, extra)
                            elapsed_ms = (time.monotonic_ns() - started) / 1e6
                            if iteration == 0:
                                subprocess.check_call(["zstd", "-qt", output], timeout=30)
                            else:
                                samples.append((summary, elapsed_ms))
                            output.unlink()
                        rss_kib = int(status(process.pid)["VmHWM"].split()[0])
                    stages = samples[0][0].get("timing_us", {})
                    print("SWEEP " + json.dumps({
                        "workload": workload,
                        "mode": mode,
                        "buffer_mib": budget,
                        "block_kib": block,
                        "repeats": repeats,
                        "pause_ms": statistics.median(
                            row.get("pause_us", row["pause_ms"] * 1000) / 1000 for row, _ in samples),
                        "ready_ms": round(statistics.median(elapsed for _, elapsed in samples), 2),
                        "staged_bytes": statistics.median(row["staged_bytes"] for row, _ in samples),
                        "peak_rss_kib": rss_kib,
                        "timing_us": {
                            key: statistics.median(row["timing_us"][key] for row, _ in samples)
                            for key in stages
                        },
                    }))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, default=ARTIFACTS)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--benchmark", action="store_true", help="Compare Zstd levels 1, 3 and 5")
    group.add_argument("--pause-sweep", action="store_true", help="Compare capture buffers and read sizes")
    parser.add_argument("--baseline-bin-dir", type=Path, help="Previous client and server for the pause sweep")
    parser.add_argument("--repeats", type=int, default=5, help="Measured captures per sweep configuration")
    args = parser.parse_args()
    if args.repeats < 1 or (args.baseline_bin_dir is not None and not args.pause_sweep):
        parser.error("use a positive repeat count and provide a baseline only with --pause-sweep")
    import run
    run.SERVER = args.bin_dir.resolve() / "aidbg-server"
    assert shutil.which("zstd"), "coredump integration test requires zstd"
    with tempfile.TemporaryDirectory(prefix="aidbg-core-") as temp:
        work = Path(temp)
        if args.pause_sweep:
            baseline = args.baseline_bin_dir.resolve() if args.baseline_bin_dir else None
            sweep_pause(work, args.bin_dir.resolve(), baseline, args.repeats)
            return
        endpoint = work / "debug.sock"
        cli = [args.bin_dir.resolve() / "aidbg", "--socket", endpoint]
        state = work / "state"
        state.mkdir(mode=0o700)
        with server(endpoint, state):
            for workload in ("typical", "stress"):
                case = work / workload
                with start_fixture(case, workload) as (fixture, addresses):
                    for mode in MODES:
                        verify_mode(cli, case, fixture, mode, addresses, workload)
                    if workload == "stress":
                        lite = case / "lite.core.zst"
                        original = lite.read_bytes()
                        capture(cli, lite, fixture, "lite", expected=1)
                        assert lite.read_bytes() == original
                        timed = case / "timed.core.zst"
                        capture(cli, timed, fixture, "full", ("--timeout-ms", "1"), expected=1)
                        assert not timed.exists() and status(fixture.pid)["TracerPid"] == "0"
                        for option in (("--buffer-mib", "65"), ("--block-kib", "100")):
                            rejected = case / "invalid.core.zst"
                            capture(cli, rejected, fixture, "full", option, expected=1)
                            assert not rejected.exists()
                        verify_mcp(cli, case, fixture)
                        verify_cancel(cli, case, fixture)
                        verify_disconnect(cli, case, fixture)
                        verify_write_failure(cli, case, fixture)
                        verify_breakpoint_conflict(cli, case, fixture, addresses["code"])
                        print("PASS MCP, no-clobber, timeout, cancellation, write failure and breakpoint conflict")
                if args.benchmark:
                    compare_compression(workload, case / "full.core.zst")


if __name__ == "__main__":
    main()
