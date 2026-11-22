#!/usr/bin/env python3
"""Validate Linux core bytes through the CLI, the Zstd decoder and GDB."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
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


def capture(cli, path, fixture, mode=None, extra=(), expected=0, traced=False):
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
    assert all((status(fixture.pid, tid.name)["TracerPid"] != "0") == traced
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
        ("anonymous_end", 0x6a, "extended"), ("protected", 0x6d, "standard"),
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
        assert read(addresses["unbacked"]) is None
        skipped = meta["coverage"]["unbacked_protected_ranges"]
        assert summary["unbacked_protected_ranges"] == skipped
        assert any(gap["start"] <= addresses["unbacked"] < gap["end"] for gap in skipped)
        assert all(not gap["start"] <= addresses["unbacked"] < gap["end"]
                   for gap in summary["missing_range_details"])
        warnings = {warning["code"] for warning in summary["warnings"]}
        gaps = summary["missing_range_details"]
        if not summary["issues"] and gaps and all(gap["reason"] == "vvar_unavailable" for gap in gaps):
            assert summary["status"] == "complete_without_vvar", summary
            assert "commonly unreadable" in summary["comment"], summary
            assert warnings == {"VVAR_UNAVAILABLE"}, summary
        elif summary["issues"] or gaps:
            assert summary["status"] == "partial" and "PARTIAL_CORE" in warnings, summary
            assert "comment" not in summary, summary
        else:
            assert summary["status"] == "complete" and "comment" not in summary, summary
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
        upstream.connect(str(backend))
        client.setblocking(False)
        upstream.setblocking(False)
        to_client, to_server = bytearray(), bytearray()
        forwarded = 0
        stalled = False
        upstream_closed = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if cut == "capture" and status(pid)["TracerPid"] != "0":
                return forwarded
            if upstream_closed and not to_client:
                assert cut is None or stalled, f"connection closed before {cut} cut"
                return forwarded

            readable = []
            writable = []
            if len(to_server) < 256 * 1024:
                readable.append(client)
            if not upstream_closed and not stalled and len(to_client) < 256 * 1024:
                readable.append(upstream)
            if to_server and not upstream_closed:
                writable.append(upstream)
            if to_client and not stalled:
                writable.append(client)
            ready, pending, _ = select.select(readable, writable, [],
                                               0.001 if cut == "capture" else 0.05)
            for source in ready:
                try:
                    data = source.recv(65536)
                except BlockingIOError:
                    continue
                if source is client:
                    if not data:
                        assert cut is None or stalled, f"connection closed before {cut} cut"
                        return forwarded
                    to_server.extend(data)
                elif data:
                    to_client.extend(data)
                else:
                    upstream_closed = True
            for destination in pending:
                buffer = to_client if destination is client else to_server
                try:
                    if destination is client and cut in ("stream", "idle"):
                        written = destination.send(buffer[:STREAM_CUT_BYTES - forwarded])
                    else:
                        written = destination.send(buffer)
                except BlockingIOError:
                    continue
                del buffer[:written]
                if destination is client:
                    forwarded += written
                    if cut == "stream" and forwarded == STREAM_CUT_BYTES:
                        return forwarded
                    if cut == "idle" and forwarded == STREAM_CUT_BYTES:
                        stalled = True
                        to_client.clear()
        raise RuntimeError("coredump connection test timed out")


@contextmanager
def proxy(cli, work):
    endpoint = work / "proxy.sock"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, ThreadPoolExecutor(1) as pool:
            listener.bind(str(endpoint))
            listener.listen()
            listener.settimeout(10)
            yield [*cli[:-1], endpoint], listener, pool
    finally:
        endpoint.unlink(missing_ok=True)


def progress(path):
    partial = Path(f"{path}.part")
    checkpoint = Path(f"{path}.part.json")
    assert partial.stat().st_mode & 0o777 == 0o600
    assert checkpoint.stat().st_mode & 0o777 == 0o600
    return json.loads(checkpoint.read_text())["dump_id"], partial


def resume(cli, path, expected=0):
    run = subprocess.run([*cli, "coredump", "--resume", "--output", path],
                         capture_output=True, timeout=30)
    if expected:
        assert run.returncode != 0 and not run.stdout, run
        return run
    assert run.returncode == 0, run.stderr.decode()
    return json.loads(run.stdout)


def verify_saved(state, path, dump_id, offset, summary):
    assert summary["dump_id"] == dump_id and summary["resumed_from"] == offset, summary
    stored = state / "coredumps" / dump_id
    original = (stored / "header.zst").read_bytes() + (stored / "payload.zst").read_bytes()
    assert path.read_bytes() == original
    assert summary["sha256"] == hashlib.sha256(original).hexdigest()
    assert not Path(f"{path}.part").exists() and not Path(f"{path}.part.json").exists()
    subprocess.check_call(["zstd", "-qt", path], timeout=30)


def interrupt(cli, proxy_cli, listener, pool, fixture, output, cut):
    first = pool.submit(relay, listener, cli[-1], fixture.pid, cut)
    extra = ("--download-idle-ms", "1000") if cut == "idle" else ()
    failure = capture(proxy_cli, output, fixture, "full", extra, expected=1)
    forwarded = first.result(timeout=10)
    if cut in ("stream", "idle"):
        assert forwarded == STREAM_CUT_BYTES, forwarded
    if cut == "idle":
        assert b"connection or download stalled" in failure.stderr, failure
    assert not failure.stdout and not output.exists()
    deadline = time.monotonic() + 10
    while any(status(fixture.pid, tid.name)["TracerPid"] != "0"
              for tid in Path(f"/proc/{fixture.pid}/task").iterdir()):
        assert time.monotonic() < deadline, "link loss left a thread traced"
        time.sleep(0.01)
    dump_id, partial = progress(output)
    if cut == "capture":
        assert partial.stat().st_size == 0
    else:
        assert 0 < partial.stat().st_size <= STREAM_CUT_BYTES
    return dump_id, partial


def verify_disconnect(cli, work, fixture, state):
    for cut in ("capture", "stream", "idle"):
        output = work / f"recovered-{cut}.core.zst"
        with proxy(cli, work) as (proxy_cli, listener, pool):
            dump_id, partial = interrupt(cli, proxy_cli, listener, pool, fixture, output, cut)
        offset = partial.stat().st_size
        jobs = set((state / "coredumps").iterdir())
        # Recreate the relay at the same path to discard any handshakes queued
        # by the first client's HTTP/2 reconnect before it exited.
        with proxy(cli, work) as (proxy_cli, listener, pool):
            reconnect = pool.submit(relay, listener, cli[-1], fixture.pid, None)
            summary = resume(proxy_cli, output)
            wire_bytes = reconnect.result(timeout=10)
        remaining = summary["compressed_bytes"] - offset
        assert remaining <= wire_bytes < remaining + 128 * 1024, (wire_bytes, remaining)
        assert set((state / "coredumps").iterdir()) == jobs
        verify_saved(state, output, dump_id, offset, summary)
        print(f"PASS {cut} interruption, same coredump resumed from offset {offset}")


def verify_mcp(cli, work, fixture, state):
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
            dump_id = result["structuredContent"]["dump_id"]
            resumed = work / "mcp-resumed.core.zst"
            partial = Path(f"{resumed}.part")
            checkpoint = Path(f"{resumed}.part.json")
            partial.write_bytes(output.read_bytes()[:256])
            checkpoint.write_text(json.dumps({"dump_id": dump_id}))
            partial.chmod(0o600)
            checkpoint.chmod(0o600)
            result = send("tools/call", {"name": "coredump", "arguments": {
                "resume": True, "output": str(resumed)}}, 3)
            assert not result.get("isError"), result
            verify_saved(state, resumed, dump_id, 256, result["structuredContent"])
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
    progress(output)


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
    progress(output)
    assert status(fixture.pid)["TracerPid"] == "0"


def verify_traced_capture(cli, work, fixture, address):
    command = [*cli, "breakpoint"]
    capabilities = json.loads(subprocess.check_output([*command, "capabilities"], timeout=15))
    if not capabilities["software_execution"]:
        print("SKIP coredump with breakpoints (software breakpoints unavailable)")
        return
    rule = json.loads(subprocess.check_output([
        *command, "set", "--kind", "software", "--address", hex(address), "--pid", str(fixture.pid),
    ], timeout=15))
    try:
        output = work / "traced.core.zst"
        summary = capture(cli, output, fixture, "lite", traced=True)
        point, = summary["breakpoint_replay"]["breakpoints"]
        assert point["breakpoint_id"] == rule["breakpoint_id"] and point["module_offset"], point
        assert output.exists()
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


def verify_restart(cli, work, state):
    case = work / "restart"
    output = case / "full.core.zst"
    with server(cli[-1], state), start_fixture(case, "typical") as (fixture, _):
        with proxy(cli, case) as (proxy_cli, listener, pool):
            dump_id, partial = interrupt(cli, proxy_cli, listener, pool, fixture, output, "stream")
    # The original tracee has exited and the original server is gone.
    prefix = partial.read_bytes()
    partial.write_bytes(bytes([prefix[0] ^ 1]) + prefix[1:])
    with server(cli[-1], state):
        corrupt = resume(cli, output, expected=1)
        assert b"SHA-256 mismatch" in corrupt.stderr and not output.exists(), corrupt
        partial.write_bytes(prefix)
        summary = resume(cli, output)
        verify_saved(state, output, dump_id, len(prefix), summary)
    print("PASS resume after server restart and target exit, with corrupt prefix rejected")


def verify_retention(cli, work):
    state = work / "quota-state"
    state.mkdir(mode=0o700)
    case = work / "quota"
    with server(cli[-1], state, "--coredump-max-mib", "2", "--coredump-retention-secs", "5"), \
         start_fixture(case, "typical") as (fixture, _):
        failure = capture(cli, case / "too-large.core.zst", fixture, "full", expected=1)
        assert b"exceeds the retained-artifact quota" in failure.stderr, failure
        first = capture(cli, case / "first.core.zst", fixture, "extended")
        failure = capture(cli, case / "quota-full.core.zst", fixture, "extended", expected=1)
        assert b"coredump retention quota exhausted" in failure.stderr, failure
        expired = case / "expired.core.zst"
        checkpoint = Path(f"{expired}.part.json")
        checkpoint.write_text(json.dumps({"dump_id": first["dump_id"]}))
        checkpoint.chmod(0o600)
        time.sleep(max(0, first["expires_unix_secs"] - time.time()) + 0.1)
        failure = resume(cli, expired, expected=1)
        assert b"retention expired" in failure.stderr and not expired.exists(), failure
        capture(cli, case / "quota-freed.core.zst", fixture, "extended")
        assert not (state / "coredumps" / first["dump_id"]).exists()
    print("PASS per-artifact and total quotas, expiration and reclaimed space")


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
                        verify_mcp(cli, case, fixture, state)
                        verify_cancel(cli, case, fixture)
                        verify_disconnect(cli, case, fixture, state)
                        verify_write_failure(cli, case, fixture)
                        verify_traced_capture(cli, case, fixture, addresses["code"])
                        print("PASS MCP, no-clobber, timeout, cancellation, write failure and coredump with active breakpoints")
                if args.benchmark:
                    compare_compression(workload, case / "full.core.zst")
        verify_restart(cli, work, state)
        verify_retention(cli, work)


if __name__ == "__main__":
    main()
