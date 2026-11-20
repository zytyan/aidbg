#!/usr/bin/env python3
import contextlib
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
BIN = ARTIFACTS / "aidbg"
FIXTURE = ARTIFACTS / "fixture"
SERVER = ARTIFACTS / "aidbg-server"


def status(pid, tid=None):
    path = Path(f"/proc/{pid}")
    if tid is not None:
        path /= f"task/{tid}"
    return dict(line.split(":\t", 1) for line in (path / "status").read_text().splitlines()
                if ":\t" in line)


@contextlib.contextmanager
def fixture(*args):
    p = subprocess.Popen([FIXTURE, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        if not select.select([p.stdout], [], [], 5)[0] or p.stdout.readline() != b"READY\n":
            raise RuntimeError("fixture did not become ready")
        yield p
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(timeout=5)
        p.stdin.close()
        p.stdout.close()


@contextlib.contextmanager
def server(socket, state):
    p = subprocess.Popen([SERVER, "--socket", socket, "--state-dir", state])
    try:
        deadline = time.monotonic() + 5
        while not socket.is_socket():
            if p.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("aidbg-server did not become ready")
            time.sleep(0.01)
        assert socket.stat().st_mode & 0o777 == 0o600
        yield
    finally:
        if p.poll() is None:
            p.terminate()
            p.wait(timeout=6)
    assert not socket.exists(), "server did not clean up its socket"


def invoke(socket, *args, expected_code=0):
    result = subprocess.run([BIN, "--socket", socket, "snapshot", *args],
                            capture_output=True, timeout=10)
    if expected_code is not None:
        assert result.returncode == expected_code, (
            args, result.returncode, result.stderr.decode(), result.stdout.decode())
    return json.loads(result.stdout)


def take(socket, pid, name, expected_code=0, extra=()):
    data = invoke(socket, "--pid", str(pid), *extra, expected_code=expected_code)
    (ARTIFACTS / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n")
    assert data["schema_version"] == 1 and data["process"]["pid"] == pid
    return data


def check_detach(p, tids):
    for tid in tids:
        assert status(p.pid, tid)["TracerPid"] == "0", tid
    p.stdin.write(b"x")
    p.stdin.flush()
    p.wait(timeout=5)
    assert p.returncode == 0 and p.stdout.read() == b"DONE\n", p.returncode


def check_running(socket):
    with fixture() as p:
        x = take(socket, p.pid, "running")
        assert x["all_threads_stopped_during_capture"] and x["freeze_achieved"] == "all"
        assert x["process"]["architecture"] == "x86_64"
        mem = x["memory"]
        assert 0 < mem["rss_bytes"] <= mem["peak_rss_bytes"] <= mem["virtual_bytes"]
        assert len(x["threads"]) == 2 and any(t["name"] == "aidbg-worker" for t in x["threads"])
        assert all(t["stop"]["kind"] == "snapshot_interrupt" for t in x["threads"])
        for t in x["threads"]:
            assert t["registers"]["rip"].startswith("0x") and t["registers"]["eflags"].startswith("0x")
            assert len(t["stack"]["frames"]) >= 2
            assert t["stack"]["frames"][0]["pc"] == t["registers"]["rip"]
            assert t["stack"]["frames"][0]["sp"] == t["registers"]["rsp"]
            mask = 1 << (signal.SIGUSR1 - 1)
            for key in ("blocked", "shared_pending", "caught"):
                assert int(t["signals"][key], 16) & mask, (t["tid"], key, t["signals"])
        lead = next(t for t in x["threads"] if t["tid"] == p.pid)
        names = [f["function"] for f in lead["stack"]["frames"]]
        assert any(n and n.split(".")[0] == "library_leaf" for n in names), names
        assert "library_wait" in names and "main" in names, names
        assert all(f["method"] == "cfi" for f in lead["stack"]["frames"][1:]), names
        assert any(m["kind"] == "shared_object" and m["path"].endswith("libfixture.so") for m in x["modules"])
        main_id = next(m["id"] for m in x["modules"] if m["kind"] == "main")
        lib_id = next(m["id"] for m in x["modules"] if m["path"].endswith("libfixture.so"))
        assert any(f["module_id"] == main_id for f in lead["stack"]["frames"])
        assert any(f["module_id"] == lib_id for f in lead["stack"]["frames"])
        check_detach(p, [t["tid"] for t in x["threads"]])
        print("PASS live threads, GPR, signal masks, memory, modules and cross-DSO -O2 CFI")


def check_group_stop(socket):
    with fixture() as p:
        os.kill(p.pid, signal.SIGSTOP)
        assert os.WIFSTOPPED(os.waitpid(p.pid, os.WUNTRACED)[1])
        x = take(socket, p.pid, "group-stop")
        assert x["process"]["state_before"] == "T"
        assert x["all_threads_stopped_during_capture"]
        assert all(t["stop"]["kind"] == "group_stop" for t in x["threads"])
        for th in x["cleanup"]["threads"]:
            assert th["outcome"] == "detached" and th["preserved_group_stop"], th
            st = status(p.pid, th["tid"])
            assert st["State"].startswith("T") and st["TracerPid"] == "0", st
        os.kill(p.pid, signal.SIGCONT)
        check_detach(p, [t["tid"] for t in x["threads"]])
        print("PASS pre-existing group stop preserved")


def check_contested_thread(socket):
    libc = ctypes.CDLL(None, use_errno=True)
    ptrace = libc.ptrace
    ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    ptrace.restype = ctypes.c_long

    def trace(request, tid):
        if ptrace(request, tid, None, None) == -1:
            raise OSError(ctypes.get_errno(), f"test ptrace {request:#x} tid={tid}")

    with fixture() as p:
        worker = next(int(t.name) for t in Path(f"/proc/{p.pid}/task").iterdir()
                      if int(t.name) != p.pid)
        trace(0x4206, worker)  # PTRACE_SEIZE
        try:
            x = take(socket, p.pid, "contested-thread", expected_code=1, extra=("--freeze", "required"))
            assert x["freeze_requested"] == "required" and x["freeze_achieved"] == "none"
            assert x["memory"] is None and not x["threads"] and not x["modules"]
            assert not x["all_threads_stopped_during_capture"] and x["status"] == "failed"
            assert any("PTRACE_SEIZE" in issue["message"] for issue in x["issues"]), x["issues"]
            assert any(th["tid"] == p.pid and th["outcome"] == "detached" for th in x["cleanup"]["threads"])
            assert status(p.pid)["TracerPid"] == "0"
            assert status(p.pid, worker)["TracerPid"] == str(os.getpid())
            fallback = take(socket, p.pid, "try-fallback")
            assert fallback["status"] == "partial" and fallback["freeze_achieved"] == "none"
            assert len(fallback["threads"]) == 2 and all(t["registers"] is None for t in fallback["threads"])
            live = take(socket, p.pid, "never-attach", extra=("--freeze", "never"))
            assert live["status"] == "complete" and live["freeze_achieved"] == "none"
            assert len(live["threads"]) == 2 and not live["cleanup"]["threads"]
            assert live["trace_window_ms"] is None
            assert all(t["registers"] is None and t["stack"] is None for t in live["threads"])
            assert status(p.pid)["TracerPid"] == "0"
            assert status(p.pid, worker)["TracerPid"] == str(os.getpid())
        finally:
            trace(0x4207, worker)  # PTRACE_INTERRUPT
            assert os.WIFSTOPPED(os.waitpid(worker, 0x40000000)[1])  # __WALL
            trace(17, worker)  # PTRACE_DETACH
        check_detach(p, [p.pid, worker])
        print("PASS required failure, try fallback and never-attach preserve the other tracer")


def check_churn(socket):
    with fixture("--churn") as p:
        for n in range(5):
            x = take(socket, p.pid, f"thread-churn-{n}", expected_code=None)
            assert x["status"] in ("complete", "partial", "failed")
            assert all(t["outcome"] != "failed" for t in x["cleanup"]["threads"]), x["cleanup"]
            for t in Path(f"/proc/{p.pid}/task").iterdir():
                try:
                    assert status(p.pid, int(t.name))["TracerPid"] == "0"
                except (FileNotFoundError, ProcessLookupError):
                    pass  # A short-lived thread may disappear before status.
        check_detach(p, [p.pid])
        print("PASS repeated sampling while target threads spawn and exit")


def check_save(socket, root):
    saved = root / "export.json"
    with fixture() as p:
        preview = invoke(socket, "--pid", str(p.pid), "--freeze", "required",
                         "--fields", "threads.stack.frames.function,process.pid",
                         "--tid", str(p.pid), "--frames", "2", "--save", saved)
        assert preview["freeze_achieved"] == "all"
        assert preview["process"] == {"pid": p.pid}
        assert len(preview["threads"]) == 1 and preview["threads"][0]["tid"] == p.pid
        stack = preview["threads"][0]["stack"]
        assert len(stack["frames"]) == 2 and stack["frames_filtered"]
        assert set(stack["frames"][0]) == {"function"}
        full = json.loads(saved.read_text())
        assert full["snapshot_id"] == preview["snapshot_id"]
        assert len(full["threads"]) == 2
        assert len(full["threads"][0]["stack"]["frames"]) > 2
        check_detach(p, [t["tid"] for t in full["threads"]])
    print("PASS projected response, strict freeze and full local export")
    return full


def check_mcp(socket, snapshot_id):
    with subprocess.Popen([BIN, "--socket", socket, "mcp"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as mcp:
        def message(payload):
            payload["jsonrpc"] = "2.0"
            mcp.stdin.write(json.dumps(payload).encode() + b"\n")
            mcp.stdin.flush()
            if "id" not in payload:
                return None
            assert select.select([mcp.stdout], [], [], 5)[0], payload
            result = json.loads(mcp.stdout.readline())
            assert result.get("id") == payload["id"] and "error" not in result, result
            return result["result"]
        try:
            message({"id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "aidbg-test", "version": "1"},
            }})
            message({"method": "notifications/initialized"})
            listed = message({"id": 2, "method": "tools/list"})
            assert {t["name"] for t in listed["tools"]} == {
        "snapshot", "snapshot_query", "breakpoint_set", "breakpoint_remove",
        "breakpoint_events", "breakpoint_capabilities", "symbols", "resolve_address", "disassemble",
    }
            result = message({"id": 3, "method": "tools/call", "params": {
                "name": "snapshot_query", "arguments": {
                    "snapshot_id": snapshot_id, "fields": ["process.pid"],
                },
            }})
            assert result["structuredContent"]["snapshot_id"] == snapshot_id
            with fixture() as p:
                capture = message({"id": 4, "method": "tools/call", "params": {
                    "name": "snapshot", "arguments": {"pid": p.pid, "freeze": "never"},
                }})["structuredContent"]
                assert capture["process"]["pid"] == p.pid and capture["freeze_achieved"] == "none"
                check_detach(p, [t["tid"] for t in capture["threads"]])
        finally:
            mcp.stdin.close()
            try:
                mcp.wait(timeout=5)
            except subprocess.TimeoutExpired:
                mcp.kill()
                mcp.wait()
                raise
    assert mcp.returncode == 0, mcp.returncode
    print("PASS MCP stdio snapshot and snapshot_query via Protobuf RPC")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="aidbg-test-") as directory:
        root = Path(directory)
        socket, state = root / "aidbg.sock", root / "state"
        state.mkdir(mode=0o700)
        with server(socket, state):
            check_running(socket)
            check_group_stop(socket)
            check_contested_thread(socket)
            check_churn(socket)
            full = check_save(socket, root)
            missing = take(socket, 2147483647, "missing-process", expected_code=1)
            assert missing["status"] == "failed" and missing["issues"] and not missing["cleanup"]["threads"]
            invalid = subprocess.run([BIN, "--socket", socket, "snapshot", "--pid", "-1"],
                                     capture_output=True)
            assert invalid.returncode == 2 and not invalid.stdout
            print("PASS missing PID and invalid CLI")
        with server(socket, state):
            again = invoke(socket, "--from", full["snapshot_id"])
            assert full == again
            (ARTIFACTS / "saved-snapshot.json").write_text(json.dumps(again, indent=2) + "\n")
            print("PASS full snapshot persists across server restart and process exit")
            check_mcp(socket, full["snapshot_id"])
