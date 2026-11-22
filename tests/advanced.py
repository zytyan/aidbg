import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time

from run import ARCH, ARTIFACTS, BIN, check_detach, fixture, server


def call(socket, *args, code=0, error=None):
    reply = subprocess.run([BIN, "--socket", socket, *map(str, args)],
                           capture_output=True, timeout=15)
    if error is not None:
        assert reply.returncode != 0 and error in reply.stderr.decode(), reply
        return
    data = json.loads(reply.stdout)
    if code is not None:
        assert reply.returncode == code, (reply, data)
    return data


def preload(library):
    return {**os.environ, "LD_PRELOAD": str(library)}


def signal_leader(pid):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.tgkill(pid, pid, signal.SIGUSR2) != 0:
        raise OSError(ctypes.get_errno(), "tgkill")


def check_software_watch(socket):
    library = ARTIFACTS / "libstep_watch.so"
    with fixture(env=preload(library)) as p:
        def symbol(name):
            result, = call(socket, "symbols", "--pid", p.pid, "--module", library.name,
                           "--pattern", name)["matches"]
            return result

        data = symbol("step_watch_value")
        function = symbol("library_wait")
        start = int(function["runtime_address"], 16)
        args = ("watch-step", "--pid", p.pid, "--address", data["runtime_address"],
                "--length", 8, "--pc-start", hex(start))
        report = call(socket, *args, "--pc-end", hex(start + function["size"]), "--max-steps", 48)
        assert report["status"] == "step_limit" and report["steps"] == 48, report
        assert 2 <= len(report["changes"]) < report["steps"], report
        for change in report["changes"]:
            before = int.from_bytes(bytes.fromhex(change["before"]), "little")
            after = int.from_bytes(bytes.fromhex(change["after"]), "little")
            assert after == before + 1, change
            assert start <= int(change["instruction_pc"], 16) < start + function["size"], change
        outside = call(socket, *args, "--pc-end", hex(start + 1))
        assert outside["status"] == "outside_window" and outside["steps"] == 0, outside
        check_detach(p, [p.pid])
    print("PASS bounded software value-change observation and clean detach")


def check_target_call(socket):
    library = ARTIFACTS / "libtarget_call.so"
    with fixture(env=preload(library)) as p:
        scratch, = call(socket, "symbols", "--pid", p.pid, "--module", library.name,
                        "--pattern", "scratch", "--mode", "regex")["matches"]
        command = ("target-call", "--pid", p.pid, "--module", library.name,
                   "--scratch-address", scratch["runtime_address"], "--scratch-length", scratch["size"])

        def invoke(symbol, return_type, *args):
            report = call(socket, *command, "--allow-side-effects", "--symbol", symbol,
                          "--return-type", return_type, *args)
            assert report["registers_and_scratch_restored"], report
            assert all(thread["outcome"] == "detached" for thread in report["cleanup"]["threads"]), report
            return report

        call(socket, *command, "--symbol", "call_spin", "--return-type", "i32", error="side effects")
        integer = invoke("call_case::add", "i32", "--arg", "i32:-4", "--arg", "i32:9")
        assert integer["status"] == "complete" and integer["return_value"] == 5, integer
        assert integer["target_side_effects_possible"], integer
        floating = invoke("call_case::add", "f64", "--arg", "i32:2", "--arg", "f64:0.25")
        assert floating["status"] == "complete" and floating["return_value"] == 2.25, floating
        fault = invoke("call_read", "i32", "--arg", "ptr:0")
        assert fault["status"] == "target_fault" and fault["stop"]["signal"] == signal.SIGSEGV, fault
        limited = invoke("call_spin", "i32", "--max-steps", "4")
        assert limited["status"] == "step_limit" and limited["steps"] == 4, limited
        timed = invoke("call_spin", "i32", "--max-steps", "512", "--timeout-ms", "50")
        assert timed["status"] == "timed_out" and timed["steps"] > 0, timed
        throwing = invoke("call_throw", "i32")
        assert throwing["status"] == "left_function", throwing

        sender = threading.Timer(0.06, signal_leader, args=(p.pid,))
        sender.start()
        try:
            stopped = invoke("call_spin", "i32", "--max-steps", "512", "--timeout-ms", "400")
            assert stopped["status"] == "interrupted" and stopped["stop"]["signal"] == signal.SIGUSR2, stopped
        finally:
            sender.cancel()
            sender.join()
        for expression, expected in [("call_case::calls", 1), ("call_case::caught_signal", 1),
                                     ("call_case::scratch[8184]", 0)]:
            result = call(socket, "inspect", "--pid", p.pid, "--module", library.name,
                          "--expression", expression)
            assert result["status"] == "complete" and result["result"]["value"] == expected, result
        check_detach(p, [p.pid])
    print("PASS typed target calls, C++ overloads, signal forwarding, fault and budget recovery")


def check_signal_stack(socket):
    library = ARTIFACTS / "libtarget_call.so"
    with fixture(env={**preload(library), "AIDBG_TEST_HOLD_SIGNAL": "1"}) as p:
        signal_leader(p.pid)
        for _ in range(15):
            capture = call(socket, "snapshot", "--pid", p.pid, "--freeze", "required")
            stack = next(t["stack"] for t in capture["threads"] if t["tid"] == p.pid)
            names = [frame["function"] or "" for frame in stack["frames"]]
            if any("on_signal" in name for name in names):
                break
            time.sleep(0.01)
        assert any("on_signal" in name for name in names), stack
        if stack["complete"]:
            assert "library_wait" in names, stack
        else:
            assert stack["stop_reason"] and stack["stop_reason"] != "end_of_stack", stack
        check_detach(p, [p.pid])
    print(f"PASS signal-handler stack and target resume ({stack['stop_reason']})")


def check_perf(socket, pid):
    for mode in ("hotspot", "stack"):
        report = call(socket, "perf", "--pid", pid, f"--{mode}", "--tid", pid,
                      "--duration-ms", 350, "--frequency-hz", 99, code=None)
        assert report["pid"] == pid and report["mode"] == mode, report
        thread, = report["threads"]
        assert thread["tid"] == pid, report
        if report["status"] == "unavailable":
            assert thread["issue"] and "perf" in thread["issue"], report
            print(f"PASS perf {mode} reports kernel or permission limitation: {thread['issue']}")
            continue
        assert report["status"] in ("complete", "partial") and report["samples"] > 0, report
        assert report["samples"] == thread["samples"], report
        rows = report["hotspots"] if mode == "hotspot" else report["stacks"]
        assert rows and sum(row["samples"] for row in rows) == report["samples"], report
        assert abs(sum(row["percent"] for row in rows) - 100) < 0.01, report
        if mode == "stack":
            assert any(row["children"] for row in rows), report
            assert report["recovered_frames"]["cfi"] > 0, report
        else:
            assert any(row["symbol"] == "library_wait" and int(row["first"], 16) <= int(row["last"], 16)
                       for row in rows), report
        print(f"PASS live perf {mode} sample counts and aggregation")


def check_overrides(socket, state):
    with fixture() as p:
        initial, = call(socket, "symbols", "--pid", p.pid, "--module", "libfixture.so",
                        "--pattern", "library_wait")["matches"]
        addr = initial["runtime_address"]
        with server(socket.with_name("overrides.sock"), state):
            alternate = socket.with_name("overrides.sock")
            rule = call(alternate, "symbol-override", "set", "--pid", p.pid, "--address", addr,
                        "--length", 4, "--name", "debugger_wait")
            assert rule["scope"] == "build_id" and rule["build_id"] == initial["module"]["build_id"], rule
            assert rule["offset"] == int(initial["module_offset"], 16), rule
        with server(socket.with_name("overrides.sock"), state):
            alternate = socket.with_name("overrides.sock")
            assert call(alternate, "symbol-override", "list") == [rule]
            inside = hex(int(addr, 16) + 1)
            result = call(alternate, "resolve", "--pid", p.pid, "--address", inside)
            assert result["display"] == "debugger_wait+0x1"
            assert result["original_symbol"]["name"] == "library_wait"
            assert result["symbol_override"] == rule
            alias, = call(alternate, "symbols", "--pid", p.pid, "--pattern", "debug*",
                          "--mode", "glob", "--module", "libfixture.so")["matches"]
            assert alias["symbol_override"] == rule and alias["runtime_address"] == addr
            call(alternate, "symbol-override", "set", "--pid", p.pid, "--address", inside,
                 "--name", "overlap", error="overlaps")
            call(alternate, "symbol-override", "remove", "--id", rule["id"])
            restored = call(alternate, "resolve", "--pid", p.pid, "--address", addr)
            assert restored["symbol"]["name"] == "library_wait" and "symbol_override" not in restored
        check_detach(p, [p.pid])
    print("PASS symbol override range, search, original source, restart persistence and undo")


def check_frame_pointer_and_session_override(socket, state):
    library = ARTIFACTS / "libunwind_fp.so"
    with fixture(env=preload(library)) as p:
        capture = call(socket, "snapshot", "--pid", p.pid, "--freeze", "required")
        thread = next(t for t in capture["threads"] if t["tid"] == p.pid)
        leaf, caller, *_ = thread["stack"]["frames"]
        assert leaf["function"] == "library_wait", leaf
        assert caller["method"] == "frame_pointer" and caller["function"] == "main", caller
        profile = call(socket, "perf", "--pid", p.pid, "--tid", p.pid, "--stack",
                       "--duration-ms", 250, code=None)
        if profile["status"] != "unavailable":
            assert profile["recovered_frames"]["frame_pointer"] > 0, profile
        print("PASS frame-pointer fallback without CFI")

        symbol, = call(socket, "symbols", "--pid", p.pid, "--module", library.name,
                       "--pattern", "library_wait")["matches"]
        address = symbol["runtime_address"]
        rule = call(socket, "symbol-override", "set", "--pid", p.pid, "--address", address,
                    "--name", "session_wait")
        assert rule["scope"] == "session", rule
        assert call(socket, "resolve", "--pid", p.pid, "--address", address)["display"] == "session_wait"
        alternate = socket.with_name("session.sock")
        with server(alternate, state):
            assert call(alternate, "symbol-override", "list") == []
            assert call(alternate, "resolve", "--pid", p.pid, "--address", address)["display"] == "library_wait"
        call(socket, "symbol-override", "remove", "--id", rule["id"])
        check_detach(p, [p.pid])
    print("PASS override without build ID is restricted to the debugger session")


def check_variables(socket, library):
    with fixture(env=preload(library)) as p:
        def inspect(expression):
            return call(socket, "inspect", "--pid", p.pid, "--module", library.name,
                        "--expression", expression)

        for expression, value in (
            ("::inspect_case::global", 42),
            ("inspect_case::object.array[1]", 5),
            ("inspect_case::object.inherited", -9),
            ("*(inspect_case::object.pointer)", 42),
            ("local", -17),
        ):
            result = inspect(expression)
            assert result["status"] == "complete" and result["result"]["value"] == value, (library.name, result)
            assert result["result"]["type"]["byte_size"] == 4, result
        for expression, value in (
            ("inspect_case::object.array[1] + local * 2", -29),
            ("(double)inspect_case::global / 4", 10.5),
            ("((unsigned int)-1) + 1u", 0),
            ("(long)-1 < 1u", True),
            ("false && *inspect_case::null_pointer", False),
            ("(local < 0) && (inspect_case::global == 42)", True),
        ):
            result = inspect(expression)
            assert result["status"] == "complete" and result["result"]["value"] == value, (expression, result)
        for expression in ("1 / 0", "2147483647 + 1"):
            result = inspect(expression)
            assert result["status"] == "invalid_expression", (expression, result)
        layout = inspect("inspect_case::object")["result"]["type"]
        assert any(field["base_class"] and field["offset"] == 0 for field in layout["fields"]), layout
        assert any(field["name"] == "array" and field["byte_size"] == 12 for field in layout["fields"]), layout
        if "-o2" in library.name:
            result = inspect("discarded")
            assert result["status"] in ("optimized_out", "unavailable_at_pc"), (library.name, result)
        for expression, status in (
            ("inspect_case::object.array[3]", "out_of_bounds"),
            ("*inspect_case::null_pointer", "null_pointer"),
            ("missing_identifier", "not_found"),
        ):
            result = inspect(expression)
            assert result["status"] == status, (library.name, result)
        assignment = inspect("inspect_case::global = 1")
        assert assignment["code"] == "INVALID_EXPRESSION", assignment
        assert "read-only" in assignment["message"], assignment
        check_detach(p, [p.pid])
    print(f"PASS DWARF variables, inlined local, type layout and read failures ({library.name})")


def check_engines(socket, root):
    if ARCH == "aarch64":
        source, original, registers = "str w1, [x0]", "1f2003d5", {"x0": "0x20000", "x1": "42"}
        loop = "b 0x10000"
    else:
        source, original, registers = "mov dword ptr [rdi], esi", "9090", {"rdi": "0x20000", "rsi": "42"}
        loop = "jmp 0x10000"
    address = "0x10000"
    asm = call(socket, "asm", "--address", address, "--source", source)
    assert asm["architecture"] == ARCH and asm["statements"] == 1, asm
    patch = ("patch", "--base", address, "--address", address, "--original", original, "--source", source)
    result = call(socket, *patch)
    assert result["original_bytes"] == original and result["patched_image"] == asm["bytes"], result
    call(socket, *patch, "--existing", f"{address}:1", error="overlaps")
    if ARCH == "x86_64":
        call(socket, "patch", "--base", address, "--address", address, "--original", "4889d8",
             "--source", "nop", error="instruction boundary")
    else:
        call(socket, "patch", "--base", address, "--address", "0x10001", "--original", original,
             "--source", "nop", error="aligned")

    state = {
        "address": address, "code": result["patched_image"], "registers": registers,
        "memory": [{"address": "0x20000", "bytes": "0000000000000000", "writable": True}],
        "watch": [{"address": "0x20000", "length": 4}],
        "objects": [{"name": "two_bytes", "address": "0x20000", "length": 2, "guard_bytes": 4}],
    }

    def emulate(current):
        path = root / "simulation.json"
        path.write_text(json.dumps(current))
        return call(socket, "emulate", "--state", path)

    simulated = emulate(state)
    assert simulated["status"] == "complete" and simulated["instructions"] == 1, simulated
    assert simulated["memory"][0]["bytes"] == "2a00000000000000", simulated
    assert {event["kind"] for event in simulated["events"]} == {"watchpoint", "object_out_of_bounds"}, simulated
    assert all(event["origin"] == "simulation" for event in simulated["events"]), simulated
    missing = emulate({**state, "memory": []})
    assert missing["status"] == "missing_state", missing
    jump = call(socket, "asm", "--address", address, "--source", loop)["bytes"]
    limited = emulate({"address": address, "code": jump, "instruction_limit": 3})
    assert limited["status"] == "instruction_limit" and limited["instructions"] == 3, limited
    print("PASS Keystone offline patch boundaries and Unicorn copied memory, probes and early termination")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="aidbg-advanced-") as directory:
        root = Path(directory)
        state = root / "state"
        state.mkdir(mode=0o700)
        socket = root / "server.sock"
        with server(socket, state):
            libraries = sorted(ARTIFACTS.glob("libvariables-*.so"))
            assert len(libraries) >= 2
            for library in libraries:
                check_variables(socket, library)
            with fixture(env=preload(ARTIFACTS / "libvariables-gcc-o2.so")) as p:
                check_perf(socket, p.pid)
                check_detach(p, [p.pid])
            check_engines(socket, root)
            check_software_watch(socket)
            check_target_call(socket)
            check_signal_stack(socket)
            check_overrides(socket, state)
            check_frame_pointer_and_session_override(socket, state)
