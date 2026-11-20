#!/usr/bin/env python3
import contextlib
import json
from pathlib import Path
import select
import shutil
import signal
import subprocess
import tempfile
import time

from run import ARTIFACTS, BIN, server, status


def read_line(process):
    assert select.select([process.stdout], [], [], 10)[0], process.poll()
    return process.stdout.readline().decode().split()


@contextlib.contextmanager
def fixture(binary, normal, stripped):
    with subprocess.Popen([binary, normal, stripped], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE) as process:
        try:
            ready, *addresses = read_line(process)
            assert ready == "READY" and len(addresses) == 11
            yield process, addresses
        finally:
            if process.poll() is None:
                process.kill()


def check(socket, root, state, binary):
    normal = ARTIFACTS / "libfixture.so"
    stripped = root / "libstripped.so"
    debug = root / "libstripped.so.debug"
    shutil.copyfile(normal, stripped)
    subprocess.run(["objcopy", "--only-keep-debug", stripped, debug], check=True)
    subprocess.run(["objcopy", "--strip-all", f"--add-gnu-debuglink={debug}", stripped], check=True)
    debug_bytes = debug.read_bytes()

    def invoke(*args, error=None):
        reply = subprocess.run([BIN, "--socket", socket, *args],
                               capture_output=True, timeout=10)
        if error is not None:
            assert reply.returncode and error in reply.stderr.decode(), reply
            return
        assert reply.returncode == 0, reply
        return json.loads(reply.stdout)

    with fixture(binary, normal, stripped) as (p, addresses):
        hit, *slots, one, two, three, bss, watched, anonymous = addresses
        pid = str(p.pid)

        def lookup(pattern, *args):
            return invoke("symbols", "--pid", pid, "--pattern", pattern, *args)["matches"]

        def resolve(address):
            return invoke("resolve", "--pid", pid, "--address", address)

        if binary.name.endswith("nopie"):
            main, = lookup("hit", "--module", binary.name)
            assert main["runtime_address"] == hit and main["load_bias"] == "0x0", main
            return

        data, = lookup("bss_buffer", "--module", binary.name)
        assert data["runtime_address"] == bss
        tail = resolve(hex(int(bss, 16) + 8192))
        assert tail["symbol"]["name"] == "bss_buffer" and tail["file_offset"] is None, tail
        hits = lookup("library_wait")
        assert {entry["runtime_address"] for entry in hits} == {one, two, three}, hits
        normal_instances = {entry["instance"] for entry in hits
                            if entry["module"]["path"].endswith("/libfixture.so")}
        assert len(normal_instances) == 2, hits
        assert len({entry["module"]["build_id"] for entry in hits}) == 1
        assert any({s["table"] for s in entry["sources"]} == {".symtab", ".dynsym"}
                   for entry in hits), hits

        locals_ = lookup("library_le*", "--mode", "glob", "--module", stripped.name)
        assert locals_ and all(row["binding"] == "local" for row in locals_), locals_
        local = locals_[0]
        assert any(source["debug_file"].endswith(debug.name) for source in local["sources"])
        assert lookup("^library_l.*$", "--mode", "regex", "--module", stripped.name) == locals_
        resolved = resolve(local["runtime_address"])
        assert resolved["elf_address"] == local["elf_address"]
        assert resolved["symbol"]["name"] == local["name"] and resolved["source_line"]["line"] > 0
        assert resolved["source_line"]["file"].endswith("shared.c")
        debug.write_bytes(debug_bytes + b"wrong crc")
        assert lookup(local["name"], "--module", stripped.name) == []
        fallback = resolve(local["runtime_address"])
        assert fallback["symbol"] is None and fallback["display"].startswith("libstripped.so+"), fallback
        debug.write_bytes(debug_bytes)
        assert lookup("library_wait", "--module", local["module"]["build_id"]) == hits
        print("PASS PIE and SO symbols, multiple load instances, debuglink CRC and external DWARF")

        def install(*args, error=None):
            budget = () if "--timeout-ms" in args else ("--timeout-ms", "500")
            return invoke("breakpoint", "set", "--pid", pid, *args, *budget, error=error)

        def remove(rule):
            return invoke("breakpoint", "remove", "--pid", pid,
                          "--breakpoint-id", str(rule["breakpoint_id"]))

        def events(rule):
            return invoke("breakpoint", "events", "--breakpoint-id", str(rule["breakpoint_id"]))["events"]

        def run_batch(n):
            p.stdin.write(b"x")
            p.stdin.flush()
            assert read_line(p) == ["DONE", str(n)], p.poll()

        def saved_events(rule, expected):
            until = time.monotonic() + 10
            while True:
                rows = events(rule)
                if len(rows) == expected and all(e["snapshot_status"] == "saved" for e in rows):
                    return rows
                assert time.monotonic() < until, rows
                time.sleep(0.01)

        install("--module", normal.name, "--symbol", "library_wait", error="ambiguous")
        unique = install("--module", normal.name, "--symbol", "library_wait",
                         "--instance", min(normal_instances))
        assert unique["address"] in {one, two}
        assert remove(unique)["status"] == "detached"

        absolute = install("--address", hit)
        spare = [install("--address", address) for address in slots[:3]]
        install("--address", slots[3], error="ResourceExhausted")
        assert remove(spare.pop())["status"] == "removed"
        spare.append(install("--address", slots[3]))
        for rule in spare:
            assert remove(rule)["status"] == "removed"
        run_batch(1)
        rows = saved_events(absolute, 6)
        assert len({e["tid"] for e in rows}) == 2
        assert all(e["resume_status"] == "resumed" and e["scope"] == "thread" for e in rows)
        snapshot = invoke("snapshot", "--from", rows[0]["snapshot_id"])
        assert invoke("snapshot", "--event", str(rows[0]["event_id"])) == snapshot
        assert len(snapshot["threads"]) == 1
        assert snapshot["threads"][0]["tid"] == rows[0]["tid"]
        assert snapshot["threads"][0]["registers"]["rip"] == hit
        assert (state / (rows[0]["snapshot_id"] + ".json")).is_file()
        assert remove(absolute)["status"] == "detached"
        assert status(p.pid)["TracerPid"] == "0"
        run_batch(2)
        assert len(events(absolute)) == 6

        process = install("--module", binary.name, "--symbol", "hit", "--all-threads")
        assert process["address"] == hit
        run_batch(3)
        rows = saved_events(process, 6)
        assert all(e["resume_status"] == "resumed" and e["scope"] == "process" for e in rows)
        snapshots = [invoke("snapshot", "--from", row["snapshot_id"]) for row in rows]
        assert all(x["all_threads_stopped_during_capture"] for x in snapshots), snapshots
        assert any(len(x["threads"]) >= 2 for x in snapshots), snapshots

        p.send_signal(signal.SIGSTOP)
        deadline = time.monotonic() + 5
        while not status(p.pid)["State"].startswith("t"):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert remove(process)["status"] == "detached"
        deadline = time.monotonic() + 5
        while not status(p.pid)["State"].startswith("T"):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        p.send_signal(signal.SIGCONT)
        run_batch(4)
        timeout = install("--address", hit, "--all-threads", "--timeout-ms", "1")
        run_batch(5)
        rows = saved_events(timeout, 6)
        assert all(e["resume_status"] == "resumed" for e in rows), rows
        assert any(e["capture_status"] == "timed_out" for e in rows), rows
        assert remove(timeout)["status"] == "detached"
        capabilities = invoke("breakpoint", "capabilities")
        assert capabilities["watch_access"] == ["write", "read_write"] and capabilities["watch_lengths"] == [1, 2, 4, 8]
        install("--kind", "write", "--length", "8", "--address", hex(int(watched, 16) + 1), error="aligned")
        rule = install("--kind", "write", "--length", "8", "--address", watched)
        p.stdin.write(b"w")
        p.stdin.flush()
        assert read_line(p) == ["WRITTEN"]
        rows = saved_events(rule, 2)
        assert all(e["tid"] != p.pid and e["kind"] == "hardware_write" for e in rows), rows
        assert [e["watch"]["value_changed"] for e in rows] == [False, True], rows
        assert [e["watch"]["value_after"] for e in rows] == ["0x7", "0x9"], rows
        assert remove(rule)["status"] == "detached"
        print("PASS x86_64 write watchpoints distinguish same-value and changed writes on a new thread")

        rule = install("--kind", "read-write", "--length", "8", "--address", watched)
        p.stdin.write(b"r")
        p.stdin.flush()
        assert read_line(p) == ["READ", "9"]
        row, = saved_events(rule, 1)
        assert row["watch"]["access"] == "read_write" and row["watch"]["write_observed"] is None
        assert row["watch"]["value_changed"] is False
        assert remove(rule)["status"] == "detached"

        writer, = lookup("force_watch", "--module", binary.name)
        soft_writer = install("--kind", "software", "--address", writer["runtime_address"])
        watch_writer = install("--kind", "write", "--length", "8", "--address", watched)
        p.stdin.write(b"w")
        p.stdin.flush()
        assert read_line(p) == ["WRITTEN"]
        assert len(saved_events(soft_writer, 1)) == 1
        assert [e["watch"]["value_after"] for e in saved_events(watch_writer, 2)] == ["0x7", "0x9"]
        assert remove(soft_writer)["status"] == "removed"
        assert remove(watch_writer)["status"] == "detached"

        soft = install("--kind", "software", "--address", hit)
        run_batch(6)
        rows = saved_events(soft, 6)
        assert len({e["tid"] for e in rows}) == 2
        assert all(e["resume_status"] == "resumed" and e["kind"] == "software_execution" for e in rows)
        snapshot = invoke("snapshot", "--event", str(rows[0]["event_id"]))
        assert snapshot["threads"][0]["registers"]["rip"] == hit
        assert remove(soft)["status"] == "detached"
        run_batch(7)
        assert len(events(soft)) == 6

        soft = install("--kind", "software", "--address", hit)
        p.stdin.write(b"f")
        p.stdin.flush()
        assert read_line(p) == ["FORKED"]
        assert status(p.pid)["TracerPid"] == "0"
        print("PASS concurrent software hits, original instructions, rearming, removal and fork cleanup")

        def disassemble(address, *args):
            return invoke("disassemble", "--pid", pid, "--address", address, *args)

        window = disassemble(hit, "--before", "0", "--after", "3")
        assert window["boundary"] == "function_entry" and window["address_is_instruction_start"], window
        assert len(window["instructions"]) == 4 and window["instructions"][0]["address"] == hit, window
        middle = window["instructions"][1]["address"]
        context = disassemble(middle, "--before", "1", "--after", "1")
        assert len(context["instructions"]) == 3 and context["instructions"][0]["address"] == hit, context
        unknown = disassemble(anonymous, "--after", "1")
        assert unknown["boundary"] == "uncertain" and unknown["truncated_before"], unknown
        assert [i["bytes"] for i in unknown["instructions"]] == ["90", "c3"], unknown
        known = disassemble(anonymous, "--start", anonymous, "--after", "1")
        assert known["boundary"] == "explicit_start" and known["address_is_instruction_start"], known
        print("PASS x86_64 disassembly with symbol, explicit and uncertain instruction boundaries")

        p.stdin.write(b"q")
        p.stdin.flush()
        assert p.wait(timeout=5) == 0
        print("PASS repeated and concurrent hits, new threads, slots, client disconnect, timeout, signals and detach")


def check_cpp_names(socket):
    library = ARTIFACTS / "libcppsymbols.so"
    with fixture(ARTIFACTS / "breakpoint_fixture", ARTIFACTS / "libfixture.so", library) as (p, _):
        def lookup(pattern, mode):
            output = subprocess.check_output([BIN, "--socket", socket, "symbols",
                                              "--pid", str(p.pid), "--module", library.name,
                                              "--pattern", pattern, "--mode", mode], timeout=10)
            return json.loads(output)["matches"]

        symbol, = lookup("string_argument", "regex")
        assert symbol["mangled_name"] == symbol["name"] and symbol["name"].startswith("_Z")
        assert "basic_string" in symbol["demangled_name"], symbol
        assert "std::string" in symbol["display_name"], symbol
        assert lookup(symbol["name"], "exact") == [symbol]
        assert lookup(symbol["display_name"], "exact") == []
        print("PASS C++ raw matching, full demangling and libstdc++ display aliases")


def check_shutdown(socket, root, state):
    with fixture(ARTIFACTS / "breakpoint_fixture", ARTIFACTS / "libfixture.so",
                 root / "libstripped.so") as (p, addresses):
        with server(socket, state):
            subprocess.run([BIN, "--socket", socket, "breakpoint", "set",
                            "--pid", str(p.pid), "--kind", "software", "--address", addresses[0]],
                           capture_output=True, check=True, timeout=10)
            assert status(p.pid)["TracerPid"] != "0"
        assert status(p.pid)["TracerPid"] == "0"
        p.stdin.write(b"xq")
        p.stdin.flush()
        assert read_line(p) == ["DONE", "1"]
        assert p.wait(timeout=5) == 0
        print("PASS graceful server shutdown releases active breakpoints")


def main():
    with tempfile.TemporaryDirectory(prefix="aidbg-debugger-") as directory:
        root = Path(directory)
        state = root / "state"
        state.mkdir(mode=0o700)
        socket = root / "server.sock"
        with server(socket, state):
            check(socket, root, state, ARTIFACTS / "breakpoint_fixture")
            check(socket, root, state, ARTIFACTS / "breakpoint_fixture_nopie")
            check_cpp_names(socket)
        print("PASS non-PIE ELF virtual addresses")
        check_shutdown(socket, root, state)


if __name__ == "__main__":
    main()
