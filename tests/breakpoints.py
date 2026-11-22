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

from run import ARCH, ARTIFACTS, BIN, server, status
from scripts import mcp


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


def check_aarch64(invoke, pid, address):
    window = invoke("disassemble", "--pid", pid, "--address", address, "--after", "1")
    assert window["boundary"] == "architecture_alignment" and window["address_is_instruction_start"], window
    start = int(address, 16)
    assert [(int(i["address"], 16), i["bytes"], i["mnemonic"]) for i in window["instructions"]] == [
        (start, "1f2003d5", "nop"), (start + 4, "c0035fd6", "ret"),
    ], window
    unaligned = invoke("disassemble", "--pid", pid, "--address", hex(start + 1), "--after", "1")
    assert not unaligned["address_is_instruction_start"], unaligned
    assert unaligned["instructions"] == window["instructions"], unaligned
    print("PASS AArch64 live instruction bytes and four-byte alignment")


def check(socket, root, state, binary):
    normal = ARTIFACTS / "libfixture.so"
    stripped = root / "libstripped.so"
    debug = root / "libstripped.so.debug"
    shutil.copyfile(ARTIFACTS / stripped.name, stripped)
    shutil.copyfile(ARTIFACTS / debug.name, debug)
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

        capabilities = invoke("breakpoint", "capabilities", "--pid", pid)
        assert capabilities["architecture"] == ARCH and capabilities["hardware_execution"], capabilities
        assert capabilities["software_execution"] and capabilities["watch_lengths"] == [1, 2, 4, 8]
        assert capabilities["execution_slots"] > 0 and capabilities["watch_slots"] > 0, capabilities
        if ARCH == "aarch64":
            assert capabilities["shared_execution_and_watch_slots"] == 0, capabilities
            print(f"PASS AArch64 reports {capabilities['execution_slots']} execution slots and {capabilities['watch_slots']} watchpoint slots")
            check_aarch64(invoke, pid, anonymous)
        pc_register = "rip" if ARCH == "x86_64" else "pc"

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
        count = capabilities["execution_slots"]
        if ARCH == "aarch64":
            slots = [hex(int(hit, 16) + 4 * n) for n in range(1, count + 1)]
        spare = [install("--address", address) for address in slots[:count - 1]]
        install("--address", slots[count - 1], error="ResourceExhausted")
        if ARCH == "aarch64":
            watch_addresses = [hex(int(bss, 16) + 8 * n) for n in range(capabilities["watch_slots"] + 1)]
            watch_slots = [install("--kind", "write", "--length", "1", "--address", address)
                           for address in watch_addresses[:-1]]
            install("--kind", "write", "--length", "1", "--address", watch_addresses[-1],
                    error="ResourceExhausted")
            for rule in watch_slots:
                assert remove(rule)["status"] == "removed"
        assert remove(spare.pop())["status"] == "removed"
        spare.append(install("--address", slots[count - 1]))
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
        assert snapshot["threads"][0]["registers"][pc_register] == hit
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
        supported = ["read", "write", "read_write"] if ARCH == "aarch64" else ["write", "read_write"]
        assert capabilities["watch_access"] == supported, capabilities
        assert capabilities["watch_lengths"] == [1, 2, 4, 8], capabilities
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
        print(f"PASS {ARCH} write watchpoints distinguish same-value and changed writes on a new thread")

        rule = install("--kind", "read-write", "--length", "8", "--address", watched)
        p.stdin.write(b"r")
        p.stdin.flush()
        assert read_line(p) == ["READ", "9"]
        row, = saved_events(rule, 1)
        assert row["watch"]["access"] == "read_write" and row["watch"]["write_observed"] is None
        assert row["watch"]["value_changed"] is False
        assert remove(rule)["status"] == "detached"

        writer, = lookup("force_watch", "--module", binary.name)
        writer_address = writer["runtime_address"]
        if ARCH == "aarch64":
            decoded = invoke("disassemble", "--pid", pid, "--address", writer_address,
                             "--before", "0", "--after", str(writer["size"] // 4 - 1))
            store, = [item for item in decoded["instructions"] if item["mnemonic"] == "str"]
            writer_address = store["address"]
        soft_writer = install("--kind", "software", "--address", writer_address)
        watch_writer = install("--kind", "write", "--length", "8", "--address", watched)
        p.stdin.write(b"w")
        p.stdin.flush()
        assert read_line(p) == ["WRITTEN"]
        assert len(saved_events(soft_writer, 1)) == 1
        assert [e["watch"]["value_after"] for e in saved_events(watch_writer, 2)] == ["0x7", "0x9"]
        assert remove(soft_writer)["status"] == "removed"
        assert remove(watch_writer)["status"] == "detached"
        print(f"PASS {ARCH} software breakpoint and watchpoint on the same execution path")

        soft = install("--kind", "software", "--address", hit)
        run_batch(6)
        rows = saved_events(soft, 6)
        assert len({e["tid"] for e in rows}) == 2
        assert all(e["resume_status"] == "resumed" and e["kind"] == "software_execution" for e in rows)
        snapshot = invoke("snapshot", "--event", str(rows[0]["event_id"]))
        assert snapshot["threads"][0]["registers"][pc_register] == hit
        assert remove(soft)["status"] == "detached"
        run_batch(7)
        assert len(events(soft)) == 6

        soft = install("--kind", "software", "--address", hit)
        p.stdin.write(b"f")
        p.stdin.flush()
        assert read_line(p) == ["FORKED"]
        assert status(p.pid)["TracerPid"] == "0"
        print("PASS concurrent software hits, original instructions, rearming, removal and fork cleanup")

        def start_worker():
            p.stdin.write(b"t")
            p.stdin.flush()
            message, tid = read_line(p)
            assert message == "THREAD"
            return int(tid)

        def join_worker():
            p.stdin.write(b"g")
            p.stdin.flush()
            assert read_line(p) == ["JOINED"]

        tid = start_worker()
        leader = install("--address", hit, "--tid", pid, "--all-threads")
        with mcp(BIN, socket) as tool:
            selected = tool("breakpoint_set", pid=p.pid, tid=tid, address=hit)
            assert selected["tid"] == tid, selected
            assert tool("breakpoint_set", pid=p.pid, address=hit)["error"]
        assert leader["tid"] == p.pid
        # Fill each selected thread's bank independently, then fail an overlapping
        # install and verify that both earlier slot maps remain usable.
        for_thread = [hex(int(hit, 16) + 4 * n) for n in range(1, count + 1)] if ARCH == "aarch64" else slots
        spare = [install("--address", address, "--tid", str(t))
                 for t in (p.pid, tid) for address in for_thread[:count - 1]]
        install("--address", for_thread[count - 1], "--tid", pid, error="ResourceExhausted")
        for rule in spare:
            assert remove(rule)["status"] == "removed"
        join_worker()
        assert {e["tid"] for e in saved_events(leader, 3)} == {p.pid}
        assert {e["tid"] for e in saved_events(selected, 3)} == {tid}
        install("--address", hit, "--tid", str(tid), error="not a tracked thread")
        removed = invoke("breakpoint", "remove", "--pid", pid, "--breakpoint-id",
                         str(selected["breakpoint_id"]))
        assert removed["status"] == "already_removed", removed
        # A newly created thread never receives the older thread's scoped rule.
        run_batch(8)
        assert {e["tid"] for e in saved_events(leader, 6)} == {p.pid}
        assert len(events(selected)) == 3
        assert remove(leader)["status"] == "detached"

        tid = start_worker()
        soft = install("--kind", "software", "--address", hit, "--tid", str(tid))
        join_worker()
        assert {e["tid"] for e in saved_events(soft, 3)} == {tid}
        run_batch(9)
        assert len(events(soft)) == 3
        assert status(p.pid)["TracerPid"] == "0"
        soft = install("--kind", "software", "--address", hit, "--tid", pid)
        p.stdin.write(b"f")
        p.stdin.flush()
        assert read_line(p) == ["FORKED"]
        assert status(p.pid)["TracerPid"] == "0"
        assert len(events(soft)) == 0
        print(f"PASS {ARCH} scoped execution, independent hardware slots, exit cleanup, and software recovery")

        if ARCH == "x86_64":
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


def check_callbacks(socket, root):
    binary = ARTIFACTS / "breakpoint_fixture"
    with fixture(binary, ARTIFACTS / "libfixture.so", root / "libstripped.so") as (p, addresses):
        rule_file = root / "rule.ts"
        pc_register = "rip" if ARCH == "x86_64" else "pc"

        def invoke(*args, error=None):
            result = subprocess.run([BIN, "--socket", socket, *args],
                                    capture_output=True, text=True, timeout=10)
            if error is not None:
                assert result.returncode != 0 and error in result.stderr, result
                return None
            assert result.returncode == 0, result
            return json.loads(result.stdout)

        def install(source, *args, error=None):
            rule_file.write_text(source)
            return invoke("breakpoint", "set", "--pid", str(p.pid), "--address", addresses[0],
                          "--rule", rule_file, *args, error=error)

        def command(action, reply):
            p.stdin.write(action)
            p.stdin.flush()
            assert read_line(p)[0] == reply

        def finished(rule, count, snapshot=False):
            until = time.monotonic() + 5
            while True:
                rows = invoke("breakpoint", "events", "--breakpoint-id",
                              str(rule["breakpoint_id"]))["events"]
                if (len(rows) == count and status(p.pid)["TracerPid"] == "0"
                    and (not snapshot or rows[-1]["snapshot_status"] == "saved")):
                    break
                assert time.monotonic() < until, rows
                time.sleep(0.01)
            assert all(row["resume_status"] == "resumed" for row in rows), rows
            if rows:
                assert rows[-1]["callback"]["disarming"], rows
            return rows

        install('defineRule({onHit(hit) { hit.unknown(); }});', error="2339")
        install("const ignored = 1;", error="must call defineRule")
        install("export default 1;", error="default export must be a function")
        assert status(p.pid)["TracerPid"] == "0"

        rule = install(f"""
            let count = 0;
            defineRule({{
                maxHits: 2,
                onHit(hit) {{
                    hit.emit("hit", ++count);
                    hit.emit("ip", hit.registers.{pc_register} ?? null);
                    if (count === 2) hit.snapshot();
                }},
            }});
        """)
        assert rule["callback"]["max_hits"] == 2
        command(b"x", "DONE")
        first, second = finished(rule, 2, snapshot=True)
        assert first["snapshot_status"] == "not_requested" and first["snapshot_id"] is None, first
        for number, row in enumerate([first, second], 1):
            assert row["callback"]["status"] == "complete", row
            assert row["callback"]["output"] == [
                {"label": "hit", "value": number},
                {"label": "ip", "value": int(addresses[0], 16)},
            ], row

        with mcp(BIN, socket) as tool:
            api = tool("script_api", mode="breakpoint")
            assert "defineRule" in api["declarations"] and "readonly view: DataView" in api["declarations"], api
            check = tool("script_check", mode="breakpoint", source=api["example"])
            assert check["status"] == "complete", check
            watch = tool("breakpoint_set", pid=p.pid, address=addresses[-2], kind="write", length=8,
                         rule_source='defineRule({maxHits: 2, onHit(hit) { hit.emit("address", hit.address); }});')
        command(b"w", "WRITTEN")
        for row in finished(watch, 2):
            assert row["kind"] == "hardware_write" and row["snapshot_status"] == "not_requested", row
            assert row["callback"]["output"] == [{"label": "address", "value": int(addresses[-2], 16)}], row

        failure = install('defineRule({onHit(hit) { throw new Error("callback failure"); }});',
                          "--kind", "software")
        command(b"x", "DONE")
        row, = finished(failure, 1)
        assert row["callback"]["status"] == "failed" and "callback failure" in row["callback"]["issue"], row
        assert row["snapshot_status"] == "not_requested"

        timeout = install("defineRule({pauseBudgetMs: 20, onHit(hit) { while (true) {} }});")
        command(b"x", "DONE")
        row, = finished(timeout, 1)
        assert row["callback"]["status"] == "timed_out" and row["pause_ms"] >= 19, row
        filtered = install('''
            let count = 0;
            defineRule({onHit(hit) {
                if (++count === 1) {
                    hit.emit("discarded", count);
                    hit.snapshot();
                    return false;
                }
                hit.emit("accepted", count);
                hit.disable();
            }});
        ''')
        command(b"x", "DONE")
        row, = finished(filtered, 1)
        assert row["callback"]["hit"] == 2 and row["snapshot_status"] == "not_requested", row
        assert row["callback"]["output"] == [{"label": "accepted", "value": 2}], row

        silent = install("export default function onHit(hit: BreakpointHit) { hit.disable(); return false; }")
        command(b"x", "DONE")
        assert not finished(silent, 0)

        script = install(f'''
            let count = 0;
            let saved: DataView | undefined;
            export default function onHit(hit: BreakpointHit) {{
                const read = hit.memory({addresses[-2]}n, 8);
                const view = read.view;
                if (!(view instanceof DataView) || !read.complete || view.byteLength !== 8 ||
                    view.getBigUint64(0) !== 0x0900000000000000n ||
                    view.getBigUint64(0, true) !== 9n || read.bytes !== "0900000000000000") {{
                    throw new Error("incorrect DataView or byte order");
                }}
                if (++count === 1) {{
                    const unavailable = hit.memory(0n, 8);
                    if (unavailable.complete || unavailable.view.byteLength !== 0) {{
                        throw new Error("incorrect unavailable view");
                    }}
                    try {{
                        unavailable.view.getUint8(0);
                        throw new Error("out-of-bounds read succeeded");
                    }} catch (issue) {{
                        if (!(issue instanceof RangeError)) throw issue;
                    }}
                    view.setUint8(0, 0x5a);
                    saved = view;
                }}
                if (count < 108) return false;
                hit.emit("hits", count);
                hit.emit("saved", saved?.getUint8(0) ?? null);
                hit.snapshot();
                hit.disable();
            }}
        ''', "--timeout-ms", "250")
        assert script["callback"] == {"pause_budget_ms": 250}, script
        for _ in range(18):
            command(b"x", "DONE")
        row, = finished(script, 1, snapshot=True)
        assert row["callback"]["hit"] == 108, row
        assert row["callback"]["output"] == [
            {"label": "hits", "value": 108}, {"label": "saved", "value": 0x5a},
        ], row
        print("PASS script-controlled filtering and disarm, persistent DataView, standard byte order and bounds")
        print("PASS TypeScript breakpoint and watchpoint callbacks, registers, optional snapshots, error and timeout recovery")


def check_rule_registry(socket, root):
    with fixture(ARTIFACTS / "breakpoint_fixture", ARTIFACTS / "libfixture.so",
                 root / "libstripped.so") as (process, addresses), mcp(BIN, socket) as tool:
        def command(action, reply):
            process.stdin.write(action)
            process.stdin.flush()
            assert read_line(process)[0] == reply

        def events(bp, expected):
            until = time.monotonic() + 5
            while True:
                rows = tool("breakpoint_events", breakpoint_id=bp["breakpoint_id"])["events"]
                if len(rows) == expected:
                    return rows
                assert len(rows) < expected and time.monotonic() < until, rows
                time.sleep(0.01)

        source = 'let count = 0; defineRule({onHit(hit) { hit.emit("v1", ++count); }});'
        named = tool("rule_define", name="shared", source=source)
        rule_id = named["rule_id"]
        assert named["revision"] == 1 and named["hits"] == 0, named
        assert tool("rule_define", name="invalid", source="const x = 0;")["error"]
        absent = tool("breakpoint_set", pid=process.pid, address=addresses[0],
                      rule_id=rule_id + 1000)
        assert absent["code"] == "RULE_NOT_FOUND", absent
        both = tool("breakpoint_set", pid=process.pid, address=addresses[0],
                    rule_id=rule_id, rule_source=source)
        assert both["code"] == "INVALID_ARGUMENT", both
        execution = tool("breakpoint_set", pid=process.pid, address=addresses[0],
                         kind="software", timeout_ms=300, rule_id=rule_id)
        watch = tool("breakpoint_set", pid=process.pid, address=addresses[-2],
                     kind="write", length=8, timeout_ms=100, rule_id=rule_id)
        assert execution["rule_id"] == watch["rule_id"] == rule_id, (execution, watch)
        denied = tool("rule_remove", rule_id=rule_id)
        assert denied["code"] == "RULE_IN_USE", denied

        command(b"x", "DONE")
        command(b"w", "WRITTEN")
        early_execution, early_watch = events(execution, 6), events(watch, 2)
        for rows, count in [(early_execution, 6), (early_watch, 2)]:
            assert len(rows) == count, rows
            assert all(row["rule_id"] == rule_id and row["rule_revision"] == 1
                       for row in rows), rows
            assert [row["callback"]["output"] for row in rows] == [
                [{"label": "v1", "value": n}] for n in range(1, count + 1)
            ], rows

        wrong_budget = tool("rule_update", rule_id=rule_id, source=
                            'defineRule({pauseBudgetMs: 150, onHit(hit) { hit.emit("rejected", 0); }});')
        assert "pauseBudgetMs" in wrong_budget["error"], wrong_budget
        command(b"x", "DONE")
        command(b"w", "WRITTEN")
        before_execution, before_watch = events(execution, 12), events(watch, 4)
        assert len(before_execution) == 12 and len(before_watch) == 4
        assert all(row["rule_revision"] == 1 for row in before_execution + before_watch)
        assert before_execution[-1]["callback"]["output"] == [{"label": "v1", "value": 12}]
        assert before_watch[-1]["callback"]["output"] == [{"label": "v1", "value": 4}]

        updated = tool("rule_update", rule_id=rule_id, source='''
            let count = 0;
            export default function onHit(hit: BreakpointHit) {
                if (hit.watch) throw new Error("watch only");
                hit.emit("v2", ++count);
            }
        ''')
        assert updated["revision"] == 2 and updated["hits"] == 16, updated
        command(b"w", "WRITTEN")
        command(b"x", "DONE")
        after_execution, after_watch = events(execution, 18), events(watch, 5)
        for before, after, installed in [(before_execution, after_execution, execution),
                                         (before_watch, after_watch, watch)]:
            assert after[:len(before)] == before, after
            assert all(row["breakpoint_id"] == installed["breakpoint_id"]
                       and row["rule_id"] == rule_id and row["rule_revision"] == 2
                       for row in after[len(before):]), after
        assert len(after_watch) == 5 and after_watch[-1]["callback"]["disarming"], after_watch
        assert "watch only" in after_watch[-1]["callback"]["issue"], after_watch
        assert len(after_execution) == 18, after_execution
        assert after_execution[-1]["callback"]["output"] == [{"label": "v2", "value": 6}]
        listed, = tool("rule_list")["rules"]
        assert listed == {"rule_id": rule_id, "name": "shared", "revision": 2, "hits": 23}, listed
        removed = tool("breakpoint_remove", pid=process.pid,
                       breakpoint_id=execution["breakpoint_id"])
        assert removed["status"] == "detached", removed
        assert tool("rule_remove", rule_id=rule_id)["removed"]
        assert tool("rule_remove", rule_id=rule_id)["status"] == "already_removed"
        assert tool("rule_list")["rules"] == []
        print("PASS named rule reuse, update rollback, revision history and independent disarming")


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
            check_callbacks(socket, root)
            check_rule_registry(socket, root)
        print("PASS non-PIE ELF virtual addresses")
        check_shutdown(socket, root, state)


if __name__ == "__main__":
    main()
