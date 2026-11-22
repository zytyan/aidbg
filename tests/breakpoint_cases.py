#!/usr/bin/env python3
"""Exercise breakpoint callback reads on the native debugging cases."""
import json
import platform
import re
import subprocess
import tempfile
import time
from pathlib import Path

from run import ARTIFACTS, BIN, server
from scripts import mcp


def run_case(tool, case):
    fixture = ARTIFACTS / "breakpoint-cases" / case
    run = tool("run", executable=str(fixture), pause_at_entry=True)
    assert run["status"] == "paused", run
    return fixture, run


def continue_to_exit(tool, run, stdout):
    run_id = run["run_id"]
    assert tool("run_continue", run_id=run_id)["status"] in ("running", "finished")
    until = time.monotonic() + 10
    while True:
        result = tool("run_status", run_id=run_id)
        if result["status"] == "finished":
            break
        assert result["status"] == "running" and time.monotonic() < until, result
        time.sleep(0.02)
    assert result["result"]["exit_code"] == 0 and result["result"]["stdout"] == stdout, result


def callback_output(tool, bp):
    rows = tool("breakpoint_events", breakpoint_id=bp["breakpoint_id"])["events"]
    assert rows, bp
    for row in rows:
        assert row["callback"]["status"] == "complete", row
        assert row["resume_status"] == "resumed", row
        yield row, {item["label"]: item["value"] for item in row["callback"]["output"]}


def line_addresses(tool, fixture, run, symbol, lines):
    match, = tool("symbols", pid=run["pid"], module=fixture.name, pattern=symbol)["matches"]
    assembly = subprocess.check_output(["objdump", "-d", "-l", f"--disassemble={symbol}", fixture],
                                       text=True)
    instructions = []
    line = None
    for row in assembly.splitlines():
        location = re.search(rf"/{fixture.name}\.cc?:([0-9]+)", row)
        address = re.match(r"\s+([a-f0-9]+):\s", row)
        if location:
            line = int(location[1])
        elif address:
            instructions.append((line, int(address[1], 16)))
    bias = int(match["runtime_address"], 16) - instructions[0][1]
    addresses = []
    for line in lines:
        indices = [i for i, (source_line, _) in enumerate(instructions) if source_line == abs(line)]
        index = indices[0] if line > 0 else indices[-1] + 1
        addresses.append(hex(bias + instructions[index][1]))
    return addresses


def d01_core_evidence(tool, root):
    fixture = ARTIFACTS / "breakpoint-cases" / "D01"
    crashed = tool("run", executable=str(fixture),
                   signal_source='dbg.onSignal(builtins.SIGSEGV, () => { dbg.coredump("full"); });')
    crash, = crashed["signals"]
    dump_id = crash["coredump"]["dump_id"]
    target = tool("core_open", dump_id=dump_id, executable=str(fixture))["target_id"]
    report = tool("inspect", target_id=target, expressions=["account->id", "account->profile"])
    assert report["status"] == "complete", report
    assert report["frame"]["function"] == "quota_for", report
    account, = report["frame"]["args"]["items"]
    assert account["name"] == "account", account
    assert account["value"]["result"]["symbol"]["name"] == "accounts", account
    assert account["value"]["result"]["symbol"]["offset"] == 16, account
    assert [row["value"]["result"]["value"] for row in report["results"]] == [9, "0x0"], report
    partial = tool("inspect", target_id=target, expressions=["account->id", "account->profile->quota"])
    assert partial["status"] == "partial", partial
    assert partial["results"][0]["value"]["result"]["value"] == 9, partial
    assert partial["results"][1]["value"]["code"] == "NULL_POINTER", partial
    types = tool("script_run", target_id=target, source='return dbg.types("Account");')
    kind, = types["return_value"]["items"]
    assert [field["name"] for field in kind["fields"]] == ["id", "profile"], types
    assert tool("core_close", target_id=target)["closed"]
    path = root / "d01.core.zst"
    tool("coredump", dump_id=dump_id, output=str(path))
    target = tool("core_open", path=str(path), executable=str(fixture))["target_id"]
    local = tool("inspect", target_id=target, expression="account->id")
    assert local["result"]["value"] == 9 and local["frame"]["function"] == "quota_for", local
    assert tool("core_close", target_id=target)["closed"]
    print("PASS D01 direct retained and local core inspection includes crash arguments and values")


def d02(tool):
    _, run = run_case(tool, "D02")
    queue = tool("inspect", run_id=run["run_id"], expression="::queue")["result"]
    data, head_type, size = queue["type"]["fields"]
    assert (data["name"], data["element_type"], data["element_count"]) == ("data", "unsigned int", 4), queue
    assert (head_type["name"], size["name"]) == ("head", "size"), queue
    head = tool("inspect", run_id=run["run_id"], expression="::queue.head")["result"]
    bp = tool("breakpoint_set", run_id=run["run_id"], address=head["address"],
              kind="write", length=4, timeout_ms=500)
    assert bp.get("breakpoint_id"), bp
    continue_to_exit(tool, run, "10 20 30 10\n")
    rows = tool("breakpoint_events", breakpoint_id=bp["breakpoint_id"])["events"]
    assert [(row["watch"]["value_before_decimal"], row["watch"]["value_after_decimal"])
            for row in rows] == [("0", "1"), ("1", "2"), ("2", "0"), ("0", "1")], rows
    assert all("callback" not in row and row["resume_status"] == "resumed" for row in rows), rows
    print("PASS D02 plain watchpoint still records queue head changes")


def d06(tool):
    _, run = run_case(tool, "D06")
    flags = tool("inspect", run_id=run["run_id"], expression="::flags")["result"]
    fixture = ARTIFACTS / "breakpoint-cases" / "D06"
    enable, = tool("symbols", pid=run["pid"], module=fixture.name, pattern="enable")["matches"]
    start = enable["runtime_address"]
    references = tool("xref", run_id=run["run_id"], address=flags["address"],
                      start=start, end=hex(int(start, 16) + enable["size"]), instruction_references=True)
    assert any(item["function"] == "enable" and item["source_line"]["line"]
               and item["kind"] in ("write", "pc_relative") for item in references["matches"]), references
    bp = tool("breakpoint_set", run_id=run["run_id"], address=flags["address"],
              kind="write", length=4, rule_source='''
        defineRule({maxHits: 1, onHit(hit) {
            hit.emit("before", hit.watch?.valueBefore ?? null);
            hit.emit("after", hit.watch?.valueAfter ?? null);
            hit.emit("changed", hit.watch?.changed ?? null);
        }});
    ''')
    assert bp.get("rule_id") and bp["rule_revision"] == 1, bp
    continue_to_exit(tool, run, "before=5\nafter=2\n")
    (row, output), = callback_output(tool, bp)
    assert output == {"before": 5, "after": 2, "changed": True}, row
    assert row["watch"]["value_before_decimal"] == str(output["before"]), row
    assert row["watch"]["value_after_decimal"] == str(output["after"]), row
    assert row["watch"]["value_changed"] == output["changed"], row
    context = row["stop_context"]
    assert context["site"]["function"] == "enable" and context["site"]["source_line"]["line"], row
    assert context["watched_symbol"]["name"] == "flags", row
    requested, = context["args"]["items"]
    assert requested["name"] == "requested" and requested["value"]["result"]["value"] == 2, row
    assert row["rule_id"] == bp["rule_id"] and row["callback"]["disarming"], row
    _, run = run_case(tool, "D06")
    flags = tool("inspect", run_id=run["run_id"], expression="::flags")["result"]
    setup = tool("script_run", run_id=run["run_id"], source=f'''
        dbg.watchpoint({flags["address"]}n, 4, "write", hit => {{
            hit.emit("before", hit.watch?.valueBefore ?? null);
            hit.emit("after", hit.watch?.valueAfter ?? null);
            hit.emit("changed", hit.watch?.changed ?? null);
        }}, {{tid: {run["pid"]}}});
    ''')
    assert setup["status"] == "complete", setup
    bp, = setup["breakpoint_ids"]
    continue_to_exit(tool, run, "before=5\nafter=2\n")
    (_, output), = callback_output(tool, {"breakpoint_id": bp})
    assert output == {"before": 5, "after": 2, "changed": True}, output
    print("PASS D06 RPC and live script watch values match the callback and event")


def d09(tool):
    fixture, run = run_case(tool, "D09")
    # Stop immediately after the last instruction attributed to ++job.attempts.
    address, = line_addresses(tool, fixture, run, "_ZL14schedule_retryv", [-17])
    bp = tool("breakpoint_set", run_id=run["run_id"], address=address,
              kind="software", timeout_ms=500, rule_source='''
        defineRule({onHit(hit) {
            if (hit.watch !== undefined) throw new Error("unexpected watch data");
            const local = hit.inspect("job.attempts");
            const original = hit.inspect("::jobs[0].attempts");
            if (!hit.locals().items.some(entry => entry.name === "job")) throw new Error("missing local job");
            if (!hit.globals("*jobs").items.some(entry => entry.name === "jobs")) throw new Error("missing global jobs");
            if (!hit.types("Job").items.some(entry => entry.name === "Job")) throw new Error("missing type Job");
            const backing = hit.inspect("::jobs._M_elems[0].attempts");
            if (original.result?.value !== backing.result?.value || hit.inspect("::jobs[9]").code !== "OUT_OF_BOUNDS") throw new Error("array indexing");
            if (!local.result || !original.result) {
                throw new Error(local.issue ?? original.issue ?? "missing value");
            }
            hit.emit("copy", local.result.value);
            hit.emit("original", original.result.value);
        }});
    ''')
    assert bp.get("breakpoint_id"), bp
    continue_to_exit(tool, run, "fetch=0\nparse=1\nsave=0\n")
    rows = list(callback_output(tool, bp))
    assert rows and all(output == {"copy": 1, "original": 0} for _, output in rows), rows
    print("PASS D09 callback reads the local copy and the original array via DWARF")


def live_events(tool, breakpoint_id):
    result = tool.raw("breakpoint_events", breakpoint_id=breakpoint_id)
    rows = result["structuredContent"]["events"]
    texts = [part["text"] for part in result["content"] if part["type"] == "text"]
    fields = {int(text.split()[1].rstrip(",")): text.splitlines()[1:]
              for text in texts if text.startswith("Event ")}
    return [(row, fields.get(row["event_id"], [])) for row in rows]


def d09_live(tool, root, socket):
    fixture, run = run_case(tool, "D09")
    body, = line_addresses(tool, fixture, run, "_ZL14schedule_retryv", [-17])
    entry, = tool("symbols", pid=run["pid"], module=fixture.name,
                  pattern="_ZL14schedule_retryv")["matches"]
    entry = entry["runtime_address"]
    api = tool("script_api", mode="live")
    assert "softwareBreakpoint" in api["declarations"], api
    assert tool("script_run", run_id=run["run_id"], target_id="core-test", source="")["error"]
    script = f"""
        const install = dbg.hardwareBreakpoint;
        let hits = 0;
        let ended: BreakpointHit | undefined;
        const onHit = (hit: BreakpointHit) => {{
            if (ended) {{
                try {{ ended.emit("late", 0); throw new Error("stale hit accepted"); }}
                catch (e) {{ if (String(e).includes("stale hit accepted")) throw e; }}
            }}
            ended = hit;
            try {{ install({entry}n); throw new Error("nested install accepted"); }}
            catch (e) {{ if (String(e).includes("nested install accepted")) throw e; }}
            hit.emit("count", ++hits);
            if (hit.address === {body}n) {{
                hit.emit("copy", hit.inspect("job.attempts").result?.value ?? null);
                hit.emit("original", hit.inspect("::jobs._M_elems[0].attempts").result?.value ?? null);
                const bytes = new Uint8Array([0xff, 0x0a, 0x0c, 0x33, 0x36, 0xff]);
                hit.emit("data", new DataView(bytes.buffer, 1, 4));
                hit.emit("array", bytes.subarray(1, 5));
                bytes[1] = 0xff;
                hit.emit("wide", 18446744073709551617n);
                hit.emit("negative", -42n);
                hit.emit("float", 1.25);
                hit.emit("pc", hit.address, {{kind: "pointer"}});
                if (hits === 3) return false;
            }}
        }};
        install({entry}n, onHit, {{tid: {run["pid"]}, timeoutMs: 500}});
        install({body}n, onHit, {{timeoutMs: 500}});
    """
    failed = tool("script_run", run_id=run["run_id"], source=f"""
        dbg.softwareBreakpoint({body}n);
        dbg.hardwareBreakpoint({entry}n);
        dbg.softwareBreakpoint({body}n);
    """)
    assert failed["status"] == "failed" and "already exists" in failed["issue"], failed
    assert failed["breakpoint_ids"] == [], failed
    result = tool("script_run", run_id=run["run_id"], source=script)
    assert result["status"] == "complete", result
    entry_id, body_id = result["breakpoint_ids"]
    assert tool("run_status", run_id=run["run_id"])["status"] == "paused"
    continue_to_exit(tool, run, "fetch=0\nparse=1\nsave=0\n")
    (entry_row, entry_fields), = live_events(tool, entry_id)
    assert entry_row["tid"] == run["pid"] and entry_fields == ["count: 1 0x1"], entry_row
    records = live_events(tool, body_id)
    assert len(records) == 2, records
    (body_row, body_fields), (later_row, later_fields) = records
    assert [body_row["callback"]["hit"], later_row["callback"]["hit"]] == [1, 3], records
    assert later_fields == ["count: 4 0x4", *body_fields[1:]], records
    assert body_row["callback"]["status"] == "complete", body_row
    output = {item["label"]: item["value"] for item in body_row["callback"]["output"]}
    assert output["wide"] == 18446744073709551617 and output["pc"] == body, output
    assert body_fields == [
        "count: 2 0x2", "copy: 1 0x1", "original: 0 0x0", "data: 0a 0c 33 36",
        "array: 0a 0c 33 36", "wide: 18446744073709551617 0x10000000000000001",
        "negative: -42 -0x2a", "float: 1.25 f64 0x3ff4000000000000", f"pc: {body}",
    ], body_fields

    release = root / "release-d09"
    run = tool("run", executable=str(fixture), detach=True,
               env={"AIDBG_WAIT_RELEASE": f"file:{release}"})
    assert run["status"] == "running", run
    body, = line_addresses(tool, fixture, run, "_ZL14schedule_retryv", [-17])
    entry, = tool("symbols", pid=run["pid"], module=fixture.name,
                  pattern="_ZL14schedule_retryv")["matches"]
    source = root / "d09-live.ts"
    source.write_text(f"""
        function factory() {{
            let count = 0;
            return (hit: BreakpointHit) => hit.emit("local", ++count);
        }}
        dbg.hardwareBreakpoint({entry['runtime_address']}n, factory());
        dbg.hardwareBreakpoint({body}n, factory());
    """)
    result = subprocess.run([BIN, "--socket", socket, "script-run", "--run-id", run["run_id"],
                             "--source", source], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result
    result = json.loads(result.stdout)
    assert result["status"] == "complete", result
    assert tool("run_status", run_id=run["run_id"])["status"] == "running"
    release.touch()
    until = time.monotonic() + 10
    while True:
        status = tool("run_status", run_id=run["run_id"])
        if status["status"] == "finished":
            break
        assert time.monotonic() < until, status
        time.sleep(0.02)
    assert status["result"]["exit_code"] == 0, status
    a, b = [live_events(tool, bp) for bp in result["breakpoint_ids"]]
    assert [fields for _, fields in a] == [["local: 1 0x1"]], a
    assert [fields for _, fields in b] == [["local: 1 0x1"], ["local: 2 0x2"], ["local: 3 0x3"]], b
    print("PASS D09 live setup, paused and running state, closures, DWARF, suppression, and typed text")


def d09_exports(tool, socket):
    source = """let n = 0;
        export function someHit(hit: BreakpointHit) { hit.emit("n", ++n); }
        export function otherHit(hit: BreakpointHit) { hit.emit("n", ++n); }
    """
    rule = tool("rule_define", name="live exports", mode="exports", source=source)
    assert rule["exports"] == ["otherHit", "someHit"], rule
    assert tool("rule_define", name="duplicate", mode="exports", source=source)["error"]
    assert tool("rule_define", name="async", mode="exports",
                source="export async function asyncHandler() {}")["error"]
    runs = []
    for _ in range(2):
        fixture, run = run_case(tool, "D09")
        body, = line_addresses(tool, fixture, run, "_ZL14schedule_retryv", [-17])
        entry, = tool("symbols", pid=run["pid"], module=fixture.name,
                      pattern="_ZL14schedule_retryv")["matches"]
        with mcp(BIN, socket) as reconnected:
            a = reconnected("breakpoint_set", run_id=run["run_id"], tid=run["pid"],
                            address=entry["runtime_address"], handler="$.someHit")
            b = reconnected("breakpoint_set", run_id=run["run_id"], address=body, handler="$.otherHit")
        assert a["tid"] == run["pid"] and a["rule_revision"] == b["rule_revision"] == 1, (a, b)
        runs.append((run, a["breakpoint_id"], b["breakpoint_id"]))
    assert tool("rule_remove", rule_id=rule["rule_id"])["code"] == "RULE_IN_USE"
    assert tool("rule_update", rule_id=rule["rule_id"],
                source='export function someHit() {}')["error"]
    updated = tool("rule_update", rule_id=rule["rule_id"], source=source.replace("n = 0", "n = 9"))
    assert updated["revision"] == 2, updated
    for run, a, b in runs:
        continue_to_exit(tool, run, "fetch=0\nparse=1\nsave=0\n")
        rows = live_events(tool, a) + live_events(tool, b)
        assert all(row["rule_revision"] == 2 for row, _ in rows), rows
        assert [fields for _, fields in rows] == [["n: 10 0xa"], ["n: 11 0xb"], ["n: 12 0xc"], ["n: 13 0xd"]], rows
    assert tool("rule_remove", rule_id=rule["rule_id"])["removed"]
    print("PASS named exports share state per target and update both breakpoints together")


def d09_runtime_failure(tool):
    fixture, run = run_case(tool, "D09")
    body, = line_addresses(tool, fixture, run, "_ZL14schedule_retryv", [-17])
    entry, = tool("symbols", pid=run["pid"], module=fixture.name,
                  pattern="_ZL14schedule_retryv")["matches"]
    entry = entry["runtime_address"]
    result = tool("script_run", run_id=run["run_id"], source=f"""
        dbg.softwareBreakpoint({entry}n, () => {{ Promise.resolve(0).then(() => {{}}); }});
        dbg.hardwareBreakpoint({body}n, hit => hit.emit("should not run", 0));
    """)
    assert result["status"] == "complete", result
    a, b = result["breakpoint_ids"]
    continue_to_exit(tool, run, "fetch=0\nparse=1\nsave=0\n")
    (row, _), = live_events(tool, a)
    assert row["callback"]["status"] == "failed" and "synchronous" in row["callback"]["issue"], row
    assert live_events(tool, b) == []

    fixture, run = run_case(tool, "D09")
    body, = line_addresses(tool, fixture, run, "_ZL14schedule_retryv", [-17])
    entry, = tool("symbols", pid=run["pid"], module=fixture.name,
                  pattern="_ZL14schedule_retryv")["matches"]
    existing = tool("script_run", run_id=run["run_id"], source=f"""
        dbg.softwareBreakpoint({entry["runtime_address"]}n, hit => hit.emit("survived", 1));
    """)
    preserved, = existing["breakpoint_ids"]
    poisoned = tool("script_run", run_id=run["run_id"], source=f"""
        dbg.hardwareBreakpoint({body}n, () => {{}});
        Promise.resolve(0).then(() => {{}});
    """)
    assert poisoned["status"] == "failed" and "synchronous" in poisoned["issue"], poisoned
    assert poisoned["breakpoint_ids"] == [], poisoned
    result = tool("script_run", run_id=run["run_id"], source=f"""
        dbg.hardwareBreakpoint({body}n, () => {{ while (true) {{}} }}, {{timeoutMs: 30}});
    """)
    assert result["status"] == "complete", result
    point, = result["breakpoint_ids"]
    continue_to_exit(tool, run, "fetch=0\nparse=1\nsave=0\n")
    assert len(live_events(tool, preserved)) == 1
    (row, _), = live_events(tool, point)
    assert row["callback"]["status"] == "timed_out" and row["callback"]["disarming"], row
    print("PASS queued jobs disarm a shared runtime and callback timeout disarms its breakpoint")


def d10(tool):
    fixture, run = run_case(tool, "D10")
    before, after = line_addresses(tool, fixture, run, "main", [24, 25])
    rule = tool("rule_define", name="buffer view", source='''
        defineRule({onHit(hit) {
            const preview = hit.inspect("first").result?.preview;
            if (!preview || preview.status !== "complete") throw new Error("missing string preview");
            hit.emit("text", preview.text);
            if (preview.text === "south") {
                const second = hit.inspect("second").result?.preview;
                if (!second || second.status !== "complete") throw new Error("missing second view");
                hit.emit("otherView", { text: second.text, address: second.address, length: second.length },
                         { kind: "json" });
            }
            const view = hit.inspect("first._M_str");
            const address = view.result?.value;
            if (typeof address !== "bigint") throw new Error(view.issue ?? "missing buffer pointer");
            const value = hit.memory(address, 5);
            const missing = hit.memory(0n, 5);
            if (!value.complete || missing.complete || missing.bytes !== "") {
                throw new Error("incorrect memory coverage");
            }
            hit.emit("address", address);
            hit.emit("bytes", value.bytes);
        }});
    ''')
    points = [tool("breakpoint_set", run_id=run["run_id"], address=address, kind="software",
                   rule_id=rule["rule_id"], timeout_ms=500) for address in (before, after)]
    assert all(bp.get("breakpoint_id") for bp in points), points
    continue_to_exit(tool, run, "south south\n")
    (first_row, first), = callback_output(tool, points[0])
    (second_row, second), = callback_output(tool, points[1])
    assert first_row["rule_id"] == second_row["rule_id"] == rule["rule_id"]
    assert first["address"] == second["address"], (first, second)
    assert [first["bytes"], second["bytes"]] == [b"north".hex(), b"south".hex()], (first, second)
    assert [first["text"], second["text"]] == ["north", "south"], (first, second)
    assert second["otherView"] == {"text": "south", "address": hex(second["address"]), "length": 5}, second
    assert tool("rule_remove", rule_id=rule["rule_id"])["removed"]
    print("PASS D10 callback reads north and south at the same buffer address")


def d07_ordered_trace(tool):
    fixture, run = run_case(tool, "D07")
    before, after = line_addresses(tool, fixture, run, "remove_next", [17, 18])
    result = tool("breakpoint_workflow", run_id=run["run_id"],
                  points=[{"address": pc, "kind": "software", "expressions": ["removed->next"]}
                          for pc in (before, after)], timeout_ms=2000)
    assert result["status"] == "complete", result
    first, second = result["return_value"]
    assert [point["observed_hits"] for point in result["points"]] == [1, 1], result
    assert [first["instruction_pc"], second["instruction_pc"]] == [before, after], result
    assert first["tid"] == second["tid"], result
    assert first["callback"]["output"][0]["value"]["result"]["value"] != "0x0", result
    assert second["callback"]["output"][0]["value"]["result"]["value"] == "0x0", result
    print("PASS D07 ordered workflow shows the link becoming null before its next use")


def d08_memory_diff(tool):
    fixture, run = run_case(tool, "D08")
    before, after = line_addresses(tool, fixture, run, "main", [20, 21])
    result = tool("breakpoint_workflow", run_id=run["run_id"],
                  points=[{"address": pc, "kind": "software", "expressions": ["::rows"]}
                          for pc in (before, after)], timeout_ms=2000)
    assert result["status"] == "complete", result
    first, second = result["return_value"]
    assert [point["observed_hits"] for point in result["points"]] == [1, 1], result
    def capture(row):
        data = row["callback"]["output"][0]["value"]["result"]
        return {"address": data["address"], "length": data["type"]["byte_size"], "bytes": data["bytes"]}
    changes = tool("memory_diff", before=capture(first), after=capture(second))
    assert changes["complete"] and changes["compared_bytes"] == 40, changes
    assert [(row["offset"], row["before"], row["after"]) for row in changes["changes"]] == [
        (4, "2e", "00"), (12, "0c", "00"), (16, "65", "00"),
    ], changes
    short = capture(second)
    short["bytes"] = short["bytes"][:16 * 2]
    partial = tool("memory_diff", before=capture(first), after=short)
    assert not partial["complete"] and partial["compared_bytes"] == 16, partial
    assert partial["first_uncompared_address"] == hex(int(short["address"], 16) + 16), partial
    print("PASS D08 before/after byte diff identifies the changed marker")


def live_workflow(tool):
    fixture, run = run_case(tool, "D09")
    rid, pid = run["run_id"], run["pid"]
    before, after = line_addresses(tool, fixture, run, "_ZL14schedule_retryv", [17, -17])
    caps = tool("breakpoint_capabilities", run_id=rid)
    assert caps["execution_slots"] == tool("breakpoint_capabilities")["execution_slots"], caps
    assert caps["watch_slots"] > 0, caps
    rejected = tool("inspect", pid=pid, expression="::jobs[0].attempts")
    assert rejected["code"] == "USE_RUN_ID" and rejected["hint"] == "use run_id", rejected
    rejected = tool("breakpoint_set", pid=pid, address=before)
    assert rejected["code"] == "USE_RUN_ID", rejected
    for name, args in [("inspect", {"expression": "::jobs[0].attempts"}),
                       ("breakpoint_set", {"address": before})]:
        rejected = tool(name, pid=pid, run_id=rid, **args)
        assert rejected["code"] == "CONFLICTING_TARGET", rejected

    before_rows = tool("breakpoint_events")["events"]
    step = caps["execution_alignment"]
    addresses = [int(before, 16) + n * step for n in range(caps["execution_slots"] + 1)]
    setup = tool("script_run", run_id=rid, source="\n".join(
        f"dbg.hardwareBreakpoint({address}n);" for address in addresses))
    assert setup["status"] == "failed" and "slots exhausted" in setup["issue"], setup
    assert setup["breakpoint_ids"] == [], setup
    assert tool("breakpoint_list", run_id=rid)["breakpoints"] == []
    assert all(row["execution"] == 0 for row in tool("breakpoint_capabilities", run_id=rid)["used_slots"])
    assert tool("breakpoint_events")["events"] == before_rows
    report = tool("script_run", run_id=rid, source=f"""
        export default async function main() {{
            const before = dbg.hardwareBreakpoint({before}n, hit => {{
                hit.emit("attempts", hit.inspect("job.attempts").result?.value ?? null);
            }});
            const after = dbg.hardwareBreakpoint({after}n, hit => {{
                hit.emit("attempts", hit.inspect("job.attempts").result?.value ?? null);
                hit.emit("wide", 18446744073709551617n);
            }});
            dbg.continue();
            const events = await dbg.events();
            return {{
                before: events.find(e => e.breakpoint_id === before.id)?.callback?.output[0]?.value,
                after: events.find(e => e.breakpoint_id === after.id)?.callback?.output[0]?.value,
                address: events.find(e => e.breakpoint_id === after.id)?.address,
                wide: events.find(e => e.breakpoint_id === after.id)?.callback?.output[1]?.value,
            }};
        }}
    """)
    assert report["status"] == "complete", report
    assert report["return_value"] == {
        "before": 0, "after": 1, "address": after, "wide": {"$bigint": "18446744073709551617"},
    }, report
    assert len(report["breakpoint_ids"]) == 2, report

    fixture, run = run_case(tool, "D09")
    after, = line_addresses(tool, fixture, run, "_ZL14schedule_retryv", [-17])
    rejected = tool("script_run", run_id=run["run_id"], source=f"""
        export {{}};
        dbg.softwareBreakpoint({after}n, hit => hit.emit("unexpected", 1));
        dbg.continue();
        if ((await dbg.events()).length > 0) throw new Error("reject after hits");
    """)
    assert rejected["status"] == "failed" and "reject after hits" in rejected["issue"], rejected
    assert rejected["breakpoint_ids"] == [], rejected
    assert all(row["pid"] != run["pid"] for row in tool("breakpoint_events")["events"])
    print("PASS D09 transactional slot exhaustion, target error codes and single-call orchestration")


def line_update_and_bundle(tool, root):
    _, run = run_case(tool, "D06")
    rid = run["run_id"]
    unavailable = tool("breakpoint_set", run_id=rid, file="D06.c", line=999, kind="software")
    assert unavailable["code"] == "LINE_UNAVAILABLE", unavailable
    line = tool("breakpoint_set", run_id=rid, file="D06.c", line=12, kind="software",
                rule_source='defineRule({onHit(hit) { hit.emit("line", 12); }});')
    assert line.get("breakpoint_id"), line
    next_line = tool("breakpoint_set", run_id=rid, file="D06.c", line=16, kind="software")
    assert next_line.get("breakpoint_id"), next_line
    rule = tool("rule_define", name="bundle D06",
                source='defineRule({onHit(hit) { hit.emit("updated", 16n); }});')
    update = {"breakpoint_id": line["breakpoint_id"], "address": next_line["address"],
              "rule_id": rule["rule_id"]}
    failed = tool("breakpoint_update", **update)
    assert "already exists" in failed["message"], failed
    assert tool("breakpoint_remove", run_id=rid, breakpoint_id=next_line["breakpoint_id"])
    changed = tool("breakpoint_update", **update)
    assert changed["breakpoint_id"] == line["breakpoint_id"] and changed["rule_revision"] == 2, changed
    flags = tool("inspect", run_id=rid, expression="::flags")["result"]["address"]
    live = tool("script_run", run_id=rid, source=f"""
        const label = "from closure";
        dbg.watchpoint({flags}n, 4, "write", hit => {{
            hit.emit(label, hit.watch?.valueAfter ?? null);
        }}, {{tid: {run["pid"]}}});
    """)
    assert live["status"] == "complete", live
    watch_id, = live["breakpoint_ids"]

    dump = tool("coredump", pid=run["pid"], output=str(root / "breakpoint.core.zst"), mode="stack")
    assert dump.get("dump_id"), dump
    bundle_path = root / "breakpoint-replay"
    bundle = tool("export_bundle", dump_id=dump["dump_id"], output=str(bundle_path))
    assert bundle["status"] == "complete", bundle
    points = json.loads((bundle_path / "breakpoints.json").read_text())
    point = next(point for point in points if point["breakpoint_id"] == changed["breakpoint_id"])
    watch = next(point for point in points if point["breakpoint_id"] == watch_id)
    assert watch["live"]["ordinal"] == 1 and watch["thread"] == "leader", watch
    assert point["address"] == changed["address"] and point["module_offset"], point
    assert 'hit.emit("updated", 16n)' in (bundle_path / "rules" / (point["source"] + ".ts")).read_text()
    continue_to_exit(tool, run, "before=5\nafter=2\n")
    (row, output), = callback_output(tool, changed)
    assert row["rule_revision"] == 2 and output == {"updated": 16}, row

    restored = tool("restore_breakpoints", launch=True, bundle=str(bundle_path))
    assert "run_id" in restored, restored
    replay = tool("run_status", run_id=restored["run_id"])
    assert replay["status"] == "paused", replay
    restored_point, restored_watch = restored["breakpoints"]
    assert restored_point["original_breakpoint_id"] == changed["breakpoint_id"], restored
    assert restored_watch["original_breakpoint_id"] == watch_id, restored
    continue_to_exit(tool, replay, "before=5\nafter=2\n")
    (_, output), = callback_output(tool, restored_point)
    assert output == {"updated": 16}, output
    (_, output), = callback_output(tool, restored_watch)
    assert output == {"from closure": 2}, output

    _, run = run_case(tool, "D06")
    point = tool("breakpoint_set", run_id=run["run_id"], file="D06.c", line=12, kind="software",
                 rule_source='defineRule({onHit(hit) { hit.emit("bad", {a: 1} as any); }});')
    continue_to_exit(tool, run, "before=5\nafter=2\n")
    row, = tool("breakpoint_events", breakpoint_id=point["breakpoint_id"])["events"]
    assert row["callback"]["status"] == "failed", row
    assert "emit expects a scalar value or byte view" in row["callback"]["issue"], row
    print("PASS D06 file:line hit, in-place update, bundle restore and emit error")


def shared_live_and_core(tool, root):
    fixture, run = run_case(tool, "D09")
    rid, pid = run["run_id"], run["pid"]
    matches = tool("symbols", pid=pid, module=str(fixture), pattern="*", mode="glob", limit=512)
    assert matches["matches"] and all(m["module"]["path"] == str(fixture) for m in matches["matches"]), matches
    live = tool("inspect", run_id=rid, expression="::jobs", expand={"offset": 1, "limit": 1},
                timeout_ms=1500)
    assert live["status"] == "complete" and live["children"]["next_offset"] == 2, live
    assert live["children"]["items"][0]["expression"] == "::jobs[1]", live

    core = root / "uploaded.core.zst"
    dump = tool("coredump", pid=pid, output=str(core), mode="full")
    opened = tool("core_open", path=str(core), executable=str(fixture), upload=True)
    assert opened["analysis_host"] == "server" and opened["dump_id"] != dump["dump_id"], opened
    retained = tool("core_retain", dump_id=opened["dump_id"], retention_secs=7200)
    assert retained["dump_id"] == opened["dump_id"], retained
    target = opened["target_id"]
    matches = tool("symbols", target_id=target, module=str(fixture), pattern="*", mode="glob", limit=512)
    assert matches["matches"] and all(m["module"]["path"] == str(fixture) for m in matches["matches"]), matches
    offline_types = tool("script_api", mode="offline")["declarations"]
    live_types = tool("script_api", mode="live")["declarations"]
    assert offline_types.split("declare const dbg:")[0] == live_types.split("declare const dbg:")[0]
    rejected = tool("script_check", mode="offline", target_id=target, source="dbg.continue();")
    assert rejected["status"] == "failed" and any(d["code"] == "2339" for d in rejected["diagnostics"]), rejected
    rejected = tool("script_check", mode="live",
                    source='dbg.watchpoint(0n, 4, "invalid", () => {});')
    assert rejected["status"] == "failed" and any(d["code"] == "2345" for d in rejected["diagnostics"]), rejected
    offline_source = """
const thread = dbg.threads()[0];
const frame = thread && dbg.frames(thread.tid)[0];
if (!frame) throw new Error("missing core frame");
const jobs: DebugValue = dbg.inspect("::jobs", {frame, expand: {offset: 1, limit: 1}});
dbg.printVal("::jobs[1].attempts", {frame});
dbg.emit("object", { slots: [1, 2] }, {kind: "json"});
return jobs.children;
"""
    check = tool("script_check", mode="offline", target_id=target, source=offline_source)
    assert check["status"] == "complete", check
    result = tool("script_run", target_id=target, timeout_ms=2000, source=offline_source)
    assert result["stop_reason"] == "completed", result
    assert (result["output"][0]["value"]["result"] or {}).get("value") == 1, result
    assert result["output"][1]["value"] == {"slots": [1, 2]}, result
    assert result["return_value"]["next_offset"] == live["children"]["next_offset"], result
    checked = tool("script_check", mode="live", source=offline_source)
    assert checked["status"] == "complete", checked
    live_setup = tool("script_run", run_id=rid, source=offline_source, timeout_ms=2000)
    assert live_setup["status"] == "complete" and live_setup["breakpoint_ids"] == [], live_setup
    assert live_setup["output"][0]["value"]["result"]["value"] == 1, live_setup
    assert live_setup["output"][1] == result["output"][1], live_setup
    assert live_setup["return_value"]["next_offset"] == result["return_value"]["next_offset"], live_setup
    assert tool("run_status", run_id=rid)["status"] == "paused"
    observed = tool("observe_threads", target_id=target)
    assert observed["source"] == "core" and observed["samples"] == 1, observed
    assert observed["timeline"][0]["tid"] == pid and observed["timeline"][0]["pc"], observed
    tool("core_close", target_id=target)

    found, = tool("symbols", pid=pid, module=str(fixture), pattern="_ZL14schedule_retryv")["matches"]
    source = f"""
dbg.softwareBreakpoint({found["runtime_address"]}n, hit => {{
    const memory: DebugMemory = hit.memory(hit.address, 1);
    hit.printVal("::jobs", {{expand: {{limit: 1}}}});
    hit.emit("memory", {{ bytes: memory.bytes, complete: memory.complete }}, {{kind: "json"}});
}});
dbg.continue();
const events: readonly LiveBreakpointEvent[] = await dbg.events();
return events.map(event => ({{pc: event.instruction_pc, output: event.callback?.output}}));
"""
    checked = tool("script_check", mode="live", source=source)
    assert checked["status"] == "complete", checked
    result = tool("script_run", run_id=rid, source=source, timeout_ms=2000)
    assert result["status"] == "complete", result
    event, = result["return_value"]
    expansion, memory = event["output"]
    assert event["pc"] == found["runtime_address"] and memory["value"]["complete"], event
    assert expansion["value"]["children"]["items"][0]["expression"] == "::jobs[0]", result

    fixture = ARTIFACTS / "breakpoint-cases" / "D06"
    workflow = tool("breakpoint_workflow", run={"executable": str(fixture)},
                    points=[{"symbol": "flags", "module": fixture.name, "kind": "write",
                             "length": 4, "expressions": ["::flags"]}], timeout_ms=2000)
    assert workflow["status"] == "complete", workflow
    event, = workflow["return_value"]
    assert event["watch"]["value_before"] == "0x5" and event["watch"]["value_after"] == "0x2", event
    accesses = tool("breakpoint_events", breakpoint_id=event["breakpoint_id"])["accesses"]
    assert accesses[0]["count"] == 1 and accesses[0]["tid"] == event["tid"], accesses
    assert accesses[0]["access"] in ("write", "unknown"), accesses
    assert tool("breakpoint_remove", run_id=workflow["run_id"],
                breakpoint_id=event["breakpoint_id"])["status"] == "already_removed"
    print("PASS shared script declarations, std::array paging, uploaded core, retention, workflow, access attribution and cleanup")


def d04_lock_graph(tool):
    fixture, run = run_case(tool, "D04")
    rid, pid = run["run_id"], run["pid"]
    locks = []
    for name in ("catalog", "ledger"):
        match, = tool("symbols", pid=pid, module=str(fixture), pattern=name)["matches"]
        locks.append({"address": match["runtime_address"]})
    tool("run_continue", run_id=rid)
    graph = tool("observe_threads", run_id=rid, locks=locks, samples=12, interval_ms=25)
    try:
        assert graph["samples"] == 12 and len(graph["timeline"]) >= 3, graph
        assert len(graph["lock_graph"]["edges"]) == 2, graph
        cycle, = graph["lock_graph"]["cycles"]
        assert len(cycle) == 2, graph
    finally:
        tool("run_cancel", run_id=rid)
    until = time.monotonic() + 2.5
    while time.monotonic() < until:
        cancelled = tool("run_status", run_id=rid)
        if cancelled["status"] == "finished":
            break
        time.sleep(0.025)
    assert cancelled["result"]["stop_reason"] == "cancelled", cancelled
    assert not Path(f"/proc/{pid}").exists(), cancelled
    print("PASS D04 futex wait graph, thread timeline, and cancelled thread-group reaping")


def d06_read_access(tool):
    _, run = run_case(tool, "D06")
    rid = run["run_id"]
    address = tool("inspect", run_id=rid, expression="::flags")["result"]["address"]
    caps = tool("breakpoint_capabilities", run_id=rid)
    if "read" not in caps["watch_access"]:
        result = tool("breakpoint_set", run_id=rid, address=address, kind="read", length=4)
        assert result["code"] == "UNSUPPORTED_WATCH_ACCESS", result
        tool("run_cancel", run_id=rid)
        return
    result = tool("script_run", run_id=rid, timeout_ms=2500, source=f"""
dbg.watchpoint({address}n, 4, "read", hit => {{
    hit.emit("value", hit.watch?.valueBefore ?? null);
}});
dbg.continue();
return await dbg.events();
""")
    assert result["status"] == "complete", result
    events = result["return_value"]
    assert [event["callback"]["output"][0]["value"] for event in events] == [5, 2], events
    assert all(event["watch"]["write_observed"] is False for event in events), events
    print(f"PASS D06 read-only watchpoints on {platform.machine()}")


def main():
    with tempfile.TemporaryDirectory(prefix="aidbg-breakpoint-cases-") as directory:
        root = Path(directory)
        state = root / "state"
        state.mkdir(mode=0o700)
        socket = root / "server.sock"
        with server(socket, state), mcp(BIN, socket) as tool:
            index = tool("capabilities")
            assert index["tools"]["variables"]["selectors"] == ["run_id", "pid", "target_id"], index
            d01_core_evidence(tool, root)
            d02(tool)
            d06(tool)
            d09(tool)
            d09_live(tool, root, socket)
            d09_exports(tool, socket)
            d09_runtime_failure(tool)
            d10(tool)
            d07_ordered_trace(tool)
            d08_memory_diff(tool)
            live_workflow(tool)
            line_update_and_bundle(tool, root)
            shared_live_and_core(tool, root)
            d04_lock_graph(tool)
            d06_read_access(tool)


if __name__ == "__main__":
    main()
