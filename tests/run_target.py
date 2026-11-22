#!/usr/bin/env python3
"""Run a native target under ptrace and read its full signal core."""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import time

from scripts import mcp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    parser.add_argument("server", type=Path)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    client, server, fixture = (path.resolve() for path in (args.client, args.server, args.fixture))

    with tempfile.TemporaryDirectory(prefix="aidbg-run-target-") as temp:
        work = Path(temp)
        socket = work / "server.sock"
        state = work / "state"
        state.mkdir(mode=0o700)
        with subprocess.Popen([server, "--socket", socket, "--state-dir", state]) as daemon:
            try:
                for _ in range(100):
                    if socket.exists():
                        break
                    assert daemon.poll() is None, daemon.returncode
                    time.sleep(0.025)
                assert socket.exists()
                verify(client, fixture, socket, work)
            finally:
                daemon.terminate()


def verify(client, fixture, socket, work):
    def cli(*args, success=True):
        result = subprocess.run([client, "--socket", socket, *args], capture_output=True,
                                text=True, timeout=25)
        assert (result.returncode == 0) == success, result
        return json.loads(result.stdout) if success else result.stderr

    hook = work / "signal.ts"
    hook.write_text('''
dbg.onSignal(builtins.SIGSEGV, (seg) => {
    if (seg.tid === seg.pid || seg.faultAddress !== 0n) throw new Error("wrong crash context");
    dbg.coredump("full");
});
''')
    result = cli("run", "--on-signal", hook, fixture, "--", "crash")
    assert result["stop_reason"] == "signaled" and result["exit_signal"] == signal.SIGSEGV, result
    crash, = result["signals"]
    assert crash["tid"] != result["pid"] and crash["fault_address"] == "0x0", crash
    assert crash["issue"] is None, crash
    dump = crash["coredump"]
    assert dump["summary"]["mode"] == "full" and dump["summary"]["threads"] == 2, dump

    core = work / "crash.core.zst"
    result = cli("coredump", "--dump-id", dump["dump_id"], "--output", core)
    assert result["mode"] == "full" and core.is_file(), result
    inspect = work / "inspect.ts"
    inspect.write_text(f'''
const frame = dbg.frames({crash["tid"]})[0];
if (frame) dbg.printVal("crash_pointer", {{ frame: frame.handle }});
''')
    result = cli("script-run", "--core", core, "--executable", fixture, "--source", inspect)
    assert result["stop_reason"] == "completed", result
    check, = result["expressions"]
    assert check["status"] == "runtime_only" and check["code"] == "RUNTIME_FRAME", check
    assert result["output"][0]["value"]["result"]["value"] == "0x0", result

    missing = cli("run", work / "missing", success=False)
    assert "No such file or directory" in missing, missing
    timed = cli("run", "--timeout-ms", "100", fixture, "--", "wait")
    assert timed["stop_reason"] == "timed_out", timed
    assert not Path(f"/proc/{timed['pid']}").exists(), timed
    realtime = cli("run", fixture, "--", "realtime")
    assert realtime["stop_reason"] == "signaled" and realtime["exit_signal"] == signal.SIGRTMIN, realtime

    with mcp(client) as tool:
        api = tool("script_api", mode="signal")
        assert "faultAddress" in api["declarations"], api
        disconnected = tool("run", executable=str(fixture))
        assert "connect" in disconnected["error"], disconnected
        connected = tool("connect", socket=str(socket))
        assert connected["status"] == "connected" and connected["socket"] == str(socket), connected
        failed = tool("connect", socket=str(work / "missing.sock"))
        assert "error" in failed, failed
        checked = tool("script_check", mode="signal", source='dbg.coredump("stack");')
        assert checked["status"] == "failed", checked
        result = tool("run", executable=str(fixture), arguments=["recover"],
                      signal_source='dbg.onSignal(builtins.SIGUSR1, () => { while (true) {} });')
        assert result["stop_reason"] == "exited" and result["exit_code"] == 7, result
        assert result["stdout"] == "delivered\n" and result["stderr"] == "target stderr\n", result
        event, = result["signals"]
        assert event["signal"] == signal.SIGUSR1 and event["issue"] and not event["coredump"], event

        assert "run_control" in connected["server"]["capabilities"], connected
        assert connected["server"]["environment"]["va_bits"] in (36, 39, 42, 47, 48, 52, 56), connected
        assert isinstance(connected["server"]["environment"]["asan_high_address_mappable"], bool), connected
        entry = tool("run", executable=str(fixture), arguments=["watch"], pause_at_entry=True, exit_coredump=True,
                     env={"AIDBG_TEST_LABEL": "passed"}, stdin="input\n")
        run_id = entry["run_id"]
        assert entry["status"] == "paused" and entry["pid"] > 0, entry
        value = tool("inspect", run_id=run_id, expression="::watched")
        assert value["status"] == "complete" and value["result"]["value"] == 17, value
        address = value["result"]["address"]
        memory = tool("search_memory", run_id=run_id, pattern="11000000",
                      start=address, end=hex(int(address, 16) + 4))
        assert memory["matches"] == [address], memory
        memory = tool("read_memory", run_id=run_id, address=address, length=4)
        assert memory["bytes"] == "11000000" and memory["complete"], memory
        missing = tool("read_memory", run_id=run_id, address="0x1", length=4)
        assert missing["bytes"] == "" and not missing["complete"] and missing["first_unread_address"] == "0x1", missing
        assert any(row["run_id"] == run_id for row in tool("run_list")["runs"])
        stepped = tool("step", run_id=run_id)
        assert stepped["steps"] == 1 and stepped["pc"] != stepped["pc_before"], stepped
        def symbol(name):
            found, = tool("symbols", pid=entry["pid"], module=fixture.name, pattern=name)["matches"]
            return found

        main = symbol("main")
        references = tool("xref", run_id=run_id, address=symbol("update_watched")["runtime_address"],
                          start=main["runtime_address"],
                          end=hex(int(main["runtime_address"], 16) + main["size"]),
                          instruction_references=True)
        assert any(row["kind"] == "branch_target" for row in references["matches"]), references
        removable = tool("breakpoint_set", run_id=run_id, module=fixture.name,
                         symbol="main", kind="software")
        removed = tool("breakpoint_remove", run_id=run_id, breakpoint_id=removable["breakpoint_id"])
        assert removed["status"] == "removed", removed
        rule = tool("breakpoint_set", run_id=run_id, address=address, kind="write", length=4)
        installed = rule["breakpoint_id"]
        listed, = tool("breakpoint_list", run_id=run_id)["breakpoints"]
        assert listed["breakpoint_id"] == installed, listed
        assert tool("breakpoint_capabilities", run_id=run_id)["used_slots"][0]["watch"] == 1
        assert tool("run_status", run_id=run_id)["status"] == "paused"
        assert tool("run_continue", run_id=run_id)["status"] in ("running", "finished")
        for _ in range(100):
            finished = tool("run_status", run_id=run_id)
            if finished["status"] == "finished":
                break
            time.sleep(0.025)
        assert finished["result"]["stdout"] == "passed:input\n", finished
        assert finished["result"]["exit_code"] == 0, finished
        exit_core = finished["result"]["exit_coredump"]
        target = tool("core_open", dump_id=exit_core["dump_id"], executable=str(fixture))["target_id"]
        memory = tool("read_memory", target_id=target, address=address, length=4)
        assert memory["bytes"] == "2a000000" and memory["complete"], memory
        assert tool("core_close", target_id=target)["closed"]
        assert not tool("breakpoint_list", run_id=run_id)["breakpoints"]
        event, = tool("breakpoint_events", breakpoint_id=installed)["events"]
        assert event["watch"]["value_after"] == "0x2a", event
        assert event["watch"]["value_after_decimal"] == "42", event

        entry = tool("run", executable=str(fixture), arguments=["inspect"],
                     pause_at_entry=True, timeout_ms=20000)
        run_id = entry["run_id"]
        prologue, = tool("symbols", run_id=run_id, pattern="inspect_values")["matches"]
        cli_symbol, = cli("symbols", "--run-id", run_id, "--pattern", "inspect_values")["matches"]
        assert cli_symbol["runtime_address"] == prologue["runtime_address"], cli_symbol
        point = tool("breakpoint_set", run_id=run_id, symbol="inspect_values", kind="software",
                     stop_after_hit=True, timeout_ms=500, rule_source="""
export default function onHit(hit: BreakpointHit) {
    hit.emit("locals", hit.locals(), {kind: "json"});
}
""")
        assert point["address"] == prologue["runtime_address"], point
        callee = tool("breakpoint_set", run_id=run_id, symbol="scope_marker",
                      stop_after_hit=True, timeout_ms=500)
        tool("run_continue", run_id=run_id)
        for _ in range(100):
            stopped = tool("run_status", run_id=run_id)
            if stopped["status"] == "paused":
                break
            time.sleep(0.025)
        assert stopped["status"] == "paused", stopped
        event, = tool("breakpoint_events", breakpoint_id=point["breakpoint_id"])["events"]
        assert event["resume_status"] == "stopped", event
        locals_page = event["callback"]["output"][0]["value"]
        assert locals_page["issue"]["code"] == "PROLOGUE", locals_page
        shadows = [row for row in locals_page["items"] if row["name"] == "shadow"]
        assert len(shadows) == 2 and shadows[0]["line"] != shadows[1]["line"], locals_page
        assert all(not row["readable"] and row["scope_ranges"] for row in shadows), shadows

        address = point["address"]
        decoded = tool("disassemble", run_id=run_id, address=address, before=0, after=1)
        assert decoded["instructions"][0]["address"] == address, decoded
        assert decoded["instructions"][0]["mnemonic"] not in ("int3", "brk"), decoded
        cli_window = cli("disassemble", "--run-id", run_id, "--address", address,
                         "--before", "0", "--after", "1")
        assert cli_window["instructions"] == decoded["instructions"], cli_window
        expressions = ["head == &samples[0]", "head != nullptr", "&head", "samples"]
        live = tool("inspect", run_id=run_id, expressions=expressions, expand={"limit": 2})
        assert live["status"] == "complete" and live["frame"]["pc"] == address, live
        a, b, holder, array = [row["value"] for row in live["results"]]
        assert a["result"]["value"] is True and b["result"]["value"] is True, live
        fields = array["children"]["items"][1]["value"]["children"]["items"]
        assert fields[0]["expression"] == "samples[1].value", fields
        assert fields[0]["value"]["result"]["value"] == 42, fields
        base = holder["result"]["value"]
        chain = tool("pointer_chain", run_id=run_id, base=base, offsets=[0])
        assert len(chain["steps"]) == 1, chain
        live_script = tool("script_run", run_id=run_id, source="""
export default function main() {
    return dbg.inspect("head == &samples[0]").result?.value;
}
""")
        assert live_script["return_value"] is True, live_script

        output = work / "held.core.zst"
        saved = tool("coredump", run_id=run_id, mode="full", output=str(output))
        assert output.is_file() and saved["dump_id"], saved
        assert tool("run_status", run_id=run_id)["status"] == "paused"
        assert tool("inspect", run_id=run_id, expressions=["head"])["frame"]["pc"] == address
        offline = tool("core_open", dump_id=saved["dump_id"], executable=str(fixture))["target_id"]
        core_report = tool("inspect", target_id=offline, expressions=expressions, expand={"limit": 2})
        assert core_report["status"] == "complete" and core_report["frame"]["pc"] == address, core_report
        assert tool("pointer_chain", target_id=offline, base=base, offsets=[0])["steps"] == chain["steps"]
        core_script = tool("script_run", target_id=offline, source="""
export default function main() {
    return dbg.inspect("head == &samples[0]").result?.value;
}
""")
        assert core_script["return_value"] is True, core_script
        invalid = tool("script_run", target_id=offline, timeout_ms=10001, source="return 0;")
        assert invalid["code"] == "INVALID_ARGUMENT", invalid
        invalid = tool("breakpoint_workflow", run_id=run_id, per_hit_timeout_ms=501,
                       points=[{"address": address}])
        assert invalid["code"] == "INVALID_ARGUMENT", invalid
        live_code = tool("read_memory", run_id=run_id, address=address, length=4)
        core_code = tool("read_memory", target_id=offline, address=address, length=4)
        assert live_code["bytes"] == core_code["bytes"], (live_code, core_code)
        tool("run_continue", run_id=run_id)
        for _ in range(100):
            stopped = tool("run_status", run_id=run_id)
            if stopped["status"] == "paused":
                break
            time.sleep(0.025)
        caller = tool("inspect", run_id=run_id, frame_index=1, expressions=["shadow"])
        assert caller["frame"]["index"] == 1, caller
        assert caller["results"][0]["value"]["result"]["value"] == 99, caller
        tool("run_continue", run_id=run_id)
        for _ in range(100):
            finished = tool("run_status", run_id=run_id)
            if finished["status"] == "finished":
                break
            time.sleep(0.025)
        assert finished["result"]["exit_code"] == 0, finished
        assert len(tool("breakpoint_events", breakpoint_id=point["breakpoint_id"])["events"]) == 1
        assert len(tool("breakpoint_events", breakpoint_id=callee["breakpoint_id"])["events"]) == 1

        opened = [offline] + [tool("core_open", dump_id=saved["dump_id"])["target_id"]
                              for _ in range(15)]
        limit = tool("core_open", dump_id=saved["dump_id"])
        assert limit["code"] == "INVALID_ARGUMENT", limit
        for target in opened:
            assert tool("core_close", target_id=target)["closed"]

        for mode in ("fork", "exec"):
            entry = tool("run", executable=str(fixture), arguments=[mode], pause_at_entry=True)
            run_id = entry["run_id"]
            point = tool("breakpoint_set", run_id=run_id, tid=entry["pid"], module=fixture.name,
                         symbol="update_watched", kind="software")
            assert point["tid"] == entry["pid"], point
            assert tool("run_continue", run_id=run_id)["status"] in ("running", "finished")
            for _ in range(100):
                finished = tool("run_status", run_id=run_id)
                if finished["status"] == "finished":
                    break
                time.sleep(0.025)
            assert finished["result"]["stdout"] == "forked:42\n", finished
            assert finished["result"]["exit_code"] == 0, finished
            assert not tool("breakpoint_events", breakpoint_id=point["breakpoint_id"])["events"]

        attached = tool("run", executable=str(fixture), arguments=["wait"], detach=True)
        run_id = attached["run_id"]
        assert attached["pid"] > 0 and attached["status"] == "running", attached
        assert tool("run_pause", run_id=run_id)["status"] == "paused"
        snapshot = tool("snapshot", run_id=run_id, freeze="required")
        assert snapshot.get("freeze_achieved") == "all", snapshot
        assert tool("run_continue", run_id=run_id)["status"] == "running"
        assert tool("run_pause", run_id=run_id)["status"] == "paused"
        assert tool("run_cancel", run_id=run_id)["cancel_requested"]
        for _ in range(100):
            cancelled = tool("run_status", run_id=run_id)
            if cancelled["status"] == "finished":
                break
            time.sleep(0.025)
        assert cancelled["result"]["stop_reason"] == "cancelled", cancelled
        assert not Path(f"/proc/{attached['pid']}").exists(), cancelled

    print("PASS run CLI/MCP, signal core, offline read, environment, stdin, pause, watchpoint and live memory")
    print("PASS held software and hardware stops, live/core inspection, and open-core limit")
    print("PASS launched scoped software breakpoint cleanup on fork and exec")


if __name__ == "__main__":
    main()
