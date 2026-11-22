#!/usr/bin/env python3
"""Exercise the embedded script engines against native ELF cores through CLI and MCP."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time


PREFIX = "const frame = dbg.frames(dbg.threads()[0].tid)[0].handle;\n"
VALID = "g_Data->foo[10].bar->baz"
READ = PREFIX + '''
const caller = dbg.frames(dbg.threads()[0].tid)[1].handle;
const result = dbg.inspect("g_Data->foo[10].bar->baz", {frame}).result;
if (result?.value !== 42 || typeof result.address !== "bigint") throw new Error("inspect value");
if (dbg.inspect("g_Wide", {frame}).result?.value !== 18446744073709551615n) throw new Error("precision");
dbg.printVal("g_Data->foo[10].bar->baz", {frame, label: "value"});
dbg.printVal("g_Null->foo[10].bar->baz", {frame});
dbg.printVal("g_Missing->foo[10].bar->baz", {frame});
dbg.printVal("frame_local", {frame});
dbg.printVal("caller_local", {frame: caller, label: "caller"});
dbg.printVal("g_Wide", {frame});
'''


def cli(exe, *args, source=None, env=None):
    result = subprocess.run([exe, *args], input=source, capture_output=True,
                            text=True, timeout=15, env=env)
    return result.returncode, json.loads(result.stdout) if result.stdout else result.stderr


@contextmanager
def mcp(exe, socket=None, *, env=None):
    command = [exe] + (["--socket", str(socket)] if socket else []) + ["mcp"]
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          text=True, bufsize=1, env=env) as process:
        next_id = 0

        def request(method, params=None, notification=False):
            nonlocal next_id
            next_id += 1
            outgoing = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                outgoing["params"] = params
            if not notification:
                outgoing["id"] = next_id
            process.stdin.write(json.dumps(outgoing) + "\n")
            if notification:
                return None
            response = json.loads(process.stdout.readline())
            assert response["id"] == next_id and "error" not in response, response
            return response["result"]

        request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "script integration", "version": "1"}})
        request("notifications/initialized", notification=True)

        def raw_tool(name, /, **args):
            return request("tools/call", {"name": name, "arguments": args})

        def tool(name, /, **args):
            return raw_tool(name, **args)["structuredContent"]

        tool.raw = raw_tool
        try:
            yield tool
        finally:
            process.stdin.close()
            process.wait(timeout=10)


def read_values(result):
    assert result["stop_reason"] == "completed", result
    reports = [entry["value"] for entry in result["output"]]
    assert [entry["status"] for entry in reports] == [
        "complete", "null_pointer", "missing_page", "complete", "complete", "complete",
    ], reports
    assert [r["result"]["value"] for r in reports if r["result"]] == [
        42, 73, 91, "18446744073709551615",
    ], reports


def print_val(expr):
    return f'dbg.printVal("{expr}", {{frame: frame}});'


def frame_prefix(tool, target):
    result = tool("script_run", target_id=target, source="""
        export default function main() {
            return dbg.frames(dbg.threads()[0].tid)[0].handle;
        }
    """)
    assert isinstance(result["return_value"], str), result
    return f'const frame = {json.dumps(result["return_value"])};\n'


def tests(tool, target, no_dwarf):
    known_frame = frame_prefix(tool, target)

    def with_known_frame(source):
        if PREFIX in source:
            source = source.replace(PREFIX, known_frame, 1).replace("{frame}", "{frame: frame}")
        return source

    def check(source, target_id=target):
        return tool("script_check", source=with_known_frame(source), target_id=target_id)

    def diagnostic(source, code, excerpt=None):
        source = with_known_frame(source)
        result = check(source)
        assert result["status"] == "failed", result
        found = next(d for d in result["diagnostics"] if d["code"] == code)
        if excerpt is not None:
            span = found["range"]
            raw = source.encode("utf-16-le")
            assert raw[span["start"] * 2:span["end"] * 2].decode("utf-16-le") == excerpt, found
        return found

    result = check(PREFIX + print_val(VALID))
    assert result["expressions"][0]["status"] == "verified", result
    diagnostic("// 🐱 prefix\n" + PREFIX + print_val(VALID[:-3] + "bza"), "UNKNOWN_MEMBER", "bza")
    diagnostic(PREFIX + print_val(VALID.replace("[10]", "[16]")), "OUT_OF_BOUNDS", "[16]")
    result = check(PREFIX + print_val("g_Data->dynamic[700].bar->baz"))
    assert result["expressions"][0]["code"] == "POINTER_BOUNDS_DEFERRED", result
    diagnostic(PREFIX + print_val(VALID.replace("[10].", "[10]->")), "TYPE_MISMATCH", "->")
    diagnostic(PREFIX + 'const access = "g_Data->foo[10].bar->bza"; dbg.printVal(access, {frame});',
               "UNKNOWN_MEMBER", "bza")
    result = check(PREFIX + "const alias = dbg; " + print_val(VALID).replace("dbg.", "alias."))
    assert result["expressions"][0]["status"] == "verified", result
    result = check('export {}; const dbg = {printVal(s: string) {return s}}; dbg.printVal("bad");')
    assert result["status"] == "complete" and result["expressions"] == [], result
    result = check(PREFIX + 'let access = "g_Data" + "->foo"; dbg.printVal(access, {frame});')
    assert result["status"] == "complete" and result["expressions"][0]["code"] == "DYNAMIC_EXPRESSION", result
    diagnostic(PREFIX + "dbg.printVal(123, {frame});", "2345", "123")
    diagnostic(PREFIX + print_val("::g_Dta->foo[10].bar->baz"), "UNKNOWN_GLOBAL", "::g_Dta")
    result = check(PREFIX + print_val(VALID), no_dwarf)
    assert result["status"] == "complete" and result["expressions"][0]["code"] == "NO_DWARF", result

    diagnostic(PREFIX + print_val(r"g_Data->foo[10].bar->b\u007Aa"), "UNKNOWN_MEMBER", r"b\u007Aa")
    diagnostic(PREFIX + 'const print = dbg.printVal; print("g_Data->bad", {frame});',
               "UNKNOWN_MEMBER", "bad")
    diagnostic(PREFIX + 'dbg["printVal"]("g_Data->bad", {frame});', "UNKNOWN_MEMBER", "bad")
    for code, source in [
        ("2339", "dbg.unknown();"), ("2365", "1n + 1;"), ("2345", "dbg.frames(null);"),
        ("CHECK_SUPPRESSION", "// @ts-ignore\ndbg.unknown();"),
        ("CHECK_SUPPRESSION", "// @ts-expect-error\ndbg.unknown();"),
        ("CHECK_SUPPRESSION", "// @ts-nocheck\ndbg.unknown();"),
        ("2583", "Atomics.wait;"),
    ]:
        diagnostic(source, code)

    blocked = tool("script_run", source=known_frame + print_val("g_Data->bad"), target_id=target)
    assert blocked["stop_reason"] == "check_failed" and blocked["output"] == [], blocked
    assert blocked["emit_us"] is None, blocked
    read_values(tool("script_run", source=READ, target_id=target))
    saved = tool("script_run", target_id=target, source=PREFIX + f"""
dbg.printVal("{VALID}", {{frame, label: dbg.frames(dbg.threads()[0].tid)[1].handle}});
""")
    caller = json.dumps(saved["output"][0]["label"])
    checked = check(f'dbg.inspect("caller_local", {{frame: {caller}}});')
    assert checked["expressions"][0]["status"] == "verified", checked
    timed = tool("script_run", source="while (true) {}", target_id=target)
    assert timed["stop_reason"] == "timed_out", timed
    print("12 prototype cases, UTF-16 spans, TypeScript checks, reads and timeout passed")


def bench(tool, target, rounds):
    def call(index, name):
        args = {"source": PREFIX + print_val(VALID.replace("[10]", f"[{index % 16}]")),
                "target_id": target}
        start = time.perf_counter_ns()
        result = tool(name, **args)
        assert result["status"] == "complete", result
        return {"round_trip_us": (time.perf_counter_ns() - start) // 1000,
                **{key: result[key] for key in ("check_us", "emit_us", "execute_us") if key in result}}

    def summary(samples):
        return {key: {"p50_us": round(statistics.median(row[key] for row in samples)),
                      "p95_us": sorted(row[key] for row in samples)[(95 * len(samples) + 99) // 100 - 1]}
                for key in samples[0]}

    cold = call(0, "script_run")
    checks = [call(i, "script_check") for i in range(rounds)]
    runs = [call(i + 1, "script_run") for i in range(rounds)]
    print(json.dumps({"cold_run": cold, "check": summary(checks), "run": summary(runs)}))


def run(args, work):
    fixture = str(args.fixture.resolve())
    bare = work / "fixture-stripped"
    symbols = work / "fixture.debug"
    subprocess.run(["objcopy", "--strip-debug", fixture, bare], check=True)
    subprocess.run(["objcopy", "--only-keep-debug", fixture, symbols], check=True)

    wrong_image = args.wrong_fixture.resolve()
    wrong_symbols = work / "wrong.debug"
    subprocess.run(["objcopy", "--only-keep-debug", wrong_image, wrong_symbols], check=True)

    core = work / "fixture.core"
    if args.core:
        core = args.core.resolve()
    else:
        subprocess.run(["gdb", "-nx", "-batch", "-ex", "run", "-ex",
                        f"generate-core-file {core}", fixture], check=True, timeout=20)
    code, report = cli(args.aidbg, "script-run", "--source", "-", "--core", str(core),
                       "--executable", str(bare), "--debug-symbols", str(symbols), source=READ)
    assert code == 0, report
    read_values(report)

    with mcp(args.aidbg) as tool:
        api = tool("script_api")
        assert "printVal" in api["declarations"], api
        result = tool("script_check", source=api["example"])
        assert result["status"] == "complete", result
        good = tool("core_open", path=str(core), executable=fixture)
        assert good["symbol_match"] == "matched" and good["dwarf_available"], good
        assert good["threads"] >= 2, good
        target = good["target_id"]
        stripped = tool("core_open", path=str(core), executable=str(bare))["target_id"]
        wrong = tool("core_open", path=str(core), executable=str(wrong_image))
        assert "does not match" in wrong["error"], wrong
        wrong = tool("core_open", path=str(core), executable=fixture, debug_symbols=str(wrong_symbols))
        assert "does not match" in wrong["error"], wrong
        tests(tool, target, stripped)
        assert tool("core_close", target_id=target)["closed"]
        assert "not found" in tool("script_check", source=PREFIX + print_val(VALID), target_id=target)["error"]
        assert tool("core_close", target_id=stripped)["closed"]

    if args.bench:
        with mcp(args.aidbg) as tool:
            core_info = tool("core_open", path=str(core), executable=fixture)
            bench(tool, core_info["target_id"], args.bench)

    socket = work / "s"
    compressed = work / "remote.core.zst"
    with subprocess.Popen([args.server, "--socket", socket, "--state-dir", work]) as server:
        try:
            for _ in range(200):
                if socket.exists():
                    break
                if server.poll() is not None:
                    raise RuntimeError("debugger server exited")
                time.sleep(0.01)
            with subprocess.Popen([fixture], stdout=subprocess.PIPE, text=True,
                                  env={**os.environ, "AIDBG_WAIT": "1"}) as process:
                try:
                    assert process.stdout.readline().strip() == "ready"
                    code, captured = cli(args.aidbg, "--socket", str(socket), "coredump",
                                         "--pid", str(process.pid), "--mode", "full",
                                         "--output", str(compressed))
                    assert code == 0, captured
                finally:
                    process.terminate()
            code, api = cli(args.aidbg, "--socket", str(socket), "script-api")
            assert code == 0 and "printVal" in api["declarations"], api
            code, check = cli(args.aidbg, "--socket", str(socket), "script-check",
                              "--source", "-", source='dbg.printVal("g_Null", {frame: "unused"});')
            assert code == 0 and check["expressions"][0]["code"] == "NO_TARGET", check
            with mcp(args.aidbg, socket) as tool:
                opened = tool("core_open", dump_id=captured["dump_id"], executable=fixture)
                assert opened["symbol_match"] == "matched", opened
                target = opened["target_id"]
                offline = tool("script_run", source=READ, target_id=target)
                read_values(offline)
                offline_null = offline["output"][1]["value"]
                expression = "::g_Null->foo[10].bar->baz"
                launched = tool("run", executable=fixture, pause_at_entry=True)
                run_id = launched["run_id"]
                live_null = tool("inspect", run_id=run_id, expression=expression)
                hit, = tool("symbols", pid=launched["pid"], module=Path(fixture).name,
                            pattern="_Z12capture_herev")["matches"]
                script = tool("script_run", run_id=run_id, source=f"""
                    export default async function main() {{
                        dbg.softwareBreakpoint({hit["runtime_address"]}n, hit => {{
                            const report = hit.inspect("{expression}");
                            hit.emit("status", report.status);
                            hit.emit("code", report.code ?? null);
                            hit.emit("hint", report.hint ?? null);
                        }});
                        dbg.continue();
                        return (await dbg.events())[0]?.callback?.output;
                    }}
                """)
                assert script["status"] == "complete", script
                callback = {field["label"]: field["value"] for field in script["return_value"]}
                for key in ("status", "code", "hint"):
                    assert callback[key] == live_null[key] == offline_null[key], (key, offline_null, live_null, callback)
                check = tool("script_check", source=frame_prefix(tool, target) + print_val(VALID), target_id=target)
                assert check["expressions"][0]["status"] == "verified", check
                code, result = cli(args.aidbg, "--socket", str(socket), "script-run",
                                   "--target-id", target, "--source", "-", source=READ)
                assert code == 0, result
                read_values(result)
                assert tool("core_close", target_id=target)["closed"]
                print("server artifact, remote MCP and remote CLI passed")
        finally:
            server.terminate()

    # Open the exported core after server shutdown and with no host commands on PATH.
    empty_path = work / "empty-path"
    empty_path.mkdir()
    env = {**os.environ, "PATH": str(empty_path)}
    client = Path(args.aidbg).resolve()
    code, report = cli(client, "script-run", "--core", str(compressed),
                       "--executable", fixture, "--source", "-", source=READ, env=env)
    assert code == 0, report
    read_values(report)
    with mcp(client, env=env) as tool:
        opened = tool("core_open", path=str(compressed), executable=fixture)
        assert opened["symbol_match"] == "matched", opened
        target = opened["target_id"]
        read_values(tool("script_run", source=READ, target_id=target))
        assert tool("core_close", target_id=target)["closed"]
    print("standalone client decoded .core.zst through CLI and MCP with an empty PATH")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("aidbg")
    parser.add_argument("server")
    parser.add_argument("fixture", type=Path)
    parser.add_argument("wrong_fixture", type=Path)
    parser.add_argument("--core", type=Path)
    parser.add_argument("--bench", type=int, default=0)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="aidbg-script-") as tmp:
        run(args, Path(tmp))
