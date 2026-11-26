#!/usr/bin/env python3
"""Exercise the public MCP entry point using only locally launched fixtures."""
import argparse
import json
import os
import re
from pathlib import Path
import select
import signal
import struct
import subprocess
import tempfile
import time

TOOLS = {"connect", "run", "attach", "script_run", "script_wait", "core_open", "send_input", "interrupt_input",
         "snapshot", "status", "gdb", "perf", "ps", "set_fork_policy", "docs", "syscall_table"}


class Client:
    def __init__(self, executable, socket, token):
        self.process = subprocess.Popen(
            [executable, "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.counter = 0
        self.rpc("initialize", protocolVersion="2024-11-05", capabilities={},
                 clientInfo={"name": "aidbg integration test", "version": "1"})
        self.write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        docs = self.rpc("tools/call", name="docs", arguments={"section": "all", "output_format": "structured"})["structuredContent"]
        debugger_types = self.rpc("resources/read", uri=docs["full_api"])["contents"][0]["text"]
        node_types = self.rpc("resources/read", uri="aidbg://node.d.ts")["contents"][0]["text"]
        assert debugger_types.replace("export declare ", "export ") in docs["declarations"]
        assert 'declare const $: AidbgGlobals & import("aidbg").GlobalScope;' in docs["declarations"]
        assert 'declare const AbortController: typeof import("aidbg").AbortController;' in docs["declarations"]
        assert node_types == docs["modules"]
        text = self.rpc("tools/call", name="docs", arguments={})["content"][0]["text"]
        assert "Quick Start" in text and len(text) * 4 < len(docs["declarations"]), text
        self.quick_start = text
        full = self.rpc("tools/call", name="docs", arguments={"section": "all"})["content"][0]["text"]
        assert docs["declarations"].strip() in full and node_types.strip() in full
        for section, declaration in {
            "debugger": "interface Debugger", "types": "interface TypeSystem",
            "value": "namespace Value", "format": "interface Format",
            "events": "type StopEvent", "breakpoints": "interface BreakpointOptions",
        }.items():
            docs_section = self.rpc("tools/call", name="docs", arguments={"section": section})
            assert declaration in docs_section["content"][0]["text"], docs_section
        unknown = self.rpc("tools/call", name="docs", arguments={"section": "invalid"})
        assert unknown["isError"] and "Unknown docs section" in unknown["content"][0]["text"], unknown
        disconnected = self.rpc("tools/call", name="ps", arguments={"output_format": "structured"})
        assert disconnected["isError"] and "connect" in disconnected["structuredContent"]["error"], disconnected
        connected = self.rpc("tools/call", name="connect", arguments={"socket": socket, "session": token, "output_format": "structured"})
        assert connected["structuredContent"] == {"status": "connected", "socket": socket, "session": token}, connected
        failed = self.rpc("tools/call", name="connect", arguments={"socket": socket + ".missing"})
        assert failed["isError"], failed

    def write(self, message):
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        self.process.stdin.flush()

    def rpc(self, method, **params):
        self.counter += 1
        self.write(dict(jsonrpc="2.0", id=self.counter, method=method, params=params))
        readable, _, _ = select.select([self.process.stdout], [], [], 20)
        if not readable:
            raise AssertionError(f"timed out on {method}")
        line = self.process.stdout.readline()
        assert line, (method, self.process.poll())
        reply = json.loads(line)
        assert reply.get("id") == self.counter and "error" not in reply, reply
        return reply["result"]

    def tool(self, name, /, *, error=False, **arguments):
        result = self.rpc("tools/call", name=name, arguments={**arguments, "output_format": "structured"})["structuredContent"]
        assert {"paused_threads", "waiting_inputs", "running_scripts", "output"} <= result.keys(), result
        if not error:
            assert result["error"] is None and result["target_error"] is None, result
        return result

    def script(self, source, *, invalid=False):
        result = self.tool("script_run", src=source)
        if invalid:
            assert result["result"]["status"] == "check_failed", result
        else:
            assert result["result"]["status"] != "check_failed", result
            assert not any(row["value"]["kind"] == "script_error" for row in result["output"]), result
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            if self.process.wait(timeout=5) != 0:
                raise AssertionError(self.process.stderr.read().decode())


def logs(result):
    return [row["value"]["values"] for row in result["output"]
            if row["value"]["kind"] == "console"]


def await_state(client, predicate):
    end = time.monotonic() + 8
    output = []
    while time.monotonic() < end:
        reply = client.tool("ps")
        output.extend(reply["output"])
        if predicate(reply):
            reply["output"] = output
            return reply
        time.sleep(.03)
    raise AssertionError(("condition timed out", output))


def validate_types_and_input(client):
    assert {tool["name"] for tool in client.rpc("tools/list")["tools"]} == TOOLS
    api = client.rpc("resources/read", uri="aidbg://debugger.d.ts")
    assert "interface TypeSystem" in api["contents"][0]["text"]
    assert logs(client.script("export const triple = (n: number) => n * 3; console.log(triple(7));")) == [[21]]
    assert logs(client.script("console.log($.triple(14));")) == [[42]]
    published = client.tool("script_run", wait_ms=2000, src="""
        await sleep(20);
        export const probe = () => 7n;
        console.log(dbg.stringify({value: probe()}));
    """)
    assert published["result"]["status"] == "completed", published
    assert logs(published) == [['{"value":"7"}']], published
    assert logs(client.script("console.log($.probe());")) == [["7"]]
    pending = client.tool("script_run", wait_ms=1, src="await sleep(100); console.log('finished');")
    assert pending["result"]["status"] == "wait_timeout", pending
    completed = client.tool("script_wait", script_id=pending["result"]["script_id"], wait_ms=2000)
    assert completed["result"]["status"] == "completed" and logs(completed) == [["finished"]], completed
    assert logs(client.script("""
        const number = m.u64();
        m.setPrettyPrinter(number, value => "u64:" + value.$read());
        console.log(number.value(8n));
        m.setPrettyPrinter(number, null);
        console.log(number.value(8n));
    """)) == [["u64:8"], ["8"]]
    client.script('$.triple("wrong")', invalid=True)
    client.script("function f() { let $ = 1; return $; }", invalid=True)
    client.script("const Packet = m.struct({len: m.u32(), data: m.array(m.u8(), ctx => ctx.lne)});", invalid=True)
    client.script("const p = m.struct({ptr: m.pointer(m.u8())}).at(0n); p.ptr = 3;", invalid=True)
    result = client.script("""
        const Tree = m.struct({ left:m.pointer(m.lazy(() => Tree)), value:m.i32() });
        const Node = m.struct({ next:m.pointer(m.self()), value:m.i32() });
        const nested = m.struct({ size:m.u16(), item:m.struct({
            pointer:m.pointer(m.u8(), (ctx) => ctx.$parent.size),
        }) });
        function verify() { return Tree.at(0n).left.$deref().value.$read() + Node.at(0n).next.$deref().value.$read(); }
        console.log(Tree.$size, Node.$size, nested.$size);
    """)
    assert logs(result) == [[16, 16, 16]], result
    assert logs(client.script("export default function main() { console.log('unexpected'); } console.log('top');")) == [["top"]]
    reply = client.script("""
        const abort = new AbortController();
        setTimeout(() => abort.abort("cancelled"), 1);
        queueMicrotask(() => console.log("microtask"));
        try { await sleep(1000, abort.signal); } catch (reason) { console.log(reason); }
    """)
    timing = logs(reply)
    if reply["running_scripts"]:
        timing += logs(await_state(client, lambda row: not row["running_scripts"]))
    assert timing == [["microtask"],["cancelled"]], reply
    thrown = client.tool("script_run", src="const label: string = 'mapped';\nthrow new Error(label);")
    error = next(row["value"] for row in thrown["output"] if row["value"]["kind"] == "script_error")
    assert error["message"] == "mapped" and error["line"] == 2 and error["file"].endswith(".ts"), error
    assert ".ts:2" in error["stack"], error
    reply = client.script("console.log(await dbg.ask({}));")
    assert len(reply["running_scripts"]) == 1 and len(reply["waiting_inputs"]) == 1, reply
    handler = reply["waiting_inputs"][0]["handler"]
    status = client.tool("status")
    assert "Active scripts:" in status["result"], status
    assert status["waiting_inputs"] == reply["waiting_inputs"]
    assert status["running_scripts"] == reply["running_scripts"]
    reply = client.tool("send_input", handler=handler, data="first response")
    assert not reply["waiting_inputs"] and logs(reply) == [["first response"]], reply
    reply = client.script("try { await dbg.ask({}); } catch (error) { console.log((error as Error).message); }")
    handler = reply["waiting_inputs"][0]["handler"]
    reply = client.tool("interrupt_input", handler=handler, msg="interrupt message")
    assert logs(reply) == [["interrupt message"]], reply
    reply = client.script("try { await dbg.ask({}, 10); } catch (error) { console.log((error as Error).message); }")
    if reply["waiting_inputs"]:
        reply = await_state(client, lambda state: not state["waiting_inputs"])
    assert logs(reply) == [["input timed out"]], reply


def validate_text_output(client, fixture, owned):
    def tool(name, /, *, error=False, **arguments):
        result = client.rpc("tools/call", name=name, arguments=arguments)
        assert "structuredContent" not in result, result
        assert bool(result.get("isError")) == error, result
        assert len(result["content"]) == 1 and result["content"][0]["type"] == "text", result
        return result["content"][0]["text"]

    def script(src, **args):
        return tool("script_run", src=src, **args)

    def running_id(text):
        match = re.search(r"Script #(\d+) running", text)
        assert match, text
        return int(match[1])

    assert script("await Promise.resolve();") == "OK"
    invalid = script('const text: string = 123; console.log(text);', error=True)
    assert "script.ts:1:7: error TS2322:" in invalid and "^" in invalid, invalid
    runtime = script('throw new Error("runtime evidence");', error=True)
    assert "runtime evidence" in runtime and ".ts:1:" in runtime, runtime
    assert "select a target" in script("await dbg.kill();", error=True)
    values = script("""
        const row = { wide: 18446744073709551615n, empty: [], no: false,
            zero: 0, none: null, absent: undefined, circular: {} };
        row.circular = row;
        fmt.print("format");
        console.log(row);
        console.log(JSON.stringify({no:false, none:null, zero:0}));
    """)
    for evidence in ("18446744073709551615n", "empty: []", "no: false", "zero: 0",
                     "none: null", "absent: undefined", "<circular>",
                     '{"no":false,"none":null,"zero":0}'):
        assert evidence in values, (evidence, values)
    native = script('const custom = m.i32().withFormatter(v => "native=" + v.$read()); console.log(custom.value(42));')
    assert native == "native=42", native
    assert values.startswith("format\n") and "Script #" not in values, values
    limited = script('console.log({a: Array(100).fill(1), s: "é".repeat(1500)});')
    assert "68 more elements" in limited and "truncated string" in limited, limited
    deep = script('let row: unknown = 0; for (let i=0; i<10; i++) row = {child:row}; console.log(row);')
    assert "truncated at depth limit" in deep, deep
    huge = script('console.log("é".repeat(1100000));')
    assert "Output truncated for display" in huge and "dropped" not in huge, huge[-200:]
    assert len(huge.encode()) <= 32768

    batch = script('console.log("first chunk " + "x".repeat(40000)); console.log("second chunk " + "y".repeat(40000));')
    assert "first chunk" in batch and "More script output is buffered" in batch, batch[:200]
    assert "second chunk" not in batch and "dropped" not in batch, batch[-200:]
    remainder = tool("syscall_table", name="read")
    assert "second chunk" in remainder and "dropped" not in remainder, remainder[-200:]

    first = running_id(script('console.log("first"); await sleep(150); console.log("last");', wait_ms=0))
    second = running_id(script('await sleep(60); fmt.print("second");', wait_ms=0))
    done = tool("script_wait", script_id=first, wait_ms=2000)
    assert f"Script #{first} completed" in done and f"Script #{second} completed" in done, done
    assert done.index("second") < done.index("last"), done
    assert f"[Script #{first}]" in done and f"[Script #{second}]" in done, done

    failure_id = running_id(script('await sleep(60); throw new Error("async evidence");', wait_ms=0))
    failed = tool("script_wait", script_id=failure_id, error=True)
    assert f"Script #{failure_id} failed" in failed and "async evidence" in failed, failed
    asking = script('console.log(await dbg.ask({question: "Which thread?"}));')
    assert "Which thread?" in asking and "awaiting input" in asking, asking
    handler = asking.split("Request ", 1)[1].split(":", 1)[0]
    assert handler in tool("status")
    answered = tool("send_input", handler=handler, data="thread answer")
    assert "thread answer" in answered and "completed" in answered, answered

    pending = running_id(script("await sleep(10000);", wait_ms=0))
    started = tool("run", path=fixture, arg=["output"])
    assert "Started process" in started and f"Script #{pending} cancelled" in started, started
    deadline = time.monotonic() + 3
    recorded = started
    while "stdout tail" not in recorded or "stderr tail" not in recorded:
        assert time.monotonic() < deadline, recorded
        recorded += tool("syscall_table", name="read")
    assert " stdout\nstdout tail" in recorded and " stderr\nstderr tail" in recorded, recorded
    assert "exited with code 39" in tool("status")

    with subprocess.Popen([fixture, "attach"], stdout=subprocess.PIPE, text=True) as target:
        try:
            assert target.stdout.readline().strip() == "ready"
            attached = tool("attach", pid=target.pid)
            assert attached.startswith(f"Attached to PID {target.pid}.\nState: running"), attached
            attached = tool("attach", pid=target.pid, pause=True)
            assert "State: paused" in attached and f"Stopped threads: {target.pid}" in attached, attached
            resumed = tool("attach", pid=target.pid)
            assert "State: running" in resumed, resumed
            assert script("await dbg.detach();") == f"Detached from PID {target.pid}."
            assert target.poll() is None
        finally:
            if target.poll() is None:
                target.kill()

    running = tool("run", path=fixture, arg=["fault"], pause=True)
    pid = int(running.split("Started process ", 1)[1].split(":", 1)[0])
    owned.add(pid)
    stopped = script("""
        fmt.print("火".repeat(40000));
        console.log("é".repeat(40000));
        const event = await dbg.continueForStop(dbg.pid, {timeoutMs: 5000});
        if (event.kind !== "signal") throw new Error(event.kind);
    """, wait_ms=3000)
    assert len(stopped.encode()) <= 32768 and "Output truncated for display" in stopped, stopped[-200:]
    assert "SIGSEGV" in stopped and "Fault address:" in stopped, stopped[-500:]
    remainder = tool("syscall_table", name="read")
    assert "é" in remainder and "dropped" not in remainder, remainder[-200:]
    assert "SIGSEGV" in tool("status")
    assert script("await dbg.kill();") == f"Killed process {pid}."
    owned.remove(pid)

    running = tool("run", path=fixture, arg=["events"], pause=True)
    pid = int(running.split("Started process ", 1)[1].split(":", 1)[0])
    owned.add(pid)
    waiting = script("""
        const addr = (await dbg.getSymbol("fixture_stop"))!.address;
        dbg.softwareBreakpoint(addr);
        const hit = await dbg.continueForStop(dbg.pid, {timeoutMs: 5000});
        console.log(hit.kind);
    """, wait_ms=0)
    assert "waiting for a target stop" in waiting, waiting
    deadline = time.monotonic() + 3
    status = tool("status")
    while "breakpoint #" not in status:
        assert time.monotonic() < deadline, status
        status = tool("status")
    assert "[event " in status and "breakpoint #" in tool("status"), status
    killed = script("await dbg.kill();")
    assert f"Killed process {pid}." in killed, killed
    owned.remove(pid)


def validate_quick_start(client, fixture, owned):
    launched = client.tool("run", pause=True, path=fixture, arg=["child"])
    pid = launched["result"]["pid"]
    owned.add(pid)
    for i, snippet in enumerate(re.findall(r"```ts\n(.*?)```", client.quick_start, re.S)):
        reply = client.tool("script_run", src=snippet, wait_ms=6000)
        assert reply["result"]["status"] == "completed", (snippet, reply)
        if i == 2:
            assert logs(reply)[0][0]["kind"] == "breakpoint", reply
    for command in ("bt", "thread apply all bt", "info registers", "info locals", "info args",
                    "info symbol main", "x/16xb main", "disassemble main"):
        reply = client.tool("gdb", command=command)
        assert reply["result"]["status"] == "completed", (command, reply)
    inline = re.findall(r"`(await dbg\.\w+\([^`]*?\))`", client.quick_start)
    trace, detach, kill = inline
    client.script(kill + ";")
    owned.remove(pid)

    pid = client.tool("run", pause=True, path=fixture, arg=["child"])["result"]["pid"]
    owned.add(pid)
    reply = client.tool("script_run", src="console.log(" + trace + ");", wait_ms=6000)
    assert reply["result"]["status"] == "completed" and logs(reply)[0][0]["limitReached"], reply
    reply = client.tool("script_run", src=detach + ";", wait_ms=6000)
    assert reply["result"]["status"] == "completed", reply
    owned.remove(pid)


def validate_presentation(client, fixture, owned):
    result = client.tool("run", path="/bin/sleep", arg=["30"])
    pid = result["result"]["pid"]
    owned.add(pid)
    assert result["result"]["state"] == "running" and not result["paused_threads"], result
    assert "State: running" in client.tool("status")["result"]
    partial = client.tool("snapshot", stop_timeout_ms=0)["result"]
    assert partial["consistency"] == "partial" and partial["threadCount"] == 1, partial
    assert not partial["threads"] and any(row.get("tid") == pid for row in partial["incomplete"]), partial
    snapshot = client.tool("snapshot")
    assert not snapshot["paused_threads"] and snapshot["result"]["threads"], snapshot
    client.script("await dbg.kill(15);")
    owned.remove(pid)

    with subprocess.Popen([fixture, "attach"], stdout=subprocess.PIPE, text=True) as target:
        try:
            assert target.stdout.readline().strip() == "ready"
            attached = client.tool("attach", pid=target.pid)
            assert attached["result"]["state"] == "running" and not attached["paused_threads"], attached
            status = client.tool("status")
            assert "Attached: true" in status["result"] and "State: running" in status["result"], status
            relocated = client.tool("script_run", wait_ms=3000, src="""
                const rows = dbg.disassemble("event_fixture",128);
                if (!rows.some(row => row.references.some(ref =>
                    ref.requested === "puts" && ref.resolvedAddress !== undefined))) {
                    throw new Error("runtime PLT binding unavailable");
                }
            """)
            assert relocated["result"]["status"] == "completed", relocated
            client.script("await dbg.detach();")
        finally:
            target.kill()

    launched = client.tool("run", pause=True, path=fixture, arg=[])
    pid = launched["result"]["pid"]
    owned.add(pid)
    assert launched["result"]["state"] == "paused" and launched["paused_threads"] == [pid], launched
    reply = client.tool("script_run", wait_ms=3000, src="""
        const Packet = m.fromDwarf("Packet");
        const packetSymbol = await dbg.getSymbol("packet");
        if (Packet !== m.fromDwarf("Packet") || packetSymbol === null) throw new Error("DWARF identity");
        if (dbg.symbolAt(packetSymbol.address)?.name !== "packet") throw new Error("symbolAt");
        const integer = m.i32().value(42);
        if (integer.$toJS() !== 42 || `${integer}` !== "42") throw new Error("scalar presentation");
        const custom = m.i32().withFormatter(value => "value=" + value.$read());
        if (custom.value(42).$format() !== "value=42" || custom.value(42).$toJS() !== 42) {
            throw new Error("formatter changed conversion");
        }
        const value = Packet.at(packetSymbol.address);
        const same = value.$asType(m.u8());
        if (same.$address() !== packetSymbol.address) throw new Error("reinterpretation");
        const before: { age: number; self?: unknown } = {age:20};
        const after: { age: number; self?: unknown } = {age:21};
        before.self = before;
        after.self = after;
        fmt.diff(before,after);
        fmt.address(packetSymbol.address + BigInt(Packet.offsetOf("node")));
        const point = dbg.softwareBreakpoint("fixture_stop",null);
        await fmt.gdb("disable " + point.id);
        await fmt.gdb("enable " + point.id);
        await fmt.gdb("delete " + point.id);
        fmt.status();
        fmt.snapshot();
        await fmt.gdb("info threads");
    """)
    assert reply["result"]["status"] == "completed", reply
    formatted = [row["value"]["text"] for row in reply["output"] if row["value"]["kind"] == "fmt"]
    assert any("age: 20 -> 21" in text for text in formatted), formatted
    assert any("Snapshot" in text for text in formatted), formatted
    assert any(("Type: Packet" in text or "Type: struct Packet" in text) and "Member: node" in text
               for text in formatted), formatted
    assert reply["paused_threads"] == [pid], reply
    disassembly = client.tool("gdb", command="disassemble fixture_sum")
    assert disassembly["result"]["status"] == "completed", disassembly
    client.script("await dbg.kill(15);")
    owned.remove(pid)


def validate_session_extensions(client, fixture, owned):
    client.script("export const value = 1;", invalid=True)
    client.script('"I know this is a no-op script"; export const allowedNoOp = 1;')
    client.script("Promise.resolve(1);", invalid=True)
    assert logs(client.script("const pending = Promise.resolve(7); console.log(await pending);")) == [[7]]
    assert logs(client.script("Promise.resolve(2).then(n => console.log(n));")) == [[2]]

    source = f"""
        import {{ accessSync, readFileSync, statSync }} from "node:fs";
        import {{ access, readFile, readdir }} from "node:fs/promises";
        import path from "node:path";
        const file = path.resolve({json.dumps(fixture)});
        accessSync(file);
        await access(file);
        const files = await readdir(path.dirname(file));
        const bytes = readFileSync(file);
        const sameBytes = (await readFile(file))[0] === bytes[0];
        console.log(path.basename(file), statSync(file).isFile(), bytes[0], sameBytes, files.includes(path.basename(file)));
    """
    reply = client.script(source)
    output = logs(reply)
    if reply["running_scripts"]:
        output += logs(await_state(client, lambda state: not state["running_scripts"]))
    assert output == [[Path(fixture).name, True, 127, True, True]], reply

    client.tool("set_fork_policy", mode="parent")
    pid = client.tool("run", pause=True, path=fixture, arg=["child"])["result"]["pid"]
    owned.add(pid)
    table = client.tool("ps")["result"]["items"]
    assert any(row["pid"] == pid and row["threads"] == 1 and "args" not in row for row in table)
    thread_table = client.tool("ps", threads=True, fields=["pid", "tid", "args"])["result"]["items"]
    assert any(row["pid"] == row["tid"] == pid and row["args"][-1] == "child" for row in thread_table)
    filtered = client.tool("ps", pattern=str(pid), limit=1)["result"]
    assert len(filtered["items"]) == 1
    context = client.tool("snapshot", tid=pid, context=True)["result"]["context"]
    assert context["TracerPid"] > 0 and context["Threads"] == 1 and "0" in context["fd"]
    table = client.tool("syscall_table", name="mmap")["result"]
    assert table["syscalls"][0]["id"] == {"x86_64": 9, "aarch64": 222}[table["architecture"]]
    assert [p["name"] for p in table["syscalls"][0]["parameters"]] == ["addr", "length", "prot", "flags", "fd", "offset"]
    reply = client.script("""
        dbg.catchSyscall(dbg.pid, "both", hit => hit.pause());
        const entry = await dbg.continueForStop(dbg.pid, {timeoutMs: 2500});
        if (entry.kind !== "syscall") throw new Error(entry.kind);
        const exit = await dbg.continueForStop(dbg.pid, {timeoutMs: 2500});
        if (exit.kind !== "syscall") throw new Error(exit.kind);
        console.log(entry.phase, exit.phase, entry.number === exit.number, exit.result !== undefined);
        dbg.catchSyscall(dbg.pid, null);
        dbg.softwareBreakpoint("fixture_stop");
        const stop = await dbg.continueForStop(dbg.pid, {timeoutMs: 2500});
        if (stop.kind !== "breakpoint") throw new Error(stop.kind);
        console.log(m.typeOfVar("packet")?.$size === m.fromDwarf("Packet").$size,
                    m.typeOfVar("no_such_var") === undefined);
    """)
    output = logs(reply)
    if reply["running_scripts"]:
        final = await_state(client, lambda state: not state["running_scripts"])
        assert not any(row["value"]["kind"] == "script_error" for row in final["output"]), final
        output += logs(final)
    assert output == [["entry", "exit", True, True], [True, True]], (reply, output)
    client.script("await dbg.kill();")
    owned.remove(pid)


def validate_inline_frames(client, fixture, owned):
    pid = client.tool("run", pause=True, path=fixture, arg=["inline"])["result"]["pid"]
    owned.add(pid)
    reply = client.tool("script_run", wait_ms=5000, src="""
        dbg.softwareBreakpoint("fixture_stop");
        const stop = await dbg.continueForStop("all", {timeoutMs:3000, pausedOnly:true});
        if (stop.kind !== "breakpoint") throw new Error(stop.kind);
        const frames = dbg.thread(stop.tid).backtrace();
        const inline = frames.flatMap(frame => frame.inlineFrames ?? [])
            .find(frame => frame.symbol === "inline_scope_probe");
        if (!inline) throw new Error(dbg.stringify(frames));
        console.log(inline.callFile?.endsWith("session_fixture.c"), (inline.callLine ?? 0) > 0);
    """)
    assert reply["result"]["status"] == "completed" and logs(reply) == [[True, True]], reply
    client.script("await dbg.kill();")
    owned.remove(pid)


def validate_spec03(client, fixture, owned):
    pid = client.tool("run", pause=True, path=fixture, arg=["memory"])["result"]["pid"]
    owned.add(pid)
    reply = client.script("""
        const Type = m.struct({
            ack: m.u32().bitfield(1), req: m.u32().bitfield(4),
            ...m.anonymous(m.u32().bitfield(3)),
            unused: m.opaque(3),
            ...m.anonymous(m.union({ipv4:m.u32(),ipv6:m.array(m.u8(),16)})),
            type: m.u32().enum({OK:1,ERR:2}),
            ptr: m.pointer(m.void()).align(16),
        });
        const packed = m.struct({kind:m.u8(),length:m.u32().be().align(16)}).pack(1);
        const zero = m.struct({a:m.char(),field:m.u32().bitfield(30),...m.anonymous(m.u32().bitfield(0)),b:m.char()}).pack(1);
        const unnamed = m.struct({a:m.char(),...m.anonymous(m.u32().bitfield(31)),b:m.char()});
        const union = m.union({...m.anonymous(m.u32().bitfield(0)),a:m.char()});
        const actual = [Type.$size, Type.$align, Type.offsetOf("unused"), Type.offsetOf("ipv4"),
            Type.offsetOf("type"), Type.offsetOf("ptr"), packed.$size, packed.$align, packed.offsetOf("length"),
            zero.$size, zero.$align, zero.offsetOf("b"), unnamed.$size, unnamed.$align, unnamed.offsetOf("b"),
            union.$size, union.$align];
        const abi = m.array(m.u32(), actual.length).at((await dbg.getSymbol("spec03_layout"))!.address);
        for (let i = 0; i < actual.length; i++) if (abi[i].$read() !== actual[i]) throw new Error(Type.layout());
        if (Type.offsetOf("ipv6[3]") !== 7 || Type.layout().includes("$anonymous")) throw new Error("layout");
        dbg.softwareBreakpoint("fixture_stop");
        const stop = await dbg.continueForStop();
        if (stop.kind !== "breakpoint" || stop.reason !== "breakpoint") throw new Error("stop reason");
        const address = (await dbg.getSymbol("spec03_packet"))!.address;
        const value = Type.at(address);
        if (value.ack.$read() !== 1 || value.req.$read() !== 13 || value.ipv4.$read() !== 0x12345678) throw new Error("read bits");
        const original = Type.$readBytes(address);
        value.req.$write(2);
        value.type.$write("ERR");
        if (Type.$readBytes(address)[0] !== 5 || value.type.$read() !== 2) throw new Error("write bits");
        Type.$writeBytes(address,original);
        const string = m.cStr().at((await dbg.getSymbol("spec03_string"))!.address);
        if (string.$deref() !== "old") throw new Error("read C string");
        if (!string.$writeContents("中文").warning || string.$deref() !== "中文") throw new Error("long C string write");
        const edge = m.cStr().at((await dbg.getSymbol("spec03_edge"))!.address);
        let failed = false;
        try { edge.$writeContents("1234"); } catch { failed = true; }
        if (!failed) throw new Error("write into protected page");
        const discovered = m.findTypes("Spec03Packet");
        if (!discovered.some(row => row.size === Type.$size && row.module)) throw new Error("type discovery");
        if (discovered.some(row => row.name === "Spec03Packet_function")) throw new Error("function in type discovery");
        const variableName: string = ["spec03", "packet"].join("_");
        if (m.typeOfVar(variableName)?.$size !== Type.$size) throw new Error("dynamic variable type");
        console.log(actual);
    """)
    output = logs(reply)
    if reply["running_scripts"]:
        final = await_state(client, lambda row: not row["running_scripts"])
        assert not any(row["value"]["kind"] == "script_error" for row in final["output"]), final
        output += logs(final)
    assert len(output) == 1 and output[0][0][:9] == [48, 16, 1, 4, 20, 32, 5, 1, 1], (reply, output)
    client.script("await dbg.kill();")
    owned.remove(pid)

    pid = client.tool("run", pause=True, path=fixture, arg=["output"])["result"]["pid"]
    owned.add(pid)
    reply = client.script("""
        const pid = dbg.pid;
        if (!(await dbg.waitOutput(pid, 0)).timedOut) throw new Error("output timeout");
        dbg.resumeThread(pid);
        let stdout = "", stderr = "";
        for (;;) {
            const chunk = await dbg.waitOutput(pid, 2000);
            if (chunk.timedOut) throw new Error("output timeout");
            stdout += chunk.stdout;
            stderr += chunk.stderr;
            if (chunk.exitCode !== undefined) {
                console.log(stdout, stderr, chunk.exitCode);
                break;
            }
        }
    """)
    output = logs(reply)
    if reply["running_scripts"]:
        final = await_state(client, lambda row: not row["running_scripts"])
        assert not any(row["value"]["kind"] == "script_error" for row in final["output"]), final
        output += logs(final)
    assert output == [["stdout tail\n", "stderr tail\n", 39]], (reply, output)
    owned.remove(pid)

    previous = client.tool("run", pause=True, path=fixture, arg=["output"])["result"]["pid"]
    owned.add(previous)
    waiter = client.script("""
        dbg.resumeAll();
        const exit = await dbg.waitExit(2000);
        if (exit.kind !== "exit" || exit.reason !== "code" || exit.code !== 39) throw new Error("exit");
    """)
    if waiter["running_scripts"]:
        waiter = await_state(client, lambda row: not row["running_scripts"])
    assert not any(row["value"]["kind"] == "script_error" for row in waiter["output"]), waiter
    owned.remove(previous)
    switched = client.tool("run", pause=True, path=fixture, arg=["child"])["result"]
    owned.add(switched["pid"])
    assert switched["released"] == [previous], switched
    archived = client.script(f"""
        const result = await dbg.waitOutput({previous}, 0);
        console.log(result.released, result.stdout, result.stderr, result.exitCode);
    """)
    assert logs(archived) == [[True, "stdout tail\n", "stderr tail\n", 39]], archived
    client.script("await dbg.kill();")
    owned.remove(switched["pid"])


def validate_stripped_cfi(client, binary, debug_image, owned):
    pid = client.tool("run", pause=True, path=binary, arg=["child"])["result"]["pid"]
    owned.add(pid)
    result = client.script("""
        dbg.softwareBreakpoint("fixture_stop");
        const stop = await dbg.continueForStop();
        if (stop.kind !== "breakpoint") throw new Error(stop.kind);
        const frames = dbg.thread(stop.tid).backtrace(4);
        console.log(frames.length >= 2, frames[1].unwindMethod,
                    frames[0].missingDebugSections?.includes(".symtab"),
                    frames[0].missingDebugSections?.includes(".debug_info"));
    """)
    output = logs(result)
    if result["running_scripts"]:
        final = await_state(client, lambda row: not row["running_scripts"])
        assert not any(row["value"]["kind"] == "script_error" for row in final["output"]), final
        output += logs(final)
    assert output == [[True, "cfi", True, True]], (result, output)
    no_dwarf = client.script("""
        const address = (await dbg.getSymbol("fixture_stop"))!.address;
        const moduleStart = dbg.mappings().find(row => row.offset === 0n &&
            row.name.endsWith("/stripped-fixture"))!.start;
        const hit = dbg.symbolAt(moduleStart);
        console.log(m.typeOfVar("spec03_packet") === undefined,
                    hit?.match, hit?.offset, hit?.name, dbg.symbolAt(address)?.match);
    """)
    assert logs(no_dwarf) == [[True, "module", "0", None, "exact"]], no_dwarf
    attached = client.script(f"""
        const address = (await dbg.getSymbol("fixture_stop"))!.address;
        dbg.attachDwarf({json.dumps(debug_image)});
        console.log(dbg.addrToLine(address)?.file.endsWith("session_fixture.c"),
            m.findTypes("Spec03Packet").some(row => row.module.endsWith("manual.debug")),
            m.typeOfVar("spec03_packet") !== undefined);
    """)
    assert logs(attached) == [[True, True, True]], attached
    dwarf = client.script("""
        const Packet = m.fromDwarf("struct Spec03Packet");
        const packet = Packet.at((await dbg.getSymbol("spec03_packet"))!.address);
        console.log(Packet.$size, Packet.offsetOf("ipv4"), packet.ipv4.$read());
    """)
    assert logs(dwarf) == [[48, 4, 0x12345678]], dwarf
    symbols = subprocess.check_output(["nm", "-D", binary], text=True).splitlines()
    link_symbol = next(int(line.split()[0], 16) for line in symbols if line.endswith(" fixture_stop"))
    sections = subprocess.check_output(["readelf", "-WS", binary], text=True).splitlines()
    text_section = next(line.split() for line in sections if ".text" in line.split())
    link_text = int(text_section[text_section.index(".text") + 2], 16)
    relocated = client.script(f"""
        const address = (await dbg.getSymbol("fixture_stop"))!.address;
        const bias = address - {link_symbol}n;
        dbg.attachDwarf({json.dumps(debug_image)}, bias);
        const byBias = dbg.addrToLine(address)?.line;
        dbg.attachDwarf({json.dumps(debug_image)}, {{".text": bias + {link_text}n}});
        console.log(byBias !== undefined && dbg.addrToLine(address)?.line === byBias);
    """)
    assert logs(relocated) == [[True]], relocated
    client.script("await dbg.kill();")
    owned.remove(pid)


def validate_automatic_dwarf(client, binaries, debug_image, directory, owned):
    with_symtab = directory / "symtab-only"
    with_debuglink = directory / "linked-debug-fixture"
    subprocess.run(["objcopy", "--strip-debug", binaries[0], with_symtab], check=True)
    companion = directory / "companion.debug"
    companion.write_bytes(Path(debug_image).read_bytes())
    subprocess.run(["objcopy", f"--add-gnu-debuglink={companion}", binaries[1], with_debuglink], check=True)
    for path, expected in [(with_symtab, False), (with_debuglink, True)]:
        pid = client.tool("run", pause=True, path=str(path), arg=["child"])["result"]["pid"]
        owned.add(pid)
        result = client.tool("script_run", wait_ms=6000, src="""
            dbg.softwareBreakpoint("fixture_stop");
            const stop = await dbg.continueForStop();
            if (stop.kind !== "breakpoint") throw Error(stop.kind);
            console.log(m.typeOfVar("spec03_packet") !== undefined);
        """)
        assert result["result"]["status"] == "completed" and logs(result) == [[expected]], result
        assert not any(row["value"]["kind"] == "diagnostic" for row in result["output"]), result
        client.script("await dbg.kill();")
        owned.remove(pid)

def validate_variable_query_budget(client, binary, directory, owned):
    # Both the foreground scan and the background index have DIE budgets.
    # This DWARF4 unit contains more DIEs than either permits.
    abbrev = directory / "lookup-abbrev"
    info = directory / "lookup-info"
    large = directory / "lookup-budget-fixture"
    abbrev.write_bytes(bytes([1, 0x11, 1, 0, 0, 2, 0x24, 0, 0, 0, 0]))
    unit = struct.pack("<HIB", 4, 0, struct.calcsize("P")) + b"\x01" + b"\x02" * 2_000_001 + b"\0"
    info.write_bytes(struct.pack("<I", len(unit)) + unit)
    subprocess.run(["objcopy", "--add-section", f".debug_info={info}",
                    "--add-section", f".debug_abbrev={abbrev}", binary, large], check=True)
    pid = client.tool("run", pause=True, path=str(large), arg=["child"])["result"]["pid"]
    owned.add(pid)
    result = client.tool("script_run", wait_ms=6000, src="""
        dbg.softwareBreakpoint("fixture_stop");
        const stop = await dbg.continueForStop();
        if (stop.kind !== "breakpoint") throw Error(stop.kind);
        const start = Date.now();
        console.log(m.typeOfVar("absent") === undefined, Date.now() - start, "continued");
    """)
    assert result["result"]["status"] == "completed", result
    assert logs(result)[0][0] is True and logs(result)[0][2] == "continued", result
    assert any(row["value"]["kind"] == "diagnostic" and "budget" in row["value"]["text"]
               for row in result["output"]), result
    print(f"typeOfVar foreground budget path: {logs(result)[0][1]} ms", flush=True)
    client.script("await dbg.kill();")
    owned.remove(pid)

def validate_xref(client):
    reply = client.script("""
        const nodes = (await dbg.getSymbol("nodes"))!;
        const target = dbg.memory.readPointer(nodes.address);
        const pointers = dbg.memory.xref(target, {start:nodes.address, end:nodes.address+8n});
        console.log(pointers.kind, pointers.matches.length === 1 && pointers.matches[0] === nodes.address);
        const main = (await dbg.getSymbol("main"))!;
        const stop = (await dbg.getSymbol("fixture_stop"))!;
        const options = {instructionReferences:true as const, start:main.address,
                         end:main.address+BigInt(main.size!), limit:1};
        const page = dbg.memory.xref(stop.address, options);
        const next = dbg.memory.xref(stop.address, {...options,resumeFrom:page.nextAddress!});
        const first = page.matches[0], second = next.matches[0];
        console.log(page.kind, first.kind, first.function, first.sourceLine?.line !== undefined,
                    first.instruction < second.instruction, next.nextAddress);
    """)
    assert logs(reply) == [["pointer_value", True],
                           ["instruction_reference", "branch_target", "main", True, True, None]], reply


def validate_debugging(client, fixture, directory, object_file, owned):
    reply = client.tool("run", pause=True, path=fixture, arg=[])
    pid = reply["result"]["pid"]
    owned.add(pid)
    assert reply["paused_threads"] == [pid], reply
    snapshot = client.tool("snapshot", tid=pid)["result"]
    assert snapshot["consistency"] == "thread" and snapshot["threads"][0]["tid"] == pid
    assert snapshot["threads"][0]["registers"] and snapshot["mappings"]
    symbols = client.script("""
        const names: string[] = [];
        for await (const sym of dbg.iterSymbols(/^fixture_(?=sum$)/)) names.push(sym.name);
        console.log(names);
    """)
    assert logs(symbols) == [[["fixture_sum"]]], symbols
    validate_xref(client)
    client.script('m.fromDwarf("NoSuchType")', invalid=True)
    client.script('m.fromDwarf("Packet").at(1n).noSuchMember', invalid=True)
    reply = client.script("""
        const Packet = m.fromDwarf("Packet");
        const packet = Packet.at((await dbg.getSymbol("packet"))!.address);
        packet.length = 8;
        packet.tail[1] = 22;
        packet.flag = 6;
        console.log(packet.length.$read(), packet.tail[1].$read(), packet.flag.$read(),
                    packet.payload.word.$read(), packet.payload.octets[0].$read());
        const thread = await dbg.pauseThread(dbg.pid);
        await dbg.prepareScratchPad();
        console.log(thread.injectSyscall(dbg.arch === "x86_64" ? 39n : 172n)[0]);
        const address = await thread.allocate(4096);
        dbg.memory.writeUint32(address, 0x11223344, "be");
        console.log(dbg.memory.readUint32(address, "le"), dbg.memory.search(
            fmt.bytesFromHex("11 22 33 44"), address, address + 4096n)[0] === address);
        await thread.free(address, 4096);
    """)
    assert logs(reply) == [[8, 22, 6, 0x12345678, 0x78], [str(pid)], [0x44332211, True]], reply
    reply = client.script("""
        dbg.softwareBreakpoint("fixture_stop", async hit => {
            console.log(hit.hitCount, hit.thread.tid, hit.thread.backtrace()[0].symbol);
            hit.preventOtherBreakpointOnThisThread();
            console.log(await hit.thread.ask({}));
            hit.pause();
            hit.breakpoint.disable();
        });
        dbg.resumeAll();
    """)
    hit_logs = logs(reply)
    if not reply["waiting_inputs"]:
        reply = await_state(client, lambda state: state["waiting_inputs"])
        hit_logs += logs(reply)
    assert reply["paused_threads"] == [pid], reply
    assert hit_logs == [[1, pid, "fixture_stop"]], reply
    assert reply["waiting_inputs"][0]["tid"] == pid, reply
    reply = client.tool("send_input", handler=reply["waiting_inputs"][0]["handler"], data="at breakpoint")
    assert reply["paused_threads"] == [pid] and logs(reply) == [["at breakpoint"]], reply
    reply = client.script("""
        const thread = dbg.thread(dbg.pid);
        const fn = m.function({args:[m.i32(),m.i32()], returns:m.i32()});
        const addr = (await dbg.getSymbol("fixture_sum"))!.address;
        console.log((await fn.at(addr, thread.tid)(7, 12)).$read(), thread.eval("fixture_sum(30, -1)").value);
        const packet = m.fromDwarf("Packet").at((await dbg.getSymbol("packet"))!.address);
        console.log(packet.node.$deref().next.$deref().value.$read());
    """)
    assert logs(reply) == [[19, 29], [29]], reply
    if object_file:
        reply = client.script(f"""
            const t = await dbg.pauseThread(dbg.pid);
            const addr = await t.allocate(4096);
            await dbg.linkObjAt({json.dumps(object_file)},addr);
            await t.protect(addr,4096,"rx");
            const linked = (await dbg.getSymbol("fixture_linked"))!;
            const fn = m.function({{args:[m.i32()],returns:m.i32()}}).at(linked.address,t.tid);
            console.log((await fn(8)).$read());
            await t.free(addr,4096);
        """)
        assert logs(reply) == [[17]], reply
    reply = client.script("""
        import type { Value } from "aidbg";
        dbg.softwareWatchpoint("watched", hit => {
            console.log("read", hit.access, hit.length, (hit.before as Value.Scalar<number>).$read());
            hit.breakpoint.remove();
        }, {length:4, access:"read"});
        dbg.softwareWatchpoint("watched", hit => {
            console.log("write", hit.access, (hit.before as Value.Scalar<number>).$read(),
                        (hit.after as Value.Scalar<number>).$read());
            hit.breakpoint.remove();
        }, {length:4, access:"write"});
        dbg.onSignal("SIGUSR1", async hit => {
            console.log(hit.signalName, hit.thread.tid);
            hit.passToTarget(false);
            hit.removeThisHandler();
            await dbg.pauseThread(hit.thread.tid);
            await hit.thread.ask({});
        });
        dbg.resumeAll();
    """)
    events = logs(reply)
    if not reply["waiting_inputs"]:
        reply = await_state(client, lambda state: state["waiting_inputs"])
        events += logs(reply)
    assert events == [["read", "read", 4, 33], ["write", "write", 33, 44], ["SIGUSR1", pid]], reply
    reply = client.tool("send_input", handler=reply["waiting_inputs"][0]["handler"], data="keep paused")
    assert reply["paused_threads"] == [pid], reply
    dump = str(directory / ("target-" + Path(fixture).name + ".zst"))
    # Instruction xref needs captured code bytes across all pages of main.
    client.script(f'dbg.coredump({json.dumps(dump)}, "full");')
    assert Path(dump).is_file()
    reply = client.tool("core_open", path=dump, executable=fixture)
    assert not reply["paused_threads"] and reply["result"]["dwarf_available"], reply
    assert client.tool("snapshot")["result"]["threads"][0]["tid"] == pid
    validate_xref(client)
    reply = client.script("""
        const packet = m.fromDwarf("Packet").at((await dbg.getSymbol("packet"))!.address);
        console.log(packet.length.$read(), packet.flag.$read(),
                    packet.node.$deref().next.$deref().value.$read());
        console.log(dbg.disassemble("fixture_sum", 3).every(instruction => instruction.bytes.length > 0));
        try { await dbg.pauseThread(dbg.pid); } catch(error) { console.log((error as Error).name); }
    """)
    assert logs(reply) == [[8, 6, 29], [True], ["NotSupport"]], reply
    os.kill(pid, signal.SIGKILL)
    owned.remove(pid)


def validate_event_queue(client, fixture, owned):
    result = client.tool("run", pause=True, path=fixture, arg=["events"])
    pid = result["result"]["pid"]
    owned.add(pid)
    assert result["result"]["scratchpad"] and not result["signals"], result
    reply = client.script("""
        const addr = (await dbg.getSymbol("fixture_stop"))!.address;
        const line = dbg.addrToLine(addr)!;
        const roundtrip = dbg.lineToAddr(line.file,line.line);
        if (typeof roundtrip === "bigint") console.log(dbg.addrToLine(roundtrip)?.line === line.line);
        dbg.softwareBreakpoint(addr);
        dbg.resumeAll();
        console.log("resumed");
    """)
    assert logs(reply)[-1] == ["resumed"] and not reply["waiting_events"], reply
    reply = await_state(client, lambda row: row["pending_events"] >= 2 and len(row["paused_threads"]) == 2)
    assert pid not in reply["paused_threads"], reply
    first = client.script("""
        const first = await dbg.continueForStop("all", {timeoutMs:1000});
        if (first.kind !== "breakpoint") throw new Error(first.kind);
        const answer = await dbg.thread(first.tid).ask({event:first, note:"inspect"});
        console.log(first.tid, answer);
    """)
    assert first["pending_events"] == 1 and len(first["waiting_inputs"]) == 1, first
    handler = first["waiting_inputs"][0]
    assert handler["payload"]["note"] == "inspect"
    event = handler["payload"]["event"]
    assert event["kind"] == "breakpoint" and event["paused"] is True, event
    assert handler["tid"] == event["tid"], handler
    second = client.script("""
        const batch = await dbg.waitStops(16,1000);
        if (batch.kind !== "stops") throw new Error(batch.kind);
        console.log(batch.events.map(e => [e.tid,e.sequence]));
        console.log((await dbg.waitStops(16,1)).kind);
    """)
    if len(logs(second)) < 2:
        tail = await_state(client, lambda row: not row["waiting_events"])
        second["output"] += tail["output"]
    assert len(logs(second)[0][0]) == 1 and logs(second)[1] == ["timeout"], second
    assert logs(second)[0][0][0][0] != event["tid"], second
    assert logs(second)[0][0][0][1] > event["sequence"], second
    answer = client.tool("send_input", handler=handler["handler"], data="release")
    assert logs(answer) == [[event["tid"],"release"]] and len(answer["paused_threads"]) == 2, answer
    table = client.tool("ps")["result"]["items"]
    rows = [row for row in table if row["pid"] == pid]
    assert len(rows) == 1 and rows[0]["threads"] == 3, rows
    thread_table = client.tool("ps", threads=True)["result"]["items"]
    tids = {row["tid"] for row in thread_table if row["pid"] == pid}
    assert tids == {pid, event["tid"], logs(second)[0][0][0][0]}, tids
    resumed = client.script('dbg.resumeAll();')
    chunks = [resumed]
    deadline = time.monotonic() + 5
    while not any(row["signals"] for row in chunks):
        assert time.monotonic() < deadline, chunks
        chunks.append(client.tool("ps"))
    reported = [sig for row in chunks for sig in row["signals"]]
    assert [(sig["signalName"], sig["paused"]) for sig in reported] == [("SIGUSR1", True)], chunks
    stop = client.script("""
        const hit = await dbg.continueForStop(dbg.pid, {until: () => false, timeoutMs:1000});
        if (hit.kind !== "signal") throw new Error(hit.kind);
        console.log(hit.kind, hit.paused);
        const deliver = hit.passToTarget;
        export function deliverPendingSignal() { deliver(true); }
    """)
    assert logs(stop) == [["signal", True]] and stop["paused_threads"] == [pid], stop
    assert not stop["signals"] and not stop["process_output"]["stdout"], stop
    held = client.script("""
        if (dbg.resumeAll() !== undefined || dbg.resumeThread(dbg.pid) !== undefined) {
            throw new Error("resume methods must return undefined synchronously");
        }
    """)
    assert held["paused_threads"] == [pid] and not held["signals"], held
    chunks.append(client.script("$.deliverPendingSignal();"))
    while not any("enter data" in row["process_output"]["stdout"] for row in chunks):
        assert time.monotonic() < deadline, chunks
        chunks.append(client.tool("ps"))
        time.sleep(.02)
    assert any("stderr ready" in row["process_output"]["stderr"] for row in chunks), chunks
    assert sum(len(row["signals"]) for row in chunks) == 1, chunks
    output = client.script(r"""
        console.log(dbg.process.stdout.read().text, dbg.process.stderr.read().text);
        console.log(dbg.process.stdin.write("answer\n"));
        dbg.process.stdin.close();
        const exit = await dbg.waitExit();
        if (exit.kind !== "exit" || exit.reason !== "code") throw new Error(exit.kind);
        console.log(exit.code);
        console.log((await dbg.waitExit(1)).kind);
    """)
    if not any(row == ["ended"] for row in logs(output)):
        tail = await_state(client, lambda row: not row["waiting_events"] and not row["running_scripts"])
        output["output"] += tail["output"]
    assert logs(output) == [["enter data\n","stderr ready\n"],[7],[37],["ended"]], output
    owned.remove(pid)

    result = client.tool("run", pause=True, path="/bin/sh", arg=["-c", "exit 29"])
    pid = result["result"]["pid"]
    owned.add(pid)
    result = client.script("""
        const stop = await dbg.continueForStop("all", {until: () => false});
        if (stop.kind !== "exit" || stop.reason !== "code" || stop.scope !== "process") throw new Error(stop.kind);
        console.log(stop.code);
    """)
    if not logs(result):
        tail = await_state(client, lambda row: not row["waiting_events"] and not row["running_scripts"])
        result["output"] += tail["output"]
    assert logs(result) == [[29]], result
    owned.remove(pid)


def validate_next_hit(client, fixture, owned):
    target = client.tool("run", pause=True, path=fixture, arg=[])
    pid = target["result"]["pid"]
    owned.add(pid)
    reply = client.script("""
        dbg.onSignal("SIGUSR1", hit => hit.passToTarget(true));
        dbg.softwareBreakpoint("fixture_stop", async hit => {
            if (hit.hitCount !== 1) return;
            const result = await hit.thread.nextHit(3000);
            if (result.kind !== "breakpoint") throw new Error(result.kind);
            console.log(result.hitCount,result.paused);
        });
        dbg.resumeAll();
    """)
    if not logs(reply):
        reply = await_state(client, lambda row: bool(logs(row)))
    assert logs(reply) == [[2,True]], reply
    assert reply["paused_threads"] == [pid], reply
    observed = client.script("""
        const stops = await dbg.waitStops(16,100);
        if (stops.kind !== "stops") throw new Error(stops.kind);
        console.log(stops.events.filter(e => e.kind === "signal").map(e => [e.signalName,e.paused]));
    """)
    assert logs(observed) == [[[["SIGUSR1", False]]]], observed
    os.kill(pid, signal.SIGKILL)
    reply = client.script("""
        const result = await dbg.waitExit(3000);
        if (result.kind !== "exit" || result.reason !== "signal") throw new Error(result.kind);
        console.log(result.signal);
    """)
    if not logs(reply):
        reply = await_state(client, lambda row: bool(logs(row)))
    assert logs(reply) == [[9]] and not reply["paused_threads"], reply
    owned.remove(pid)


def validate_fault_and_kill(client, fixture, owned):
    result = client.tool("run", pause=True, path=fixture, arg=["fault"])
    pid = result["result"]["pid"]
    owned.add(pid)
    hit = client.script("""
        dbg.onSignal("SIGSEGV", hit => console.log("callback", hit.signalName));
        const stop = await dbg.continueForStop("all", {timeoutMs:3000});
        if (stop.kind !== "signal") throw new Error(stop.kind);
        console.log(stop.signalName, stop.paused, stop.faultAddress === 0n);
    """)
    reported = hit["signals"]
    if len(logs(hit)) < 2:
        tail = await_state(client, lambda row: not row["running_scripts"])
        tail["output"] = hit["output"] + tail["output"]
        reported += tail["signals"]
        hit = tail
    assert logs(hit) == [["callback", "SIGSEGV"], ["SIGSEGV", True, True]] and hit["paused_threads"] == [pid], hit
    assert [(sig["signalName"], sig["paused"]) for sig in reported] == [("SIGSEGV", True)], hit
    time.sleep(.1)
    still = client.tool("ps")
    assert still["paused_threads"] == [pid] and not still["signals"] and still["pending_events"] == 0, still
    suppressed = client.script("dbg.thread(dbg.pid).passToTarget(false);")
    assert suppressed["paused_threads"] == [pid] and not suppressed["signals"], suppressed
    killed = client.script("await dbg.kill();")
    assert not killed["paused_threads"] and not killed["signals"], killed
    assert client.tool("snapshot", error=True)["error"], killed
    deadline = time.monotonic() + 3
    while Path(f"/proc/{pid}").exists():
        assert time.monotonic() < deadline, pid
        time.sleep(.02)
    owned.remove(pid)

    with subprocess.Popen([fixture, "attach"], stdout=subprocess.PIPE, text=True) as target:
        try:
            assert target.stdout.readline().strip() == "ready"
            client.tool("attach", pause=True, pid=target.pid)
            os.kill(target.pid, signal.SIGUSR1)
            waiting = client.script("""
                const stop = await dbg.continueForStop("all", {timeoutMs:3000});
                if (stop.kind !== "signal") throw new Error(stop.kind);
                console.log(stop.signalName, stop.paused);
            """)
            if not logs(waiting):
                waiting = await_state(client, lambda row: bool(logs(row)))
            assert logs(waiting) == [["SIGUSR1", True]], waiting
            untraced = client.script("await dbg.kill(15);")
            assert not untraced["paused_threads"], untraced
            assert target.wait(timeout=3) == -signal.SIGTERM
        finally:
            if target.poll() is None:
                target.kill()


def validate_attach(client, fixture, client_exe, socket, token, lease):
    with subprocess.Popen([fixture, "attach"], stdout=subprocess.PIPE, text=True) as target:
        try:
            assert target.stdout.readline().strip() == "ready"
            reply = client.tool("attach", pause=True, pid=target.pid)
            assert reply["paused_threads"] == [target.pid], reply
            if lease:
                previous_status = client.tool("status")["result"]
                client.close()
                client = Client(client_exe, socket, token)
                assert client.tool("status")["result"] == previous_status
                reply = client.tool("snapshot")
                assert reply["paused_threads"] == [target.pid], reply
                client.close()
                start = time.monotonic()
                while time.monotonic() - start < 34:
                    tracer = next(line for line in Path(f"/proc/{target.pid}/status").read_text().splitlines()
                                  if line.startswith("TracerPid:")).split()[1]
                    if tracer == "0":
                        elapsed = time.monotonic() - start
                        assert 26 < elapsed < 34, elapsed
                        break
                    time.sleep(.25)
                else:
                    raise AssertionError("session lease did not detach the target")
            else:
                client.script("await dbg.detach();")
        finally:
            target.kill()
            client.close()


def validate_process_lifecycle(client, fixture, library, owned):
    def launch(*args):
        result = client.tool("run", pause=True, path=fixture, arg=list(args))
        pid = result["result"]["pid"]
        owned.add(pid)
        return pid

    def check(source, expected):
        reply = client.script(source)
        if len(logs(reply)) < len(expected):
            tail = await_state(client, lambda row: not row["running_scripts"])
            reply["output"] += tail["output"]
        assert logs(reply) == expected, reply

    parent = launch("kid")
    check("""
        const parent = dbg.pid;
        const pending = dbg.pendingBreakpoint("fixture_stop", null);
        if (pending.address === null) throw new Error("initial symbol was not bound");
        dbg.setForkPolicy("child");
        const fork = await dbg.continueForStop(parent, {timeoutMs:3000});
        if (fork.kind !== "fork") throw new Error(fork.kind);
        console.log(fork.parentPid === parent && fork.tid !== parent && dbg.pid === fork.tid, fork.paused);
        const exec = await dbg.continueForStop(dbg.pid, {timeoutMs:3000});
        if (exec.kind !== "exec") throw new Error(exec.kind);
        console.log(exec.paused, pending.address !== null);
        const hit = await dbg.continueForStop(dbg.pid, {timeoutMs:3000});
        if (hit.kind !== "breakpoint") throw new Error(hit.kind);
        console.log(hit.breakpointId === pending.id && hit.address === pending.address);
        dbg.resumeAll();
        const exit = await dbg.waitExit(3000);
        console.log(exit.kind === "exit" && exit.reason === "code" && exit.code);
    """, [[True, True], [True, True], [True], [23]])
    owned.remove(parent)

    child = launch("dlopen", library)
    check("""
        const point = dbg.pendingBreakpoint("fixture_linked", null, {module:"session-test.so"});
        console.log(point.address === null);
        for (let i = 1; i <= 2; ++i) {
            const hit = await dbg.continueForStop(dbg.pid, {timeoutMs:3000});
            if (hit.kind !== "breakpoint") throw new Error(hit.kind);
            console.log(hit.breakpointId === point.id && hit.address === point.address, hit.hitCount);
            if (i === 1) {
                if (m.typeOfVar("input")?.$size !== 4 || m.typeOfVar("global_context") !== undefined) {
                    throw Error("incorrect lookup in the shared-library frame");
                }
                let crossModule = false;
                try { dbg.thread(hit.tid).eval("global_context.type"); crossModule = true; } catch {}
                if (crossModule) throw Error("a local miss searched the executable's global DWARF");
                await fmt.gdb("up");
                if (m.typeOfVar("library")?.$size !== 8 || m.typeOfVar("input") !== undefined) {
                    throw Error("typeOfVar ignored the selected caller frame");
                }
                await fmt.gdb("down");
            }
        }
        dbg.resumeAll();
        const exit = await dbg.waitExit(3000);
        console.log(exit.kind === "exit" && exit.reason === "code" && exit.code, point.address === null);
    """, [[True], [True, 1], [True, 2], [24, True]])
    owned.remove(child)


def validate_debug_cases(client, fixtures, owned):
    def launch(case):
        target = client.tool("run", pause=True, path=str(fixtures / case), arg=[])
        pid = target["result"]["pid"]
        owned.add(pid)
        return pid

    def script(source, expected):
        result = client.script(source)
        if len(logs(result)) < len(expected):
            tail = await_state(client, lambda row: not row["running_scripts"])
            result["output"] += tail["output"]
        assert logs(result) == expected, result

    reply = client.tool("script_run", run={"path": str(fixtures / "D02"), "pause": True}, wait_ms=5000, src="""
        const trace = await dbg.traceHits("push", {timeoutMs:3000});
        const history = await dbg.waitStops(64, 0);
        if (history.kind !== "stops") throw new Error(history.kind);
        console.log(trace.stop.kind, trace.hits.map(hit => hit.hitCount),
            history.events.filter(row => row.kind === "breakpoint").length);
    """)
    assert reply["result"]["status"] == "completed", reply
    assert logs(reply) == [["exit", [1, 2, 3, 4], 4]], reply
    assert reply["process_output"]["stdout"] == "10 20 30 10\n", reply

    pid = launch("D04")
    reply = client.tool("script_run", wait_ms=5000, src="""
        dbg.resumeAll();
        let output = "";
        for (let attempt = 0; attempt < 4; attempt++) {
            output += (await dbg.waitOutput(dbg.pid, 500)).stdout;
            if (output.includes("refresh started") && output.includes("reconcile started")) break;
        }
        if (!output.includes("refresh started") || !output.includes("reconcile started")) throw new Error(output);
        const {threads, incomplete} = await dbg.backtraceAll();
        if (incomplete?.some(issue => ["stop","registers"].includes(issue.stage))) {
            throw new Error(dbg.stringify(incomplete));
        }
        if (threads.some(thread => Object.keys(thread.registers).length === 0)) {
            throw new Error("snapshot lost registers");
        }
        const frames = threads.flatMap(thread => thread.frames);
        if (!frames.some(frame => frame.symbol === "refresh") || !frames.some(frame => frame.symbol === "reconcile"))
            throw new Error(dbg.stringify(threads));
        console.log(threads.length);
    """)
    assert reply["result"]["status"] == "completed", reply
    assert logs(reply) == [[3]], reply
    client.script("await dbg.kill();")
    owned.remove(pid)

    for case, symbol, offset, before, after in (("D06", "flags", 0, 5, 2), ("D08", "rows", 16, 101, 0)):
        pid = launch(case)
        script(f"""
            import type {{Value}} from "aidbg";
            const at = (await dbg.getSymbol("{symbol}"))!.address + {offset}n;
            dbg.hardwareWatchpoint(at, null, {{length:4, access:"write"}});
            const stop = await dbg.continueForStop(dbg.pid, {{timeoutMs:3000}});
            if (stop.kind !== "watchpoint") throw new Error(stop.kind);
            console.log((stop.before as Value.Scalar<number>).$read(),
                        (stop.after as Value.Scalar<number>).$read(), dbg.memory.readUint32(at));
        """, [[before, after, after]])
        client.script("await dbg.kill();")
        owned.remove(pid)

    pid = launch("D09")
    script("""
        const mangled = await dbg.getSymbol("_ZL14schedule_retryv");
        const short = await dbg.getSymbol("schedule_retry");
        const full = await dbg.getSymbol("schedule_retry()");
        console.log(short?.demangledName, short?.address === mangled?.address,
                    full?.address === mangled?.address);
    """, [["schedule_retry()", True, True]])
    client.script("await dbg.kill();")
    owned.remove(pid)

    pid = launch("D02")
    reply = client.tool("script_run", wait_ms=5000, src="""
        const at = (await dbg.getSymbol("push"))!.address;
        dbg.softwareBreakpoint(at, null, {condition: hit => hit.hitCount === 3});
        const stop = await dbg.continueForStop("all", {timeoutMs:3000, pausedOnly:true});
        if (stop.kind !== "breakpoint") throw new Error(stop.kind);
        const source = dbg.addrToLine(at);
        if (!source) throw new Error("missing DWARF source");
        const directory = source.file.slice(0, source.file.lastIndexOf("/"));
        const mapped = dbg.list(at, 1, [{from:directory, to:directory + "/../cases"}]);
        console.log(stop.hitCount, mapped?.originalFile === source.file && mapped?.file !== source.file,
            mapped?.lines.some(row => row.text.includes("static void push")));
    """)
    assert reply["result"]["status"] == "completed", reply
    assert logs(reply) == [[3, True, True]], reply
    client.script("await dbg.kill();")
    owned.remove(pid)

    pid = launch("D10")
    script("""
        const at = (await dbg.getSymbol("Reader::read"))!.address;
        const point = dbg.softwareBreakpoint(at);
        const first = await dbg.continueForStop(dbg.pid, {timeoutMs:3000});
        if (first.kind !== "breakpoint") throw new Error(first.kind);
        const untypedTid: any = first.tid;
        const thread = await dbg.pauseThread(untypedTid);
        if (thread.locals().length !== 0) throw new Error("unreadable locals at entry");
        if ((await dbg.pauseAll()).length !== 1) throw new Error("unexpected thread count");
        await thread.next(1);
        const next = await dbg.continueForStop(dbg.pid, {timeoutMs:3000});
        if (next.kind !== "breakpoint") throw new Error(next.kind);
        console.log(next.breakpointId === point.id, next.hitCount);
    """, [[True, 2]])
    client.script("await dbg.kill();")
    owned.remove(pid)

    pid = launch("D05")
    script("""
        dbg.softwareBreakpoint("blocks_for");
        const stop = await dbg.continueForStop(dbg.pid, {timeoutMs:3000});
        if (stop.kind !== "breakpoint") throw new Error(stop.kind);
        const [callee, caller] = dbg.thread(stop.tid).backtrace(2);
        const listing = dbg.list(caller, 2);
        console.log(callee.symbol, caller.symbol, caller.locals?.bytes?.value,
                    listing?.lines.some(row => row.text.includes("blocks_for(bytes)")));
        // Read the same caller PC again before resuming. The scope plan can
        // be reused, but the value must reflect the changed stack slot.
        const slot = caller.locals?.bytes?.address;
        if (slot === undefined || slot === null) throw new Error("missing caller local address");
        dbg.memory.writeUint32(BigInt(slot), 70001);
        const updated = dbg.thread(stop.tid).backtrace(2)[1].locals?.bytes?.value;
        dbg.memory.writeUint32(BigInt(slot), 70000);
        console.log(updated);
        const controlled = await dbg.pauseThread(stop.tid);
        let parameter: import("aidbg").Variable["value"] = null;
        for (let i = 0; i < 5; ++i) {
            await controlled.next(1);
            parameter = controlled.backtrace(1)[0].parameters?.bytes?.value ?? null;
            if (parameter === 4464) break;
        }
        console.log(parameter);
    """, [["blocks_for", "main", 70000, True], [70001], [4464]])
    client.script("await dbg.kill();")
    owned.remove(pid)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("server")
    parser.add_argument("fixtures", nargs="+")
    parser.add_argument("--object")
    parser.add_argument("--lease", action="store_true")
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--library")
    parser.add_argument("--stripped")
    parser.add_argument("--debug-image")
    args = parser.parse_args()
    client_exe, server_exe = map(os.path.abspath, (args.client, args.server))
    fixtures = list(map(os.path.abspath, args.fixtures))
    object_file = os.path.abspath(args.object) if args.object else None
    with tempfile.TemporaryDirectory(prefix="aidbg-session-") as tmp:
        directory = Path(tmp)
        socket = str(directory / "server.sock")
        with subprocess.Popen([server_exe, "--socket", socket, "--state-dir", tmp], stderr=subprocess.PIPE) as server:
            owned = set()
            client = None
            try:
                for _ in range(200):
                    if Path(socket).exists() or server.poll() is not None:
                        break
                    time.sleep(.025)
                assert Path(socket).exists(), "debugger server did not start"
                token = "integration-session-" + os.urandom(16).hex()
                client = Client(client_exe, socket, token)
                validate_text_output(client, fixtures[0], owned)
                validate_types_and_input(client)
                validate_quick_start(client, fixtures[0], owned)
                validate_presentation(client, fixtures[0], owned)
                validate_session_extensions(client, fixtures[0], owned)
                validate_inline_frames(client, fixtures[0], owned)
                validate_spec03(client, fixtures[0], owned)
                if args.stripped and args.debug_image:
                    validate_automatic_dwarf(client, (fixtures[0], os.path.abspath(args.stripped)),
                                             os.path.abspath(args.debug_image), directory, owned)
                    validate_stripped_cfi(client, os.path.abspath(args.stripped), os.path.abspath(args.debug_image), owned)
                    validate_variable_query_budget(client, os.path.abspath(args.stripped), directory, owned)
                validate_event_queue(client, fixtures[0], owned)
                validate_next_hit(client, fixtures[0], owned)
                validate_fault_and_kill(client, fixtures[0], owned)
                if args.cases:
                    validate_debug_cases(client, args.cases.resolve(), owned)
                if args.library:
                    validate_process_lifecycle(client, fixtures[0], os.path.abspath(args.library), owned)
                for fixture in fixtures:
                    validate_debugging(client, fixture, directory, object_file, owned)
                    print("validated", Path(fixture).name, flush=True)
                validate_attach(client, fixtures[0], client_exe, socket, token, args.lease)
            finally:
                if client is not None:
                    client.close()
                server.terminate()
                for pid in owned:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    _, stderr = server.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    server.kill()
                    _, stderr = server.communicate()
                if server.returncode or stderr:
                    print(stderr.decode())
                    assert server.returncode == 0, server.returncode
    print("MCP session integration passed")


if __name__ == "__main__":
    main()
