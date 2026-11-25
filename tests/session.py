#!/usr/bin/env python3
"""Exercise the public MCP entry point using only locally launched fixtures."""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time

TOOLS = {"connect", "run", "attach", "script_run", "core_open", "send_input", "interrupt_input",
         "snapshot", "perf", "ps", "set_fork_policy"}


class Client:
    def __init__(self, executable, socket, token):
        self.process = subprocess.Popen(
            [executable, "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.counter = 0
        self.rpc("initialize", protocolVersion="2024-11-05", capabilities={},
                 clientInfo={"name": "aidbg integration test", "version": "1"})
        self.write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        disconnected = self.rpc("tools/call", name="ps", arguments={})
        assert disconnected["isError"] and "connect" in disconnected["structuredContent"]["error"], disconnected
        connected = self.rpc("tools/call", name="connect", arguments={"socket": socket, "session": token})
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

    def tool(self, name, *, error=False, **arguments):
        result = self.rpc("tools/call", name=name, arguments=arguments)["structuredContent"]
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
    status = client.tool("ps")
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
    pid = client.tool("run", path=fixture, arg=["child"])["result"]["pid"]
    owned.add(pid)
    table = client.tool("ps")["result"]
    assert table.startswith("PID PPID THREADS ARGS\n")
    assert any(row.startswith(f"{pid} ") and row.split(maxsplit=3)[2] == "1" for row in table.splitlines())
    thread_table = client.tool("ps", threads=True)["result"]
    assert thread_table.startswith("PID PPID TID ARGS\n")
    assert any(row.startswith(f"{pid} ") and row.split(maxsplit=3)[2] == str(pid) for row in thread_table.splitlines())
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
    reply = client.tool("run", path=fixture, arg=[])
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
            console.bytesFromHex("11 22 33 44"), address, address + 4096n)[0] === address);
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
    result = client.tool("run", path=fixture, arg=["events"])
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
    table = client.tool("ps")["result"]
    rows = [row for row in table.splitlines() if row.startswith(f"{pid} ")]
    assert len(rows) == 1 and rows[0].split(maxsplit=3)[2] == "3", rows
    thread_table = client.tool("ps", threads=True)["result"]
    tids = {int(row.split(maxsplit=3)[2]) for row in thread_table.splitlines() if row.startswith(f"{pid} ")}
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

    result = client.tool("run", path="/bin/sh", arg=["-c", "exit 29"])
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
    target = client.tool("run", path=fixture, arg=[])
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
    result = client.tool("run", path=fixture, arg=["fault"])
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
            client.tool("attach", pid=target.pid)
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
            reply = client.tool("attach", pid=target.pid)
            assert reply["paused_threads"] == [target.pid], reply
            if lease:
                client.close()
                client = Client(client_exe, socket, token)
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
        result = client.tool("run", path=fixture, arg=list(args))
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
        }
        dbg.resumeAll();
        const exit = await dbg.waitExit(3000);
        console.log(exit.kind === "exit" && exit.reason === "code" && exit.code, point.address === null);
    """, [[True], [True, 1], [True, 2], [24, True]])
    owned.remove(child)


def validate_debug_cases(client, fixtures, owned):
    def launch(case):
        target = client.tool("run", path=str(fixtures / case), arg=[])
        pid = target["result"]["pid"]
        owned.add(pid)
        return pid

    def script(source, expected):
        result = client.script(source)
        if len(logs(result)) < len(expected):
            tail = await_state(client, lambda row: not row["running_scripts"])
            result["output"] += tail["output"]
        assert logs(result) == expected, result

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
        const controlled = await dbg.pauseThread(stop.tid);
        let parameter: import("aidbg").Variable["value"] = null;
        for (let i = 0; i < 5; ++i) {
            await controlled.next(1);
            parameter = controlled.backtrace(1)[0].parameters?.bytes?.value ?? null;
            if (parameter === 4464) break;
        }
        console.log(parameter);
    """, [["blocks_for", "main", 70000, True], [4464]])
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
                validate_types_and_input(client)
                validate_session_extensions(client, fixtures[0], owned)
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
