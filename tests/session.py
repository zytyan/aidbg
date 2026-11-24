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

TOOLS = {"run", "attach", "script_run", "core_open", "send_input", "interrupt_input",
         "snapshot", "perf", "ps"}


class Client:
    def __init__(self, executable, socket, token):
        self.process = subprocess.Popen(
            [executable, "--socket", socket, "--session", token],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.counter = 0
        self.rpc("initialize", protocolVersion="2024-11-05", capabilities={},
                 clientInfo={"name": "aidbg integration test", "version": "1"})
        self.write({"jsonrpc": "2.0", "method": "notifications/initialized"})

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
        reply = client.script("")
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
    reply = client.script("console.log(await console.waitInput());")
    assert len(reply["running_scripts"]) == 1 and len(reply["waiting_inputs"]) == 1, reply
    handler = reply["waiting_inputs"][0]["handler"]
    status = client.tool("ps")
    assert status["waiting_inputs"] == reply["waiting_inputs"]
    assert status["running_scripts"] == reply["running_scripts"]
    reply = client.tool("send_input", handler=handler, data="first response")
    assert not reply["waiting_inputs"] and logs(reply) == [["first response"]], reply
    reply = client.script("try { await console.waitInput(); } catch (error) { console.log((error as Error).message); }")
    handler = reply["waiting_inputs"][0]["handler"]
    reply = client.tool("interrupt_input", handler=handler, msg="interrupt message")
    assert logs(reply) == [["interrupt message"]], reply
    reply = client.script("try { await console.waitInput(0.01); } catch (error) { console.log((error as Error).message); }")
    if reply["waiting_inputs"]:
        reply = await_state(client, lambda state: not state["waiting_inputs"])
    assert logs(reply) == [["input timed out"]], reply


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
        const thread = await dbg.pause(dbg.pid);
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
            console.log(await console.waitInput());
            hit.pause();
            hit.breakpoint.disable();
        });
        await dbg.continue("all");
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
            const t = await dbg.pause(dbg.pid);
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
            await dbg.pause(hit.thread.tid);
            await console.waitInput();
        });
        await dbg.continue("all");
    """)
    events = logs(reply)
    if not reply["waiting_inputs"]:
        reply = await_state(client, lambda state: state["waiting_inputs"])
        events += logs(reply)
    assert events == [["read", "read", 4, 33], ["write", "write", 33, 44], ["SIGUSR1", pid]], reply
    reply = client.tool("send_input", handler=reply["waiting_inputs"][0]["handler"], data="keep paused")
    assert reply["paused_threads"] == [pid], reply
    dump = str(directory / ("target-" + Path(fixture).name + ".zst"))
    client.script(f'dbg.coredump({json.dumps(dump)}, "standard");')
    assert Path(dump).is_file()
    reply = client.tool("core_open", path=dump, executable=fixture)
    assert not reply["paused_threads"] and reply["result"]["dwarf_available"], reply
    assert client.tool("snapshot")["result"]["threads"][0]["tid"] == pid
    reply = client.script("""
        const packet = m.fromDwarf("Packet").at((await dbg.getSymbol("packet"))!.address);
        console.log(packet.length.$read(), packet.flag.$read(),
                    packet.node.$deref().next.$deref().value.$read());
        console.log(dbg.disassemble("fixture_sum", 3).every(instruction => instruction.bytes.length > 0));
        try { await dbg.pause(dbg.pid); } catch(error) { console.log((error as Error).name); }
    """)
    assert logs(reply) == [[8, 6, 29], [True], ["NotSupport"]], reply
    os.kill(pid, signal.SIGKILL)
    owned.remove(pid)


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("server")
    parser.add_argument("fixtures", nargs="+")
    parser.add_argument("--object")
    parser.add_argument("--lease", action="store_true")
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
