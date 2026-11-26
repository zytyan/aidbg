# aidbg Quick Start

aidbg debugs Linux processes and core dumps. Connect to aidbg-server with
`connect({socket: "/absolute/path/to/aidbg.sock"})` or supply its HTTP endpoint.
Use `ps` to find a PID, `run` to launch a program, `attach` to inspect an
existing process, or `core_open` for postmortem debugging. Both `run` and
`attach` leave the live target running by default. Set `pause: true` to inspect
a stopped target immediately.

Use `status` to check target state and pending requests, `snapshot` to sample
threads, and `gdb` for common debugger commands. Use `script_run({src: "..."})`
for TypeScript, and `script_wait({script_id: ...})` if the script is still
running. Follow stop events and input requests reported in tool responses.
Snapshot sampling can temporarily stop threads and may report partial results.

Scripts execute as TypeScript modules at the top level. A function executes
when called. Await Promise-returning operations at the top level when the
script needs their result. Addresses and 64-bit integers use `bigint`.
Named exports from successful scripts become available on `$` until the target
changes. `fmt` prints directly. Use structured `dbg` methods for calculations,
and use MCP `output_format: "structured"` when a client needs structured results.
Text responses distinguish display truncation, buffered output, and buffer loss.
Use `ps` offsets for more processes, or another collecting call such as
`status` to read buffered output.

## Inspect a stopped target

Use your target's symbol names and addresses. The next example assumes
`main` is a defined symbol and its code is mapped. Locals and arguments also
require usable DWARF and an appropriate stopped frame.

```ts
fmt.status();
fmt.backtraceAll();
const main = await dbg.getSymbol("main");
if (main) {
    fmt.address(main.address);
    fmt.disassemble(main.address);
    console.log(dbg.symbolAt(main.address));
    console.log(m.u32().at(main.address).$read());
}
```

GDB tool examples include `bt`, `thread apply all bt`, `info registers`,
`info locals`, `info args`, `info symbol 0x12340000`, `x/16xb 0x12340000`,
and `disassemble main`. Replace the sample address with a mapped target address.

## Inspect typed memory

The example looks up a global with this layout. Use a symbol and field layout
from your target. `typeOfVar` can use matched DWARF for the current stopped
frame, and returns `undefined` when the type is unavailable.

```ts
const Header = m.struct({type: m.u32(), length: m.u32(), data: m.pointer(m.void())});
fmt.pType(Header);
const symbol = await dbg.getSymbol("global_context");
if (symbol) {
    const header = Header.at(symbol.address);
    fmt.print(header);
    console.log(header.$toJS({pointer: "string"}));
}
const type = m.typeOfVar("global_context");
if (type !== undefined) fmt.pType(type);
```

`$format()` provides bounded display and marks unreadable memory inline.
`$read()` and `$toJS()` read strictly. `$toJS()` returns ordinary JS data,
including bigint and supported shared or cyclic references. `$toJson()` returns
JSON text. Setting `pointer: "string"` only changes address-valued pointers.

## Run to a breakpoint

On a paused live target, install a breakpoint for a symbol the program will
execute after resuming. A breakpoint callback temporarily stops its thread.
Here `hit.pause()` keeps it paused. A wait can also return a timeout or exit.

```ts
export const breakpoint = dbg.softwareBreakpoint("main", hit => hit.pause());
console.log(await dbg.continueForStop("all", {pausedOnly: true, timeoutMs: 5000}));
```

For repeated hits, `await dbg.traceHits("main", {limit: 1, timeoutMs: 5000})`
collects hits while allowing execution to continue. Use `await dbg.detach()`
to release a target or `await dbg.kill()` to terminate it.

## Reuse declarations across scripts

Run this script first.

```ts
export const Header = m.struct({type: m.u32(), length: m.u32()});
```

Then run this script in the same session, before switching targets.

```ts
const symbol = await dbg.getSymbol("global_context");
if (symbol) fmt.pVar($.Header.at(symbol.address));
```
