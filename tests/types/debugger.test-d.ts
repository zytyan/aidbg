import { expectError, expectType } from "tsd";
import { __assign, dbg, m } from "../../docs/debugger";
import type { ControlledThread, Thread, Type, Value } from "../../docs/debugger";

expectType<Type.Scalar<number>>(m.u32());
expectType<bigint>(m.i64().value(-1n).$read());
expectError(m.u64().value(1));
expectType<Thread>(dbg.thread(17));
expectType<Promise<ControlledThread>>(dbg.pause(17));
expectType<Promise<ControlledThread[]>>(dbg.pause("all"));
expectType<Promise<ControlledThread>>(dbg.pauseThread(17));
expectType<Promise<ControlledThread[]>>(dbg.pauseAll());
expectError(dbg.thread(1).next());
expectType<bigint>(dbg.memory.readPointer(1n));
expectError(dbg.memory.readPointer(1));

const Layout = m.struct({ size: m.u32(), ptr: m.pointer(m.u8()), flags: m.array(m.u16(), 3) });
const layout = Layout.at(0n);
expectType<Value.Scalar<number>>(layout.size);
expectType<number>(layout.flags[0].$read());
expectType<bigint>(layout.ptr.$read());
expectError(layout.other);
expectError(Layout.refine({ missing: m.u8() }));
expectType<9>(__assign(layout.size, 9 as const));
expectError(__assign(layout.size, 9n));

const call = m.function({ args: [m.i64(), m.u32()], returns: m.i32() }).at(0n, 1);
expectType<Promise<Value.Scalar<number>>>(call(1n, m.u32().value(1)));
expectError(call(1, 1));
expectError(call(1n));
const variadic = m.function({ args: [m.u32()], returns: m.void(), variadic: true }).at(0n, 1);
expectType<Promise<void>>(variadic(1, m.f64().value(1)));
expectError(variadic(1, 2));

dbg.hardwareWatchpoint(1n, hit => {
    expectType<number | undefined>(hit.length);
}, { access: "write", length: 1 });
dbg.onSignal("SIGUSR1", null);
