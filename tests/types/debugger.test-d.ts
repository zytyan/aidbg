import { expectError, expectType } from "tsd";
import { __assign, dbg, m } from "../../docs/debugger";
import type { ControlledThread, Thread, Type, Value } from "../../docs/debugger";

expectType<Type.EndianInteger<number>>(m.u32());
expectType<Type.EndianInteger<number>>(m.u32().be().le());
expectType<bigint>(m.i64().value(-1n).$read());
expectError(m.u64().value(1));
expectType<Thread>(dbg.thread(17));
expectType<Promise<ControlledThread>>(dbg.pauseThread(17));
expectType<Promise<ControlledThread[]>>(dbg.pauseAll());
expectType<Promise<ControlledThread>>(dbg.pauseThread(17));
expectType<Promise<ControlledThread[]>>(dbg.pauseAll());
expectError(dbg.thread(1).next());
expectType<bigint>(dbg.memory.readPointer(1n));
expectError(dbg.memory.readPointer(1));

const Layout = m.struct({ size: m.u32(), ptr: m.pointer(m.u8()), flags: m.array(m.u16(), 3) });
const layout = Layout.at(0n);
expectType<Uint8Array>(Layout.$readBytes(0n));
expectType<void>(Layout.$writeBytes(0n, new Uint8Array()));
expectError(Layout.$readBytes(0));
expectType<number>(Layout.offsetOf("flags[2]"));
expectType<Type.Array<Type.Integer<number>>>(m.opaque(32));
expectType<string>(m.cStr().at(0n).$deref());
expectType<string[]>(m.pointer(m.cStr()).nullTerminate().at(0n).$deref());
expectType<number[]>(m.pointer(m.u32()).nullTerminate().at(0n).$deref());
expectType<number>(m.u32().enum({ OK: 1 }).value("OK").$read());
expectError(m.u32().enum({ OK: 1 }).value("UNKNOWN"));
const Anonymous = m.struct({ ...m.anonymous(m.union({ n: m.u32() })) });
expectType<number>(Anonymous.at(0n).n.$read());
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
