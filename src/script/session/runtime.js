(() => {
    "use strict";

    let host, arch, targetGeneration;
    let nextPoint = 0;
    let callbackTid;
    let callbackContext;
    const eventWaiters = new Map();
    const inputs = new Map();
    const points = new Map();
    const signals = new Map();
    const exports = Object.create(null);
    const stringify = JSON.stringify;
    const parse = JSON.parse;

    const rpc = (name, args = {}) => parse(host(name, stringify(args)));
    const word = value => {
        if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn) {
            throw new RangeError("expected an unsigned 64-bit bigint");
        }
        return "0x" + value.toString(16);
    };
    const bits = value => word(BigInt.asUintN(64, BigInt(value)));
    const checkedAddress = at => typeof at === "string" ? at : word(at);
    const addr = (address, offset) => BigInt(word(address + BigInt(offset)));
    const integer = (value, description) => {
        if (typeof value === "bigint") value = Number(value);
        if (!Number.isSafeInteger(value) || value < 0) throw new RangeError(description);
        return value;
    };
    const optional = value => value ?? undefined;
    function utf8(text) {
        const bytes = [];
        for (const char of text) {
            let n = char.codePointAt(0);
            if (n < 0x80) bytes.push(n);
            else if (n < 0x800) bytes.push(0xc0 | n >> 6, 0x80 | n & 63);
            else if (n < 0x10000) {
                if (n >= 0xd800 && n <= 0xdfff) n = 0xfffd;
                bytes.push(0xe0 | n >> 12, 0x80 | n >> 6 & 63, 0x80 | n & 63);
            } else bytes.push(0xf0 | n >> 18, 0x80 | n >> 12 & 63, 0x80 | n >> 6 & 63, 0x80 | n & 63);
        }
        return Uint8Array.from(bytes);
    }
    function fromUtf8(bytes) {
        let text = "";
        for (let i = 0; i < bytes.length;) {
            const initial = bytes[i++];
            if (initial < 0x80) { text += String.fromCharCode(initial); continue; }
            const count = initial >= 0xc2 && initial <= 0xdf ? 1
                : initial >= 0xe0 && initial <= 0xef ? 2 : initial >= 0xf0 && initial <= 0xf4 ? 3 : 0;
            let code = initial & (0x7f >> (count + 1));
            let valid = count !== 0;
            for (let j = 0; j < count; j++) {
                const b = bytes[i];
                if (!(b >= 0x80 && b <= 0xbf)
                    || (j === 0 && ((initial === 0xe0 && b < 0xa0) || (initial === 0xed && b >= 0xa0)
                        || (initial === 0xf0 && b < 0x90) || (initial === 0xf4 && b >= 0x90)))) {
                    valid = false;
                    break;
                }
                i++;
                code = code << 6 | b & 63;
            }
            text += valid ? String.fromCodePoint(code) : "\ufffd";
        }
        return text;
    }

    function bytesFromHex(text) {
        const hex = text.trim().replace(/0x/gi, "").replace(/[\s:_-]/g, "");
        if (hex.length % 2 || !/^[0-9a-f]*$/i.test(hex)) throw new TypeError("invalid hexadecimal bytes");
        const data = new Uint8Array(hex.length / 2);
        for (let i = 0; i < data.length; i++) data[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        return data;
    }

    function hexdump(data, options = {}) {
        if (!(data instanceof Uint8Array)) throw new TypeError("expected Uint8Array");
        const group = integer(options.groupSize ?? 1, "invalid group size") || data.length || 1;
        const groups = integer(options.groupsPerLine ?? 16, "invalid groups per line") || Math.ceil(data.length / group) || 1;
        const sep = options.separator ?? " ";
        const lines = [];
        for (let i = 0; i < data.length; i += groups * group) {
            const chunks = [], line = data.subarray(i, i + groups * group);
            for (let j = 0; j < line.length; j += group) {
                const bytes = Array.from(line.subarray(j, j + group));
                if (options.endian === "le" || options.endian === "host") bytes.reverse();
                chunks.push((options.prefix ? "0x" : "") + bytes.map(b => b.toString(16).padStart(2, "0")).join(""));
            }
            let out = chunks.join(sep);
            if (options.showAscii) out += "  |" + Array.from(line, b => b >= 32 && b <= 126 ? String.fromCharCode(b) : ".").join("") + "|";
            lines.push(out);
        }
        return lines.join("\n");
    }

    function jsonText(value) {
        const ancestors = [];
        return stringify(value, function (_, value) {
            if (typeof value === "bigint") return value.toString();
            if (typeof value === "function") return String(value);
            if (value instanceof Uint8Array) return Array.from(value);
            if (value && typeof value === "object") {
                if (valueStore(value)) return summarize(value);
                while (ancestors.length && ancestors[ancestors.length - 1] !== this) ancestors.pop();
                if (ancestors.includes(value)) return "[Circular]";
                ancestors.push(value);
            }
            return value;
        }) ?? "null";
    }

    function sprintf(format, ...args) {
        let index = 0;
        return format.replace(/%([#0 +\-]*)(\d+)?(?:\.(\d+))?(?:hh|ll|[hljztL])?([%sdifeguxXopc])/g,
            (_, flags, width, precision, kind) => {
                if (kind === "%") return "%";
                if (index >= args.length) throw new TypeError("not enough printf arguments");
                let value = args[index++], text, prefix = "";
                const digits = precision === undefined ? undefined : Math.min(100, Number(precision));
                if (kind !== "s" && valueStore(value) && value.$read) value = value.$read();
                if (kind === "s") text = String(value).slice(0, digits ?? Infinity);
                else if (kind === "c") text = String.fromCodePoint(Number(value));
                else if ("feg".includes(kind)) {
                    const number = Number(value);
                    text = kind === "f" ? Math.abs(number).toFixed(digits ?? 6)
                        : kind === "e" ? Math.abs(number).toExponential(digits ?? 6)
                        : Math.abs(number).toPrecision(Math.max(1, digits ?? 6));
                    prefix = number < 0 ? "-" : flags.includes("+") ? "+" : flags.includes(" ") ? " " : "";
                } else {
                    let number = BigInt(value);
                    if ("uxXop".includes(kind)) number = BigInt.asUintN(64, number);
                    const base = "xXp".includes(kind) ? 16 : kind === "o" ? 8 : 10;
                    if (number < 0) { prefix = "-"; number = -number; }
                    else if (flags.includes("+") && "di".includes(kind)) prefix = "+";
                    else if (flags.includes(" ") && "di".includes(kind)) prefix = " ";
                    if (kind === "p" || (flags.includes("#") && number !== 0n)) {
                        prefix += kind === "o" ? "0" : kind === "X" ? "0X" : base === 16 ? "0x" : "";
                    }
                    text = number === 0n && digits === 0 ? "" : number.toString(base).padStart(digits ?? 0, "0");
                    if (kind === "X") text = text.toUpperCase();
                }
                const padding = Math.max(0, Math.min(65536, Number(width ?? 0)) - text.length - prefix.length);
                if (flags.includes("-")) return prefix + text + " ".repeat(padding);
                if (flags.includes("0") && digits === undefined && kind !== "s" && kind !== "c") return prefix + "0".repeat(padding) + text;
                return " ".repeat(padding) + prefix + text;
            });
    }

    const timers = new Map();
    const abortSignals = new WeakMap();
    class AbortController {
        constructor() {
            const state = {aborted:false, reason:undefined, listeners:new Set()};
            const signal = Object.freeze({
                get aborted() { return state.aborted; },
                get reason() { return state.reason; },
            });
            abortSignals.set(signal,state);
            Object.defineProperty(this,"signal",{value:signal});
        }
        abort(reason = new Error("operation aborted")) {
            const state = abortSignals.get(this.signal);
            if (state.aborted) return;
            state.aborted = true;
            state.reason = reason;
            for (const notify of state.listeners) notify();
            state.listeners.clear();
        }
    }
    function reportError(error, kind = "callback_error") {
        rpc("reportError", {kind, message:error instanceof Error && error.name === "Error" ? error.message : String(error),
            stack:typeof error?.stack === "string" ? error.stack : undefined});
    }
    function setTimeout(callback, ms = 0) {
        if (typeof callback !== "function") throw new TypeError("expected a timer callback");
        if (!Number.isFinite(ms) || ms < 0 || ms > 86400000) throw new RangeError("invalid timer duration");
        const id = rpc("setTimer",{ms:Math.ceil(ms)});
        timers.set(id,{callback});
        return id;
    }
    function clearTimeout(id) {
        timers.delete(id);
        rpc("clearTimer",{id});
    }
    function queueMicrotask(callback) {
        if (typeof callback !== "function") throw new TypeError("expected a microtask callback");
        Promise.resolve().then(callback).catch(reportError);
    }
    function sleep(ms, signal) {
        const state = signal === undefined ? undefined : abortSignals.get(signal);
        if (signal !== undefined && !state) throw new TypeError("expected an AbortSignal");
        return new Promise((resolve,reject) => {
            if (state?.aborted) { reject(state.reason); return; }
            const abort = () => { clearTimeout(id); reject(state.reason); };
            const id = setTimeout(() => { state?.listeners.delete(abort); resolve(); },ms);
            timers.get(id).cancel=() => {state?.listeners.delete(abort); reject(new Error("target changed"));};
            state?.listeners.add(abort);
        });
    }

    function makeConsole(id, generation) {
        const check = () => {
            if (generation !== targetGeneration()) throw new Error("debugger target changed");
        };
        return Object.freeze({
            log(...values) {
                check();
                rpc("log", {id, value:{kind:"console", values:parse(jsonText(values))}});
            },
            printf(format, ...args) {
                check();
                rpc("log", {id, value:{kind:"printf", text:sprintf(format, ...args)}});
            },
            sprintf, hexdump, bytesFromHex,
        });
    }

    function readBytes(address, length) {
        return Uint8Array.from(rpc("read", {address:word(address), length:integer(length, "invalid read length")}));
    }
    function writeBytes(address, bytes) {
        if (!(bytes instanceof Uint8Array)) throw new TypeError("expected Uint8Array");
        rpc("write", {address:word(address), bytes:Array.from(bytes)});
    }
    const view = bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const little = endian => {
        if (endian !== undefined && endian !== "le" && endian !== "be") throw new TypeError("invalid byte order");
        return endian !== "be";
    };
    const memory = {
        readBytes, writeBytes,
        readCString(address, maxLen = 4096) {
            const length = integer(maxLen, "invalid string length");
            const bytes = rpc("readPrefix", {address:word(address), length});
            let end = bytes.indexOf(0);
            if (end === -1) {
                if (bytes.length < length) throw new Error("C string crosses unavailable memory");
                end = bytes.length;
            }
            return fromUtf8(bytes.slice(0, end));
        },
        readAsType(address, type) { return type.at(address); },
        xref(address, options = {}) {
            const {start, end, instructionReferences, limit, maxScanBytes, alignment, resumeFrom} = options;
            const row = rpc("xref", {address:word(address), instructionReferences, limit, maxScanBytes, alignment,
                start:start === undefined ? undefined : word(start), end:end === undefined ? undefined : word(end),
                resumeFrom:resumeFrom === undefined ? undefined : word(resumeFrom)});
            const result = {kind:row.kind, scannedBytes:row.scanned_bytes,
                nextAddress:row.next_address === null ? null : BigInt(row.next_address), warnings:row.warnings};
            if (row.kind === "pointer_value") {
                return {...result, matches:row.matches.map(value => BigInt(value)), uncapturedBytes:row.uncaptured_bytes};
            }
            return {...result, matches:row.matches.map(match => ({instruction:BigInt(match.instruction),
                kind:match.kind, mnemonic:match.mnemonic, function:match.function ?? null,
                sourceLine:match.source_line ?? null}))};
        },
        search(pattern, startRange, endRange) {
            const needle = typeof pattern === "string" ? utf8(pattern) : pattern;
            if (!(needle instanceof Uint8Array) || !needle.length || needle.length > 65536) throw new TypeError("invalid search pattern");
            word(startRange); word(endRange);
            if (endRange < startRange) throw new RangeError("invalid search range");
            const matches = [], chunk = 65536n;
            const mappings = dbg.mappings().filter(m => m.prot.startsWith("r"));
            for (const map of mappings) {
                let start = startRange > map.start ? startRange : map.start;
                const end = endRange < map.end ? endRange : map.end;
                while (start < end && start + BigInt(needle.length) <= endRange) {
                    const stop = start + chunk < end ? start + chunk : end;
                    const extended = stop + BigInt(needle.length - 1);
                    const limit = extended < endRange ? extended : endRange;
                    const bytes = rpc("readPrefix", {address:word(start), length:Number(limit - start)});
                    for (let i = 0; i + needle.length <= bytes.length && BigInt(i) < stop - start; i++) {
                        if (needle.every((byte, offset) => byte === bytes[i + offset])) {
                            if (matches.length === 65536) throw new RangeError("memory search produced too many matches");
                            matches.push(start + BigInt(i));
                        }
                    }
                    start = stop;
                }
            }
            return matches;
        },
    };
    for (const [name, native, width] of [
        ["Int8","Int8",1], ["Uint8","Uint8",1], ["Int16","Int16",2], ["Uint16","Uint16",2],
        ["Int32","Int32",4], ["Uint32","Uint32",4], ["Int64","BigInt64",8], ["Uint64","BigUint64",8],
        ["Pointer","BigUint64",8], ["Float32","Float32",4], ["Float64","Float64",8],
    ]) {
        memory["read" + name] = (at, endian) => view(readBytes(at, width))["get" + native](0, little(endian));
        memory["write" + name] = (at, value, endian) => {
            const bytes = new Uint8Array(width);
            view(bytes)["set" + native](0, value, little(endian));
            writeBytes(at, bytes);
        };
    }
    Object.freeze(memory);

    function mapping(map) {
        return Object.freeze({...map, start:BigInt(map.start), end:BigInt(map.end), offset:BigInt(map.offset)});
    }
    function registers(raw) {
        return Object.fromEntries(Object.entries(raw).map(([name, value]) => [
            name, typeof value === "string" ? BigInt(value) : Array.isArray(value) ? Uint8Array.from(value) : value,
        ]));
    }
    function variable(value) {
        return {...value, address:value.address == null ? undefined : BigInt(value.address), type:optional(value.type)};
    }
    function frame(raw) {
        const {handle, ...row} = raw;
        const variables = values => values == null ? undefined : Object.freeze(
            Object.fromEntries(Object.entries(values).map(([name, item]) => [name, Object.freeze(variable(item))]))
        );
        return Object.freeze({...row, pc:BigInt(raw.pc), sp:BigInt(raw.sp ?? 0), fp:BigInt(raw.fp ?? 0),
            lookupPc:BigInt(raw.lookupPc ?? raw.pc), locals:variables(raw.locals), parameters:variables(raw.parameters),
            unwindMethod:optional(raw.unwindMethod),
            missingDebugSections:raw.missingDebugSections == null ? undefined : Object.freeze(raw.missingDebugSections),
            symbol:optional(raw.symbol), file:optional(raw.file), line:optional(raw.line)});
    }
    function snapshot(raw) {
        return Object.freeze({...raw, mappings:Object.freeze(raw.mappings.map(mapping)),
            threads:Object.freeze(raw.threads.map(thread => Object.freeze({...thread,
                registers:Object.freeze(registers(thread.registers)), frames:Object.freeze(thread.frames.map(frame)),
                locals:Object.freeze(thread.locals.map(variable)),
            }))),
        });
    }
    const protection = prot => {
        if (!["none","r","w","x","rw","rx","wx","rwx"].includes(prot)) throw new TypeError("invalid memory protection");
        return prot;
    };
    function stopEvent(row) {
        if (row.kind === "syscall") {
            row.args = Object.freeze(row.args.map(BigInt));
            if (row.result != null) row.result = BigInt(row.result);
            else { delete row.result; delete row.failed; }
            if (row.name == null) delete row.name;
            if (row.pathname == null) delete row.pathname;
            if (row.parameterNames == null) delete row.parameterNames;
            else Object.freeze(row.parameterNames);
            if (row.parameters == null) delete row.parameters;
            else row.parameters = Object.freeze(row.parameters.map(parameter => parameter && Object.freeze(parameter)));
        }
        if (row.kind === "signal") {
            const {tid, sequence} = row, generation = targetGeneration();
            Object.defineProperty(row, "passToTarget", {
                value(pass) { rpc("passSignal", {tid, sequence, generation, pass}); },
            });
        }
        if (row.address != null) row.address = BigInt(row.address);
        if (row.faultAddress != null) row.faultAddress = BigInt(row.faultAddress);
        else delete row.faultAddress;
        if (row.length != null) {
            if (row.before != null) row.before = immediateWatch(row.length, row.before);
            else delete row.before;
            if (row.after != null) row.after = immediateWatch(row.length, row.after);
            else delete row.after;
            if (row.access == null) delete row.access;
        }
        return Object.freeze(row);
    }

    function waitEvent(options, callback) {
        let args = options;
        if (callback?.active) {
            if (options.kind !== "hit") {
                throw new Error("finish the current callback before waiting for another stop");
            }
            if (callback.signal && callback.pass === undefined) {
                throw new Error("call passToTarget before waiting for the next hit");
            }
            args = {...options, handoff:callback.token, handoffTid:callback.tid,
                pass:callback.pass, counts:callback.counts};
        }
        const id = rpc("eventWait", args);
        if (callback?.active) callback.active = false;
        return new Promise((resolve, reject) => eventWaiters.set(id, {resolve, reject}));
    }

    function ask(payload, timeoutMs, tid) {
        if (payload == null || typeof payload !== "object") throw new TypeError("ask requires a JSON object or array");
        if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 86400000)) {
            throw new RangeError("invalid timeoutMs");
        }
        const handler = rpc("ask", {payload:parse(jsonText(payload)), timeoutMs, tid});
        return new Promise((resolve, reject) => inputs.set(handler,{resolve,reject}));
    }

    function scope(tid) {
        if (tid === undefined || tid === "all") return undefined;
        if (!Number.isSafeInteger(tid) || tid <= 0 || tid > 0x7fffffff) throw new RangeError("invalid thread ID");
        return tid;
    }

    async function continueForStop(tid = "all", options = {}) {
        const {until:predicate, timeoutMs = 180000} = options;
        if (predicate !== undefined && typeof predicate !== "function") throw new TypeError("expected a stop predicate");
        scope(tid);
        if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 86400000) throw new RangeError("invalid timeoutMs");
        const deadline = rpc("clock") + timeoutMs;
        while (true) {
            const event = await waitEvent({kind:"stop", tid:scope(tid), resume:true,
                timeoutMs:Math.max(0,deadline-rpc("clock"))}, callbackContext);
            if (predicate === undefined || ["exit","ended","timeout"].includes(event.kind)) return event;
            if (event.kind === "signal" && event.paused) return event;
            if (event.paused && predicate(event) === true) return event;
            if (event.paused) rpc("continue", {tid:event.tid});
            if (rpc("clock") >= deadline) return Object.freeze({kind:"timeout"});
        }
    }

    function makeThread(tid, controlled = false, callback) {
        const generation = targetGeneration();
        let identity;
        try { identity = rpc("identity", {tid}); } catch (_) {}
        const exists = () => {
            if (generation !== targetGeneration() || identity === undefined) return false;
            try { return rpc("identity", {tid}) === identity && rpc("status", {tid}) !== "Unexists"; }
            catch (_) { return false; }
        };
        const check = () => { if (!exists()) throw new Error("thread no longer exists"); };
        const access = (name, fields = {}) => { check(); return rpc(name, {...fields, tid}); };
        const control = (name, fields = {}) => {
            if (callback && !callback.active) throw new Error("the callback no longer controls this stop");
            return access(name,fields);
        };
        const proxy = full => new Proxy(Object.create(null), {
            get(_, name) { return registers(access("registers", {full}))[name]; },
            set(_, name, value) { access("writeRegisters", {values:{[name]:encodeRegister(value)}}); return true; },
            ownKeys() { return Object.keys(access("registers", {full})); },
            getOwnPropertyDescriptor(_, name) {
                const value = registers(access("registers", {full}))[name];
                return value === undefined ? undefined : {enumerable:true, configurable:true, writable:true, value};
            },
        });
        const thread = {
            get tid() { check(); return tid; },
            get status() { return exists() ? rpc("status", {tid}) : "Unexists"; },
            get registers() { check(); return proxy(false); },
            set registers(values) { access("writeRegisters", {values:Object.fromEntries(Object.entries(values).map(([k,v]) => [k,encodeRegister(v)]))}); },
            get fullRegisters() { check(); return proxy(true); },
            set fullRegisters(values) { this.registers = values; },
            eval(expr) {
                const result = access("eval", {expr});
                const bigint = typeof result.value === "string" && (["i64","u64","ptr"].includes(result.type)
                    || /^0x[0-9a-f]+$/i.test(result.value));
                return {...result,type:optional(result.type),value:bigint ? BigInt(result.value) : result.value};
            },
            backtrace(limit) { return Object.freeze(access("backtrace", {limit}).map(frame)); },
            locals() { return access("locals").map(variable); },
            async waitThreadStop(timeoutMs) {
                return waitEvent({kind:"stop",tid,timeoutMs}, callback?.active ? callback : callbackContext);
            },
            async waitThreadExit(timeoutMs) {
                return waitEvent({kind:"thread_exit",tid,timeoutMs}, callback?.active ? callback : callbackContext);
            },
            passToTarget(pass) {
                check();
                rpc("passSignal", {tid, generation, pass});
            },
            async ask(payload, timeoutMs) {
                check();
                return ask(payload,timeoutMs,tid);
            },
            injectSyscall(id, ...args) { return access("syscall", {number:word(id), args:args.map(bits)}).map(BigInt); },
        };
        if (controlled) Object.assign(thread, {
            async nextHit(timeoutMs) {
                check();
                return waitEvent({kind:"hit",tid,timeoutMs,resume:true,fresh:true},callback);
            },
            async step(count) { control("step", {mode:"step", count}); },
            async next(count) { control("step", {mode:"next", count}); },
            async nextBranch(count) { control("step", {mode:"branch", count}); },
            async nextCall(count, follow) { control("step", {mode:"call", count, follow}); },
            async finish() { control("step", {mode:"finish"}); },
            async until(at) { control("step", {mode:"until", at:word(at)}); },
            recordBranch(allReg) { control("recordBranch", {allReg}); },
            async allocate(size, prot = "rw") { return BigInt(control("allocate", {size, prot:protection(prot)})); },
            async free(address, size) { control("free", {address:word(address), size}); },
            async protect(address, size, prot) { control("protect", {address:word(address), size, prot:protection(prot)}); },
        });
        return Object.freeze(thread);
    }
    const encodeRegister = value => typeof value === "bigint" ? word(value)
        : value instanceof Uint8Array ? Array.from(value) : value;

    function install(type, at, callback, options = {}) {
        if (callback != null && typeof callback !== "function") throw new TypeError("expected breakpoint callback");
        const generation = targetGeneration();
        const id = ++nextPoint;
        const pending = type === "pending";
        const address = pending
            ? rpc("addPendingPoint", {id, name:at, ...options})
            : BigInt(rpc("addPoint", {id, kind:type, at:checkedAddress(at), ...options}));
        const change = remove => {
            if (generation !== targetGeneration()) throw new Error("breakpoint no longer exists");
            rpc("point", {id, remove});
            points.delete(id);
        };
        const point = Object.freeze({
            id, type:pending ? "software_breakpoint" : type,
            get address() {
                if (!pending) return address;
                if (generation !== targetGeneration()) return null;
                const bound = rpc("pendingPointAddress", {id});
                return bound == null ? null : BigInt(bound);
            },
            get tid() {
                if (generation !== targetGeneration()) return Object.freeze([]);
                return Object.freeze(options.tid === undefined ? rpc("threads") : [options.tid]);
            },
            get callback() { return callback; },
            set callback(value) {
                if (typeof value !== "function") throw new TypeError("expected breakpoint callback");
                callback = value;
            },
            disable() { change(false); },
            remove() { change(true); },
        });
        points.set(id, {point, count:0});
        return point;
    }

    const symbol = row => Object.freeze({...row, address:BigInt(row.address), module:optional(row.module),
        demangledName:optional(row.demangledName)});
    const processIo = Object.freeze({
        stdin:Object.freeze({
            write:data => rpc("stdio",{operation:"write",data}),
            close:() => {rpc("stdio",{operation:"close"});},
        }),
        stdout:Object.freeze({read:() => rpc("stdio",{operation:"stdout"})}),
        stderr:Object.freeze({read:() => rpc("stdio",{operation:"stderr"})}),
        combinedOutErr:Object.freeze({read:() => rpc("stdio",{operation:"combined"})}),
    });
    const syscallCatches = new Map();
    let nextSyscallCatch = 0;
    const dbg = Object.freeze({
        get arch() { return arch; },
        endian:"le",
        get pid() { return rpc("pid"); },
        process:processIo,
        memory,
        thread:tid => makeThread(tid),
        threads:() => Object.freeze(rpc("threads").map(tid => makeThread(tid))),
        mappings:() => Object.freeze(rpc("mappings").map(mapping)),
        async snapshot(options) {
            const request = typeof options === "object" ? options : {tid:options};
            return snapshot(rpc("snapshot", request));
        },
        async waitOutput(tid, timeoutMs = 180000) {
            tid = integer(tid, "invalid thread ID");
            timeoutMs = integer(timeoutMs, "invalid output timeout");
            if (timeoutMs > 86400000) throw new RangeError("invalid output timeout");
            const deadline = rpc("clock") + timeoutMs;
            for (;;) {
                const result = rpc("waitOutput", {tid});
                if (result.stdout || result.stderr || result.truncated || result.released ||
                    result.ended || result.exitCode !== undefined || result.exitSignal !== undefined) {
                    return Object.freeze({...result, timedOut:false});
                }
                const remaining = deadline - rpc("clock");
                if (remaining <= 0) return Object.freeze({...result, timedOut:true});
                await sleep(Math.min(remaining, 20));
            }
        },
        async pauseThread(tid) {
            if (scope(tid) === undefined) throw new TypeError("pauseThread requires a numeric thread ID");
            return makeThread(rpc("pause", {tid})[0], true);
        },
        async pauseAll() {
            return rpc("pause", {tid:"all"}).map(tid => makeThread(tid, true));
        },
        resumeThread(tid) {
            if (scope(tid) === undefined) throw new TypeError("resumeThread requires a numeric thread ID");
            rpc("continue", {tid});
        },
        resumeAll() { rpc("continue", {tid:"all"}); },
        continueForStop,
        async waitExit(timeoutMs) { return waitEvent({kind:"process_exit",timeoutMs},callbackContext); },
        async waitStops(limit, timeoutMs) { return waitEvent({kind:"batch",limit,timeoutMs},callbackContext); },
        async ask(payload, timeoutMs) { return ask(payload,timeoutMs,callbackTid); },
        async detach() { rpc("detach"); },
        setForkPolicy(mode) { rpc("setForkPolicy", {mode}); },
        attachDwarf(file, position) {
            if (position !== undefined && typeof position !== "bigint" &&
                (!position || typeof position !== "object" || Array.isArray(position))) {
                throw new TypeError("expected an ELF load bias or a section address map");
            }
            const encoded = position === undefined ? undefined : typeof position === "bigint" ? word(position) :
                Object.fromEntries(Object.entries(position).map(([section,address]) => [section,word(address)]));
            rpc("attachDwarf", {file,position:encoded});
        },
        catchSyscall(tid, phase, callback) {
            const key = scope(tid) ?? "all";
            if (callback != null && typeof callback !== "function") throw new TypeError("expected a syscall callback");
            const catchId = nextSyscallCatch++;
            rpc("catchSyscall", {tid:key, phase, catchId});
            if (phase == null) syscallCatches.delete(key);
            else syscallCatches.set(key, {id:catchId, callback});
        },
        async kill(signal) { rpc("kill", {signal}); },
        async prepare() { rpc("prepare"); },
        async prepareScratchPad() { rpc("prepareScratchPad"); },
        onSignal(signal, callback) {
            if (callback != null && typeof callback !== "function") throw new TypeError("expected signal callback");
            const n = rpc("signal", {signal, remove:callback == null});
            if (callback == null) signals.delete(n);
            else signals.set(n, callback);
        },
        lineToAddr(file,line) {
            const result = rpc("lineToAddr",{file,line});
            return result == null ? null : BigInt(result);
        },
        addrToLine(address) { return rpc("addrToLine",{address:word(address)}); },
        list(at, radius = 5) {
            return rpc("listSource", {address:word(typeof at === "bigint" ? at : at.lookupPc),
                radius:integer(radius,"invalid source context")});
        },
        async getSymbol(name) {
            const rows = rpc("symbols", {pattern:name});
            return rows.length ? symbol(rows[0]) : null;
        },
        async *iterSymbols(pattern) {
            if (!(pattern instanceof RegExp)) throw new TypeError("expected a regular expression");
            const matching = new RegExp(pattern.source, pattern.flags);
            const seen = new Set();
            function *matches(rows) {
                for (const row of rows) {
                    matching.lastIndex = 0;
                    if (!matching.test(row.name)) continue;
                    const key = stringify([row.name,row.address,row.module]);
                    if (!seen.has(key)) {
                        seen.add(key);
                        yield symbol(row);
                    }
                }
            }
            let cursor = null;
            do {
                const page = rpc("symbolPage", {cursor});
                yield* matches(page.items);
                cursor = page.next;
            } while (cursor != null);
            yield* matches(rpc("linkedSymbols"));
        },
        hardwareBreakpoint(at, callback, tid) { return install("hardware_breakpoint",at,callback,{tid}); },
        pendingBreakpoint(name, callback, options) { return install("pending",name,callback,options); },
        softwareBreakpoint(at, callback, tid) { return install("software_breakpoint",at,callback,{tid}); },
        hardwareWatchpoint(at, callback, options) { return install("hardware_watchpoint",at,callback,options); },
        softwareWatchpoint(at, callback, options) { return install("software_watchpoint",at,callback,options); },
        assemble(at, src) { return bytesFromHex(rpc("assemble", {at:checkedAddress(at), src}).bytes); },
        disassemble(at, count) {
            return rpc("disassemble", {at:checkedAddress(at), count}).map(row => ({...row,address:BigInt(row.address), bytes:typeof row.bytes === "string" ? bytesFromHex(row.bytes) : Uint8Array.from(row.bytes)}));
        },
        async linkObjAt(path, address) { rpc("linkObjAt", {path, address:word(address)}); },
        coredump(path, kind) { rpc("coredump", {path, kind}); },
        async *iterDwarfTypes(pattern) {
            if (!(pattern instanceof RegExp)) throw new TypeError("expected a regular expression");
            for (const row of dwarfRows("*")) {
                pattern.lastIndex = 0;
                if (pattern.test(row.name)) yield dwarfType(row);
            }
        },
        async *getDwarfTypes(name) {
            for (const row of dwarfRows(name,true)) yield dwarfType(row);
        },
    });

    async function dispatch(tid, token, events) {
        const generation = targetGeneration();
        const context = {tid,token,active:true,pause:null,signal:false,pass:undefined,counts:{}};
        const thread = makeThread(tid, true, context);
        const check = () => {
            if (!context.active || targetGeneration() !== generation) throw new Error("the callback no longer controls this stop");
        };
        try {
            for (const event of parse(events)) {
                if (!context.active || targetGeneration() !== generation) return;
                let result;
                const previousContext = callbackContext, previousTid = callbackTid;
                callbackContext = context;
                callbackTid = tid;
                try {
                    if (event.kind === "syscall") {
                        const installed = [syscallCatches.get(tid), syscallCatches.get("all")]
                            .find(catchpoint => catchpoint?.id === event.catchId);
                        if (!installed) continue;
                        if (installed.callback == null) context.pause = true;
                        else result = installed.callback(Object.freeze({
                            ...stopEvent(event), thread,
                            pause() { check(); context.pause = true; },
                            continue() { check(); context.pause = false; },
                        }));
                    } else if (event.breakpointId !== undefined) {
                        const installed = points.get(event.breakpointId);
                        if (!installed) continue;
                        context.counts[event.sequence] = ++installed.count;
                        const hit = {
                            thread, breakpoint:installed.point, hitCount:installed.count,
                            pause() { check(); context.pause = true; },
                            continue() { check(); context.pause = false; },
                            preventOtherBreakpointOnThisThread() { check(); rpc("preventOtherStops", {tid}); },
                        };
                        if (event.length != null) {
                            hit.length = event.length;
                            if (event.before != null) hit.before = immediateWatch(event.length, event.before);
                            if (event.after != null) hit.after = immediateWatch(event.length, event.after);
                            if (event.access != null) hit.access = event.access;
                        }
                        const callback = installed.point.callback;
                        if (callback == null) context.pause = true;
                        else result = callback(Object.freeze(hit));
                    } else {
                        context.signal = true;
                        const callback = signals.get(event.signalNumber);
                        if (!callback) continue;
                        result = callback(Object.freeze({
                            thread, signalNumber:event.signalNumber, signalName:event.signalName,
                            faultAddress:event.faultAddress == null ? undefined : BigInt(event.faultAddress),
                            passToTarget(value) {
                                check();
                                if (typeof value !== "boolean") throw new TypeError("expected a boolean signal decision");
                                context.pass = value;
                            },
                            removeThisHandler() {
                                if (signals.get(event.signalNumber) === callback) dbg.onSignal(event.signalNumber, null);
                            },
                        }));
                    }
                } finally {
                    callbackTid = previousTid;
                    callbackContext = previousContext;
                }
                await result;
            }
        } catch (error) {
            if (targetGeneration() === generation) reportError(error);
        } finally {
            if (context.active) {
                context.active = false;
                rpc("callbackDone", {generation,tid,token,pause:context.pause,pass:context.pass,counts:context.counts});
            }
        }
    }

    // Type descriptors carry layout. Every value has its own storage and thread binding.
    const types = new WeakMap(), values = new WeakMap();
    const valueKeys = {
        address: Symbol(),
        bytes: Symbol(),
        root: Symbol(),
        tid: Symbol(),
        inheritTid: Symbol(),
        parent: Symbol(),
        self: Symbol(),
        type: Symbol(),
        info: Symbol(),
        value: Symbol(),
        terminatedElement: Symbol(),
        readBytesMethod: Symbol(),
        writeBytesMethod: Symbol(),
        readMethod: Symbol(),
        inline: Symbol(),
    };
    let lookupNativeValue, createCompactValue, compactValueKeys;
    const valueStore = value => values.get(value) ?? lookupNativeValue(value);
    const typeInfo = type => {
        const info = types.get(type);
        if (!info) throw new TypeError("expected a TypeSystem descriptor");
        return info;
    };
    const rounded = (size, align) => integer(Math.ceil(size / align) * align, "type layout exceeds safe integer range");
    const alignment = value => {
        const align = integer(value, "invalid alignment");
        if (!align || align > 2 ** 30 || (align & (align - 1))) throw new RangeError("alignment must be a positive power of two");
        return align;
    };
    const scalarSpec = {
        u8:["Uint8",1], i8:["Int8",1], u16:["Uint16",2], i16:["Int16",2],
        u32:["Uint32",4], i32:["Int32",4], u64:["BigUint64",8], i64:["BigInt64",8],
        f32:["Float32",4], f64:["Float64",8], ptr:["BigUint64",8],
    };
    const scalarDescriptors = {};
    const anonymousFields = new WeakSet();
    let nextAnonymousField = 0;
    function scalarBytes(kind, value, littleEndian = true) {
        const [native, width] = scalarSpec[kind];
        const bytes = new Uint8Array(width);
        if (kind === "ptr") word(value);
        else if (kind === "i64" || kind === "u64") {
            if (typeof value !== "bigint") throw new TypeError("expected bigint");
            const normalized = kind === "i64" ? BigInt.asIntN(64,value) : BigInt.asUintN(64,value);
            if (value !== normalized) throw new RangeError("integer does not fit the C type");
        } else {
            if (typeof value !== "number") throw new TypeError("expected number");
            if (kind[0] !== "f") {
                const signed = kind[0] === "i", limit = 2 ** (width * 8 - Number(signed));
                if (!Number.isInteger(value) || value >= limit || value < (signed ? -limit : 0)) throw new RangeError("integer does not fit the C type");
            }
        }
        view(bytes)["set" + native](0,value,littleEndian);
        return bytes;
    }

    function descriptor(info) {
        const type = {
            get $size() { return info.kind === "lazy" ? typeInfo(resolve(type)).size : info.size; },
            get $align() { return info.kind === "lazy" ? typeInfo(resolve(type)).align : info.align; },
            at(address, tid) { word(address); return makeValue(type, {[valueKeys.address]:address, [valueKeys.tid]:tid, [valueKeys.root]:targetGeneration()}); },
            $readBytes(address) {
                word(address);
                return readBytes(address, staticStorageSize(type));
            },
            $writeBytes(address, bytes) {
                word(address);
                if (!(bytes instanceof Uint8Array)) throw new TypeError("expected Uint8Array");
                if (bytes.length !== staticStorageSize(type)) throw new RangeError("byte length differs from C storage size");
                if (bytes.length) writeBytes(address, bytes);
            },
            offsetOf(path) { return fieldOffset(type, path); },
            layout() { return describeType(type); },
        };
        if (info.align && info.kind !== "bitfield") {
            type.align = value => {
                const explicitAlign = alignment(value);
                const align = Math.max(info.align, explicitAlign);
                const size = info.fields ? rounded(info.size, align) : info.size;
                return descriptor({...info, align, size, explicitAlign:align});
            };
        }
        if (info.kind === "scalar" && info.size > 1) {
            type.be = () => descriptor({...info, littleEndian:false});
            type.le = () => descriptor({...info, littleEndian:true});
        }
        if (info.kind === "scalar" && /^[ui]/.test(info.scalar)) {
            type.bitfield = width => {
                width = integer(width, "invalid bitfield width");
                if (width > info.size * 8 || info.littleEndian === false || info.explicitAlign || info.enumerators) {
                    throw new TypeError("unsupported bitfield type or width");
                }
                return descriptor({...info, kind:"bitfield", bit:[0,width]});
            };
            type.enum = values => {
                const enumerators = Object.assign(Object.create(null), values);
                for (const [name, value] of Object.entries(enumerators)) {
                    if (!/^[a-zA-Z_]\w*$/.test(name)) throw new TypeError("invalid enum name " + name);
                    scalarBytes(info.scalar, value);
                }
                return descriptor({...info, enumerators:Object.freeze(enumerators)});
            };
        }
        if (info.kind === "scalar" || info.kind === "ptr") {
            type.value = value => makeValue(type, {[valueKeys.bytes]:encodeValue(info, value)});
        }
        if (info.kind === "ptr") {
            type.pointee = () => typeInfo(info.element).kind === "self" ? info.element : resolve(info.element);
            type.nullTerminate = (limit = 4096) => {
                limit = integer(limit, "invalid termination limit");
                const element = typeInfo(resolve(info.element));
                if (!limit || info.length !== undefined || !["scalar", "ptr"].includes(element.kind)
                    || element.scalar.startsWith("f") || element.size % element.align) {
                    throw new TypeError("unsupported terminated pointer type or length");
                }
                return descriptor({...info, terminated:limit});
            };
        }
        if (info.kind === "array") type.element = () => info.element;
        if (info.fields) {
            type.field = name => {
                if (!Object.hasOwn(info.fields,name)) throw new Error("unknown C field " + name);
                return info.fields[name].type;
            };
            type.refine = fields => refine(type, fields);
            type.pack = value => {
                if (!info.entries) throw new TypeError("cannot repack a resolved or refined layout");
                return aggregate(info.kind, info.entries, {pack:value,align:info.explicitAlign});
            };
        }
        types.set(type,info);
        return Object.freeze(type);
    }

    function describeType(type) {
        const seen = new Set();
        function describe(type, name, depth) {
            const info = typeInfo(resolve(type));
            const align = info.explicitAlign ? "_Alignas(" + info.explicitAlign + ") " : "";
            const order = info.littleEndian === false ? " big-endian" : "";
            const label = name ? " " + name : "";
            if (seen.has(type) || depth > 24) return "<recursive type>" + label;
            if (info.kind === "ptr") {
                const element = typeInfo(info.element);
                const pointee = info.terminated === undefined ? element : typeInfo(resolve(info.element));
                const extent = info.terminated !== undefined
                    ? " " + (pointee.char ? "NUL-terminated UTF-8" : pointee.kind === "ptr" ? "NULL-terminated" : "zero-terminated") + ", max " + info.terminated
                    :
                    typeof info.length === "function" ? " context length" :
                    info.length === undefined ? "" : " length " + info.length;
                seen.add(type);
                const text = align + (element.kind === "self" ? "self" : describe(info.element,"",depth+1)) + " *" + label + extent;
                seen.delete(type);
                return text;
            }
            if (info.kind === "array") {
                const count = typeof info.length === "function" ? "context length" : info.length ?? "";
                return align + describe(info.element,"",depth+1) + label + "[" + count + "]";
            }
            if (info.fields) {
                seen.add(type);
                const indent = "    ".repeat(depth + 1);
                const fields = info.declarations ?? Object.entries(info.fields).map(([name,field]) => ({...field,name}));
                const lines = [align + info.kind + " {"];
                let occupied = 0;
                for (const {name,type,offset} of fields) {
                    const member = typeInfo(resolve(type));
                    if (info.kind === "struct" && offset > occupied) lines.push(indent + "// padding: " + (offset - occupied));
                    const bit = member.bit ? ", bitoffset: " + member.bit[0] : "";
                    lines.push(indent + describe(type,name,depth+1) + "; // byteoffset: " + offset + bit);
                    occupied = Math.max(occupied, offset + (member.bit ? Math.ceil((member.bit[0]+member.bit[1])/8) : member.size ?? 0));
                }
                if (info.size > occupied) lines.push(indent + "// tail padding: " + (info.size - occupied));
                lines.push("    ".repeat(depth) + "}" + label);
                seen.delete(type);
                if (info.pack !== undefined) lines.unshift("#pragma pack(" + info.pack + ")");
                return lines.join("\n");
            }
            const base = info.char ? "char" : info.scalar ? (info.scalar[0] === "f" ?
                (info.size === 4 ? "float" : "double") :
                (info.scalar[0] === "u" ? "uint" : "int") + info.scalar.slice(1) + "_t") : info.kind;
            const enumValues = info.enumerators ? " enum {" + Object.entries(info.enumerators).map(([key,value]) => key + " = " + value).join(", ") + "}" : "";
            return align + base + enumValues + label + (info.bit ? " : " + info.bit[1] : "") + order;
        }
        const info = typeInfo(resolve(type));
        return describe(type,"",0) + ";\n// sizeof: " + (info.size ?? "dynamic") +
            "\n// alignof: " + (info.align ?? "unknown");
    }
    function encodeValue(info, value) {
        if (info.enumerators && typeof value === "string") {
            if (!Object.hasOwn(info.enumerators, value)) throw new TypeError("unknown enumerator " + value);
            value = info.enumerators[value];
        }
        return scalarBytes(info.scalar, value, info.littleEndian);
    }

    function terminatedBytes(base, element, limit) {
        if (base === 0n) throw new RangeError("null pointer");
        const total = integer(element.size * limit, "terminated sequence is too large");
        const collected = [];
        let offset = 0;
        while (offset < total) {
            const length = Math.min(total - offset,4096);
            const chunk = rpc("readPrefix", {address:word(addr(base,offset)), length});
            for (let i = 0; i + element.size <= chunk.length; i += element.size) {
                const bytes = chunk.slice(i,i + element.size);
                if (bytes.every(byte => byte === 0)) return Uint8Array.from(collected);
                collected.push(...bytes);
            }
            if (chunk.length < length) throw new Error("terminated sequence crosses unavailable memory");
            offset += length;
        }
        throw new RangeError("terminator not found within the element limit");
    }
    function staticStorageSize(type) {
        const info = typeInfo(resolve(type));
        if (info.size === undefined || info.kind === "bitfield") {
            throw new TypeError("type has no independently addressable static storage");
        }
        return info.size;
    }

    function fieldOffset(type, path) {
        if (typeof path !== "string" || !path.length) throw new TypeError("expected a member path");
        let offset = 0;
        let remaining = path;
        while (remaining.length) {
            const info = typeInfo(resolve(type));
            if (remaining.startsWith("[")) {
                const index = /^\[(\d+)\]/.exec(remaining);
                if (!index || info.kind !== "array" || typeof info.length !== "number") {
                    throw new TypeError("expected an index into a fixed array");
                }
                const element = integer(Number(index[1]), "invalid array index");
                if (element >= info.length) throw new RangeError("array index out of bounds");
                type = info.element;
                offset += element * staticStorageSize(type);
                remaining = remaining.slice(index[0].length);
            } else {
                const member = /^[^.\[\]]+/.exec(remaining)?.[0];
                const field = member && info.fields && Object.hasOwn(info.fields, member) && info.fields[member];
                if (!field || !Number.isSafeInteger(field.offset)) throw new TypeError("unknown or dynamic C member");
                type = field.type;
                offset += field.offset;
                remaining = remaining.slice(member.length);
            }
            if (remaining.startsWith(".")) {
                remaining = remaining.slice(1);
                if (!remaining || /^[.\[\]]/.test(remaining)) throw new TypeError("invalid member path");
            } else if (remaining && !remaining.startsWith("[")) throw new TypeError("invalid member path");
        }
        if (typeInfo(resolve(type)).kind === "bitfield") throw new TypeError("bitfields have no byte offset");
        return integer(offset, "invalid byte offset");
    }
    function resolve(type, self) {
        for (let i = 0; i < 32; i++) {
            const info = typeInfo(type);
            if (info.kind === "self") {
                if (!self) throw new TypeError("self() must be used inside an aggregate");
                type = self;
            } else if (info.kind === "lazy") {
                info.result ??= info.getter();
                type = info.result;
            } else return type;
        }
        throw new TypeError("recursive type must contain a pointer");
    }
    const scalar = kind => scalarDescriptors[kind] ??= descriptor({
        kind:"scalar", scalar:kind, size:scalarSpec[kind][1], align:scalarSpec[kind][1],
    });
    function sequence(kind, type, length) {
        typeInfo(type);
        if (typeof length !== "function" && length !== undefined) length = integer(length, "invalid element count");
        const item = kind === "array" ? typeInfo(resolve(type)) : null;
        if (item && (!item.size || !item.align || item.kind === "bitfield" || item.size % item.align)) {
            throw new TypeError("array element must have a nonzero size divisible by its alignment");
        }
        return descriptor({kind, element:type, length, scalar:kind === "ptr" ? "ptr" : undefined,
            size:kind === "ptr" ? 8 : typeof length === "number" ? integer(length * item.size, "array size too large") : undefined,
            align:kind === "ptr" ? 8 : item.align});
    }

    function aggregate(kind, fields, option = {}) {
        const pack = option.pack === undefined || option.pack === 0 ? Infinity : alignment(option.pack);
        if (pack !== Infinity && pack > 16) throw new RangeError("GCC packing must be 0, 1, 2, 4, 8 or 16");
        const entries = Reflect.ownKeys(fields).filter(key => Object.prototype.propertyIsEnumerable.call(fields,key));
        const layout = Object.create(null);
        const declarations = [];
        const addField = (name, type, offset) => {
            if (Object.hasOwn(layout,name)) throw new TypeError("duplicate C field name " + name);
            layout[name] = {type,offset};
        };
        let occupiedBits = 0, natural = 1, tail;
        for (const [index,name] of entries.entries()) {
            const type = fields[name];
            const anonymous = typeof name === "string" && name.startsWith("$") && anonymousFields.has(type);
            if (!anonymous && (typeof name !== "string" || name.startsWith("$") ||
                (/^(0|[1-9]\d*)$/.test(name) && Number(name) < 4294967295))) {
                throw new TypeError("invalid C field name " + String(name));
            }
            const member = anonymous ? type.type : type;
            const info = typeInfo(resolve(member));
            if (info.kind === "bitfield" && info.size !== undefined) {
                const width = info.bit[1], unit = info.size * 8;
                if (width === 0) {
                    if (!anonymous) throw new TypeError("zero-width bitfields must be unnamed");
                    if (arch === "aarch64") natural = Math.max(natural,info.align);
                    if (kind === "struct") occupiedBits = rounded(occupiedBits,info.align * 8);
                    declarations.push({type:member,offset:kind === "struct" ? occupiedBits / 8 : 0});
                    continue;
                }
                const align = Math.min(info.align,pack);
                const contributesAlignment = !anonymous || arch === "aarch64";
                if (contributesAlignment) natural = Math.max(natural,align);
                let start = kind === "union" ? 0 : occupiedBits;
                if (pack >= info.align && start % unit + width > unit) start = rounded(start,unit);
                const offset = Math.floor(start / 8);
                const placed = descriptor({...info,bit:[start % 8,width]});
                if (!anonymous) addField(name,placed,offset);
                declarations.push({name:anonymous ? undefined : name,type:placed,offset});
                const end = kind === "union" && contributesAlignment ? Math.max(width,align * 8) : start + width;
                occupiedBits = Math.max(occupiedBits,end);
                continue;
            }
            if (!info.align || info.kind === "void" || info.kind === "fn") throw new TypeError("field " + name + " does not have a C object type");
            const align = Math.min(info.align,pack);
            natural = Math.max(natural,align);
            const offset = kind === "struct" ? rounded(Math.ceil(occupiedBits / 8),align) : 0;
            if (anonymous) {
                if (!info.fields || info.tail !== undefined) throw new TypeError("expected an anonymous fixed aggregate");
                for (const [child, field] of Object.entries(info.fields)) addField(child,field.type,offset + field.offset);
            } else addField(name,member,offset);
            declarations.push({name:anonymous ? undefined : name,type:member,offset});
            if (info.size === undefined) {
                if (kind !== "struct" || index !== entries.length - 1 || info.kind !== "array") {
                    throw new TypeError("an unsized array must be the final struct field");
                }
                tail = name;
            }
            occupiedBits = Math.max(occupiedBits, (offset + (info.size ?? 0)) * 8);
        }
        const explicitAlign = option.align === undefined ? undefined : alignment(option.align);
        const align = Math.max(natural, explicitAlign ?? 1);
        return descriptor({kind, fields:layout, tail, size:rounded(Math.ceil(occupiedBits / 8),align),
            align, explicitAlign, pack:option.pack, declarations, entries:Object.fromEntries(entries.map(key => [key,fields[key]]))});
    }

    function refine(type, fields) {
        const info = typeInfo(type);
        const layout = Object.assign(Object.create(null),info.fields);
        for (const [name,type] of Object.entries(fields)) {
            const original = layout[name];
            if (!original) throw new TypeError("unknown C field " + name);
            const before = typeInfo(resolve(original.type)), after = typeInfo(resolve(type));
            if (before.kind !== after.kind || before.size !== after.size || before.align !== after.align) {
                throw new TypeError("refined field changes its C layout");
            }
            layout[name] = {...original,type};
        }
        return descriptor({...info,fields:layout,entries:undefined});
    }

    const m = {
        void: () => voidType,
        struct: (fields, options) => aggregate("struct",fields,options),
        union: (fields, options) => aggregate("union",fields,options),
        array: (type,length) => sequence("array",type,length),
        opaque: length => sequence("array",scalar("u8"),integer(length,"invalid opaque byte count")),
        anonymous(type) {
            typeInfo(type);
            const member = Object.freeze({type});
            anonymousFields.add(member);
            return {["$anonymous" + nextAnonymousField++]:member};
        },
        pointer: (type,length) => sequence("ptr",type,length),
        char: () => descriptor({...typeInfo(scalar(arch === "aarch64" ? "u8" : "i8")), char:true}),
        cStr: limit => m.pointer(m.char()).nullTerminate(limit),
        function(signature) {
            for (const type of signature.args) typeInfo(type);
            typeInfo(signature.returns);
            return descriptor({kind:"fn",args:[...signature.args],returns:signature.returns,variadic:!!signature.variadic});
        },
        lazy(getter) { return descriptor({kind:"lazy",getter}); },
        self() { return selfType; },
        typeOfVar(name) {
            const graph = rpc("typeOfVar", {name, tid:callbackTid});
            return graph == null ? undefined : dwarfType({graph});
        },
        fromDwarf(name) {
            return dwarfType({graph:rpc("fromDwarf", {name})});
        },
        findTypes(query) {
            if (typeof query !== "string" || !query) throw new TypeError("expected a DWARF type query");
            const pattern = /[*?\[]/.test(query) ? query : "*" + query + "*";
            return Array.from(dwarfRows(pattern), ({name,module,size}) => ({name,module,size}));
        },
    };
    const voidType = descriptor({kind:"void"});
    const selfType = descriptor({kind:"self"});
    for (const kind of Object.keys(scalarSpec)) if (kind !== "ptr") m[kind] = () => scalar(kind);
    Object.freeze(m);

    function bound(store) {
        const root = store[valueKeys.root];
        if (root !== undefined && root !== targetGeneration()) throw new Error("value belongs to a previous target");
    }

    function dynamicLength(info, store) {
        if (typeof info.length !== "function") return info.length;
        let length = info.length(store[valueKeys.parent]);
        if (valueStore(length) && length.$read) length = length.$read();
        return integer(length,"dynamic length must be a nonnegative safe integer");
    }

    function valueSize(info, store) {
        if (info.kind === "array") {
            const length = dynamicLength(info,store);
            return length === undefined ? undefined : integer(length * info.element.$size,"array byte size exceeds safe integer range");
        }
        if (info.tail !== undefined) {
            const tail = store[valueKeys.value][info.tail].$size;
            return tail === undefined ? info.size : Math.max(info.size, info.fields[info.tail].offset + tail);
        }
        return info.size;
    }

    function getValueBytes(store) {
        const info = store[valueKeys.info];
        bound(store);
        const bytes = store[valueKeys.bytes];
        if (bytes !== undefined) return bytes;
        const size = valueSize(info,store);
        if (size === undefined) throw new TypeError("value has no known byte size");
        return readBytes(store[valueKeys.address],size);
    }

    function setValueBytes(store, bytes) {
        const info = store[valueKeys.info];
        bound(store);
        if (!(bytes instanceof Uint8Array)) throw new TypeError("expected Uint8Array");
        if (bytes.length !== valueSize(info,store)) throw new RangeError("byte length differs from C storage size");
        if (store[valueKeys.inline]) {
            store[valueKeys.bytes] = bytes;
            return;
        }
        writeBytes(store[valueKeys.address],bytes);
    }

    function readScalar(store) {
        const info = store[valueKeys.info];
        return view(getValueBytes(store))["get" + scalarSpec[info.scalar][0]](0,info.littleEndian ?? true);
    }

    function writeScalar(store, value) {
        setValueBytes(store,encodeValue(store[valueKeys.info],value));
    }

    function readBitWord(store, bytes) {
        bound(store);
        return readBytes(store[valueKeys.address],bytes).reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
    }

    function readBitfield(store) {
        const {scalar, bit:[shift,width]} = store[valueKeys.info];
        const mask = (1n << BigInt(width)) - 1n;
        const raw = (readBitWord(store,Math.ceil((shift + width) / 8)) >> BigInt(shift)) & mask;
        const n = scalar.startsWith("i") ? BigInt.asIntN(width,raw) : raw;
        return scalarSpec[scalar][1] === 8 ? n : Number(n);
    }

    function writeBitfield(store, value) {
        const {scalar, bit:[shift,width]} = store[valueKeys.info];
        scalarBytes(scalar,value);
        const n = BigInt(value);
        if (n !== (scalar.startsWith("i") ? BigInt.asIntN(width,n) : BigInt.asUintN(width,n))) {
            throw new RangeError("integer does not fit the bitfield");
        }
        const bytes = Math.ceil((shift + width) / 8);
        const mask = (1n << BigInt(width)) - 1n;
        let raw = (readBitWord(store,bytes) & ~(mask << BigInt(shift))) | ((n & mask) << BigInt(shift));
        const data = new Uint8Array(bytes);
        for (let i = 0; i < bytes; i++, raw >>= 8n) data[i] = Number(raw & 255n);
        writeBytes(store[valueKeys.address],data);
    }

    function valueAddress(store) {
        bound(store);
        const address = store[valueKeys.address];
        if (address === undefined) throw new TypeError("value is not bound to target memory");
        return address;
    }

    function valueField(store, name) {
        const info = store[valueKeys.info];
        bound(store);
        const {offset,type} = info.fields[name];
        return makeValue(type,{[valueKeys.address]:addr(store[valueKeys.address],offset), [valueKeys.parent]:store[valueKeys.value],
            [valueKeys.inheritTid]:true, [valueKeys.self]:store[valueKeys.type], [valueKeys.root]:store[valueKeys.root]});
    }

    function valueAtIndex(store, index, checked) {
        const info = store[valueKeys.info];
        bound(store);
        index = integer(index,"array index must be a nonnegative safe integer");
        const count = checked ? dynamicLength(info,store) : undefined;
        if (count !== undefined && index >= count) throw new RangeError("index exceeds the length");
        const element = resolve(info.element,store[valueKeys.self]), size = element.$size;
        if (checked && info.kind === "array" && count === undefined) throw new TypeError("use $atUnchecked for an unsized array");
        if (size === undefined && index !== 0) throw new TypeError("element size is unknown");
        const base = info.kind === "ptr" ? readScalar(store) : store[valueKeys.address];
        if (info.kind === "ptr" && base === 0n) throw new RangeError("null pointer");
        return makeValue(element,{[valueKeys.address]:addr(base,BigInt(index) * BigInt(size ?? 0)), [valueKeys.parent]:store[valueKeys.value],
            [valueKeys.inheritTid]:true, [valueKeys.self]:store[valueKeys.self], [valueKeys.root]:store[valueKeys.root] ?? targetGeneration()});
    }

    function derefTerminated(store) {
        const info = store[valueKeys.info], element = store[valueKeys.terminatedElement];
        const bytes = terminatedBytes(readScalar(store),element,info.terminated);
        if (element.char) return fromUtf8(bytes);
        const data = view(bytes);
        return Array.from({length:bytes.length / element.size}, (_, index) => {
            const item = data["get" + scalarSpec[element.scalar][0]](index * element.size,element.littleEndian ?? true);
            return element.terminated === undefined ? item : valueAtIndex(store,index,false).$deref();
        });
    }

    function writeTerminated(store, contents) {
        const info = store[valueKeys.info], element = store[valueKeys.terminatedElement];
        const base = readScalar(store);
        const previous = terminatedBytes(base,element,info.terminated);
        const length = element.char ? (typeof contents === "string" ? utf8(contents) : undefined) : contents;
        if (element.char ? !length : !Array.isArray(length)) throw new TypeError("invalid terminated sequence contents");
        const count = length.length;
        const bytes = new Uint8Array(integer((count + 1) * element.size,"terminated sequence is too large"));
        for (let index = 0; index < count; index++) {
            const encoded = element.char ? [length[index]] : encodeValue(element,length[index]);
            if (encoded.every(byte => byte === 0)) throw new TypeError("sequence content contains a terminator");
            bytes.set(encoded,index * element.size);
        }
        writeBytes(base,bytes);
        const previousBytes = previous.length + element.size;
        return bytes.length > previousBytes ?
            {writtenBytes:bytes.length, previousBytes, warning:"write exceeded the previous sequence extent"} :
            {writtenBytes:bytes.length, previousBytes};
    }

    const isIndexed = kind => kind === "ptr" || kind === "array";
    const arrayIndex = key => typeof key === "string" && /^(?:0|[1-9][0-9]*)$/.test(key);
    const summarizeValue = store => jsonText(summarize(store[valueKeys.value]));
    const uncheckedIndex = (store,index) => valueAtIndex(store,index,false);
    const derefPointer = store => valueAtIndex(store,0,false);
    const valueTargets = new WeakMap();

    const missingValueProperty = Symbol();

    function getValueProperty(store,key) {
        const info = store[valueKeys.info];
        const {kind} = info;
        switch (key) {
        case "$type": return store[valueKeys.type];
        case "$size": return valueSize(info,store);
        case "$parent": return store[valueKeys.parent];
        case "$tid": return store[valueKeys.tid] ?? (store[valueKeys.inheritTid] ? store[valueKeys.parent]?.$tid : undefined);
        case "$toJson":
        case "$dumpString": return summarizeValue.bind(undefined,store);
        case "$address":
            if (kind !== "bitfield") return valueAddress.bind(undefined,store);
            break;
        case "$readBytes":
            if (kind !== "fn" && kind !== "bitfield") {
                return store[valueKeys.readBytesMethod] ??= getValueBytes.bind(undefined,store);
            }
            break;
        case "$writeBytes":
            if (kind !== "fn" && kind !== "bitfield") {
                return store[valueKeys.writeBytesMethod] ??= setValueBytes.bind(undefined,store);
            }
            break;
        case "$read":
            if (kind === "bitfield") return readBitfield.bind(undefined,store);
            if (kind === "scalar" || kind === "ptr") {
                return store[valueKeys.readMethod] ??= readScalar.bind(undefined,store);
            }
            break;
        case "$write":
            if (kind === "bitfield") return writeBitfield.bind(undefined,store);
            if (kind === "scalar" || kind === "ptr") return writeScalar.bind(undefined,store);
            break;
        case "$length":
            if (isIndexed(kind)) return dynamicLength(info,store);
            break;
        case "$atUnchecked":
            if (isIndexed(kind)) return uncheckedIndex.bind(undefined,store);
            break;
        case "$deref":
            if (kind === "ptr") {
                return (store[valueKeys.terminatedElement] ? derefTerminated : derefPointer).bind(undefined,store);
            }
            break;
        case "$writeContents":
            if (store[valueKeys.terminatedElement]) return writeTerminated.bind(undefined,store);
            break;
        }
        if (info.fields && Object.hasOwn(info.fields,key)) return valueField(store,key);
        if (isIndexed(kind) && arrayIndex(key)) return valueAtIndex(store,Number(key),true);
        return missingValueProperty;
    }

    function setValueProperty(store,key,value) {
        const info = store[valueKeys.info];
        if (key === "$tid") {
            if (value !== undefined && (!Number.isSafeInteger(value) || value <= 0)) throw new RangeError("invalid TID");
            store[valueKeys.tid] = value;
            store[valueKeys.inheritTid] = false;
            return true;
        }
        if (info.fields && Object.hasOwn(info.fields,key)) { assign(valueField(store,key),value); return true; }
        if (isIndexed(info.kind) && arrayIndex(key)) { assign(valueAtIndex(store,Number(key),true),value); return true; }
        throw new TypeError("value property is read-only");
    }

    const valueHandler = {
        get(object,key) {
            const value = getValueProperty(valueTargets.get(object),key);
            return value === missingValueProperty ? Reflect.get(object,key) : value;
        },
        set(object,key,value) {
            return setValueProperty(valueTargets.get(object),key,value);
        },
    };

    const nativeValueHooks = {
        get(store,key) {
            const value = getValueProperty(store,key);
            if (value !== missingValueProperty) return value;
            const prototype = Object.getPrototypeOf(store[valueKeys.value]);
            return prototype === null ? undefined : Reflect.get(prototype,key,store[valueKeys.value]);
        },
        set: setValueProperty,
    };

    function makeValue(original, store) {
        const type = resolve(original,store[valueKeys.self]);
        const info = typeInfo(type);
        if (info.kind === "void") return undefined;
        const terminatedElement = info.kind === "ptr" && info.terminated !== undefined
            ? typeInfo(resolve(info.element)) : undefined;
        if (info.kind !== "fn") {
            return createCompactValue(store,type,info,terminatedElement,compactValueKeys);
        }
        if (terminatedElement !== undefined) store[valueKeys.terminatedElement] = terminatedElement;
        store[valueKeys.type] = type;
        store[valueKeys.info] = info;
        const object = (...args) => invoke(info,store,args);
        const proxy = new Proxy(object,valueHandler);
        store[valueKeys.value] = proxy;
        valueTargets.set(object,store);
        values.set(proxy,store);
        return proxy;
    }

    function assign(target, source) {
        const dest = valueStore(target), src = valueStore(source);
        if (!dest || (!target.$writeBytes && !target.$write)) throw new TypeError("value is not assignable");
        if (!src) {
            if (!target.$write) throw new TypeError("assign a C Value of the same type");
            target.$write(source);
            return;
        }
        const expected = typeInfo(dest[valueKeys.type]), actual = typeInfo(src[valueKeys.type]);
        if (dest[valueKeys.type] !== src[valueKeys.type] && (expected.kind !== actual.kind || expected.kind !== "scalar" || expected.scalar !== actual.scalar)) {
            throw new TypeError("incompatible C types");
        }
        if (expected.kind === "scalar" && expected.littleEndian !== actual.littleEndian) target.$write(source.$read());
        else if (target.$writeBytes && source.$readBytes) target.$writeBytes(source.$readBytes());
        else if (target.$write && source.$read) target.$write(source.$read());
        else throw new TypeError("value storage is not assignable");
    }

    function summarize(value, depth = 0) {
        const info = typeInfo(valueStore(value)[valueKeys.type]);
        if (value.$read) {
            const result = value.$read();
            return typeof result === "bigint" ? (info.kind === "ptr" ? word(result) : result.toString()) : result;
        }
        if (depth >= 16) return "[Depth limit]";
        if (info.fields) return Object.fromEntries(Object.keys(info.fields).map(name => [name,summarize(value[name],depth+1)]));
        if (info.kind === "array" && value.$length !== undefined) {
            return Array.from({length:Math.min(value.$length,1024)}, (_,i) => summarize(value[i],depth+1));
        }
        if (info.kind === "fn") return word(value.$address());
        return "[Unsized array]";
    }

    function invoke(info, store, args) {
        const tid = store[valueKeys.value].$tid;
        if (tid === undefined) throw new TypeError("bind a thread before calling a C function");
        bound(store);
        if (args.length < info.args.length || (!info.variadic && args.length !== info.args.length)) throw new TypeError("incorrect C argument count");
        const encoded = args.map((value,i) => {
            const inferred = valueStore(value);
            const type = info.args[i] ?? inferred?.[valueKeys.type];
            if (!type) throw new TypeError("variadic arguments must be typed C Values");
            const arg = typeInfo(resolve(type));
            if (!arg.scalar) throw new TypeError("unsupported C argument type");
            if (inferred) {
                if (typeInfo(inferred[valueKeys.type]).scalar !== arg.scalar) throw new TypeError("incompatible C argument");
                value = value.$read();
            }
            return {kind:arg.scalar, bytes:Array.from(scalarBytes(arg.scalar,value))};
        });
        const ret = typeInfo(resolve(info.returns));
        return Promise.resolve().then(() => {
            const bytes = rpc("call", {tid,address:word(store[valueKeys.address]),args:encoded,returns:ret.scalar ?? ret.kind,fixed:info.args.length,variadic:info.variadic});
            return ret.kind === "void" ? undefined : makeValue(info.returns, {[valueKeys.bytes]:Uint8Array.from(bytes)});
        });
    }

    function *dwarfRows(pattern, exact = false) {
        let offset = 0;
        do {
            const page = rpc("types", {pattern,exact,offset});
            for (const row of page.items) yield row;
            offset = page.next_offset;
        } while (offset != null);
    }

    function dwarfType(row) {
        const {nodes,root} = row.graph;
        const cache = new Map();
        function node(id) {
            if (cache.has(id)) return cache.get(id);
            const info = nodes[id];
            let type;
            switch (info.kind) {
            case "void": type = voidType; break;
            case "scalar": type = scalar(info.scalar); break;
            case "pointer": type = m.pointer(m.lazy(() => node(info.element))); break;
            case "array":
                type = node(info.element);
                for (const size of info.dimensions.length ? [...info.dimensions].reverse() : [undefined]) {
                    type = m.array(type,size);
                }
                break;
            case "aggregate": {
                const fields = Object.create(null);
                const declarations = [];
                const insert = (name, type, offset) => {
                    if (Object.hasOwn(fields,name)) throw new TypeError("duplicate DWARF member " + name);
                    fields[name] = {type,offset};
                };
                for (const {name,offset,ty,bit} of info.fields) {
                    const member = node(ty);
                    const underlying = typeInfo(member);
                    const type = bit ? descriptor({kind:"bitfield",scalar:underlying.scalar,bit}) : member;
                    declarations.push({name,offset,type});
                    if (name != null) insert(name,type,offset);
                    else if (underlying.fields) {
                        for (const [child,field] of Object.entries(underlying.fields)) {
                            insert(child,field.type,offset + field.offset);
                        }
                    }
                }
                type = descriptor({kind:info.union ? "union" : "struct",size:info.size,align:info.align,fields,declarations});
                break;
            }
            case "function":
                type = m.function({args:info.args.map(node),returns:node(info.returns),variadic:info.variadic});
                break;
            case "opaque":
                type = descriptor({kind:"opaque",size:info.size,align:info.align});
                break;
            }
            cache.set(id,type);
            return type;
        }
        return node(root);
    }

    function immediateWatch(length,value) {
        return scalar("u" + length * 8).value(length === 8 ? BigInt(value) : Number(value));
    }

    return {
        nativeValueKeys: valueKeys,
        nativeValueHooks,
        installCompactValue(create, lookup, keys) {
            createCompactValue = create;
            lookupNativeValue = lookup;
            compactValueKeys = keys;
        },
        initialize(operation, architecture, generation) {
            host = operation; arch = architecture; targetGeneration = generation;
            const scope = new Proxy(exports,{
                get(target,key) { return target[key]?.[key]; },
                set() { return false; },
                deleteProperty() { return false; },
                defineProperty() { return false; },
                setPrototypeOf() { return false; },
                preventExtensions() { return false; },
                getOwnPropertyDescriptor(target,key) {
                    return Object.hasOwn(target,key)
                        ? {configurable:true,enumerable:true,value:target[key][key]}
                        : undefined;
                },
            });
            for (const [name,value] of Object.entries({dbg,m,$:scope,__aidbgConsole:makeConsole,setTimeout,clearTimeout,queueMicrotask,sleep,AbortController})) {
                Object.defineProperty(globalThis,name,{value});
            }
        },
        fireTimer(id) {
            const timer = timers.get(id);
            if (!timer) return;
            timers.delete(id);
            queueMicrotask(timer.callback);
        },
        eventResult(id, data) {
            const entry = eventWaiters.get(id);
            if (!entry) return;
            eventWaiters.delete(id);
            const result = parse(data);
            if (result.kind === "stops") {
                entry.resolve(Object.freeze({...result,events:Object.freeze(result.events.map(stopEvent))}));
            } else entry.resolve(stopEvent(result));
        },
        input(handler, ok, text) {
            const entry = inputs.get(handler);
            if (!entry) return;
            inputs.delete(handler);
            if (ok) entry.resolve(text);
            else entry.reject(new Error(text));
        },
        dispatch,
        publish(namespace, keys) { for (const key of parse(keys)) exports[key] = namespace; },
        reset() {
            for (const timer of timers.values()) timer.cancel?.();
            timers.clear();
            for (const waiter of eventWaiters.values()) waiter.reject(new Error("target changed"));
            eventWaiters.clear();
            points.clear();
            syscallCatches.clear();
            signals.clear();
            for (const key of Object.keys(exports)) delete exports[key];
        },
    };
})()
