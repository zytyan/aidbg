(() => {
    "use strict";

    let host, arch;
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
                if (values.has(value)) return summarize(value);
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
                if (kind !== "s" && values.has(value) && value.$read) value = value.$read();
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
            if (generation !== rpc("generation")) throw new Error("debugger target changed");
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
            waitInput(seconds) {
                check();
                if (seconds !== undefined && (typeof seconds !== "number" || !Number.isFinite(seconds))) {
                    throw new RangeError("invalid input timeout");
                }
                const handler = rpc("wait", {id, seconds, tid:callbackTid});
                return new Promise((resolve, reject) => inputs.set(handler, {resolve, reject}));
            },
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
        return Object.freeze({...row, pc:BigInt(raw.pc), sp:BigInt(raw.sp ?? 0), fp:BigInt(raw.fp ?? 0),
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
            if (event.paused && predicate(event) === true) return event;
            if (event.paused) rpc("continue", {tid:event.tid});
            if (rpc("clock") >= deadline) return Object.freeze({kind:"timeout"});
        }
    }

    function makeThread(tid, controlled = false, callback) {
        const generation = rpc("generation");
        let identity;
        try { identity = rpc("identity", {tid}); } catch (_) {}
        const exists = () => {
            if (generation !== rpc("generation") || identity === undefined) return false;
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
        const generation = rpc("generation");
        const id = ++nextPoint;
        const address = BigInt(rpc("addPoint", {id, kind:type, at:checkedAddress(at), ...options}));
        const change = remove => {
            if (generation !== rpc("generation")) throw new Error("breakpoint no longer exists");
            rpc("point", {id, remove});
            points.delete(id);
        };
        const point = Object.freeze({
            id, type, address,
            get tid() {
                if (generation !== rpc("generation")) return Object.freeze([]);
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

    const symbol = row => Object.freeze({...row, address:BigInt(row.address), module:optional(row.module)});
    const processIo = Object.freeze({
        stdin:Object.freeze({
            write:data => rpc("stdio",{operation:"write",data}),
            close:() => {rpc("stdio",{operation:"close"});},
        }),
        stdout:Object.freeze({read:() => rpc("stdio",{operation:"stdout"})}),
        stderr:Object.freeze({read:() => rpc("stdio",{operation:"stderr"})}),
        combinedOutErr:Object.freeze({read:() => rpc("stdio",{operation:"combined"})}),
    });
    const dbg = Object.freeze({
        get arch() { return arch; },
        endian:"le",
        get pid() { return rpc("pid"); },
        process:processIo,
        memory,
        thread:tid => makeThread(tid),
        threads:() => Object.freeze(rpc("threads").map(tid => makeThread(tid))),
        mappings:() => Object.freeze(rpc("mappings").map(mapping)),
        async snapshot(tid) { return snapshot(rpc("snapshot", {tid})); },
        async pause(tid) {
            const threads = rpc("pause", {tid}).map(tid => makeThread(tid, true));
            return tid === "all" ? threads : threads[0];
        },
        async resume(tid = "all") { rpc("continue", {tid:scope(tid) ?? "all"}); },
        async continue(tid = "all") { return dbg.resume(tid); },
        continueForStop,
        async waitExit(timeoutMs) { return waitEvent({kind:"process_exit",timeoutMs},callbackContext); },
        async waitStops(limit, timeoutMs) { return waitEvent({kind:"batch",limit,timeoutMs},callbackContext); },
        async ask(payload, timeoutMs) { return ask(payload,timeoutMs,callbackTid); },
        async detach() { rpc("detach"); },
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
        const generation = rpc("generation");
        const context = {tid,token,active:true,pause:null,pass:true,counts:{}};
        const thread = makeThread(tid, true, context);
        const check = () => {
            if (!context.active || rpc("generation") !== generation) throw new Error("the callback no longer controls this stop");
        };
        try {
            for (const event of parse(events)) {
                if (!context.active || rpc("generation") !== generation) return;
                let result;
                const previousContext = callbackContext, previousTid = callbackTid;
                callbackContext = context;
                callbackTid = tid;
                try {
                    if (event.breakpointId !== undefined) {
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
                        const callback = signals.get(event.signalNumber);
                        if (!callback) continue;
                        result = callback(Object.freeze({
                            thread, signalNumber:event.signalNumber, signalName:event.signalName,
                            faultAddress:event.faultAddress == null ? undefined : BigInt(event.faultAddress),
                            passToTarget(value) { check(); context.pass = !!value; },
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
            if (rpc("generation") === generation) reportError(error);
        } finally {
            if (context.active) {
                context.active = false;
                rpc("callbackDone", {generation,tid,token,pause:context.pause,pass:context.pass,counts:context.counts});
            }
        }
    }

    // Type descriptors carry layout. Every value has its own storage and thread binding.
    const types = new WeakMap(), values = new WeakMap();
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
    function scalarBytes(kind, value) {
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
        view(bytes)["set" + native](0,value,true);
        return bytes;
    }

    function descriptor(info) {
        const type = {
            get $size() { return info.kind === "lazy" ? typeInfo(resolve(type)).size : info.size; },
            get $align() { return info.kind === "lazy" ? typeInfo(resolve(type)).align : info.align; },
            at(address, tid) { word(address); return makeValue(type, {address, tid, root:rpc("generation")}); },
        };
        if (info.kind === "scalar" || info.kind === "ptr") {
            type.value = value => makeValue(type, {bytes:scalarBytes(info.scalar, value)});
        }
        if (info.kind === "ptr") type.pointee = () => typeInfo(info.element).kind === "self" ? info.element : resolve(info.element);
        if (info.kind === "array") type.element = () => info.element;
        if (info.fields) {
            type.field = name => {
                if (!Object.hasOwn(info.fields,name)) throw new Error("unknown C field " + name);
                return info.fields[name].type;
            };
            type.refine = fields => refine(type, fields);
        }
        types.set(type,info);
        return Object.freeze(type);
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
        if (item && (!item.size || !item.align)) throw new TypeError("array element size must be known and nonzero");
        return descriptor({kind, element:type, length, scalar:kind === "ptr" ? "ptr" : undefined,
            size:kind === "ptr" ? 8 : typeof length === "number" ? integer(length * item.size, "array size too large") : undefined,
            align:kind === "ptr" ? 8 : item.align});
    }

    function aggregate(kind, fields, option = {}) {
        const pack = option.pack === undefined ? Infinity : alignment(option.pack);
        const entries = Object.entries(fields);
        const layout = Object.create(null);
        let size = 0, natural = 1, tail;
        for (const [index,[name,type]] of entries.entries()) {
            if (name.startsWith("$")) throw new TypeError("C field names cannot begin with $");
            const info = typeInfo(resolve(type));
            if (!info.align || info.kind === "void" || info.kind === "fn") throw new TypeError("field " + name + " does not have a C object type");
            const align = Math.min(info.align,pack);
            natural = Math.max(natural,align);
            const offset = kind === "struct" ? rounded(size,align) : 0;
            layout[name] = {type,offset};
            if (info.size === undefined) {
                if (kind !== "struct" || index !== entries.length - 1 || info.kind !== "array") {
                    throw new TypeError("an unsized array must be the final struct field");
                }
                tail = name;
            }
            size = Math.max(size, offset + (info.size ?? 0));
        }
        const align = Math.max(natural, option.align === undefined ? 1 : alignment(option.align));
        return descriptor({kind, fields:layout, tail, size:rounded(size,align), align});
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
        return descriptor({...info,fields:layout});
    }

    const m = {
        void: () => voidType,
        struct: (fields, options) => aggregate("struct",fields,options),
        union: (fields, options) => aggregate("union",fields,options),
        array: (type,length) => sequence("array",type,length),
        pointer: (type,length) => sequence("ptr",type,length),
        function(signature) {
            for (const type of signature.args) typeInfo(type);
            typeInfo(signature.returns);
            return descriptor({kind:"fn",args:[...signature.args],returns:signature.returns,variadic:!!signature.variadic});
        },
        lazy(getter) { return descriptor({kind:"lazy",getter}); },
        self() { return selfType; },
        fromDwarf(name) {
            const rows = Array.from(dwarfRows(name,true));
            if (rows.length !== 1) throw new Error("expected one DWARF type named " + name + ", found " + rows.length);
            return dwarfType(rows[0]);
        },
    };
    const voidType = descriptor({kind:"void"});
    const selfType = descriptor({kind:"self"});
    for (const kind of Object.keys(scalarSpec)) if (kind !== "ptr") m[kind] = () => scalar(kind);
    Object.freeze(m);

    function bound(store) {
        if (store.root !== undefined && store.root !== rpc("generation")) throw new Error("value belongs to a previous target");
    }

    function dynamicLength(info, store) {
        if (typeof info.length !== "function") return info.length;
        let length = info.length(store.parent);
        if (values.has(length) && length.$read) length = length.$read();
        return integer(length,"dynamic length must be a nonnegative safe integer");
    }

    function valueSize(info, store) {
        if (info.kind === "array") {
            const length = dynamicLength(info,store);
            return length === undefined ? undefined : integer(length * info.element.$size,"array byte size exceeds safe integer range");
        }
        if (info.tail !== undefined) {
            const tail = store.value[info.tail].$size;
            return tail === undefined ? info.size : Math.max(info.size, info.fields[info.tail].offset + tail);
        }
        return info.size;
    }

    function makeValue(original, store) {
        const type = resolve(original,store.self);
        const info = typeInfo(type);
        if (info.kind === "void") return undefined;
        const object = info.kind === "fn" ? (...args) => invoke(info,store,args) : Object.create(null);
        const getBytes = () => {
            bound(store);
            if (store.bytes) return store.bytes.slice();
            const size = valueSize(info,store);
            if (size === undefined) throw new TypeError("value has no known byte size");
            return readBytes(store.address,size);
        };
        const setBytes = bytes => {
            bound(store);
            if (!(bytes instanceof Uint8Array)) throw new TypeError("expected Uint8Array");
            if (bytes.length !== valueSize(info,store)) throw new RangeError("byte length differs from C storage size");
            if (store.bytes) store.bytes.set(bytes);
            else writeBytes(store.address,bytes);
        };
        const read = () => view(getBytes())["get" + scalarSpec[info.scalar][0]](0,true);
        const own = {
            $type:() => type, $size:() => valueSize(info,store), $parent:() => store.parent,
            $tid:() => store.tid ?? (store.inheritTid ? store.parent?.$tid : undefined),
            $toJson:() => () => jsonText(summarize(store.value)),
            $dumpString:() => () => jsonText(summarize(store.value)),
        };
        if (info.kind !== "fn" && info.kind !== "bitfield") {
            own.$readBytes = () => getBytes;
            own.$writeBytes = () => setBytes;
        }
        if (info.kind === "scalar" || info.kind === "ptr") {
            own.$read = () => read;
            own.$write = () => value => setBytes(scalarBytes(info.scalar,value));
        }
        if (info.kind === "bitfield") {
            const [shift,width] = info.bit;
            const bytes = Math.ceil((shift + width) / 8);
            const readWord = () => {
                bound(store);
                return readBytes(store.address,bytes).reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
            };
            const native = scalarSpec[info.scalar];
            const signed = info.scalar.startsWith("i");
            const mask = (1n << BigInt(width)) - 1n;
            own.$read = () => () => {
                const raw = (readWord() >> BigInt(shift)) & mask;
                const n = signed ? BigInt.asIntN(width,raw) : raw;
                return native[1] === 8 ? n : Number(n);
            };
            own.$write = () => value => {
                scalarBytes(info.scalar,value);
                const n = BigInt(value);
                if (n !== (signed ? BigInt.asIntN(width,n) : BigInt.asUintN(width,n))) {
                    throw new RangeError("integer does not fit the bitfield");
                }
                let raw = (readWord() & ~(mask << BigInt(shift))) | ((n & mask) << BigInt(shift));
                const data = new Uint8Array(bytes);
                for (let i = 0; i < bytes; i++, raw >>= 8n) data[i] = Number(raw & 255n);
                writeBytes(store.address,data);
            };
        }
        if (info.kind !== "bitfield") own.$address = () => () => {
            bound(store);
            if (store.address === undefined) throw new TypeError("value is not bound to target memory");
            return store.address;
        };
        const field = name => {
            bound(store);
            const {offset,type} = info.fields[name];
            return makeValue(type,{address:addr(store.address,offset), parent:store.value, inheritTid:true,
                self:store.selfForFields, root:store.root});
        };
        const atIndex = (index, checked) => {
            bound(store);
            index = integer(index,"array index must be a nonnegative safe integer");
            const count = checked ? dynamicLength(info,store) : undefined;
            if (count !== undefined && index >= count) throw new RangeError("index exceeds the length");
            const element = resolve(info.element,store.self), size = element.$size;
            if (checked && info.kind === "array" && count === undefined) throw new TypeError("use $atUnchecked for an unsized array");
            if (size === undefined && index !== 0) throw new TypeError("element size is unknown");
            const base = info.kind === "ptr" ? read() : store.address;
            if (info.kind === "ptr" && base === 0n) throw new RangeError("null pointer");
            return makeValue(element,{address:addr(base,BigInt(index) * BigInt(size ?? 0)), parent:store.value,
                inheritTid:true, self:store.self, root:store.root ?? rpc("generation")});
        };
        const indexed = info.kind === "ptr" || info.kind === "array";
        if (indexed) {
            own.$length = () => dynamicLength(info,store);
            own.$atUnchecked = () => index => atIndex(index,false);
        }
        if (info.kind === "ptr") own.$deref = () => () => atIndex(0,false);
        const arrayIndex = key => typeof key === "string" && /^(?:0|[1-9][0-9]*)$/.test(key);
        const proxy = new Proxy(object,{
            get(object,key) {
                if (Object.hasOwn(own,key)) return own[key]();
                if (info.fields && Object.hasOwn(info.fields,key)) return field(key);
                if (indexed && arrayIndex(key)) return atIndex(key === "0" ? 0 : Number(key),true);
                return Reflect.get(object,key);
            },
            set(_,key,value) {
                if (key === "$tid") {
                    if (value !== undefined && (!Number.isSafeInteger(value) || value <= 0)) throw new RangeError("invalid TID");
                    store.tid = value;
                    store.inheritTid = false;
                    return true;
                }
                if (info.fields && Object.hasOwn(info.fields,key)) { assign(field(key),value); return true; }
                if (indexed && arrayIndex(key)) { assign(atIndex(Number(key),true),value); return true; }
                throw new TypeError("value property is read-only");
            },
        });
        store.value = proxy;
        store.selfForFields = info.fields ? type : store.self;
        values.set(proxy,{type,store});
        return proxy;
    }

    function assign(target, source) {
        const dest = values.get(target), src = values.get(source);
        if (!dest || (!target.$writeBytes && !target.$write)) throw new TypeError("value is not assignable");
        if (!src) {
            if (!target.$write) throw new TypeError("assign a C Value of the same type");
            target.$write(source);
            return;
        }
        const expected = typeInfo(dest.type), actual = typeInfo(src.type);
        if (dest.type !== src.type && (expected.kind !== actual.kind || expected.kind !== "scalar" || expected.scalar !== actual.scalar)) {
            throw new TypeError("incompatible C types");
        }
        if (target.$writeBytes && source.$readBytes) target.$writeBytes(source.$readBytes());
        else if (target.$write && source.$read) target.$write(source.$read());
        else throw new TypeError("value storage is not assignable");
    }

    function summarize(value, depth = 0) {
        const info = typeInfo(values.get(value).type);
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
        const tid = store.value.$tid;
        if (tid === undefined) throw new TypeError("bind a thread before calling a C function");
        bound(store);
        if (args.length < info.args.length || (!info.variadic && args.length !== info.args.length)) throw new TypeError("incorrect C argument count");
        const encoded = args.map((value,i) => {
            const inferred = values.get(value);
            const type = info.args[i] ?? inferred?.type;
            if (!type) throw new TypeError("variadic arguments must be typed C Values");
            const arg = typeInfo(resolve(type));
            if (!arg.scalar) throw new TypeError("unsupported C argument type");
            if (inferred) {
                if (typeInfo(inferred.type).scalar !== arg.scalar) throw new TypeError("incompatible C argument");
                value = value.$read();
            }
            return {kind:arg.scalar, bytes:Array.from(scalarBytes(arg.scalar,value))};
        });
        const ret = typeInfo(resolve(info.returns));
        return Promise.resolve().then(() => {
            const bytes = rpc("call", {tid,address:word(store.address),args:encoded,returns:ret.scalar ?? ret.kind,fixed:info.args.length,variadic:info.variadic});
            return ret.kind === "void" ? undefined : makeValue(info.returns, {bytes:Uint8Array.from(bytes)});
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
                for (const {name,offset,ty,bit} of info.fields) {
                    const member = node(ty);
                    if (bit) {
                        const underlying = typeInfo(member);
                        fields[name] = {offset,type:descriptor({kind:"bitfield",scalar:underlying.scalar,bit})};
                    } else fields[name] = {offset,type:member};
                }
                type = descriptor({kind:info.union ? "union" : "struct",size:info.size,align:info.align,fields});
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
        initialize(operation, architecture) {
            host = operation; arch = architecture;
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
            signals.clear();
            for (const key of Object.keys(exports)) delete exports[key];
        },
    };
})()
