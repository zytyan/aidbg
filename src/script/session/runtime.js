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

    const hostErrors = new WeakSet();
    const rpc = (name, args = {}) => {
        try { return parse(host(name, stringify(args))); }
        catch (error) {
            if (error instanceof Error) hostErrors.add(error);
            throw error;
        }
    };
    const maxAddress = 0xffffffffffffffffn;
    const word = value => {
        if (typeof value !== "bigint" || value < 0n || value > maxAddress) {
            throw new RangeError("expected an unsigned 64-bit bigint");
        }
        return "0x" + value.toString(16);
    };
    const symbolLabel = row => {
        if (!row || row.match === "nearest") return "";
        const name = row.match === "module" ? row.module.path.split("/").pop() : row.name;
        return " <" + name + (row.offset ? "+" + word(row.offset) : "") + ">";
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

    function boundedText(text) {
        const limit = 14 * 1024;
        if (text.length <= limit / 3) return text;
        let bytes = 0, end = 0;
        for (const char of text) {
            const code = char.codePointAt(0);
            bytes += code < 128 ? 1 : code < 2048 ? 2 : code < 65536 ? 3 : 4;
            if (bytes > limit) {
                const line = text.lastIndexOf("\n", end - 1);
                return text.slice(0,line > 0 ? line : end) + "\n* Output truncated for display.";
            }
            end += char.length;
        }
        return text;
    }

    function consoleText(values) {
        // A standalone string is already formatted by the script.
        if (values.length === 1 && typeof values[0] === "string") return values[0];

        const active = new WeakSet();
        const chunks = [];
        let remaining = 16_384;
        let truncated = false;
        const write = text => {
            if (text.length > remaining) {
                chunks.push(text.slice(0, remaining).replace(/[\uD800-\uDBFF]$/, ""));
                truncated = true;
                remaining = 0;
            } else {
                chunks.push(text);
                remaining -= text.length;
            }
        };
        const format = (value, depth) => {
            if (valueStore(value)) { write(value.$format()); return; }
            if (typeof value === "string") {
                const excerpt = value.slice(0, 1024).replace(/[\uD800-\uDBFF]$/, "");
                write(depth === 0 ? excerpt : stringify(excerpt));
                if (excerpt.length < value.length) write(" <truncated string>");
                return;
            }
            if (typeof value === "bigint") { write(String(value) + "n"); return; }
            if (typeof value === "number" && Object.is(value, -0)) { write("-0"); return; }
            if (value === null || typeof value !== "object") { write(String(value)); return; }
            if (active.has(value)) { write("<circular>"); return; }
            if (depth >= 5) { write("<truncated at depth limit>"); return; }
            const indexed = Array.isArray(value) || ArrayBuffer.isView(value) && Number.isSafeInteger(value.length);
            const keys = indexed ? undefined : Object.keys(value);
            const count = keys?.length ?? value.length;
            const limit = Math.min(count, 32);
            active.add(value);
            write(indexed ? "[" : "{");
            for (let i = 0; i < limit && !truncated; i++) {
                if (i) write(", ");
                const key = indexed ? String(i) : keys[i];
                if (!indexed) write((/^[a-zA-Z_$][\w$]*$/.test(key) ? key : stringify(key)) + ": ");
                const property = Object.getOwnPropertyDescriptor(value, key);
                if (property && !("value" in property)) write("<accessor>");
                else format(property?.value, depth + 1);
            }
            if (count > limit) write((limit ? ", " : "") + "<truncated: " + (count - limit) +
                (indexed ? " more elements>" : " more fields>"));
            write(indexed ? "]" : "}");
            active.delete(value);
        };
        for (let i = 0; i < values.length && !truncated; i++) {
            if (i) write(" ");
            try { format(values[i], 0); }
            catch (error) { write("<formatting failed: " + error + ">"); }
        }
        if (truncated) chunks.push("\n* Output truncated: console formatting limit reached.");
        return chunks.join("");
    }

    function makeConsole(id, generation, textOutput) {
        const check = () => {
            if (generation !== targetGeneration()) throw new Error("debugger target changed");
        };
        return Object.freeze({
            log(...values) {
                check();
                if (textOutput) {
                    rpc("log", {id, value:{kind:"console", text:boundedText(consoleText(values))}});
                } else {
                    rpc("log", {id, value:{kind:"console", values:parse(jsonText(values))}});
                }
            },

        });
    }

    let selectedTid, selectedFrame = 0;
    const sourcePaths = new Map();
    const storedSourcePaths = () => [...sourcePaths].map(([from,to]) => ({from,to}));
    function makeFormat(id, generation) {
        const write = (kind,text) => {
            if (generation !== targetGeneration()) throw new Error("debugger target changed");
            rpc("log", {id, value:{kind,text:boundedText(text)}});
        };
        const print = (...items) => {
            const parts = [];
            let size = 0;
            for (const item of items) {
                if (size >= 14 * 1024) {
                    parts.push("\n* Output truncated for display.");
                    break;
                }
                const text = display(item);
                parts.push(text);
                size += text.length + 1;
            }
            write("fmt",parts.join(" "));
        };
        const resolveAddress = at => typeof at === "bigint" ? at : /^\d+$/.test(at) ? BigInt(at) :
            BigInt(rpc("address", {at:checkedAddress(at)}));
        const currentTid = () => callbackTid ?? selectedTid ?? dbg.pid;
        const trace = tid => rpc("backtrace", {tid, limit:25}).map(frame);
        const frames = rows => rows.slice(0, 24).flatMap((row, i) => {
            const source = row.file ? " at " + row.file.split("/").pop() + ":" + row.line : "";
            const args = Object.entries(parametersOf(row)).map(([name, item]) => name + "=" + shownVariable(item)).join(", ");
            const inline = (row.inlineFrames ?? []).slice(0,8).map(item =>
                "    [inline] " + item.symbol + (item.callFile ? " at " + item.callFile.split("/").pop() + ":" + item.callLine : ""));
            return [...inline, "#" + i + " " + (row.symbol ?? word(row.pc)) + "(" + args + ")" + source];
        }).concat(rows.length > 24 ? ["… more frames (capture limit)"] : []);
        const shownVariable = item => item.value == null ? ({
            optimized_out:"<optimized out>", read_failed:"<unreadable>", missing_page:"<unreadable>",
        }[item.availability] ?? "<not available>") : display(item.value);
        const variables = (label, values) => Object.entries(values ?? {}).map(([name, item]) =>
            "  " + name + (item.type ? ": " + item.type : "") + " = " + shownVariable(item)
        ).reduce((lines, line) => (lines.push(line), lines), [label]);
        const parametersOf = row => ({...row.unavailableParameters, ...row.parameters});
        const localsOf = row => ({...row.unavailableLocals, ...row.locals});
        const currentFrame = () => {
            const row = trace(currentTid())[selectedFrame];
            if (!row) throw new RangeError("frame is unavailable");
            return row;
        };
        const snapshotText = options => {
            const request = typeof options === "object" ? {...options} : {tid:options};
            request.frameLimit = 25;
            request.presentation = true;
            const raw = rpc("snapshot", request);
            const row = snapshot(raw);
            const lines = [row.incomplete?.length ? "Snapshot: partial" : "Snapshot",
                "Captured threads: " + row.threads.length + "/" + (row.threadCount ?? row.threads.length)];
            let size = 0, shown = 0;
            for (const thread of row.threads) {
                const group = ["Thread " + thread.tid, ...frames(thread.frames)];
                size += group.reduce((total,line) => total + line.length + 1,0);
                if (shown > 0 && size > 9 * 1024) break;
                lines.push(...group);
                shown++;
            }
            const remaining = row.threads.length - shown + (raw.threadsOmitted ?? 0);
            if (remaining > 0) lines.push("* Output truncated: " + remaining + " more threads.");
            for (const item of row.incomplete ?? []) {
                lines.push((item.tid ? "Thread " + item.tid + ": " : "") + item.stage + ": " + item.error);
            }
            print(lines.join("\n"));
        };
        const location = (address, row = dbg.symbolAt(address)) => {
            return word(address) + symbolLabel(row);
        };
        const fmt = {
            print,
            printf(format,...args) { write("fmt",sprintf(format,...args)); },
            sprintf, hexdump, bytesFromHex,
            pVar:print,
            pType(...items) { print(...items.map(item => (item?.$type ?? item).layout())); },
            status() { print(rpc("sessionStatus")); },
            snapshot:snapshotText,
            backtrace(tid = currentTid()) { print(["Thread " + tid,...frames(trace(tid))].join("\n")); },
            backtraceAll:snapshotText,
            locals() { print(variables("Locals:",localsOf(currentFrame())).join("\n")); },
            args() { print(variables("Arguments:",parametersOf(currentFrame())).join("\n")); },
            frame() {
                const row = currentFrame();
                print(["Frame " + frames([row]).at(-1).replace(/^#0 /,"#" + selectedFrame + " "),
                    ...variables("Arguments:",parametersOf(row)), ...variables("Locals:",localsOf(row))].join("\n"));
            },
            registers() {
                const raw = registers(rpc("registers", {tid:currentTid()}));
                const maps = dbg.mappings();
                print(Object.entries(raw).map(([name, value]) => {
                    if (typeof value !== "bigint") return name + "  " + display(value);
                    const map = maps.find(row => row.start <= value && value < row.end);
                    return name.padEnd(5) + (map ? location(value) + (map.name?.startsWith("[") ? " " + map.name : "") :
                        word(value) + (value > 0n && value < 65536n ? " (" + value + ")" : ""));
                }).join("\n"));
            },
            address(at) {
                const address = resolveAddress(at);
                const map = dbg.mappings().find(row => row.start <= address && address < row.end);
                const line = dbg.addrToLine(address);
                const row = dbg.symbolAt(address);
                const typed = row?.kind === "data" && row.match !== "nearest"
                    ? rpc("dataAt",{address:word(address)}) : null;
                const data = typed ? describeDataAddress(row,typed) : [];
                print(["Address: " + location(address,row),
                    ...(row?.match === "nearest" ? ["Nearest preceding symbol: " + row.name + "+" + word(row.offset)] : []),
                    ...(row?.section ? ["Section: " + row.section] : []),
                    ...(map ? ["Mapping: " + word(map.start) + "-" + word(map.end) + " " + map.prot + " " + (map.name || "anonymous")] : []),
                    ...(line ? ["Source: " + line.file + ":" + line.line] : []), ...data].join("\n"));
            },
            memory(at, length) {
                const address = resolveAddress(at);
                const count = Math.min(integer(length, "invalid memory length"), 512);
                print([location(address), hexdump(readBytes(address,count), {showAscii:true}),
                    ...(length > count ? ["… " + (length - count) + " more bytes"] : [])].join("\n"));
            },
            disassemble(at, {count = 16} = {}) {
                const instructions = dbg.disassemble(at, count);
                const start = instructions[0]?.address;
                const row = start === undefined ? null : dbg.symbolAt(start);
                const heading = row?.match === "module" ? [location(start,row)] : [];
                print(heading.concat(instructions.map(row => word(row.address) + "  " + row.mnemonic + " " + row.opStr +
                    (row.references?.length ? "  ; " + row.references.map(ref => ref.requested ?
                        ref.kind + " " + location(ref.address) + " requested: " + ref.requested +
                            (ref.resolved ? ", resolved: " + ref.resolved : "") :
                        ref.kind + " " + location(ref.address)).join(", ") : ""))).join("\n"));
            },
            modules() {
                const paths = new Map();
                for (const map of dbg.mappings()) {
                    if (map.name?.startsWith("/") && !paths.has(map.name)) paths.set(map.name,map.start);
                }
                print([...paths].map(([path,address]) => word(address) + "  " + path).join("\n"));
            },
            async symbols({pattern = /.*/, limit = 32, functionsOnly = false} = {}) {
                integer(limit, "invalid symbol limit");
                if (limit > 128) throw new RangeError("symbol limit exceeds 128");
                const rows = [];
                for await (const row of dbg.iterSymbols(pattern)) {
                    if (functionsOnly && row.kind !== "text") continue;
                    if (rows.length === limit) { rows.push("… more symbols"); break; }
                    rows.push(word(row.address) + "  " + (row.demangledName ?? row.name));
                }
                print(rows.join("\n"));
            },
            diff(before, after) { print(diffData(before,after).join("\n") || "No changes"); },
            async gdb(command) {
                const tokens = command.trim().split(/\s+/);
                const [verb, sub, ...rest] = tokens;
                const noArgs = sub === undefined;
                if (verb === "bt" && noArgs) return fmt.backtrace();
                if (command.trim() === "thread apply all bt") return fmt.backtraceAll();
                if (verb === "thread" && /^\d+$/.test(sub) && !rest.length) {
                    const tid = Number(sub);
                    if (!rpc("threads").includes(tid)) throw new RangeError("thread is unavailable");
                    selectedTid = tid;
                    selectedFrame = 0;
                    return fmt.frame();
                }
                if ((verb === "frame" && (noArgs || /^\d+$/.test(sub)) && !rest.length) ||
                    (["up","down"].includes(verb) && noArgs)) {
                    const index = verb === "frame" ? (noArgs ? selectedFrame : Number(sub)) :
                        selectedFrame + (verb === "up" ? 1 : -1);
                    if (!trace(currentTid())[index]) throw new RangeError("frame is unavailable");
                    selectedFrame = index;
                    return fmt.frame();
                }
                if (verb === "info") {
                    if (!rest.length && ["locals","args","registers"].includes(sub)) return fmt[sub]();
                    if (!rest.length && sub === "breakpoints") return fmt.status();
                    if (!rest.length && sub === "threads") {
                        return print(rpc("threads").map(tid => (tid === currentTid() ? "* " : "  ") + tid).join("\n"));
                    }
                    if (sub === "symbol" && rest.length === 1) {
                        const row = dbg.symbolAt(resolveAddress(rest[0]));
                        return print(row?.match === "nearest" ? "Nearest preceding symbol: " + row.name + "+" + word(row.offset) :
                            row ? location(row.match === "module" ? row.address : row.address + row.offset,row) : "No matching symbol");
                    }
                    if (sub === "address" && rest.length === 1) return fmt.address(rest[0]);
                    if (sub === "functions" && rest.length <= 1) {
                        const pattern = rest[0] === undefined ? /.*/ : new RegExp(rest[0]);
                        return fmt.symbols({pattern,functionsOnly:true});
                    }
                }
                if (["p","ptype"].includes(verb) && /^[a-zA-Z_$][\w$]*$/.test(sub) && !rest.length) {
                    const row = currentFrame();
                    const item = localsOf(row)[sub] ?? parametersOf(row)[sub];
                    if (!item) throw new Error("Unsupported expression or variable is unavailable: " + sub);
                    return print(verb === "ptype" ? item.type ?? "<not available>" : shownVariable(item));
                }
                if (verb === "disassemble" && sub && !rest.length) return fmt.disassemble(sub);
                if (verb === "b" && sub && !rest.length) return print("Breakpoint #" + dbg.softwareBreakpoint(sub).id);
                if (["delete","disable","enable"].includes(verb) && /^\d+$/.test(sub) && !rest.length) {
                    const point = points.get(Number(sub))?.point;
                    if (!point) throw new RangeError("breakpoint is unavailable");
                    return verb === "delete" ? point.remove() : point[verb]();
                }
                if (verb === "c" && noArgs) {
                    const row = await dbg.continueForStop("all", {pausedOnly:true});
                    return print(stopSummary(row));
                }
                if (["si","ni","finish"].includes(verb) && noArgs && selectedFrame === 0) {
                    const tid = currentTid();
                    if (verb === "finish") {
                        const caller = trace(tid)[1];
                        if (!caller?.pc || !caller.sp) throw new Error("caller frame is unavailable");
                        rpc("step",{tid,mode:"untilFrame",at:word(caller.pc),sp:word(caller.sp)});
                    } else {
                        rpc("step",{tid,mode:verb === "si" ? "step" : "next"});
                    }
                    return fmt.backtrace(tid);
                }
                if (verb === "x" && sub && !rest.length) {
                    const address = resolveAddress(sub);
                    return print(location(address) + ": " + word(BigInt(view(readBytes(address,4)).getUint32(0,true))));
                }
                if (verb === "x/16xb" && sub && !rest.length) return fmt.memory(sub,16);
                if (verb === "list" && noArgs) {
                    const row = dbg.list(currentFrame());
                    if (!row) return print("Source unavailable");
                    return print([row.file, ...row.lines.map(line => line.line + "  " + line.text)].join("\n"));
                }
                if (verb === "set" && sub === "substitute-path" && rest.length === 2) {
                    return dbg.substitutePath(rest[0],rest[1]);
                }
                throw new Error("Unsupported GDB command or arguments: " + command);
            },
        };
        return Object.freeze(fmt);
    }

    function describeDataAddress(symbol, typed) {
        const type = dwarfType(typed);
        const lines = typed.type ? ["Type: " + typed.type] : [];
        let value = type.at(symbol.address);
        if (symbol.offset === 0n) return value ? [...lines,"Value: " + value.$format()] : lines;
        let offset = Number(symbol.offset);
        if (!Number.isSafeInteger(offset)) return lines;
        const path = [];
        for (let depth = 0; depth < 8; depth++) {
            const info = typeInfo(value.$type);
            if (info.kind !== "struct") break;
            const matches = Object.entries(info.fields).filter(([, index]) => {
                const start = info.members[index + memberOffset];
                const member = typeInfo(resolve(info.members[index + memberType],value.$type));
                return member.kind !== "bitfield" && member.size !== undefined
                    && start <= offset && offset - start < member.size;
            });
            if (matches.length !== 1) break;
            const [name,index] = matches[0];
            offset -= info.members[index + memberOffset];
            value = value[name];
            path.push(name);
            if (offset === 0) return [...lines,"Member: " + path.join("."),"Value: " + value.$format()];
        }
        return lines;
    }

    function stopSummary(row) {
        const kind = row.kind === "signal" ? row.signalName ?? "signal" : row.kind;
        return ["Stopped: " + kind + (row.breakpointId === undefined ? "" : " #" + row.breakpointId),
            ...(row.tid === undefined ? [] : ["Thread: " + row.tid]),
            ...(row.faultAddress == null ? [] : ["Fault address: " + row.faultAddress]),
            ...(row.address == null ? [] : ["Address: " + row.address])].join("\n");
    }

    function display(value) {
        const active = new WeakSet();
        const format = (item,depth) => {
            if (valueStore(item)) return item.$format();
            if (typeof item === "string") {
                return depth === 0 ? item : JSON.stringify(item.slice(0,256)) + (item.length > 256 ? " …" : "");
            }
            if (item === undefined) return "<not available>";
            if (typeof item === "bigint") return item.toString() + "n";
            if (item === null || typeof item !== "object") return String(item);
            if (active.has(item)) return "<cycle>";
            if (depth >= 4) return "…";
            active.add(item);
            const indexed = Array.isArray(item) || ArrayBuffer.isView(item) && Number.isSafeInteger(item.length);
            const keys = indexed ? undefined : Object.keys(item);
            const length = keys?.length ?? item.length;
            const rows = [];
            for (let i = 0; i < Math.min(32,length); i++) {
                rows.push(indexed ? format(item[i],depth+1) : keys[i] + ": " + format(item[keys[i]],depth+1));
            }
            if (length > 32) rows.push("… " + (length - 32) + " more " + (indexed ? "items" : "fields"));
            active.delete(item);
            return (indexed ? "[" : "{") + rows.join(", ") + (indexed ? "]" : "}");
        };
        return format(value,0);
    }

    function diffData(before, after) {
        const visited = new WeakMap(), lines = [];
        let budget = 10000;
        const walk = (left, right, path, depth) => {
            --budget;
            if (Object.is(left,right)) return;
            if (depth < 32 && left && right && typeof left === "object" && typeof right === "object" &&
                Array.isArray(left) === Array.isArray(right)) {
                let matches = visited.get(left);
                if (!matches) visited.set(left, matches = new WeakSet());
                if (matches.has(right)) return;
                matches.add(right);
                for (const key of new Set([...Object.keys(left), ...Object.keys(right)])) {
                    if (budget <= 0 || lines.length >= 128) break;
                    const child = /^\d+$/.test(key) && Array.isArray(left) ? path + "[" + key + "]" :
                        (path ? path + "." : "") + key;
                    walk(Object.hasOwn(left,key) ? left[key] : missing,
                        Object.hasOwn(right,key) ? right[key] : missing,child,depth+1);
                }
                if (Array.isArray(left) && left.length !== right.length) {
                    walk(left.length,right.length,path + ".length",depth+1);
                }
                return;
            }
            const render = value => value === missing ? "<absent>" :
                typeof value === "string" ? JSON.stringify(value.slice(0,256)) + (value.length > 256 ? " …" : "") : display(value);
            lines.push((path || "<root>") + ": " + render(left) + " -> " + render(right));
        };
        const missing = Symbol();
        walk(before,after,"",0);
        if (budget <= 0 || lines.length >= 128) lines.push("… diff limit reached");
        return lines;
    }

    function readBytes(address, length) {
        return Uint8Array.from(presentationRead("read", address, integer(length, "invalid read length")));
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
            unavailableLocals:variables(raw.unavailableLocals), unavailableParameters:variables(raw.unavailableParameters),
            inlineFrames:raw.inlineFrames == null ? undefined : Object.freeze(raw.inlineFrames.map(Object.freeze)),
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
        const id = rpc("eventWait", {...args, scriptStack: new Error().stack});
        if (callback?.active) callback.active = false;
        return new Promise((resolve, reject) => eventWaiters.set(id, {resolve, reject}));
    }

    function ask(payload, timeoutMs, tid) {
        if (payload == null || typeof payload !== "object") throw new TypeError("ask requires a JSON object or array");
        if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 86400000)) {
            throw new RangeError("invalid timeoutMs");
        }
        const handler = rpc("ask", {payload:parse(jsonText(payload)), timeoutMs, tid, scriptStack: new Error().stack});
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
            const event = await waitEvent({kind:"stop", tid:scope(tid), resume:true, pausedOnly:options.pausedOnly,
                timeoutMs:Math.max(0,deadline-rpc("clock"))}, callbackContext);
            if (["exit","ended","timeout"].includes(event.kind)) return event;
            if (predicate === undefined) return event;
            if (event.kind === "signal" && event.paused) return event;
            if (event.paused && predicate?.(event) === true) return event;
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
        const {condition, ...targetOptions} = options ?? {};
        if (condition !== undefined && typeof condition !== "function") throw new TypeError("expected breakpoint condition");
        const generation = targetGeneration();
        const id = ++nextPoint;
        const pending = type === "pending";
        const address = pending
            ? rpc("addPendingPoint", {id, name:at, ...targetOptions})
            : BigInt(rpc("addPoint", {id, kind:type, at:checkedAddress(at), ...targetOptions}));
        const change = (remove,enable = false) => {
            if (generation !== targetGeneration()) throw new Error("breakpoint no longer exists");
            rpc("point", {id, remove, enable});
            if (remove) points.delete(id);
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
                return Object.freeze(targetOptions.tid === undefined ? rpc("threads") : [targetOptions.tid]);
            },
            get callback() { return callback; },
            set callback(value) {
                if (typeof value !== "function") throw new TypeError("expected breakpoint callback");
                callback = value;
            },
            disable() { change(false); },
            enable() { change(false,true); },
            remove() { change(true); },
        });
        points.set(id, {point, condition, count:0});
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
        async backtraceAll() {
            const {threads, incomplete} = await dbg.snapshot();
            return Object.freeze({threads, incomplete});
        },
        async traceHits(at, {tid, timeoutMs, limit = 1024} = {}) {
            if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1024) {
                throw new RangeError("trace hit limit must be in 1..=1024");
            }
            const generation = targetGeneration();
            const hits = [];
            const point = dbg.softwareBreakpoint(at, hit => {
                hits.push(Object.freeze({tid:hit.thread.tid, hitCount:hit.hitCount}));
                if (hits.length >= limit) hit.pause();
                else hit.continue();
            }, tid);
            let stop;
            try {
                stop = await continueForStop("all", {timeoutMs, pausedOnly:true});
                return Object.freeze({stop, hits:Object.freeze(hits), limitReached:hits.length >= limit});
            } finally {
                if (generation === targetGeneration()) {
                    if (stop?.kind === "exit" || stop?.kind === "ended") points.delete(point.id);
                    else point.remove();
                }
            }
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
        async detach() { rpc("detach", {scriptStack: new Error().stack}); },
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
        async kill(signal) { rpc("kill", {signal, scriptStack: new Error().stack}); },
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
        symbolAt(address) {
            const row = rpc("symbolAt", {address:word(address)});
            return row == null ? null : Object.freeze({...row,address:BigInt(row.address),offset:row.offset == null ? undefined : BigInt(row.offset)});
        },
        substitutePath(from,to) {
            if (typeof from !== "string" || typeof to !== "string" || !from || !to) {
                throw new TypeError("expected source path prefixes");
            }
            sourcePaths.set(from,to);
        },
        addrToLine(address) { return rpc("addrToLine",{address:word(address)}); },
        stringify(value) { return jsonText(value); },
        list(at, radius = 5, sourcePaths = []) {
            return rpc("listSource", {address:word(typeof at === "bigint" ? at : at.lookupPc),
                radius:integer(radius,"invalid source context"), sourcePaths:[...sourcePaths, ...storedSourcePaths()]});
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
        hardwareBreakpoint(at, callback, options) {
            return install("hardware_breakpoint", at, callback, typeof options === "number" ? {tid: options} : options);
        },
        pendingBreakpoint(name, callback, options) { return install("pending",name,callback,options); },
        softwareBreakpoint(at, callback, options) {
            return install("software_breakpoint", at, callback, typeof options === "number" ? {tid: options} : options);
        },
        hardwareWatchpoint(at, callback, options) { return install("hardware_watchpoint",at,callback,options); },
        softwareWatchpoint(at, callback, options) { return install("software_watchpoint",at,callback,options); },
        assemble(at, src) { return bytesFromHex(rpc("assemble", {at:checkedAddress(at), src}).bytes); },
        disassemble(at, count) {
            return rpc("disassemble", {at:checkedAddress(at), count}).map(row => ({...row,address:BigInt(row.address), bytes:typeof row.bytes === "string" ? bytesFromHex(row.bytes) : Uint8Array.from(row.bytes), references:(row.references ?? []).map(ref => ({...ref,address:BigInt(ref.address),
                resolvedAddress:ref.resolvedAddress == null ? undefined : BigInt(ref.resolvedAddress),
                slot:ref.slot == null ? undefined : BigInt(ref.slot)}))}));
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
        let skippedPoint = false, matchedPoint = false;
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
                        Object.freeze(hit);
                        if (installed.condition && installed.condition(hit) !== true) {
                            skippedPoint = true;
                        } else {
                            matchedPoint = true;
                            const callback = installed.point.callback;
                            if (callback == null) context.pause = true;
                            else result = callback(hit);
                        }
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
                if (skippedPoint && !matchedPoint && !context.signal) context.pause ??= false;
                rpc("callbackDone", {generation,tid,token,pause:context.pause,pass:context.pass,counts:context.counts});
            }
        }
    }

    // Type descriptors carry layout. Every value has its own storage and thread binding.
    const types = new WeakMap(), values = new WeakMap();
    let prettyPrinters = new WeakMap();
    const activePrinters = new WeakSet();
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

    const typeMethods = {
        at(type,address,tid) {
            word(address);
            return makeValue(type, {[valueKeys.address]:address, [valueKeys.tid]:tid, [valueKeys.root]:targetGeneration()});
        },
        $readBytes(type,address) {
            word(address);
            return readBytes(address, staticStorageSize(type));
        },
        $writeBytes(type,address,bytes) {
            word(address);
            if (!(bytes instanceof Uint8Array)) throw new TypeError("expected Uint8Array");
            if (bytes.length !== staticStorageSize(type)) throw new RangeError("byte length differs from C storage size");
            if (bytes.length) writeBytes(address, bytes);
        },
        offsetOf: fieldOffset,
        layout: describeType,
        align(type,value) {
            const info = typeInfo(type);
            const explicitAlign = alignment(value);
            const align = Math.max(info.align, explicitAlign);
            const size = info.fields ? rounded(info.size, align) : info.size;
            return descriptor({...info, align, size, explicitAlign:align});
        },
        be: type => descriptor({...typeInfo(type), littleEndian:false}),
        le: type => descriptor({...typeInfo(type), littleEndian:true}),
        bitfield(type,width) {
            const info = typeInfo(type);
            width = integer(width, "invalid bitfield width");
            if (width > info.size * 8 || info.littleEndian === false || info.explicitAlign || info.enumerators) {
                throw new TypeError("unsupported bitfield type or width");
            }
            return descriptor({...info, kind:"bitfield", bit:[0,width]});
        },
        enum(type,values) {
            const info = typeInfo(type);
            const enumerators = Object.assign(Object.create(null), values);
            for (const [name, value] of Object.entries(enumerators)) {
                if (!/^[a-zA-Z_]\w*$/.test(name)) throw new TypeError("invalid enum name " + name);
                scalarBytes(info.scalar, value);
            }
            return descriptor({...info, enumerators:Object.freeze(enumerators)});
        },
        value(type,value) {
            return makeValue(type, {[valueKeys.bytes]:encodeValue(typeInfo(type), value)});
        },
        pointee(type) {
            const {element} = typeInfo(type);
            return typeInfo(element).kind === "self" ? element : resolve(element);
        },
        nullTerminate(type,limit = 4096) {
            const info = typeInfo(type);
            limit = integer(limit, "invalid termination limit");
            const element = typeInfo(resolve(info.element));
            if (!limit || info.length !== undefined || !["scalar", "ptr"].includes(element.kind)
                || element.scalar.startsWith("f") || element.size % element.align) {
                throw new TypeError("unsupported terminated pointer type or length");
            }
            return descriptor({...info, terminated:limit});
        },
        element: type => typeInfo(type).element,
        field(type,name) {
            const {fields,members} = typeInfo(type);
            if (!Object.hasOwn(fields,name)) throw new Error("unknown C field " + name);
            return members[fields[name] + memberType];
        },
        refine,
        withFormatter(type,formatter) {
            if (typeof formatter !== "function") throw new TypeError("expected a formatter function");
            return descriptor({...typeInfo(type),formatter});
        },
        pack(type,value) {
            const info = typeInfo(type);
            if (!info.entries) throw new TypeError("cannot repack a resolved or refined layout");
            const entries = info.entries === repackFromMembers
                ? Object.fromEntries(Object.keys(info.fields).map(name => [name, info.members[info.fields[name] + memberType]]))
                : info.entries;
            return aggregate(info.kind, entries, {pack:value,align:info.explicitAlign});
        },
    };

    const boundTypeMethods = new WeakMap();
    const typeProperties = {
        $size: {enumerable:true, get() {
            const info = typeInfo(this);
            return info.kind === "lazy" ? typeInfo(resolve(this)).size : info.size;
        }},
        $align: {enumerable:true, get() {
            const info = typeInfo(this);
            return info.kind === "lazy" ? typeInfo(resolve(this)).align : info.align;
        }},
    };
    for (const [name,method] of Object.entries(typeMethods)) {
        typeProperties[name] = {enumerable:true, get() {
            let methods = boundTypeMethods.get(this);
            if (!methods) boundTypeMethods.set(this,methods = Object.create(null));
            return methods[name] ??= method.bind(undefined,this);
        }};
    }

    function descriptor(info) {
        const properties = {
            $size:typeProperties.$size, $align:typeProperties.$align, at:typeProperties.at,
            $readBytes:typeProperties.$readBytes, $writeBytes:typeProperties.$writeBytes,
            offsetOf:typeProperties.offsetOf, layout:typeProperties.layout, withFormatter:typeProperties.withFormatter,
        };
        if (info.align && info.kind !== "bitfield") properties.align = typeProperties.align;
        if (info.kind === "scalar" && info.size > 1) {
            properties.be = typeProperties.be;
            properties.le = typeProperties.le;
        }
        if (info.kind === "scalar" && /^[ui]/.test(info.scalar)) {
            properties.bitfield = typeProperties.bitfield;
            properties.enum = typeProperties.enum;
        }
        if (info.kind === "scalar" || info.kind === "ptr") properties.value = typeProperties.value;
        if (info.kind === "ptr") {
            properties.pointee = typeProperties.pointee;
            properties.nullTerminate = typeProperties.nullTerminate;
        }
        if (info.kind === "array") properties.element = typeProperties.element;
        if (info.fields) {
            properties.field = typeProperties.field;
            properties.refine = typeProperties.refine;
            properties.pack = typeProperties.pack;
        }
        const type = Object.defineProperties({},properties);
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
                const {members} = info;
                const lines = [align + info.kind + " {"];
                let occupied = 0;
                for (let i = 0; i < members.length; i += memberStride) {
                    const name = members[i];
                    if (name === lookupOnlyMember) continue;
                    const type = members[i + memberType], offset = members[i + memberOffset];
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
            if (element.char) {
                const end = chunk.indexOf(0);
                if (end !== -1) {
                    collected.push(...chunk.slice(0,end));
                    return Uint8Array.from(collected);
                }
                collected.push(...chunk);
                if (chunk.length < length) throw new Error("terminated sequence crosses unavailable memory");
                offset += length;
                continue;
            }
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
                const field = member && info.fields ? info.fields[member] : undefined;
                const fieldOffset = field === undefined ? undefined : info.members[field + memberOffset];
                if (!Number.isSafeInteger(fieldOffset)) throw new TypeError("unknown or dynamic C member");
                type = info.members[field + memberType];
                offset += fieldOffset;
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

    // Each member occupies [display name, type, byte offset]. The lookup table
    // stores indices into this array, including promoted and refined members.
    const memberType = 1, memberOffset = 2, memberStride = 3;
    const lookupOnlyMember = Symbol();
    const repackFromMembers = Symbol();

    function addMember(fields, members, name, type, offset, displayName = name, duplicatePrefix = "duplicate C field name ") {
        if (name != null) {
            if (Object.hasOwn(fields,name)) throw new TypeError(duplicatePrefix + name);
            fields[name] = members.length;
        }
        members.push(displayName,type,offset);
    }

    function promoteMembers(fields, members, overlaps, info, offset, duplicatePrefix) {
        for (const name of Object.keys(info.fields)) {
            const index = info.fields[name];
            if (info.kind === "union" || info.overlaps?.has(name)) overlaps.add(name);
            addMember(fields,members,name,info.members[index + memberType],
                offset + info.members[index + memberOffset],lookupOnlyMember,duplicatePrefix);
        }
    }

    function aggregate(kind, fields, option = {}) {
        const pack = option.pack === undefined || option.pack === 0 ? Infinity : alignment(option.pack);
        if (pack !== Infinity && pack > 16) throw new RangeError("GCC packing must be 0, 1, 2, 4, 8 or 16");
        const entries = Reflect.ownKeys(fields).filter(key => Object.prototype.propertyIsEnumerable.call(fields,key));
        const layout = Object.create(null);
        const members = [];
        const overlaps = new Set();
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
                    addMember(layout,members,undefined,member,kind === "struct" ? occupiedBits / 8 : 0);
                    continue;
                }
                const align = Math.min(info.align,pack);
                const contributesAlignment = !anonymous || arch === "aarch64";
                if (contributesAlignment) natural = Math.max(natural,align);
                let start = kind === "union" ? 0 : occupiedBits;
                if (pack >= info.align && start % unit + width > unit) start = rounded(start,unit);
                const offset = Math.floor(start / 8);
                const placed = descriptor({...info,bit:[start % 8,width]});
                addMember(layout,members,anonymous ? undefined : name,placed,offset);
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
                promoteMembers(layout,members,overlaps,info,offset);
            }
            addMember(layout,members,anonymous ? undefined : name,member,offset);
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
        const size = rounded(Math.ceil(occupiedBits / 8),align);
        const packOption = option.pack;
        const originalEntries = entries.map(key => [key,fields[key]]);
        // Bitfields, anonymous entries and changing getters can require the original input.
        const packEntries = originalEntries.every(([name,type]) =>
            Object.hasOwn(layout,name) && members[layout[name] + memberType] === type)
            ? repackFromMembers : Object.fromEntries(originalEntries);
        return descriptor({kind, fields:layout, tail, size, align, explicitAlign,
            pack:packOption, members, overlaps, entries:packEntries});
    }

    function refine(type, fields) {
        const info = typeInfo(type);
        const layout = Object.assign(Object.create(null),info.fields);
        const members = info.members.slice();
        for (const [name,type] of Object.entries(fields)) {
            const original = layout[name];
            if (original === undefined) throw new TypeError("unknown C field " + name);
            const before = typeInfo(resolve(members[original + memberType])), after = typeInfo(resolve(type));
            if (before.kind !== after.kind || before.size !== after.size || before.align !== after.align) {
                throw new TypeError("refined field changes its C layout");
            }
            layout[name] = members.length;
            members.push(lookupOnlyMember,type,members[original + memberOffset]);
        }
        return descriptor({...info,fields:layout,members,entries:undefined});
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
            const graph = rpc("typeOfVar", {name, tid:callbackTid ?? selectedTid,
                frame:callbackTid === undefined ? selectedFrame : 0});
            return graph == null ? undefined : dwarfType({graph});
        },
        fromDwarf(name) {
            return dwarfType({graph:rpc("fromDwarf", {name})});
        },
        setPrettyPrinter(type, printer) {
            typeInfo(type);
            if (printer === null) prettyPrinters.delete(type);
            else {
                if (typeof printer !== "function") throw new TypeError("expected a pretty-printer");
                prettyPrinters.set(type, printer);
            }
        },
        findTypes(query, {exact = false, module:modulePath} = {}) {
            if (typeof query !== "string" || !query) throw new TypeError("expected a DWARF type query");
            const pattern = exact || /[*?\[]/.test(query) ? query : "*" + query + "*";
            const rows = [];
            for (const {name,module,size} of dwarfRows(pattern, exact, true)) {
                if (modulePath === undefined || module === modulePath || module.endsWith("/" + modulePath)) {
                    rows.push({name,module,size});
                }
            }
            return rows;
        },
    };
    const voidType = descriptor({kind:"void"});
    const selfType = descriptor({kind:"self"});
    for (const kind of Object.keys(scalarSpec)) if (kind !== "ptr") m[kind] = () => scalar(kind);
    Object.freeze(m);

    function bound(store) {
        const root = store[valueKeys.root];
        if (root !== undefined && root !== targetGeneration()) {
            const error = new Error("value belongs to a previous target");
            hostErrors.add(error);
            throw error;
        }
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
            return tail === undefined ? info.size : Math.max(info.size, info.members[info.fields[info.tail] + memberOffset] + tail);
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

    function valueOffset(base, offset) {
        if (activeFormat && base + BigInt(offset) > maxAddress) {
            throw new UnreadableValue(base, "address range overflow");
        }
        return addr(base,offset);
    }

    function valueField(store, name) {
        const info = store[valueKeys.info];
        bound(store);
        const field = info.fields[name];
        const type = info.members[field + memberType], offset = info.members[field + memberOffset];
        return makeValue(type,{[valueKeys.address]:valueOffset(store[valueKeys.address],offset), [valueKeys.parent]:store[valueKeys.value],
            [valueKeys.inheritTid]:true, [valueKeys.self]:store[valueKeys.type], [valueKeys.root]:store[valueKeys.root]});
    }

    function valueAtIndex(store, index, checked) {
        const info = store[valueKeys.info];
        bound(store);
        index = integer(index,"array index must be a nonnegative safe integer");
        const count = checked ? dynamicLength(info,store) : undefined;
        if (count !== undefined && index >= count) throw new RangeError("index exceeds the length");
        const element = resolve(info.element,store[valueKeys.self]);
        if (checked && info.kind === "array" && count === undefined) throw new TypeError("use $atUnchecked for an unsized array");
        const base = info.kind === "ptr" ? readScalar(store) : store[valueKeys.address];
        if (info.kind === "ptr" && base === 0n) throw new RangeError("null pointer");
        return elementAt(store,element,base,index);
    }

    function elementAt(store, element, base, index) {
        const size = element.$size;
        if (size === undefined && index !== 0) throw new TypeError("element size is unknown");
        return makeValue(element,{[valueKeys.address]:valueOffset(base,BigInt(index) * BigInt(size ?? 0)), [valueKeys.parent]:store[valueKeys.value],
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

    function valueFormatOptions(options) {
        if (options !== undefined && (options === null || typeof options !== "object")) {
            throw new TypeError("expected Value format options");
        }
        const defaults = {indent:2, maxDepth:4, maxElements:32, maxFields:32, maxStringLength:256, maxNodes:200, deref:2};
        return Object.fromEntries(Object.entries(defaults).map(([key, fallback]) => {
            const n = integer(options?.[key] === undefined ? fallback : options[key], "invalid " + key);
            const max = ["maxElements", "maxFields", "maxStringLength", "maxNodes"].includes(key) ? 4096 : 32;
            if (n > max) throw new RangeError(key + " exceeds the format limit");
            return [key,n];
        }));
    }

    class UnreadableValue extends Error {
        constructor(address, reason) {
            super(reason);
            this.address = address;
        }
    }

    let activeFormat;
    function presentationRead(operation, address, length) {
        if (activeFormat && address + BigInt(length) > maxAddress) {
            throw new UnreadableValue(address, "address range overflow");
        }
        const result = rpc(operation, {address:word(address), length, format:activeFormat !== undefined});
        if (result?.unreadable !== undefined) throw new UnreadableValue(address,result.unreadable);
        return result;
    }

    function formatScalar(value, info) {
        const name = info.enumerators && Object.entries(info.enumerators).find(([, n]) => BigInt(n) === BigInt(value))?.[0];
        return name ?? (info.kind === "ptr" || info.kind === "fn" ? word(value) : String(value));
    }

    function formatValue(store, requestedOptions) {
        let checked;
        try { checked = valueFormatOptions(requestedOptions); }
        catch (error) {
            if (error instanceof Error) hostErrors.add(error);
            throw error;
        }
        if (activeFormat) return activeFormat.nested(store, checked, requestedOptions !== undefined);
        const path = [];
        let remaining = checked.maxNodes, exhausted = false;
        const unreadable = (error, pointer) => {
            if (!(error instanceof UnreadableValue)) throw error;
            return "<unreadable: " + error.message.slice(0,120) +
                (error.address === pointer ? "" : " @ " + word(error.address)) + ">";
        };
        const crop = (count, unit) => "… " + count + " more " + unit;
        const noBudget = () => {
            if (remaining > 0) return false;
            exhausted = true;
            return true;
        };
        const onPath = (type,self,base,length) => path.some(view =>
            view.type === type && view.self === self && view.base === base && view.length === length);
        const walk = (item, options, depth, hops, inUnion, child = false, sourcePointer = false) => {
            bound(item);
            if (noBudget()) return "<max nodes>";
            remaining--;
            const type = item[valueKeys.type], info = item[valueKeys.info], {kind} = info;
            const value = item[valueKeys.value], address = item[valueKeys.address];
            const self = info.fields ? undefined : item[valueKeys.self];
            const printer = info.formatter ?? prettyPrinters.get(type);
            if (printer && !activePrinters.has(type)) {
                const nested = activeFormat.nested;
                activeFormat.nested = (target, explicit, override) =>
                    walk(target, override ? explicit : options, depth + Number(target !== item), hops, inUnion, true);
                activePrinters.add(type);
                try {
                    const result = printer(value);
                    if (result !== undefined) {
                        if (typeof result !== "string") throw new TypeError("formatter must return a string");
                        return result;
                    }
                } catch (error) {
                    if (error instanceof UnreadableValue) return unreadable(error);
                    if (hostErrors.has(error)) throw error;
                    return "<formatter error: " + String(error?.message ?? error).slice(0,120) + ">";
                } finally {
                    activePrinters.delete(type);
                    activeFormat.nested = nested;
                }
            }
            if (kind === "scalar" || kind === "bitfield" || kind === "fn") {
                const scalar = kind === "scalar" ? readScalar(item) : kind === "bitfield" ? readBitfield(item) : valueAddress(item);
                return formatScalar(info.boolean ? Boolean(scalar) : scalar,info);
            }
            const base = kind === "ptr" ? readScalar(item) : address;
            const element = info.element === undefined ? undefined : resolve(info.element,item[valueKeys.self]);
            const scalar = element === undefined ? undefined : typeInfo(element);
            let annotate;
            if (kind === "ptr") {
                if (base === 0n) return "NULL";
                annotate = () => {
                    const row = rpc("symbolAt", {address:word(base)});
                    return word(base) + symbolLabel(row && {...row,offset:row.offset == null ? undefined : BigInt(row.offset)});
                };
                if (inUnion) return annotate();
                if (scalar?.char && info.length === undefined) {
                    if (depth >= options.maxDepth) return annotate() + " <max depth>";
                    const limit = info.terminated ?? 4096;
                    const count = Math.min(limit, options.maxStringLength + 1);
                    const data = presentationRead("readPrefix",base,count);
                    const end = data.indexOf(0);
                    const text = JSON.stringify(fromUtf8(data.slice(0,end < 0 ? options.maxStringLength : end)));
                    if (end >= 0) return text;
                    if (data.length < count) return text + " <unreadable @ " + word(addr(base,data.length)) + ">";
                    return text + (count > options.maxStringLength ? " … (truncated)" : " <unterminated string>");
                }
            }
            const length = kind === "opaque" ? info.size :
                (kind === "array" || kind === "ptr") ? dynamicLength(info,item) : undefined;
            if (kind === "ptr" && length === undefined && info.terminated === undefined) {
                const label = annotate();
                if (hops >= options.deref || !scalar?.size || scalar.kind === "fn") return label;
                if (onPath(type,self,address,length)) return label + " <cycle>";
                if (depth >= options.maxDepth) return label + " <max depth>";
                if (noBudget()) return label + " <max nodes>";
                path.push({type,self,base:address,length});
                try {
                    const target = valueStore(elementAt(item,element,base,0));
                    const result = walk(target,options,depth + Number(scalar.kind === "ptr"),hops+1,false,true,true);
                    return label + (result === "<cycle>" ? " " : " -> ") + result;
                } catch (error) {
                    return label + " " + unreadable(error,base);
                } finally {
                    path.pop();
                }
            }
            if (depth >= options.maxDepth) return (annotate ? annotate() + " " : "") + "<max depth>";
            if (kind === "array" && length === undefined) throw new TypeError("array length is unknown");
            if (onPath(type,self,base,length)) {
                return "<cycle>";
            }
            path.push({type,self,base,length});
            const descend = get => {
                try { return walk(valueStore(get()), options, depth+1, hops, inUnion || kind === "union", true); }
                catch (error) { return unreadable(error); }
            };
            try {
                if (info.fields) {
                    const names = Object.keys(info.fields);
                    const lines = [];
                    let firstError, successes = 0;
                    for (const name of names.slice(0,options.maxFields)) {
                        if (noBudget()) break;
                        const overlapping = info.overlaps?.has(name);
                        const label = name + ": " + (overlapping ? "<union member> " : "");
                        try {
                            lines.push(label + walk(valueStore(value[name]), options, depth+1, hops,
                                inUnion || kind === "union" || overlapping, true));
                            successes++;
                        } catch (error) {
                            lines.push(label + unreadable(error));
                            firstError ??= error;
                        }
                    }
                    if (firstError && !successes && sourcePointer) throw firstError;
                    if (lines.length < names.length) lines.push(crop(names.length-lines.length,"fields"));
                    const indent = " ".repeat(options.indent * (depth+1));
                    let heading = kind === "union" ? "union" + (info.name ? " " + info.name : "") : info.name ?? kind;
                    if (!child && address !== undefined && options.deref > 0) heading += " @" + word(address);
                    return heading + " {" + (lines.length ? "\n" + lines.map(line => indent + line).join("\n") +
                        "\n" + " ".repeat(options.indent * depth) : "") + "}";
                }
                const output = [];
                const max = Math.min(length ?? info.terminated ?? 0, options.maxElements);
                const count = Math.min(max,remaining);
                if (count < max) exhausted = true;
                if (length !== undefined && scalar?.kind === "scalar" && !scalar.formatter && !prettyPrinters.has(element)) {
                    try {
                        for (const n of scalarRange(scalar,base,count)) output.push(formatScalar(scalar.boolean ? Boolean(n) : n,scalar));
                        remaining -= count;
                    } catch (error) {
                        if (!(error instanceof UnreadableValue)) throw error;
                    }
                }
                let terminated = false;
                for (let i = output.length; i < count && !noBudget(); i++) {
                    if (kind === "opaque" || length === undefined) {
                        try {
                            const at = valueOffset(base,i * (scalar?.size ?? 1));
                            const bytes = readBytes(at,scalar?.size ?? 1);
                            if (length === undefined && bytes.every(byte => byte === 0)) {
                                terminated = true;
                                break;
                            }
                            if (kind === "opaque") {
                                remaining--;
                                output.push(String(bytes[0]));
                                continue;
                            }
                        } catch (error) {
                            remaining--;
                            output.push(unreadable(error));
                            if (length === undefined) { terminated = true; break; }
                            continue;
                        }
                    }
                    output.push(descend(() => elementAt(item,element,base,i)));
                }
                if (length !== undefined && output.length < length) output.push(crop(length-output.length,"elements"));
                if (length === undefined && !terminated) output.push("… <truncated sequence>");
                return "[" + output.join(", ") + "]";
            } finally {
                path.pop();
            }
        };
        activeFormat = {nested:walk};
        try {
            let text;
            try { text = walk(store,checked,0,0,false); }
            catch (error) { text = unreadable(error); }
            return text + (exhausted ? "\n* Formatting truncated: node budget exhausted." : "");
        } finally {
            activeFormat = undefined;
        }
    }

    // Decode a contiguous leaf range in one target read. Aggregate and dynamic
    // members use the existing typed views, including bitfields and length hooks.
    function scalarRange(element, base, count) {
        if (!count) return [];
        const spec = scalarSpec[element.scalar];
        const result = new Array(count);
        const perChunk = Math.floor(16384 / element.size);
        for (let i = 0; i < count; i += perChunk) {
            const length = Math.min(count - i, perChunk);
            const data = view(readBytes(valueOffset(base,i * element.size), length * element.size));
            for (let j = 0; j < length; j++) {
                result[i+j] = data["get" + spec[0]](j * element.size, element.littleEndian ?? true);
            }
        }
        return result;
    }

    function plainPointer(info, self) {
        return info.kind === "ptr" && info.length === undefined && info.terminated === undefined
            && !typeInfo(resolve(info.element,self)).char;
    }

    function recordPlan(type, depth = 0) {
        if (depth > 16) return undefined;
        const info = typeInfo(type);
        if (!info.fields || info.tail || !info.size) return undefined;
        const fields = [];
        for (const [name,index] of Object.entries(info.fields)) {
            const member = resolve(info.members[index + memberType],type);
            const offset = info.members[index + memberOffset];
            const descriptor = typeInfo(member);
            if (descriptor.kind === "scalar" || plainPointer(descriptor,type)) {
                fields.push({name,offset,descriptor});
            } else {
                const nested = recordPlan(member,depth+1);
                if (!nested) return undefined;
                fields.push({name,offset,nested});
            }
        }
        return {type,size:info.size,fields};
    }

    function presentValue(store, options) {
        bound(store);
        if (options !== undefined && (options === null || typeof options !== "object")) {
            throw new TypeError("expected Value conversion options");
        }
        const pointer = options?.pointer === undefined ? "bigint" : options.pointer;
        if (pointer !== "bigint" && pointer !== "string") throw new TypeError("invalid pointer conversion option");
        const seen = new Map();
        let budget = 1000000;
        const convert = (value, info) => {
            if (info.kind === "ptr") return value === 0n ? null : pointer === "string" ? word(value) : value;
            return info.boolean ? Boolean(value) : value;
        };
        const convertTerminated = (items, element) => {
            if (!Array.isArray(items)) return items;
            const info = typeInfo(element);
            if (info.kind !== "ptr") return items;
            return items.map(item => typeof item === "bigint" ? convert(item,info) :
                convertTerminated(item,resolve(info.element)));
        };
        const conversionViews = (type, self) => {
            let entries = seen.get(type);
            if (!entries) seen.set(type, entries = new Map());
            let views = entries.get(self);
            if (!views) entries.set(self, views = new Map());
            return views;
        };
        const record = (plan, data, offset, base) => {
            const views = conversionViews(plan.type,undefined);
            const key = String(addr(base,offset)) + ":undefined";
            if (views.has(key)) return views.get(key);
            const output = {};
            views.set(key,output);
            for (const {name,offset:field,descriptor,nested} of plan.fields) {
                if (--budget < 0) throw new RangeError("Value conversion resource limit reached");
                const at = offset + field;
                const value = nested ? record(nested,data,at,base) :
                    convert(data["get" + scalarSpec[descriptor.scalar][0]](at,descriptor.littleEndian ?? true),descriptor);
                Object.defineProperty(output,name,{value,enumerable:true, writable:true, configurable:true});
            }
            return output;
        };
        const walk = (item, depth) => {
            if (--budget < 0 || depth > 64) throw new RangeError("Value conversion resource limit reached");
            const type = item[valueKeys.type], info = item[valueKeys.info], kind = info.kind;
            const value = item[valueKeys.value];
            if (kind === "scalar" || kind === "bitfield" || kind === "fn") {
                const scalar = kind === "scalar" ? readScalar(item) : kind === "bitfield" ? readBitfield(item) : valueAddress(item);
                return info.boolean ? Boolean(scalar) : scalar;
            }
            const base = kind === "ptr" ? readScalar(item) : item[valueKeys.address];
            const element = info.element === undefined ? undefined : resolve(info.element,item[valueKeys.self]);
            const scalar = element === undefined ? undefined : typeInfo(element);
            if (kind === "ptr" && base === 0n) return null;
            if (kind === "ptr" && scalar?.char && info.length === undefined) {
                const limit = info.terminated ?? 4096;
                if (limit > budget) throw new RangeError("string conversion budget exceeded");
                return fromUtf8(terminatedBytes(base,scalar,limit));
            }
            const length = kind === "opaque" ? info.size :
                (kind === "array" || kind === "ptr") ? dynamicLength(info,item) : undefined;
            if (kind === "ptr" && length === undefined && info.terminated === undefined) return convert(base,info);
            if (kind === "array" && length === undefined) throw new TypeError("array length is unknown");
            const self = info.fields ? undefined : item[valueKeys.self];
            const views = conversionViews(type,self);
            const key = base === undefined ? value : String(base) + ":" + length;
            if (views.has(key)) return views.get(key);
            const plan = scalar?.fields ? recordPlan(element) : undefined;
            const ownPlan = info.fields ? recordPlan(type) : undefined;
            if (ownPlan && ownPlan.size <= 16384) {
                return record(ownPlan,view(readBytes(base,ownPlan.size)),0,base);
            }
            const output = info.fields ? {} : [];
            views.set(key,output);
            const child = value => walk(valueStore(value),depth+1);
            if (info.fields) {
                for (const name of Object.keys(info.fields)) {
                    Object.defineProperty(output,name,{value:child(value[name]),
                        enumerable:true, writable:true, configurable:true});
                }
            } else if (length === undefined) {
                if (info.terminated > budget) throw new RangeError("terminated sequence conversion budget exceeded");
                const items = value.$deref();
                budget -= items.length;
                const result = pointer === "string" ? convertTerminated(items,element) : items;
                views.set(key,result);
                return result;
            } else {
                if (length > budget) throw new RangeError("Value conversion element limit reached");
                if (kind === "opaque") {
                    for (let i = 0; i < length; i += 16384) {
                        output.push(...readBytes(addr(base,i),Math.min(16384,length-i)));
                    }
                    budget -= length;
                } else if (scalar && (scalar.kind === "scalar" || plainPointer(scalar,item[valueKeys.self]))) {
                    for (const n of scalarRange(scalar,base,length)) output.push(convert(n,scalar));
                    budget -= length;
                } else if (plan && plan.size <= 16384) {
                    const stride = Math.floor(16384 / plan.size);
                    for (let i = 0; i < length; i += stride) {
                        const count = Math.min(length-i,stride);
                        const baseAddress = addr(base,i * plan.size);
                        const data = view(readBytes(baseAddress,count * plan.size));
                        for (let j = 0; j < count; j++) output.push(record(plan,data,j * plan.size,baseAddress));
                    }
                    budget -= length;
                } else {
                    for (let i = 0; i < length; i++) output.push(child(value[i]));
                }
            }
            return output;
        };
        return walk(store,0);
    }

    function getValueProperty(store,key) {
        const info = store[valueKeys.info];
        const {kind} = info;
        switch (key) {
        case "$type": return store[valueKeys.type];
        case "$asType": return type => type.at(valueAddress(store),store[valueKeys.value].$tid);
        case "$toJS": return options => presentValue(store,options);
        case "$format": return options => formatValue(store,options);
        case Symbol.toPrimitive: return hint => {
            if (hint !== "string") throw new TypeError("Value requires an explicit numeric read");
            return formatValue(store);
        };
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
        toPrimitive:Symbol.toPrimitive,
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
        const type = valueStore(value)[valueKeys.type];
        const info = typeInfo(type);
        const printer = prettyPrinters.get(type);
        if (printer && !activePrinters.has(type)) {
            activePrinters.add(type);
            try {
                const formatted = printer(value);
                if (formatted !== undefined) {
                    if (typeof formatted !== "string") throw new TypeError("expected a pretty-printer string");
                    return formatted;
                }
            } finally {
                activePrinters.delete(type);
            }
        }
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

    function *dwarfRows(pattern, exact = false, typesOnly = false) {
        let offset = 0;
        do {
            const page = rpc("types", {pattern,exact,typesOnly,offset});
            for (const row of page.items) yield row;
            offset = page.next_offset;
        } while (offset != null);
    }

    const dwarfTypes = new Map();
    const dwarfTypeFinalizer = new FinalizationRegistry(([key,ref]) => {
        if (dwarfTypes.get(key) === ref) dwarfTypes.delete(key);
    });
    function dwarfType(row) {
        const {nodes,root,identity,module} = row.graph;
        const key = identity == null ? undefined : stringify([module,identity]);
        const cached = dwarfTypes.get(key)?.deref();
        if (cached !== undefined) return cached;
        const cache = new Map();
        function node(id) {
            if (cache.has(id)) return cache.get(id);
            const info = nodes[id];
            let type;
            switch (info.kind) {
            case "void": type = voidType; break;
            case "scalar":
                type = scalar(info.scalar);
                if (info.boolean || info.character) type = descriptor({...typeInfo(type), boolean:info.boolean, char:info.character});
                break;
            case "pointer": type = m.pointer(m.lazy(() => node(info.element))); break;
            case "array":
                type = node(info.element);
                for (const size of info.dimensions.length ? [...info.dimensions].reverse() : [undefined]) {
                    type = m.array(type,size);
                }
                break;
            case "aggregate": {
                const fields = Object.create(null);
                const members = [];
                const overlaps = new Set();
                const duplicatePrefix = "duplicate DWARF member ";
                for (const {name,offset,ty,bit} of info.fields) {
                    const member = node(ty);
                    const underlying = typeInfo(member);
                    const type = bit ? descriptor({kind:"bitfield",scalar:underlying.scalar,bit}) : member;
                    addMember(fields,members,name,type,offset,name,duplicatePrefix);
                    if (name == null && underlying.fields) {
                        promoteMembers(fields,members,overlaps,underlying,offset,duplicatePrefix);
                    }
                }
                type = descriptor({kind:info.union ? "union" : "struct",name:info.name,size:info.size,align:info.align,fields,members,overlaps});
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
        const type = node(root);
        if (key !== undefined) {
            const ref = new WeakRef(type);
            dwarfTypes.set(key,ref);
            dwarfTypeFinalizer.register(type,[key,ref]);
        }
        return type;
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
            for (const [name,value] of Object.entries({dbg,m,$:scope,__aidbgOutput(id,generation,textOutput) { return [makeConsole(id,generation,textOutput),makeFormat(id,generation)]; },setTimeout,clearTimeout,queueMicrotask,sleep,AbortController})) {
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
            selectedTid = undefined;
            selectedFrame = 0;
            syscallCatches.clear();
            signals.clear();
            prettyPrinters = new WeakMap();
            dwarfTypes.clear();
            for (const key of Object.keys(exports)) delete exports[key];
        },
    };
})()
