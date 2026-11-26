// API map for tool clients. See aidbg://debugger.d.ts for complete signatures.
declare const dbg: Debugger;
declare const m: TypeSystem;
declare const $: Record<string, unknown>;
declare const console: Console;
// Shared output methods, live inspection, and compatibility commands.
declare const fmt: import("aidbg").Format;
declare function setTimeout(callback: () => void, ms?: number): number;
declare function clearTimeout(id: number): void;
declare function queueMicrotask(callback: () => void): void;
declare function sleep(ms: number, signal?: AbortSignal): Promise<void>;

interface Debugger {
    readonly arch: string;
    readonly endian: string;
    readonly pid: number;
    readonly memory: MemoryView;
    readonly process: Process;
    thread(tid: number): Thread;
    threads(): readonly Thread[];
    snapshot(options?: number | { tid?: number; context?: boolean; stopTimeoutMs?: number }): Promise<DebugSnapshot>;
    backtraceAll(): Promise<Pick<DebugSnapshot, "threads" | "incomplete">>;
    traceHits(at: bigint | string, options?: { tid?: number; timeoutMs?: number; limit?: number }): Promise<{ stop: WaitResult<StopEvent>; hits: readonly { tid: number; hitCount: number }[]; limitReached: boolean }>;
    waitOutput(tid: number, timeoutMs?: number): Promise<WaitOutputResult>;
    mappings(): readonly MemoryMapping[];
    pauseThread(tid: number): Promise<ControlledThread>;
    pauseAll(): Promise<ControlledThread[]>;
    resumeThread(tid: number): void;
    resumeAll(): void;
    continueForStop(tid?: number | "all", options?: ContinueOptions): Promise<WaitResult<StopEvent>>;
    waitStops(limit?: number, timeoutMs?: number): Promise<WaitResult<StopBatch | ExitEvent>>;
    waitExit(timeoutMs?: number): Promise<WaitResult<ExitEvent>>;
    detach(): Promise<void>;
    kill(signal?: number): Promise<void>;
    ask(payload: object, timeoutMs?: number): Promise<string>;
    prepare(): Promise<void>;
    prepareScratchPad(): Promise<void>;
    setForkPolicy(mode: "parent" | "child" | "both"): void;
    attachDwarf(file: string, position?: bigint | Record<string, bigint>): void;
    onSignal(signal: number | string, callback: SignalCallback | null): void;
    catchSyscall(tid: number | "all", phase: "entry" | "exit" | "both" | null, callback?: (hit: SyscallCaught) => void | Promise<void>): void;
    getSymbol(name: string): Promise<SymbolInfo | null>;
    iterSymbols(pattern: RegExp): AsyncIterableIterator<SymbolInfo>;
    iterDwarfTypes(pattern: RegExp): AsyncIterableIterator<Type>;
    getDwarfTypes(name: string): AsyncIterableIterator<Type>;
    softwareBreakpoint(at: bigint | string, callback?: BreakpointCallback | null, options?: number | BreakpointOptions): Breakpoint;
    hardwareBreakpoint(at: bigint | string, callback?: BreakpointCallback | null, options?: number | BreakpointOptions): Breakpoint;
    pendingBreakpoint(name: string, callback: BreakpointCallback | null, options?: { module?: string }): PendingBreakpoint;
    hardwareWatchpoint(at: bigint | string, callback: WatchpointCallback | null, options: WatchpointOptions): Breakpoint;
    softwareWatchpoint(at: bigint | string, callback: WatchpointCallback | null, options: WatchpointOptions): Breakpoint;
    coredump(file: string, kind: CoredumpKind): void;
    linkObjAt(file: string, address: bigint): Promise<void>;
    disassemble(at: bigint | string, count?: number): Instruction[];
    assemble(at: bigint | string, source: string): Uint8Array;
    addrToLine(address: bigint): { file: string; line: number } | null;
    lineToAddr(file: string, line: number): bigint | null;
    list(location: bigint | StackFrame, radius?: number, sourcePaths?: readonly { from: string; to: string }[]): SourceListing | null;
    stringify(value: unknown): string | undefined;
}

interface TypeSystem {
    void(): Type;
    i8(): IntegerType; i16(): IntegerType & EndianType;
    i32(): IntegerType & EndianType; i64(): IntegerType & EndianType;
    u8(): IntegerType; u16(): IntegerType & EndianType;
    u32(): IntegerType & EndianType; u64(): IntegerType & EndianType;
    f32(): EndianType; f64(): EndianType;
    char(): IntegerType;
    cStr(maxLength?: number): PointerType;
    struct(fields: Record<string, Type>, options?: AggregateOptions): AggregateType;
    union(fields: Record<string, Type>, options?: AggregateOptions): AggregateType;
    array(element: Type, length?: Length): Type;
    pointer(element: Type, length?: Length): PointerType;
    opaque(length: number): Type;
    anonymous(type: Type): object;
    function(signature: Signature): Type;
    lazy(getter: () => Type): Type;
    self(): Type;
    fromDwarf(name: string): Type;
    setPrettyPrinter(type: Type, printer: ((value: CValue) => string | undefined) | null): void;
    findTypes(query: string, options?: { exact?: boolean; module?: string }): readonly { name: string; module: string; size: number | null }[];
    typeOfVar(name: string): Type | undefined;
}

interface Type {
    readonly $size: number | undefined;
    readonly $align: number | undefined;
    at(address: bigint, tid?: number): CValue;
    offsetOf(path: string): number;
    layout(): string;
    $readBytes(address: bigint): Uint8Array;
    $writeBytes(address: bigint, bytes: Uint8Array): void;
}

interface IntegerType extends Type {
    bitfield(width: number): Type;
    enum(values: Record<string, number | bigint>): Type;
}

interface AggregateType extends Type {
    pack(bytes: number): AggregateType;
    align(bytes: number): AggregateType;
    field(name: string): Type;
    refine(fields: Record<string, Type>): AggregateType;
}

interface PointerType extends Type {
    align(bytes: number): PointerType;
    pointee(): Type;
    nullTerminate(maxLength?: number): PointerType;
}

interface EndianType extends Type {
    be(): EndianType;
    le(): EndianType;
}

// Values compose capabilities for addresses, typed reads and writes, raw bytes,
// indexing, dereferencing, aggregate fields and calls. See the full declarations
// for the capabilities available on each value.
