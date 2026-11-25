/**
 * aidbg TypeScript API 正式类型声明文件
 *
 * 目标：
 * - 面向 AI Agent 的强类型脚本环境，配合 tsrs 在脚本编译期完成类型与常量校验（验证左移）。
 * - 统一 live 调试（run / attach）与 coredump 调试（core_open）接口；不支持的操作在运行时抛出 NotSupport 异常。
 * - `fromDwarf`、`lazy`、`self` 与 `Length` 回调中的 `ctx` 由两遍式编译在第二遍注入精确类型。
 * - 全局命名空间 `$`（GlobalScope）通过每次 `script_run` 导出的声明增量合并维护强类型。
 */

// ============================================================================
// 基础枚举与通用类型
// ============================================================================

export type Arch = "x86_64" | "aarch64";

export type Endian = "le" | "be";

export type ThreadStatus = "R" | "S" | "D" | "Unexists";

export type MemoryProtection =
    | "none"
    | "r"
    | "w"
    | "x"
    | "rw"
    | "rx"
    | "wx"
    | "rwx";

export type BreakpointType =
    | "hardware_breakpoint"
    | "software_breakpoint"
    | "hardware_watchpoint"
    | "software_watchpoint";

export type CoredumpKind =
    /** 最小可用 Core：仅记录全量线程、内存映射、全量寄存器 */
    | "minimal"
    /** minimal + SP 附近 4K 内容（按栈方向决定；x86_64 包含 Red Zone） */
    | "stack-4k"
    /** minimal + 全量栈映射 */
    | "stack"
    /** stack + 具名 .so 的 .data 与匿名 .bss 段，不含堆内存 */
    | "standard"
    /** standard + 堆内存、共享内存、脏页及可选内核资源（文件路径、cgroup 等） */
    | "extended"
    /** 全量内存映射，包括非脏页与只读映射（如 .text）；不可读特殊映射（如 vvar）作特殊标记 */
    | "full";

export interface MemoryMapping {
    readonly start: bigint;
    readonly end: bigint;
    readonly offset: bigint;
    /** Linux 风格权限串，如 "r-xp"、"rw-p" */
    readonly prot: string;
    /** 映射名称，如 "[heap]"、"[vdso]"、"/usr/lib/libc.so" */
    readonly name: string;
}

export interface Module {
    readonly name: string;
    readonly path: string;
    readonly base: bigint;
    readonly size: number;
}

export interface SymbolInfo {
    readonly name: string;
    readonly demangledName?: string;
    readonly address: bigint;
    readonly size?: number;
    readonly module?: string;
}

export interface Instruction {
    readonly address: bigint;
    readonly bytes: Uint8Array;
    readonly mnemonic: string;
    readonly opStr: string;
}

export interface Variable {
    readonly name: string;
    readonly type?: string;
    readonly address?: bigint;
    readonly value: Value.Base | string | number | bigint | boolean | null;
}

export type LocalVariables = Record<string, Variable>;

export interface EvalResult {
    readonly type?: string;
    readonly value: Value.Base | string | number | bigint | boolean | null;
    readonly text: string;
}

// ============================================================================
// 寄存器类型定义
// ============================================================================

export interface X86Registers {
    rax: bigint;
    rbx: bigint;
    rcx: bigint;
    rdx: bigint;
    rsi: bigint;
    rdi: bigint;
    rbp: bigint;
    rsp: bigint;
    r8: bigint;
    r9: bigint;
    r10: bigint;
    r11: bigint;
    r12: bigint;
    r13: bigint;
    r14: bigint;
    r15: bigint;
    rip: bigint;
    rflags: bigint;
    fs_base: bigint;
    gs_base: bigint;
}

export interface FullX86Registers extends X86Registers {
    xmm0: Uint8Array;
    xmm1: Uint8Array;
    xmm2: Uint8Array;
    xmm3: Uint8Array;
    xmm4: Uint8Array;
    xmm5: Uint8Array;
    xmm6: Uint8Array;
    xmm7: Uint8Array;
    xmm8: Uint8Array;
    xmm9: Uint8Array;
    xmm10: Uint8Array;
    xmm11: Uint8Array;
    xmm12: Uint8Array;
    xmm13: Uint8Array;
    xmm14: Uint8Array;
    xmm15: Uint8Array;
}

export interface ARM64Registers {
    x0: bigint;
    x1: bigint;
    x2: bigint;
    x3: bigint;
    x4: bigint;
    x5: bigint;
    x6: bigint;
    x7: bigint;
    x8: bigint;
    x9: bigint;
    x10: bigint;
    x11: bigint;
    x12: bigint;
    x13: bigint;
    x14: bigint;
    x15: bigint;
    x16: bigint;
    x17: bigint;
    x18: bigint;
    x19: bigint;
    x20: bigint;
    x21: bigint;
    x22: bigint;
    x23: bigint;
    x24: bigint;
    x25: bigint;
    x26: bigint;
    x27: bigint;
    x28: bigint;
    x29: bigint;
    x30: bigint;
    sp: bigint;
    pc: bigint;
    cpsr: bigint;
}

export interface FullARM64Registers extends ARM64Registers {
    v0: Uint8Array;
    v1: Uint8Array;
    v2: Uint8Array;
    v3: Uint8Array;
    v4: Uint8Array;
    v5: Uint8Array;
    v6: Uint8Array;
    v7: Uint8Array;
    v8: Uint8Array;
    v9: Uint8Array;
    v10: Uint8Array;
    v11: Uint8Array;
    v12: Uint8Array;
    v13: Uint8Array;
    v14: Uint8Array;
    v15: Uint8Array;
    v16: Uint8Array;
    v17: Uint8Array;
    v18: Uint8Array;
    v19: Uint8Array;
    v20: Uint8Array;
    v21: Uint8Array;
    v22: Uint8Array;
    v23: Uint8Array;
    v24: Uint8Array;
    v25: Uint8Array;
    v26: Uint8Array;
    v27: Uint8Array;
    v28: Uint8Array;
    v29: Uint8Array;
    v30: Uint8Array;
    v31: Uint8Array;
    fpsr: number;
    fpcr: number;
}

export type RegisterSnapshot =
    | Readonly<X86Registers>
    | Readonly<ARM64Registers>;

// ============================================================================
// 核心类型：Snapshot / StackFrame / Breakpoint / SignalHit
// ============================================================================

export interface StackFrame {
    readonly pc: bigint;
    /** 调用者帧用于查找源码和变量作用域的地址。 */
    readonly lookupPc: bigint;
    readonly sp: bigint;
    /** Frame Pointer */
    readonly fp: bigint;
    readonly module?: Module;
    /** 尝试解析出的函数名 */
    readonly symbol?: string;
    /** 距离函数入口的偏移 */
    readonly offset?: number;
    /** 此帧可读的局部变量。缺少 DWARF 或无法恢复帧上下文时省略。 */
    readonly locals?: LocalVariables;
    /** 此帧可读的形参。 */
    readonly parameters?: LocalVariables;
    /** 若dwarf信息存在，则显示文件名与行号 */
    readonly file?: string;
    readonly line?: number;
}

export interface ThreadSnapshot {
    readonly tid: number;
    readonly registers: RegisterSnapshot;
    readonly frames: readonly StackFrame[];
    readonly locals?: readonly Variable[];
}

export interface SourceListing {
    readonly file: string;
    readonly line: number;
    readonly lines: readonly { readonly line: number; readonly text: string }[];
}

export interface DebugSnapshot {
    readonly timestamp: number;
    readonly threads: readonly ThreadSnapshot[];
    readonly mappings: readonly MemoryMapping[];
    readonly consistency: "thread" | "all-stopped" | "best-effort";
}

export type BreakpointCallback = (hit: BreakpointHit) => void | Promise<void>;

export interface Breakpoint {
    readonly id: number;
    readonly tid: readonly number[];
    readonly address: bigint;
    readonly type: BreakpointType;

    callback: BreakpointCallback;
    disable(): void;
    /** 删除该断点 */
    remove(): void;
}

export interface PendingBreakpoint extends Omit<Breakpoint, "address"> {
    readonly address: bigint | null;
}

export interface BreakpointHit {
    readonly thread: ControlledThread;
    readonly breakpoint: Breakpoint;
    readonly hitCount: number;

    /** 回调结束后继续保持暂停本线程（与 continue() 均支持多次调用，以最后一次为准） */
    pause(): void;
    /** 回调结束后放开本线程（与 pause() 均支持多次调用，以最后一次为准） */
    continue(): void;
    /** 在本次回调执行及 await 期间，禁止该线程因命中其他断点而触发回调 */
    preventOtherBreakpointOnThisThread(): void;
}

export interface WatchpointHit extends BreakpointHit {
    readonly access?: "read" | "write";
    readonly length?: number;
    readonly before?: Value.Base;
    readonly after?: Value.Base;
}

export type WatchpointCallback = (hit: WatchpointHit) => void | Promise<void>;

export type SignalCallback = (hit: SignalHit) => void | Promise<void>;

export interface SignalHit {
    readonly thread: ControlledThread;
    /** 信号编号，如 11 (SIGSEGV) */
    readonly signalNumber: number;
    /** 信号名称，如 "SIGSEGV" */
    readonly signalName: string;
    /** 导致崩溃的内存地址（从 siginfo_t 提取） */
    readonly faultAddress?: bigint;

    /** 回调结束后放行并恢复线程，或丢弃信号并保持暂停。省略调用时保留待投递信号。 */
    passToTarget(pass: boolean): void;
    /** 取消本信号处理器 */
    removeThisHandler(): void;
}

// ============================================================================
// 核心类型：Thread 与 ControlledThread
// ============================================================================

export interface Thread {
    readonly tid: number;
    readonly status: ThreadStatus;
    /** 处理本线程待投递的信号。true 投递并恢复线程，false 丢弃信号并维持暂停。 */
    passToTarget(pass: boolean): void;

    /**
     * 类似 gdb 的 print / inferior call，自动计算作用域；
     * 所有 C 函数 inferior call 均绑定到特定线程执行。
     */
    eval(expr: string): EvalResult;

    /** 通用寄存器 + SP + PC 的代理对象，跨 await 点可能发生变化 */
    registers: X86Registers | ARM64Registers;
    /** 通用寄存器 + 浮点/向量寄存器的代理对象 */
    fullRegisters: FullX86Registers | FullARM64Registers;

    /** 注入系统调用；根据 scratchpad 状态决定是否需暂停其他线程 */
    injectSyscall(id: bigint, ...args: bigint[]): bigint[];
    /** 获取调用栈 */
    backtrace(limit?: number): readonly StackFrame[];
    /** 获取当前位置作用域内可读的局部变量（若有 DWARF 信息）。 */
    locals(): Variable[];

    /** 消费该线程最早的停点事件。仅观察，不恢复线程。默认等待 180 秒。 */
    waitThreadStop(timeoutMs?: number): Promise<WaitResult<StopEvent>>;
    /** 消费该线程的退出事件。默认等待 180 秒。 */
    waitThreadExit(timeoutMs?: number): Promise<WaitResult<ExitEvent>>;
    /** 在 MCP 回包中请求 LLM 回复。携带本线程 TID，不消费停点。 */
    ask(payload: object, timeoutMs?: number): Promise<string>;
}

export interface ControlledThread extends Thread {
    /** 步进完成时线程仍暂停。步进完成本身不进入公共停点队列。 */
    next(n?: number): Promise<void>;
    /** 走到下 n 个分支指令时断住 */
    nextBranch(n?: number): Promise<void>;
    nextCall(n?: number, followCall?: boolean): Promise<void>;
    /** 先登记等待，再恢复本线程。只匹配恢复后的断点或观察点，默认 180 秒。 */
    nextHit(timeoutMs?: number): Promise<WaitResult<BreakpointStop | ExitEvent>>;

    step(n?: number): Promise<void>;
    /** 走到 ret 指令后断住 */
    finish(): Promise<void>;
    until(at: bigint): Promise<void>;

    /** 记录分支指令的执行结果及当时使用的寄存器内容 */
    recordBranch(allReg?: boolean): void;

    /** 在目标进程中分配一块匿名映射内存（底层依赖 Syscall Injection） */
    allocate(size: number, prot?: MemoryProtection): Promise<bigint>;
    /** 释放通过 allocate 申请的内存 */
    free(address: bigint, size: number): Promise<void>;
    /** 修改目标进程指定内存区域的读写执行权限 */
    protect(address: bigint, size: number, prot: MemoryProtection): Promise<void>;
}

// ============================================================================
// 核心类型：MemoryView
// ============================================================================

interface XrefScanOptions {
    /** 最多返回 1–256 条结果，默认 64。 */
    limit?: number;
    maxScanBytes?: number;
}

export interface PointerXrefOptions extends XrefScanOptions {
    instructionReferences?: false;
    start?: bigint;
    end?: bigint;
    /** 候选地址的字节对齐，默认 8，须为不超过 4096 的 2 的幂。 */
    alignment?: number;
}

export interface InstructionXrefOptions extends XrefScanOptions {
    instructionReferences: true;
    /** 同一可执行映射内的指令区间，至多 64 KiB。start 必须是指令边界。 */
    start: bigint;
    end: bigint;
    /** 继续扫描时保留原 start 和 end，将 nextAddress 传给 resumeFrom。 */
    resumeFrom?: bigint;
}

interface XrefScanResult {
    scannedBytes: number;
    nextAddress: bigint | null;
    warnings: { code: string; message: string; hint: string | null }[];
}

export interface PointerXrefResult extends XrefScanResult {
    kind: "pointer_value";
    matches: bigint[];
    uncapturedBytes: number;
}

export interface InstructionXrefResult extends XrefScanResult {
    kind: "instruction_reference";
    matches: {
        instruction: bigint;
        kind: "branch_target" | "pc_relative" | "address" | "read" | "write";
        mnemonic: string | null;
        function: string | null;
        sourceLine: { file: string; line: number | null; column: number | null; source: string | null } | null;
    }[];
}

export interface MemoryView {
    // 1. 标量读取（同步操作，底层直调 process_vm_readv）
    readInt8(address: bigint): number;
    readUint8(address: bigint): number;

    readInt16(address: bigint, endian?: Endian): number;
    readUint16(address: bigint, endian?: Endian): number;

    readInt32(address: bigint, endian?: Endian): number;
    readUint32(address: bigint, endian?: Endian): number;

    readInt64(address: bigint, endian?: Endian): bigint;
    readUint64(address: bigint, endian?: Endian): bigint;

    /** 根据目标进程位数（32/64）自动决定读取 4 字节或 8 字节 */
    readPointer(address: bigint, endian?: Endian): bigint;

    readFloat32(address: bigint, endian?: Endian): number;
    readFloat64(address: bigint, endian?: Endian): number;

    // 2. 标量写入（同步操作，底层直调 process_vm_writev）
    writeInt8(address: bigint, value: number): void;
    writeUint8(address: bigint, value: number): void;

    writeInt16(address: bigint, value: number, endian?: Endian): void;
    writeUint16(address: bigint, value: number, endian?: Endian): void;

    writeInt32(address: bigint, value: number, endian?: Endian): void;
    writeUint32(address: bigint, value: number, endian?: Endian): void;

    writeInt64(address: bigint, value: bigint, endian?: Endian): void;
    writeUint64(address: bigint, value: bigint, endian?: Endian): void;

    writePointer(address: bigint, value: bigint, endian?: Endian): void;

    writeFloat32(address: bigint, value: number, endian?: Endian): void;
    writeFloat64(address: bigint, value: number, endian?: Endian): void;

    // 3. 块级与特殊格式操作
    /** 读取一段连续内存，每次调用返回独立的 Uint8Array */
    readBytes(address: bigint, length: number): Uint8Array;
    /** 将字节数组写入目标内存 */
    writeBytes(address: bigint, data: Uint8Array): void;
    /** 以 Null-Terminated (C-String) 方式读取字符串，默认 maxLen 如 4096 */
    readCString(address: bigint, maxLen?: number): string;
    /** 按给定 TypeSystem 类型直接读取并包装目标内存 */
    readAsType<V>(address: bigint, type: Type.Base<V>): V;

    // 4. 内存搜索
    /** 在目标地址范围内搜索字节特征码或字符串，返回匹配地址列表 */
    search(
        pattern: Uint8Array | string,
        startRange: bigint,
        endRange: bigint
    ): bigint[];
    /** 查找存储目标地址的 64 位小端指针。分页时将 nextAddress 传为 start。 */
    xref(address: bigint, options?: PointerXrefOptions): PointerXrefResult;
    /** 在指定代码区间查找直接分支、PC 相对引用和可解析的地址引用。 */
    xref(address: bigint, options: InstructionXrefOptions): InstructionXrefResult;
    xref(address: bigint, options: PointerXrefOptions | InstructionXrefOptions): PointerXrefResult | InstructionXrefResult;
}
/**  */
interface WatchpointOptions {
    length: number;
    access: "read" | "write" | "read_write";
    tid?: number;
}

// ============================================================================
// 核心类型：Debugger
// ============================================================================

export interface Debugger {
    detach(): Promise<void>;
    /** 新的 fork 默认跟踪父进程。child 模式切换至子进程并暂停在 fork 边界。 */
    followFork(mode: "parent" | "child"): void;
    /** 分离调试器并丢弃待投递信号，再发送指定信号。默认 SIGKILL。 */
    kill(signal?: number): Promise<void>;
    /** 消费进程退出事件。正常退出或信号退出都作为结果返回。 */
    waitExit(timeoutMs?: number): Promise<WaitResult<ExitEvent>>;
    /** 在 MCP 回包中携带 payload 和 handler，等待 send_input 提供字符串。默认 180 秒。 */
    ask(payload: object, timeoutMs?: number): Promise<string>;
    readonly process: Process;
    readonly arch: Arch;
    readonly endian: Endian;
    readonly pid: number;

    thread(tid: number): Thread;
    threads(): readonly Thread[];
    readonly memory: MemoryView;

    /**
     * 默认在 run / attach 时执行，也可在脚本中调用（幂等）。
     * 已有 scratchpad 时可仅令当前线程执行 eval 与 injectSyscall；否则需暂停所有其他线程。
     */
    prepareScratchPad(): Promise<void>;
    snapshot(tid?: number): Promise<DebugSnapshot>;
    mappings(): readonly MemoryMapping[];
    prepare(): Promise<void>;

    /** 回调必须明确调用 passToTarget 才会处理待投递信号。 */
    onSignal(signal: number | string, cb: SignalCallback | null): void;

    /** 依次查找 ELF 原名、完整 C++ 签名、唯一 C++ 函数名。C++ 匹配有歧义时抛错。 */
    getSymbol(name: string): Promise<SymbolInfo | null>;
    /** 流式遍历符号（模糊搜索、全量扫描） */
    iterSymbols(pattern: RegExp): AsyncIterableIterator<SymbolInfo>;
    /** 暂停预算暂时有意不加 */
    /** 按原始 ELF 符号持续绑定软件断点。映像或共享库尚未加载时 address 为 null。 */
    pendingBreakpoint(name: string, callback: BreakpointCallback | null, options?: { module?: string }): PendingBreakpoint;
    hardwareBreakpoint(
        at: bigint | string,
        cb?: BreakpointCallback | null,
        tid?: number
    ): Breakpoint;
    softwareBreakpoint(
        at: bigint | string,
        cb?: BreakpointCallback | null,
        tid?: number
    ): Breakpoint;
    hardwareWatchpoint(
        at: bigint | string,
        cb: WatchpointCallback | null,
        opt: WatchpointOptions
    ): Breakpoint;
    softwareWatchpoint(
        at: bigint | string,
        cb: WatchpointCallback | null,
        opt: WatchpointOptions
    ): Breakpoint;

    // 使用 Unicorn 做模拟执行，复杂度高暂不实现，保留接口占位：
    // unicornBreakpoint(at: bigint | string, cb: BreakpointCallback, tid?: number): Breakpoint;
    // unicornWatchpoint(at: bigint | string, cb: BreakpointCallback, tid?: number): Breakpoint;

    linkObjAt(objfile: string, address: bigint): Promise<void>;
    disassemble(at: bigint | string, count?: number): Instruction[];
    assemble(at: bigint | string, src: string): Uint8Array;

    /**
     * 生成 coredump（默认 zstd level 1 压缩；可用双核时采用采集+压缩双线程）。
     * coredump 调试模式下调用将抛出 NotSupport 异常。
     */
    coredump(toFile: string, kind: CoredumpKind): void;

    pause(tid: number): Promise<ControlledThread>;
    pause(tid: "all"): Promise<ControlledThread[]>;
    pauseThread(tid: number): Promise<ControlledThread>;
    pauseAll(): Promise<ControlledThread[]>;
    /** 立即恢复指定范围，默认 "all"。 */
    resume(tid?: number | "all"): Promise<void>;
    /** resume 的同义词。立即返回，不消费停点。 */
    continue(tid?: number | "all"): Promise<void>;
    /** 先取最早匹配的排队事件。没有时先登记等待，再恢复指定范围。 */
    continueForStop(tid?: number | "all", options?: ContinueOptions): Promise<WaitResult<StopEvent>>;
    /** 等待并消费一批已排队的停点，不恢复线程。默认最多 16 条。 */
    waitStops(limit?: number, timeoutMs?: number): Promise<WaitResult<StopBatch | ExitEvent>>;
    iterDwarfTypes(pattern: RegExp): AsyncIterableIterator<Type.Base<unknown>>;
    getDwarfTypes(name: string): AsyncIterableIterator<Type.Base<unknown>>;

    /** 返回唯一匹配的运行时地址。无匹配或存在多个地址时返回 null。 */
    lineToAddr(file: string, line: number): bigint | null;
    addrToLine(addr: bigint): { file: string; line: number } | null;
    /** 从调试服务端读取地址或帧对应的源码。默认前后各 5 行，找不到源码时返回 null。 */
    list(at: bigint | StackFrame, radius?: number): SourceListing | null;
}

export type WaitResult<T> = T | { readonly kind: "timeout" } | { readonly kind: "ended" };

export interface ContinueOptions {
    /** 默认 180 秒。超时不改变目标状态。 */
    timeoutMs?: number;
    /** 只在仍暂停的停点调用。返回 false 时释放该停点并继续等待。 */
    until?: (stop: StoppedEvent) => boolean;
}

export interface StopBatch {
    readonly kind: "stops";
    readonly events: readonly StoppedEvent[];
}

interface EventLocation {
    readonly sequence: number;
    readonly tid: number;
    /** 此事件交付时线程是否仍由调试器暂停。 */
    readonly paused: boolean;
}

export type BreakpointStop = EventLocation & {
    readonly kind: "breakpoint" | "watchpoint";
    readonly breakpointId: number;
    readonly address: bigint;
    readonly hitCount?: number;
    readonly length?: number;
    readonly access?: "read" | "write";
    readonly before?: Value.Base;
    readonly after?: Value.Base;
};

export type StoppedEvent =
    | BreakpointStop
    | (EventLocation & { readonly kind: "fork"; readonly parentPid: number })
    | (EventLocation & { readonly kind: "exec"; readonly executable: string | null })
    | (EventLocation & {
        readonly kind: "signal";
        readonly signalNumber: number;
        readonly signalName: string;
        readonly faultAddress?: bigint;
        /** true 投递原信号并恢复线程，false 丢弃信号并保持暂停。只对仍待投递的信号有效。 */
        passToTarget(pass: boolean): void;
    });

export type StopEvent = StoppedEvent | ExitEvent;

export interface ProcessOutput {
    readonly text: string;
    readonly eof: boolean;
    readonly truncated: boolean;
}

export interface Readable {
    read(): ProcessOutput;
}

export interface Writable {
    /** 非阻塞写入，返回本次写入的 UTF-8 字节数。 */
    write(data: string): number;
    close(): void;
}

/** 仅适用于 run 启动的进程。每个读取端与 MCP 输出各自保存游标。 */
export interface Process {
    readonly stdin: Writable;
    readonly stdout: Readable;
    readonly stderr: Readable;
    /** 按调试器收到两个管道输出的顺序合并。 */
    readonly combinedOutErr: Readable;
}

// ============================================================================
// 核心类型：GlobalScope ($) 与 Console
// ============================================================================

/**
 * 全局跨脚本持久化命名空间。
 * 每次 `script_run` 通过 `export` 导出的符号都会挂载到 `$` 下，
 * 服务端通过增量 `.d.ts` 声明合并为其提供强类型检查。
 */
export interface GlobalScope {
    // 由历次 script_run 导出的声明增量合并填充
}

export interface HexdumpOptions {
    /** 每组字节数，0 表示不分组，默认 1 或 4 */
    groupSize?: number;
    /** 每行组数，0 表示不换行，默认 16 */
    groupsPerLine?: number;
    /** 是否带 0x 前缀，默认 false */
    prefix?: boolean;
    /** 组间分隔符，默认 " " */
    separator?: string;
    /** 右侧是否附带 ASCII 预览 */
    showAscii?: boolean;
    /** 字节序 */
    endian?: Endian | "host";
}

export interface Console {
    /** 同步写入会话输出缓冲区，与 printf 使用相同的回包规则。 */
    log(...args: unknown[]): void;
    /**
     * 同步写入会话输出缓冲区，由写入后第一个收集输出的 MCP 响应携带。
     * 当前 script_run 尚未收集输出时，该响应即可带回这条日志。
     * 输出缓冲区上限为 1 MiB，溢出时丢弃最旧的输出并报告截断。
     */
    printf(fmt: string, ...args: unknown[]): void;
    sprintf(fmt: string, ...args: unknown[]): string;
    /**
     * 等待外部通过 MCP `send_input(handler, data)` 发送输入；
     * 超时或收到 `interrupt_input(handler, msg)` 时抛出异常以跳出循环。
     */
    waitInput(timeoutSec?: number): Promise<string>;
    hexdump(data: Uint8Array, options?: HexdumpOptions): string;
    bytesFromHex(s: string): Uint8Array;
}

// ============================================================================
// 核心类型：TypeSystem（声明式 C/内存类型系统）
// ============================================================================

declare const valueBrand: unique symbol;

export type LiteralString<T extends string> =
    string extends T ? never : T;

export type Infer<T> = T extends Type.Base<infer V> ? V : never;

export type Fields = Record<string, Type.Base<unknown>>;

export type RefinedFields<F extends Fields, P extends Fields> = {
    [K in keyof F]: K extends keyof P ? P[K] : F[K];
};

export type Arg<T> = T extends Read<infer P> ? T | P : T;

export type Args<A extends readonly Type.Base<unknown>[]> = {
    -readonly [K in keyof A]: Arg<Infer<A[K]>>;
};

export interface AggregateOptions {
    align?: number;
    pack?: number;
}

export type IntegerLike =
    | number
    | bigint
    | (Value.Base & Read<number | bigint>);

/** ctx 的精确类型由第二遍编译注入 */
export type Length =
    | number
    | bigint
    | ((ctx: any) => IntegerLike);

export type Signature<
    A extends readonly Type.Base<unknown>[],
    R extends Type.Base<unknown>,
    V extends boolean = false
> = {
    args: A;
    returns: R;
    variadic?: V;
} & (true extends V ? { variadic: V } : unknown);

// Value 能力接口（仅用于静态类型检查）

export interface Read<T extends number | bigint> {
    $read(): T;
}

export interface Write<T extends number | bigint> {
    $write(value: T): void;
}

export interface Address {
    $address(): bigint;
}

export interface Call<A extends unknown[], R> {
    (...args: A): Promise<R>;
}

export interface Index<T> {
    readonly $length: number | undefined;

    /** Proxy set 支持 Value 及基础类型赋值；后者由第二遍编译校验。 */
    [index: number]: T;
    $atUnchecked(index: number): T;
}

export interface Deref<T> {
    $deref(): T;
}

export interface Bytes {
    $readBytes(): Uint8Array;
    $writeBytes(data: Uint8Array): void;
}

export interface Sized {
    readonly $size: number;
}

// Value：运行时值，按能力组合

export declare namespace Value {
    export interface Base {
        readonly $type: Type.Base<unknown>;
        readonly $size: number | undefined;
        /** 当前 Value 绑定的线程；不修改共享 Type。 */
        $tid: number | undefined;

        $toJson(): string;
        $dumpString(): string;
    }

    export type Scalar<T extends number | bigint> =
        Base & Sized & Read<T> & Write<T> & Address & Bytes;

    export type Bitfield<T extends number | bigint> =
        Base & Read<T> & Write<T>;

    export type Pointer<V> =
        Base & Sized & Read<bigint> & Write<bigint> &
        Address & Bytes & Index<V> & Deref<V>;

    export type Array<V> =
        Base & Address & Bytes & Index<V>;

    export type Aggregate<F extends Fields> =
        Base & Address & Bytes & {
            [K in keyof F]: Infer<F[K]>;
        };

    export type Fn<
        A extends readonly Type.Base<unknown>[],
        R extends Type.Base<unknown>,
        V extends boolean = false
    > = Base & Address & Call<
        [V] extends [true] ? [...Args<A>, ...Base[]] : Args<A>,
        Infer<R>
    >;
}

// 第二遍编译专用：Proxy 赋值静态检查。

/**
 * 允许 Value 到 Value 的赋值；具有 Write 能力的 Value 还接受对应基础类型。
 * 函数 Value 不可赋值。真实 C 类型、ABI、取值范围与存储位置由运行时校验。
 */
export type AssignArg<T> =
    T extends (...args: any[]) => unknown ? never :
    T extends Write<infer P> ? T | P : T;

/**
 * @internal 仅供第二遍编译器生成的检查代码使用，不是 QuickJS 运行时 API。
 * 将已确认的 Value 成员或索引简单赋值 `obj[key] = rhs`
 * 在检查副本中转换为 `__assign(obj[key], rhs)`。
 * NoInfer 禁止右值参与目标类型推导；返回右值类型，保留赋值表达式语义。
 * 编译器须另外验证左值可写性，禁止普通变量、只读系统属性等误用；
 * 原始 JS 输出保留赋值表达式，由 Proxy.set 实施实际内存写入。
 * 不用于复合赋值、自增、自减或解构赋值。
 */
export declare function __assign<
    T extends Value.Base,
    S extends AssignArg<NoInfer<T>>
>(dst: T, src: S): S;

// Type：类型描述符

export declare namespace Type {
    export interface Base<V> {
        readonly [valueBrand]: V;
        readonly $size: number | undefined;
        readonly $align: number | undefined;

        /**
         * 将类型绑定到目标内存地址；
         * 需要 call 能力时必须绑定线程 tid（也可后续修改返回 Value 的 $tid）。
         */
        at(address: bigint, tid?: number): V;
    }

    export interface Scalar<T extends number | bigint>
        extends Base<Value.Scalar<T>> {
        value(value: T): Value.Scalar<T>;
    }

    export interface Pointer<T extends Base<unknown>>
        extends Base<Value.Pointer<Infer<T>>> {
        value(address: bigint): Value.Pointer<Infer<T>>;
        pointee(): T;
    }

    export interface Array<T extends Base<unknown>>
        extends Base<Value.Array<Infer<T>>> {
        element(): T;
    }

    export interface Aggregate<F extends Fields>
        extends Base<Value.Aggregate<F>> {
        field<K extends keyof F>(name: K): F[K];

        refine<const P extends Fields>(
            fields: P & Record<Exclude<keyof P, keyof F>, never>
        ): Aggregate<RefinedFields<F, P>>;
    }
}

// TypeSystem：声明式类型构造接口

export interface TypeSystem {
    void(): Type.Base<void>;

    u8(): Type.Scalar<number>;
    i8(): Type.Scalar<number>;
    u16(): Type.Scalar<number>;
    i16(): Type.Scalar<number>;
    u32(): Type.Scalar<number>;
    i32(): Type.Scalar<number>;
    u64(): Type.Scalar<bigint>;
    i64(): Type.Scalar<bigint>;

    f32(): Type.Scalar<number>;
    f64(): Type.Scalar<number>;

    struct<F extends Fields>(
        fields: F,
        option?: AggregateOptions
    ): Type.Aggregate<F>;
    union<F extends Fields>(
        fields: F,
        option?: AggregateOptions
    ): Type.Aggregate<F>;

    array<T extends Type.Base<unknown>>(type: T, length?: Length): Type.Array<T>;
    pointer<T extends Type.Base<unknown>>(type: T, length?: Length): Type.Pointer<T>;

    /** 变参由运行时按照 C 默认参数提升规则处理 */
    function<
        const A extends readonly Type.Base<unknown>[],
        R extends Type.Base<unknown>,
        const V extends boolean = false
    >(signature: Signature<A, R, V>): Type.Base<Value.Fn<A, R, V>>;

    /** 延迟求值类型，需两遍式编译注入递归类型 */
    lazy<T extends Type.Base<unknown>>(getter: () => T): T;
    /** lazy 的语法糖，简化树、链表等常见自递归结构 */
    self(): Type.Base<unknown>;

    /** 第二遍编译根据 DWARF 信息替换为精确类型 */
    fromDwarf<const S extends string>(name: S & LiteralString<S>): any;
    /** 从变量中获取dwarf信息，有可能返回undefined代表找不到类型 */
    typeOfVar<const S extends string>(name: S & LiteralString<S>): any;
}

export type ExitEvent = {
    readonly kind: "exit";
    readonly sequence: number;
    readonly scope: "thread" | "process";
    readonly tid: number;
} & (
    | { readonly reason: "code"; readonly code: number }
    | { readonly reason: "signal"; readonly signal: number }
    | { readonly reason: "unknown" }
);

export interface ScriptError {
    message: string;
    stack?: string;
    file?: string;
    line?: number;
    column?: number;
    scriptId?: number;
}

// ============================================================================
// 全局导出单例
// ============================================================================

export declare const dbg: Debugger;
export declare const m: TypeSystem;
export declare const $: GlobalScope;
export declare const console: Console;

export declare function setTimeout(cb: () => void, ms?: number): number;
export declare function clearTimeout(id: number): void;
export declare function queueMicrotask(cb: () => void): void;
export declare function sleep(ms: number, signal?: AbortSignal): Promise<void>;


export interface AbortSignal {
    readonly aborted: boolean;
    readonly reason: unknown;
}

export declare class AbortController {
    readonly signal: AbortSignal;
    abort(reason?: unknown): void;
}
