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
    readonly kind?: string;
    readonly name: string;
    readonly demangledName?: string;
    readonly address: bigint;
    readonly size?: number;
    readonly module?: string;
}

export interface SymbolMatch {
    readonly name: string;
    /** Start address of the matched symbol. */
    readonly address: bigint;
    readonly offset: bigint;
    readonly module?: { readonly path: string } | null;
    readonly kind?: string;
    readonly section?: string | null;
    readonly match: "exact" | "within" | "nearest";
}

export interface ModuleAddressMatch {
    /** The address passed to symbolAt. */
    readonly address: bigint;
    readonly module: { readonly path: string };
    /** Relative to the ELF load instance base when the layout is known. */
    readonly offset?: bigint;
    readonly name?: never;
    readonly kind?: never;
    readonly section?: never;
    readonly match: "module";
}

export type AddressSymbol = SymbolMatch | ModuleAddressMatch;

export interface Instruction {
    readonly address: bigint;
    readonly bytes: Uint8Array;
    readonly mnemonic: string;
    readonly opStr: string;
    readonly references: readonly {
        address: bigint;
        kind: string;
        slot?: bigint;
        requested?: string;
        resolved?: string;
        resolvedAddress?: bigint;
    }[];
}

export interface Variable {
    readonly name: string;
    readonly type?: string;
    readonly address?: bigint;
    readonly value: Value.Base | string | number | bigint | boolean | null;
    readonly availability?: string;
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
    /** 覆盖当前地址的逻辑内联帧，由内向外排列。变量由所属物理帧的作用域解析。 */
    readonly inlineFrames?: readonly {
        readonly symbol: string;
        readonly callFile: string | null;
        readonly callLine: number | null;
    }[];
    readonly unwindMethod?: string;
    readonly missingDebugSections?: readonly string[];
    /** 距离函数入口的偏移 */
    readonly offset?: number;
    /** 此帧可读的局部变量。缺少 DWARF 或无法恢复帧上下文时省略。 */
    readonly locals?: LocalVariables;
    /** 此帧可读的形参。 */
    readonly parameters?: LocalVariables;
    readonly unavailableLocals?: LocalVariables;
    readonly unavailableParameters?: LocalVariables;
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
    readonly originalFile?: string;
    readonly file: string;
    readonly line: number;
    readonly lines: readonly { readonly line: number; readonly text: string }[];
}

export interface DebugSnapshot {
    readonly threadCount: number;
    readonly timestamp: number;
    readonly threads: readonly ThreadSnapshot[];
    readonly mappings: readonly MemoryMapping[];
    readonly incomplete?: readonly { readonly tid?: number; readonly stage: string; readonly error: string }[];
    readonly consistency: "thread" | "all-stopped" | "best-effort" | "partial";
    readonly context?: {
        readonly State?: string;
        readonly TracerPid?: number;
        readonly Threads?: number;
        readonly syscall?: string;
        readonly wchan?: string;
        readonly fd?: Readonly<Record<number, string>>;
    };
}

export interface WaitOutputResult {
    readonly stdout: string;
    readonly stderr: string;
    readonly truncated: boolean;
    readonly eof: boolean;
    readonly released: boolean;
    readonly ended: boolean;
    readonly timedOut: boolean;
    readonly exitCode?: number;
    readonly exitSignal?: number;
}

/** 回调可使用 await；通过 hit.pause() 或 hit.continue() 指定回调结束后的线程状态。 */
export type BreakpointCallback = (hit: BreakpointHit) => void | Promise<void>;

export interface BreakpointOptions {
    readonly tid?: number;
    /** 只有返回 true 时执行回调或停下。 */
    readonly condition?: (hit: BreakpointHit) => boolean;
}

export interface Breakpoint {
    readonly id: number;
    readonly tid: readonly number[];
    readonly address: bigint;
    readonly type: BreakpointType;

    callback: BreakpointCallback;
    disable(): void;
    enable(): void;
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

/** 地址使用 bigint，块读取长度以字节计。对 core 写入会抛出 NotSupport。 */
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
interface WatchpointOptions {
    length: number;
    access: "read" | "write" | "read_write";
    tid?: number;
}

// ============================================================================
// 核心类型：Debugger
// ============================================================================

/** live 和 core 共用此接口。core 中的目标写入和执行控制会抛出 NotSupport。 */
export interface Debugger {
    detach(): Promise<void>;
    /** 普通 fork 默认跟踪父进程。child 模式切换至子进程并暂停在 fork 边界。both 需要多实例支持。 */
    setForkPolicy(mode: "parent" | "child" | "both"): void;
    /** Load additional DWARF for the active target. An explicit position may be needed for cores. */
    attachDwarf(file: string, position?: bigint | Readonly<Record<string, bigint>>): void;
    /** 设置或移除指定范围的系统调用捕获。省略回调时命中会保持暂停。 */
    catchSyscall(tid: number | "all", phase: "entry" | "exit" | "both" | null,
        callback?: (hit: SyscallCaught) => void | Promise<void>): void;
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
    /** 可在 live 目标运行时采集。检查 incomplete 了解未完成阶段；stopTimeoutMs 为 0 时仅采样已暂停线程。 */
    snapshot(options?: number | { tid?: number; context?: boolean; stopTimeoutMs?: number }): Promise<DebugSnapshot>;
    backtraceAll(): Promise<Pick<DebugSnapshot, "threads" | "incomplete">>;
    /** 记录指定断点的命中并自动继续，直到退出、超时、达到命中上限或遇到其他暂停事件。 */
    traceHits(at: bigint | string, options?: { tid?: number; timeoutMs?: number; limit?: number }): Promise<{
        readonly stop: WaitResult<StopEvent>;
        readonly hits: readonly { readonly tid: number; readonly hitCount: number }[];
        readonly limitReached: boolean;
    }>;
    /** 从脚本专用游标读取进程输出，可传进程 PID。默认等 180 秒，通过 timedOut 判断超时。 */
    waitOutput(tid: number, timeoutMs?: number): Promise<WaitOutputResult>;
    mappings(): readonly MemoryMapping[];
    prepare(): Promise<void>;

    /** 回调必须明确调用 passToTarget 才会处理待投递信号。 */
    onSignal(signal: number | string, cb: SignalCallback | null): void;

    /** 依次查找 ELF 原名、完整 C++ 签名、唯一 C++ 函数名。C++ 匹配有歧义时抛错。 */
    getSymbol(name: string): Promise<SymbolInfo | null>;
    /** 流式遍历符号（模糊搜索、全量扫描） */
    iterSymbols(pattern: RegExp): AsyncIterableIterator<SymbolInfo>;
    /** 按原始 ELF 符号持续绑定软件断点。映像或共享库尚未加载时 address 为 null。 */
    pendingBreakpoint(name: string, callback: BreakpointCallback | null, options?: { module?: string }): PendingBreakpoint;
    hardwareBreakpoint(
        at: bigint | string,
        cb?: BreakpointCallback | null,
        options?: number | BreakpointOptions
    ): Breakpoint;
    softwareBreakpoint(
        at: bigint | string,
        cb?: BreakpointCallback | null,
        options?: number | BreakpointOptions
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

    pauseThread(tid: number): Promise<ControlledThread>;
    pauseAll(): Promise<ControlledThread[]>;
    /** 立即恢复指定线程。 */
    resumeThread(tid: number): void;
    /** 立即恢复所有线程。 */
    resumeAll(): void;
    /** 先取最早匹配的排队事件。没有时先登记等待，再恢复指定范围。 */
    continueForStop(tid?: number | "all", options?: ContinueOptions): Promise<WaitResult<StopEvent>>;
    /** 等待并消费一批已排队的停点，不恢复线程。默认最多 16 条。 */
    waitStops(limit?: number, timeoutMs?: number): Promise<WaitResult<StopBatch | ExitEvent>>;
    iterDwarfTypes(pattern: RegExp): AsyncIterableIterator<Type.Base<unknown>>;
    getDwarfTypes(name: string): AsyncIterableIterator<Type.Base<unknown>>;

    /** 返回唯一匹配的运行时地址。无匹配或存在多个地址时返回 null。 */
    lineToAddr(file: string, line: number): bigint | null;
    /** Resolve a symbol or its containing module. Returns null when neither can be identified. */
    symbolAt(addr: bigint): AddressSymbol | null;
    substitutePath(from: string, to: string): void;
    addrToLine(addr: bigint): { file: string; line: number } | null;
    /** 从调试服务端读取地址或帧对应的源码。默认前后各 5 行，找不到源码时返回 null。 */
    list(at: bigint | StackFrame, radius?: number,
        sourcePaths?: readonly { readonly from: string; readonly to: string }[]): SourceListing | null;
    /** 序列化调试值，BigInt 表示为十进制字符串。 */
    stringify(value: unknown): string | undefined;
}

/** 按 kind 区分事件、超时及等待结束；目标退出也可作为 exit 事件返回。 */
export type WaitResult<T> = T | { readonly kind: "timeout" } | { readonly kind: "ended" };

export interface ContinueOptions {
    /** 只交付仍暂停的停点及退出结果。已恢复的记录保留给其他等待接口。 */
    pausedOnly?: boolean;
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
    readonly reason: "fork" | "exec" | "signal" | "breakpoint" | "syscall";
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

export type SyscallStop = EventLocation & {
    readonly kind: "syscall";
    readonly catchId: number;
    readonly phase: "entry" | "exit";
    readonly number: number;
    /** Linux audit architecture identifier. */
    readonly abi: number;
    readonly name?: string;
    readonly parameterNames?: readonly string[];
    readonly parameters?: readonly ({ readonly name: string | null; readonly type: string | null } | null)[];
    readonly pathname?: string;
    readonly args: readonly bigint[];
    readonly result?: bigint;
    readonly failed?: boolean;
};

export type SyscallCaught = SyscallStop & {
    readonly thread: ControlledThread;
    pause(): void;
    continue(): void;
};

export type StoppedEvent =
    | BreakpointStop
    | SyscallStop
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
 * 成功完成的脚本将具名导出挂到 `$` 下，供同一会话的后续脚本使用。
 * 服务端增量合并这些导出的类型声明，切换目标时清空。
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
    log(...args: unknown[]): void;
}

export interface Format {
    print(...values: unknown[]): void;
    printf(format: string, ...args: unknown[]): void;
    sprintf(format: string, ...args: unknown[]): string;
    hexdump(data: Uint8Array, options?: HexdumpOptions): string;
    bytesFromHex(text: string): Uint8Array;
    pVar(...values: unknown[]): void;
    pType(...typesOrValues: (Type.Base<unknown> | Value.Base)[]): void;
    status(): void;
    snapshot(options?: number | { tid?: number; context?: boolean; stopTimeoutMs?: number }): void;
    backtrace(tid?: number): void;
    backtraceAll(): void;
    locals(): void;
    args(): void;
    frame(): void;
    registers(): void;
    address(at: bigint | string): void;
    memory(at: bigint | string, length: number): void;
    disassemble(at: bigint | string, options?: { count?: number }): void;
    modules(): void;
    symbols(options?: { pattern?: RegExp; limit?: number; functionsOnly?: boolean }): Promise<void>;
    diff(before: unknown, after: unknown): void;
    gdb(command: string): Promise<void>;
}

/**
 * Bounded, best-effort presentation. Limits mark truncation inline. Unreadable
 * memory and cycles are marked at the affected branch. Invalid options and
 * invalid debugger sessions throw. Unions show overlapping members without
 * automatically following pointers anywhere in their members.
 */
export interface ValueFormatOptions {
    /** Spaces per level. Default 2, integer 0–32. */
    indent?: number;
    /** Aggregate nesting limit independent of pointer hops. Default 4, integer 0–32. */
    maxDepth?: number;
    /** Elements per array or pointer sequence. Default 32, integer 0–4096. */
    maxElements?: number;
    /** Fields per structure or union. Default 32, integer 0–4096. */
    maxFields?: number;
    /** UTF-8 bytes displayed per string. Default 256, integer 0–4096. */
    maxStringLength?: number;
    /** Global node budget, shared across branches. Default 200, integer 0–4096. */
    maxNodes?: number;
    /**
     * Ordinary pointer dereferences per path. Default 2, integer 0–32.
     * Zero leaves ordinary pointer addresses as-is and retains string and
     * known-length sequence formatting. maxDepth still limits expansion.
     */
    deref?: number;
}

export interface ValueToJSOptions {
    /**
     * Address-valued pointers use bigint by default or hexadecimal strings
     * with "string". Applies recursively. Null pointers remain null, and
     * string and known-length pointers retain their existing conversions.
     * Bigint integers and cycles may still prevent JSON.stringify.
     */
    pointer?: "bigint" | "string";
}

export type PlainValue = number | bigint | boolean | string | null | PlainValue[] | { [key: string]: PlainValue };

// ============================================================================
// 核心类型：TypeSystem（声明式 C/内存类型系统）
// ============================================================================

declare const valueBrand: unique symbol;
declare const charBrand: unique symbol;

export type LiteralString<T extends string> =
    string extends T ? never : T;

export type Infer<T> = T extends Type.Base<infer V> ? V : never;
type PointerItem<T> = Infer<T> extends Read<infer P> ? P : never;
type TerminatedItem<T> = T extends Type.TerminatedPointer<any, infer R, any> ? R : PointerItem<T>;

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

export interface Write<T extends number | bigint | string> {
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

        $asType<T extends Type.Base<unknown>>(type: T): Infer<T>;
        /** Bounded, best-effort presentation for reading. */
        $format(options?: ValueFormatOptions): string;
        /** Strict conversion to ordinary JavaScript data for computation. */
        $toJS(options?: ValueToJSOptions): PlainValue;
        /** Serialize the Value to JSON text. */
        $toJson(): string;
        $dumpString(): string;
    }

    export type Scalar<T extends number | bigint> =
        Base & Sized & Read<T> & Write<T> & Address & Bytes;

    export type Bitfield<T extends number | bigint> =
        Base & Read<T> & Write<T>;

    export type Enum<T extends number | bigint, K extends string> =
        Base & Sized & Read<T> & Write<T | K> & Address & Bytes;

    export type Pointer<V> =
        Base & Sized & Read<bigint> & Write<bigint> &
        Address & Bytes & Index<V> & Deref<V>;

    export type TerminatedPointer<V, R, W> =
        Omit<Pointer<V>, "$deref"> & Deref<R> & {
            $writeContents(contents: W): { writtenBytes: number; previousBytes: number; warning?: string };
        };

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
        withFormatter(formatter: (value: V) => string): this;
        readonly $size: number | undefined;
        readonly $align: number | undefined;

        /**
         * 将类型绑定到目标内存地址；
         * 需要 call 能力时必须绑定线程 tid（也可后续修改返回 Value 的 $tid）。
         */
        at(address: bigint, tid?: number): V;
        $readBytes(address: bigint): Uint8Array;
        $writeBytes(address: bigint, data: Uint8Array): void;
        offsetOf(path: string): number;
        layout(): string;
    }

    export interface Scalar<T extends number | bigint>
        extends Base<Value.Scalar<T>> {
        value(value: T): Value.Scalar<T>;
        align(bytes: number): this;
    }

    export interface EndianScalar<T extends number | bigint> extends Scalar<T> {
        be(): this;
        le(): this;
    }

    export interface Integer<T extends number | bigint> extends Scalar<T> {
        bitfield(width: number): Base<Value.Bitfield<T>>;
        enum<const E extends Readonly<Record<string, T>>>(values: E): Enum<T, Extract<keyof E, string>>;
    }

    export interface EndianInteger<T extends number | bigint> extends Integer<T>, EndianScalar<T> {
        enum<const E extends Readonly<Record<string, T>>>(values: E): EndianEnum<T, Extract<keyof E, string>>;
    }

    export interface Enum<T extends number | bigint, K extends string> extends Base<Value.Enum<T, K>> {
        align(bytes: number): this;
        value(value: T | K): Value.Enum<T, K>;
    }

    export interface EndianEnum<T extends number | bigint, K extends string> extends Enum<T, K> {
        be(): this;
        le(): this;
    }

    export interface Char extends Integer<number> {
        readonly [charBrand]: true;
    }

    export interface TerminatedPointer<T extends Base<unknown>, R, W> extends Base<Value.TerminatedPointer<Infer<T>, R, W>> {
        align(bytes: number): this;
        value(address: bigint): Value.TerminatedPointer<Infer<T>, R, W>;
        pointee(): T;
    }

    export interface Pointer<T extends Base<unknown>>
        extends Base<Value.Pointer<Infer<T>>> {
        value(address: bigint): Value.Pointer<Infer<T>>;
        pointee(): T;
        align(bytes: number): this;
        nullTerminate(maxLength?: number): T extends Char
            ? TerminatedPointer<T, string, string>
            : TerminatedPointer<T, TerminatedItem<T>[], readonly PointerItem<T>[]>;
    }

    export interface Array<T extends Base<unknown>>
        extends Base<Value.Array<Infer<T>>> {
        element(): T;
        align(bytes: number): this;
    }

    export interface Aggregate<F extends Fields>
        extends Base<Value.Aggregate<F>> {
        field<K extends keyof F>(name: K): F[K];
        align(bytes: number): this;
        pack(bytes: number): this;

        refine<const P extends Fields>(
            fields: P & Record<Exclude<keyof P, keyof F>, never>
        ): Aggregate<RefinedFields<F, P>>;
    }
}

// TypeSystem：声明式类型构造接口

export interface TypeSystem {
    void(): Type.Base<void>;

    u8(): Type.Integer<number>;
    i8(): Type.Integer<number>;
    u16(): Type.EndianInteger<number>;
    i16(): Type.EndianInteger<number>;
    u32(): Type.EndianInteger<number>;
    i32(): Type.EndianInteger<number>;
    u64(): Type.EndianInteger<bigint>;
    i64(): Type.EndianInteger<bigint>;

    f32(): Type.EndianScalar<number>;
    f64(): Type.EndianScalar<number>;

    struct<F extends Fields>(
        fields: F,
        option?: AggregateOptions
    ): Type.Aggregate<F>;
    union<F extends Fields>(
        fields: F,
        option?: AggregateOptions
    ): Type.Aggregate<F>;

    array<T extends Type.Base<unknown>>(type: T, length?: Length): Type.Array<T>;
    opaque(length: number): Type.Array<Type.Integer<number>>;
    char(): Type.Char;
    cStr(maxLength?: number): Type.TerminatedPointer<Type.Char, string, string>;
    anonymous<F extends Fields>(type: Type.Aggregate<F>): F;
    anonymous(type: Type.Base<Value.Bitfield<number | bigint>>): {};
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
    /** 为同一类型描述符注册结构化日志和调试值的格式化函数。 */
    setPrettyPrinter<V>(type: Type.Base<V>, printer: ((value: V) => string | undefined) | null): void;
    findTypes(query: string, options?: { exact?: boolean; module?: string }): readonly { readonly name: string; readonly module: string; readonly size: number | null }[];
    /**
     * Get a variable type in the callback thread or main thread’s top frame.
     * Missing DWARF, no match, and exhausted lookups return undefined. An
     * exhausted lookup also emits a diagnostic to the debugger output.
     */
    typeOfVar<const S extends string>(name: S & LiteralString<S>): Type.Base<unknown> | undefined;
    typeOfVar(name: string): Type.Base<unknown> | undefined;
}

export type ExitEvent = {
    readonly kind: "exit";
    readonly sequence: number;
    readonly scope: "thread" | "process";
    readonly tid: number;
    readonly stopReason: "exit";
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
export declare const fmt: Format;

/** 默认延时 0 毫秒。延时须介于 0 和 86400000 毫秒之间，向上取整。返回值可交给 clearTimeout。 */
export declare function setTimeout(cb: () => void, ms?: number): number;
export declare function clearTimeout(id: number): void;
export declare function queueMicrotask(cb: () => void): void;
/** 等待指定毫秒数。signal 由 aidbg 的 AbortController 创建，取消时以 signal.reason 拒绝。 */
export declare function sleep(ms: number, signal?: AbortSignal): Promise<void>;


export interface AbortSignal {
    readonly aborted: boolean;
    readonly reason: unknown;
}

export declare class AbortController {
    readonly signal: AbortSignal;
    /** 取消信号；省略原因时使用 Error，后续调用保留首次取消的原因。 */
    abort(reason?: unknown): void;
}
