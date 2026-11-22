interface DebugValue {
    readonly status: string;
    readonly result: {
        readonly type: {
            readonly name: string | null;
            readonly kind: string;
            readonly byte_size: number;
            readonly element_count?: number;
            readonly dimensions?: readonly number[];
            readonly fields?: readonly DebugField[];
        };
        readonly address: bigint | null;
        readonly bytes: string;
        readonly value: bigint | number | boolean | null;
        readonly symbol?: DebugAddressSymbol;
        readonly preview?: {
            readonly address: string;
            readonly length: number | null;
            readonly text: string;
            readonly bytes: string;
            readonly status: string;
        };
    } | null;
    readonly issue: string | null;
    readonly code?: string;
    readonly message?: string;
    readonly hint?: string | null;
    readonly children?: DebugPage<{ readonly expression: string; readonly value: DebugValue }>;
}

interface DebugField {
    readonly name: string | null;
    readonly type_name: string | null;
    readonly offset: number | null;
    readonly byte_size: number | null;
    readonly base_class: boolean;
    readonly element_type?: string;
    readonly element_count?: number;
    readonly dimensions?: readonly number[];
}

type DebugJson = null | boolean | number | string | readonly DebugJson[]
    | { readonly [key: string]: DebugJson };


interface DebugWarning {
    readonly code: string;
    readonly message: string;
    readonly hint: string | null;
}

interface DebugPage<T> {
    readonly items: readonly T[];
    readonly next_offset: number | null;
    readonly warnings: readonly DebugWarning[];
}

interface DebugPageOptions {
    readonly offset?: number;
    readonly limit?: number;
}

interface DebugVariable {
    readonly name: string;
    readonly kind: "parameter" | "variable";
    readonly scope: "local" | "global";
    readonly scope_depth: number;
    readonly module: string;
    readonly unit_offset: number | null;
    readonly availability: string;
}

interface DebugType {
    readonly fields?: readonly DebugField[] | null;
    readonly layout_issue?: string | null;
    readonly name: string;
    readonly kind: string;
    readonly module: string;
    readonly byte_size: number | null;
    readonly unit_offset: number | null;
}

interface DebugModule {
    readonly path: string;
    readonly build_id?: string;
    readonly device?: string;
    readonly inode?: string;
    readonly mappings?: readonly {
        readonly start: string;
        readonly end: string;
        readonly offset: string | null;
    }[];
}

interface DebugMemory {
    readonly view: DataView;
    readonly bytes: string;
    readonly complete: boolean;
}

interface DebugInspectOptions {
    readonly expand?: DebugPageOptions;
}

interface DebugPrintOptions extends DebugInspectOptions {
    readonly label?: string;
}

interface DebugEmit {
    (label: string, value: string | number | bigint | boolean | null | DataView | Uint8Array): void;
    (label: string, value: bigint, options: { kind: "pointer" }): void;
    (label: string, value: unknown, options: { kind: "json" }): void;
}

type DebugFrameRef = string | DebugFrame;

interface DebugMemoryScope {
    threads(): readonly DebugThread[];
    frames(tid: number): readonly DebugFrame[];
    modules(): readonly DebugModule[];
    memory(address: bigint, length: number): DebugMemory;
    globals(glob?: string, page?: DebugPageOptions): DebugPage<DebugVariable>;
    types(glob?: string, page?: DebugPageOptions): DebugPage<DebugType>;
    readonly emit: DebugEmit;
}
interface DebugThread {
    readonly tid: number;
}

interface DebugArguments {
    readonly status: string;
    readonly items: readonly { readonly name: string; readonly value: DebugJson }[];
}

interface DebugFrame {
    readonly args?: DebugArguments;
    readonly handle: string;
    readonly pc: string;
    readonly function: string | null;
    readonly file: string | null;
    readonly line: number | null;
    readonly column: number | null;
}

interface DebugConsole {
    log(...values: unknown[]): void;
}

interface DebugCoreScope extends DebugMemoryScope {
    locals(frame: DebugFrameRef, page?: DebugPageOptions): DebugPage<DebugVariable>;
    inspect(expr: string, options: DebugInspectOptions & { frame: DebugFrameRef }): DebugValue;
    printVal(expr: string, options: DebugPrintOptions & { frame: DebugFrameRef }): void;
}
interface DebugStoppedScope extends DebugMemoryScope {
    inspect(expression: string, options?: DebugInspectOptions & { readonly frame?: DebugFrameRef }): DebugValue;
    printVal(expression: string, options?: DebugPrintOptions & { readonly frame?: DebugFrameRef }): void;
    locals(page?: DebugPageOptions): DebugPage<DebugVariable>;
    locals(frame: DebugFrameRef, page?: DebugPageOptions): DebugPage<DebugVariable>;
}

interface BreakpointHit extends DebugStoppedScope {
    readonly pid: number;
    readonly tid: number;
    readonly address: bigint;
    readonly kind: "hardware_execution" | "software_execution" | "hardware_read" | "hardware_write" | "hardware_read_write";
    readonly registers: Readonly<Record<string, bigint | undefined>>;
    readonly watch?: {
        readonly valueBefore?: bigint;
        readonly valueAfter?: bigint;
        readonly changed?: boolean;
    };
    snapshot(): void;
    /** Disarm this breakpoint after the current hit. */
    disable(): void;
}
interface DebugRuleDefinition {
    /** Return false to suppress this successful hit and its snapshot. */
    onHit: (hit: BreakpointHit) => void;
    maxHits?: number;
    pauseBudgetMs?: number;
}
interface LiveBreakpointOptions {
    tid?: number;
    timeoutMs?: number;
}

interface BreakpointHandle {
    readonly id: number;
}

type BreakpointCallback = (hit: BreakpointHit) => void | boolean;

interface DebugAddressSymbol {
    readonly address: string;
    readonly name: string;
    readonly offset: number;
    readonly display: string | null;
}

interface LiveBreakpointEvent {
    readonly breakpoint_id: number;
    readonly rule_id?: number;
    readonly rule_revision?: number;
    readonly pid: number;
    readonly tid: number;
    readonly address: string;
    readonly kind: BreakpointHit["kind"];
    readonly instruction_pc: string;
    readonly pc_relation: "at_instruction" | "after_instruction";
    readonly stop_context?: {
        readonly site: {
            readonly address: string;
            readonly function?: string | null;
            readonly symbol?: DebugAddressSymbol | null;
            readonly source_line?: { readonly file: string; readonly line: number | null } | null;
        };
        readonly watched_symbol: DebugAddressSymbol | null;
        readonly args: DebugArguments;
    };
    readonly observed_unix_ms: number;
    readonly pause_ms: number;
    readonly capture_status: string;
    readonly resume_status: string;
    readonly watch: {
        readonly length: number;
        readonly access: "read" | "write" | "read_write";
        readonly write_observed: boolean | null;
        readonly value_before: string | null;
        readonly value_after: string | null;
        readonly value_changed: boolean | null;
        readonly reported_address?: string;
        readonly attribution?: string;
    } | null;
    readonly callback?: {
        readonly hit: number;
        readonly status: string;
        readonly issue: string | null;
        readonly disarming: boolean;
        readonly output: readonly {
            readonly label: string;
            readonly value: bigint | DebugJson;
        }[];
    };
}

interface DebugLiveScope extends DebugStoppedScope {
    hardwareBreakpoint(address: bigint, callback?: BreakpointCallback, options?: LiveBreakpointOptions): BreakpointHandle;
    softwareBreakpoint(address: bigint, callback?: BreakpointCallback, options?: LiveBreakpointOptions): BreakpointHandle;
    watchpoint(address: bigint, length: 1 | 2 | 4 | 8, access: "read" | "write" | "read_write", callback: BreakpointCallback, options?: LiveBreakpointOptions): BreakpointHandle;
    continue(): void;
    events(): Promise<readonly LiveBreakpointEvent[]>;
}
