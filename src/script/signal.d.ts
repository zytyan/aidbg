type SignalNumber = number & { readonly __signalNumber: unique symbol };
declare const builtins: Readonly<Record<
    "SIGHUP" | "SIGINT" | "SIGQUIT" | "SIGILL" | "SIGTRAP" | "SIGABRT" |
    "SIGBUS" | "SIGFPE" | "SIGUSR1" | "SIGSEGV" | "SIGUSR2" | "SIGPIPE" |
    "SIGALRM" | "SIGTERM" | "SIGCHLD" | "SIGCONT" | "SIGTSTP" |
    "SIGTTIN" | "SIGTTOU" | "SIGURG" | "SIGXCPU" | "SIGXFSZ" |
    "SIGVTALRM" | "SIGPROF" | "SIGWINCH" | "SIGIO" | "SIGSYS", SignalNumber>>;

interface SignalEvent {
    readonly pid: number;
    readonly tid: number;
    readonly signal: SignalNumber;
    readonly name: string;
    readonly code: number;
    readonly faultAddress: bigint | null;
}

declare const dbg: {
    onSignal(signal: SignalNumber, callback: (event: SignalEvent) => void): void;
    /** Save a server-side ELF core from the current signal stop. The run result contains its dump ID. */
    coredump(mode: "full"): void;
};
