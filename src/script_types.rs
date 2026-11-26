pub const DEBUGGER_DECLARATIONS: &str = include_str!("../docs/debugger.d.ts");
pub const NODE_DECLARATIONS: &str = include_str!("script/session/node.d.ts");

/// The aidbg module and globals available at the start of a script session.
pub fn declarations() -> String {
    let api = DEBUGGER_DECLARATIONS.replace("export declare ", "export ");
    format!(
        r#"declare module "aidbg" {{
{api}
}}
interface AidbgGlobals {{}}
declare const dbg: import("aidbg").Debugger;
declare const m: import("aidbg").TypeSystem;
declare const $: AidbgGlobals & import("aidbg").GlobalScope;
declare const console: import("aidbg").Console;
declare const fmt: import("aidbg").Format;
declare const setTimeout: typeof import("aidbg").setTimeout;
declare const clearTimeout: typeof import("aidbg").clearTimeout;
declare const queueMicrotask: typeof import("aidbg").queueMicrotask;
declare const sleep: typeof import("aidbg").sleep;
declare const AbortController: typeof import("aidbg").AbortController;
type AbortSignal = import("aidbg").AbortSignal;
"#
    )
}
