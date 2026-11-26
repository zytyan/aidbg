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

pub const QUICK_START: &str = include_str!("../docs/quick-start.md");
pub const SECTIONS: &[(&str, &str)] = &[
    ("debugger", "Targets, memory, threads and execution control"),
    ("types", "TypeSystem, layout and DWARF"),
    ("value", "Typed memory, formatting and data conversion"),
    ("format", "Readable output and Value format options"),
    ("events", "Signals, stop events and waits"),
    ("breakpoints", "Breakpoints, watchpoints and callbacks"),
    ("all", "Complete TypeScript declarations and module APIs"),
];

pub fn section_index() -> String {
    let entries = SECTIONS
        .iter()
        .map(|(name, text)| format!("- `{name}` — {text}"))
        .collect::<Vec<_>>();
    format!(
        "## More documentation\n\n{}\n\nCall docs({{section: \"...\"}}).",
        entries.join("\n")
    )
}

pub fn section(name: &str) -> Option<String> {
    let (intro, roots) = match name {
        "debugger" => (
            "Use dbg for typed access to the active process or core.",
            "Debugger ControlledThread",
        ),
        "types" => (
            "Use m to define types or load types from available DWARF.",
            "TypeSystem",
        ),
        "value" => (
            "Values provide typed access to memory and explicit reading, formatting and conversion.",
            "Value",
        ),
        "format" => (
            "fmt writes readable output directly. Value.$format returns a string.",
            "Format ValueFormatOptions",
        ),
        "events" => (
            "Use dbg.waitStops, dbg.continueForStop and dbg.onSignal for target events.",
            "StopEvent StopBatch ContinueOptions WaitResult SignalHit SignalCallback SyscallCaught",
        ),
        "breakpoints" => (
            "Install points with dbg.softwareBreakpoint, dbg.pendingBreakpoint, dbg.hardwareBreakpoint or dbg.hardwareWatchpoint or dbg.softwareWatchpoint.",
            "Breakpoint BreakpointOptions PendingBreakpoint BreakpointCallback WatchpointCallback WatchpointOptions",
        ),
        _ => return None,
    };
    let source = DEBUGGER_DECLARATIONS;
    let mut declarations = Vec::new();
    let mut offset = 0;
    let mut comment = None;
    let mut separator = None;
    for line in source.split_inclusive('\n') {
        if line.starts_with("// ===") {
            separator.get_or_insert(offset);
        } else if line.starts_with("/**") || line.starts_with("// ") {
            comment.get_or_insert(offset);
        } else if let Some(line) = line.strip_prefix("export ").or_else(|| {
            (line.starts_with("interface ") || line.starts_with("declare ")).then_some(line)
        }) {
            let line = line.strip_prefix("declare ").unwrap_or(line);
            if let Some((_, signature)) = line.split_once(' ') {
                let symbol = signature
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or_default();
                let start = comment
                    .filter(|&start| separator.is_none_or(|section| start > section))
                    .unwrap_or(offset);
                let end = separator.or(comment).unwrap_or(offset);
                declarations.push((symbol, start, end));
            }
            comment = None;
            separator = None;
        } else if !line.trim().is_empty() && !line.starts_with(" *") {
            comment = None;
        }
        offset += line.len();
    }
    let methods: &[&str] = match name {
        "events" => &[
            "onSignal",
            "catchSyscall",
            "waitStop",
            "waitStops",
            "continueForStop",
            "waitExit",
        ],
        "breakpoints" => &[
            "pendingBreakpoint",
            "softwareBreakpoint",
            "hardwareBreakpoint",
            "softwareWatchpoint",
            "hardwareWatchpoint",
        ],
        _ => &[],
    };
    let mut methods_text = String::new();
    if let Some((i, (_, start, _))) = declarations
        .iter()
        .enumerate()
        .find(|(_, entry)| entry.0 == "Debugger")
        && !methods.is_empty()
    {
        let end = declarations
            .get(i + 1)
            .map_or(source.len(), |entry| entry.2);
        let mut in_method = false;
        for line in source[*start..end].lines() {
            if !in_method {
                in_method = line
                    .strip_prefix("    ")
                    .and_then(|line| line.split_once('('))
                    .is_some_and(|(name, _)| methods.contains(&name));
            }
            if in_method {
                methods_text.push_str(line);
                methods_text.push('\n');
                in_method = !line.ends_with(';');
            }
        }
    }
    let words = |c: char| !c.is_ascii_alphanumeric() && c != '_';
    let mut selected: std::collections::BTreeSet<_> = roots.split_whitespace().collect();
    selected.extend(
        methods_text
            .split(words)
            .filter(|candidate| declarations.iter().any(|entry| entry.0 == *candidate)),
    );
    loop {
        let before = selected.len();
        for (i, (symbol, start, _)) in declarations.iter().enumerate() {
            if selected.contains(symbol) {
                let end = declarations
                    .get(i + 1)
                    .map_or(source.len(), |entry| entry.2);
                selected.extend(
                    source[*start..end]
                        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .filter(|candidate| declarations.iter().any(|entry| entry.0 == *candidate)),
                );
            }
        }
        if before == selected.len() {
            break;
        }
    }
    let body = declarations
        .iter()
        .enumerate()
        .filter_map(|(i, (symbol, start, _))| {
            let end = declarations
                .get(i + 1)
                .map_or(source.len(), |entry| entry.2);
            selected
                .contains(symbol)
                .then(|| source[*start..end].trim())
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    if methods_text.is_empty() {
        Some(format!("{intro}\n\n```ts\n{body}\n```"))
    } else {
        Some(format!(
            "{intro}\n\n```ts\ninterface Debugger {{\n{methods_text}}}\n\n{body}\n```"
        ))
    }
}
