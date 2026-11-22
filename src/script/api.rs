use crate::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct CoreSymbols {
    pub executable: Option<PathBuf>,
    pub debug_symbols: Option<PathBuf>,
}

pub(super) const DECLARATIONS: &str = concat!(
    include_str!("debugger.d.ts"),
    "\ndeclare const dbg: DebugCoreScope;\ndeclare const console: DebugConsole;\n"
);
const EXAMPLE: &str = r#"const thread: DebugThread | undefined = dbg.threads().find(t => t.tid === 1234);
if (thread) {
    const frame: DebugFrame | undefined = dbg.frames(thread.tid)[0];
    if (frame) dbg.printVal("g_Data->foo[10].bar->baz", { frame: frame.handle });
}
"#;
const DISCOVERY_EXAMPLE: &str = r#"export default function main() {
    const thread: DebugThread | undefined = dbg.threads()[0];
    if (!thread) return null;

    const frame: DebugFrame | undefined = dbg.frames(thread.tid)[0];
    if (!frame) return null;

    const locals: DebugPage<DebugVariable> = dbg.locals(frame.handle, { limit: 16 });
    console.log(frame.function, frame.file, frame.line);
    for (const variable of locals.items) {
        if (variable.availability === "readable") {
            dbg.printVal(variable.name, { frame: frame.handle });
        }
    }
    return { pc: frame.pc, locals: locals.items.map(variable => variable.name) };
}
"#;
pub(super) const RULE_DECLARATIONS: &str = concat!(
    include_str!("debugger.d.ts"),
    "\ndeclare function defineRule(rule: DebugRuleDefinition): void;\n"
);
pub(super) const LIVE_DECLARATIONS: &str = concat!(
    include_str!("debugger.d.ts"),
    "\ndeclare const dbg: DebugLiveScope;\n"
);
const LIVE_EXAMPLE: &str = r#"let hits = 0;
dbg.hardwareBreakpoint(0x401020n, hit => {
    hit.emit("hits", ++hits);
    if (hits === 3) hit.disable();
}, { tid: 1234, timeoutMs: 50 });
"#;
const RULE_EXAMPLE: &str = r#"let matches = 0;
export default function onHit(hit: BreakpointHit) {
    if (hit.watch?.changed === false) return false;
    hit.emit("address", hit.address);
    if (++matches === 3) hit.disable();
}
"#;
pub(super) const SIGNAL_DECLARATIONS: &str = include_str!("signal.d.ts");
const SIGNAL_EXAMPLE: &str = r#"dbg.onSignal(builtins.SIGSEGV, (seg) => {
    dbg.coredump("full");
});
"#;

#[derive(Clone, Copy, Default, Serialize, Deserialize, JsonSchema, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Offline,
    Breakpoint,
    Live,
    Signal,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct OpenRequest {
    pub path: Option<std::path::PathBuf>,
    pub dump_id: Option<String>,
    #[serde(default)]
    pub upload: bool,
    #[serde(flatten)]
    pub symbols: CoreSymbols,
}

#[derive(Deserialize, Serialize)]
pub struct CoreImagesRequest {
    pub dump_id: String,
    #[serde(flatten)]
    pub symbols: CoreSymbols,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CloseRequest {
    pub target_id: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ApiRequest {
    #[serde(default)]
    pub mode: Mode,
}

#[derive(Serialize)]
pub struct Api {
    mode: Mode,
    declarations: &'static str,
    example: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    discovery_example: Option<&'static str>,
}

pub fn api(request: ApiRequest) -> Result<Api> {
    let (declarations, example) = match request.mode {
        Mode::Offline => (DECLARATIONS, EXAMPLE),
        Mode::Breakpoint => (RULE_DECLARATIONS, RULE_EXAMPLE),
        Mode::Live => (LIVE_DECLARATIONS, LIVE_EXAMPLE),
        Mode::Signal => (SIGNAL_DECLARATIONS, SIGNAL_EXAMPLE),
    };
    Ok(Api {
        mode: request.mode,
        declarations,
        example,
        discovery_example: matches!(request.mode, Mode::Offline).then_some(DISCOVERY_EXAMPLE),
    })
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CheckRequest {
    pub source: String,
    #[serde(default)]
    pub mode: Mode,
    pub target_id: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RunRequest {
    pub source: String,
    pub target_id: Option<String>,
    pub run_id: Option<String>,
    pub timeout_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(skip)]
    pub replay_points: Vec<LiveReplayPoint>,
}

impl RunRequest {
    pub fn budget(&self) -> Result<std::time::Duration> {
        let millis = self.timeout_ms.unwrap_or(1000);
        if !(1..=10_000).contains(&millis) {
            return Err(crate::Diagnostic::new(
                "INVALID_ARGUMENT",
                "script timeout_ms must be in 1..=10000",
                None,
            )
            .into());
        }
        Ok(std::time::Duration::from_millis(u64::from(millis)))
    }
}

#[derive(Deserialize, Serialize)]
pub struct LiveReplayPoint {
    pub original_breakpoint_id: u64,
    pub ordinal: usize,
    pub requested_address: u64,
    pub module: String,
    pub offset: u64,
    pub kind: String,
    pub leader_only: bool,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    #[default]
    Breakpoint,
    Exports,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RuleDefine {
    #[serde(default)]
    pub mode: RuleMode,
    pub name: String,
    pub source: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RuleUpdate {
    pub rule_id: u64,
    pub source: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RuleId {
    pub rule_id: u64,
}
