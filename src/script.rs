pub(crate) mod breakpoint;
mod compiler;
mod core;
mod debugger;
pub(crate) use core::memory::{live_missing_memory, pointer_chain_with, read_range};
pub use core::memory::{pointer_chain_live, read_live, search_live};
pub(crate) mod live;
mod runtime;
pub mod synchronization;
pub use live::RunResult as LiveRunResult;
pub(crate) mod signal;

pub use core::CoreInfo;

use self::{compiler::Compiler, core::Target};
use crate::{Result, error};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};

mod api;
pub use api::*;
use api::{DECLARATIONS, LIVE_DECLARATIONS, RULE_DECLARATIONS, SIGNAL_DECLARATIONS};

const MAX_SOURCE_BYTES: usize = 64 * 1024;
pub const MAX_OPEN_CORES: u32 = 16;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Range {
    // Offsets are zero-based UTF-16 code units, with the end exclusive.
    pub start: u32,
    pub end: u32,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub source: &'static str,
    pub code: String,
    pub severity: &'static str,
    pub message: String,
    pub file: Option<String>,
    pub range: Option<Range>,
}

impl Diagnostic {
    fn is_error(&self) -> bool {
        self.severity == "error"
    }
}

#[derive(Serialize)]
pub struct ExpressionCheck {
    status: &'static str,
    expression: Option<String>,
    code: &'static str,
    range: Range,
}

#[derive(Serialize)]
pub struct CheckResult {
    pub status: &'static str,
    pub diagnostics: Vec<Diagnostic>,
    pub expressions: Vec<ExpressionCheck>,
    pub warnings: Vec<crate::Diagnostic>,
    pub check_us: u64,
}

#[derive(Serialize)]
pub struct RunResult {
    pub stop_reason: &'static str,
    pub output: Vec<Value>,
    pub return_value: Value,
    #[serde(flatten)]
    pub check: CheckResult,
    pub emit_us: Option<u64>,
    pub execute_us: Option<u64>,
}

#[derive(Default)]
pub struct Scripts {
    remote_limit: Option<u32>,
    compiler: Mutex<Option<Compiler>>,
    rules_compiler: Mutex<Option<Compiler>>,
    live_compiler: Mutex<Option<Compiler>>,
    signals_compiler: Mutex<Option<Compiler>>,
    targets: Mutex<BTreeMap<String, Arc<Target>>>,
}

impl Scripts {
    pub fn remote(max_open_cores: u32) -> Self {
        Self {
            remote_limit: Some(max_open_cores.clamp(1, MAX_OPEN_CORES)),
            ..Self::default()
        }
    }

    pub fn max_open_cores(&self) -> u32 {
        self.remote_limit.unwrap_or(MAX_OPEN_CORES)
    }

    pub fn open(&self, path: &Path, symbols: CoreSymbols) -> Result<CoreInfo> {
        self.add_target(core::open_path(path)?, symbols, false)
    }

    pub fn open_compressed(&self, source: impl Read, symbols: CoreSymbols) -> Result<CoreInfo> {
        self.add_target(
            core::decompress(source)?,
            symbols,
            self.remote_limit.is_some(),
        )
    }

    fn add_target(
        &self,
        file: std::fs::File,
        symbols: CoreSymbols,
        use_recorded_symbols: bool,
    ) -> Result<CoreInfo> {
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| error("target store unavailable"))?;
        let limit = self.max_open_cores();
        if targets.len() >= limit as usize {
            return Err(crate::Diagnostic::new(
                "INVALID_ARGUMENT",
                format!("At most {limit} cores can be open. Close a core before opening another."),
                None,
            )
            .into());
        }
        let temporary = tempfile::Builder::new()
            .prefix(if self.remote_limit.is_some() {
                "remote-core-"
            } else {
                "core-"
            })
            .rand_bytes(24)
            .tempfile()?;
        let id = temporary
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let (target, info) = Target::open(id.clone(), file, symbols, use_recorded_symbols)?;
        targets.insert(id, Arc::new(target));
        Ok(info)
    }

    pub fn core_images(
        source: impl Read,
        symbols: CoreSymbols,
    ) -> Result<(Value, Vec<(String, Vec<u8>)>)> {
        let (target, info) = Target::open(String::new(), core::decompress(source)?, symbols, true)?;
        let metadata = serde_json::to_value(info)?;
        Ok((metadata, target.into_images()?))
    }

    pub fn close(&self, id: &str) -> Result<Value> {
        if self
            .targets
            .lock()
            .map_err(|_| error("target store unavailable"))?
            .remove(id)
            .is_none()
        {
            return Err(crate::Diagnostic::new(
                "TARGET_GONE",
                "core target ID not found",
                Some("Open the core again to get a current target_id."),
            )
            .into());
        }
        Ok(serde_json::json!({ "target_id": id, "closed": true }))
    }

    fn target(&self, id: &str) -> Result<Arc<Target>> {
        self.targets
            .lock()
            .map_err(|_| error("target store unavailable"))?
            .get(id)
            .cloned()
            .ok_or_else(|| {
                crate::Diagnostic::new(
                    "TARGET_GONE",
                    "core target ID not found",
                    Some("Open the core again to get a current target_id."),
                )
                .into()
            })
    }

    pub fn symbols(&self, request: crate::rpc::SearchSymbolsRequest) -> Result<Value> {
        self.query_target(request.pid, request.target_id.as_deref())?
            .symbols(&request)
    }

    pub fn resolve(&self, request: crate::rpc::ResolveAddressRequest) -> Result<Value> {
        self.query_target(request.pid, request.target_id.as_deref())?
            .resolve(request.address)
    }

    pub fn disassemble(&self, request: crate::rpc::DisassembleRequest) -> Result<Value> {
        let target = self.query_target(request.pid, request.target_id.as_deref())?;
        let mut window = target.disassemble(&request)?;
        window.warnings.extend(target.warnings.iter().cloned());
        Ok(serde_json::to_value(window)?)
    }

    pub fn patch(&self, request: crate::rpc::PatchRequest) -> Result<Value> {
        if let Some(id) = &request.target_id {
            return self.target(id)?.patch(request);
        }
        if request.original_length.is_some() {
            return Err(crate::Diagnostic::new(
                "INVALID_ARGUMENT",
                "original_length requires a core target_id",
                None,
            )
            .into());
        }
        Ok(serde_json::to_value(crate::code::patch(request)?)?)
    }

    pub fn emulate(&self, request: crate::rpc::EmulateRequest) -> Result<Value> {
        if let Some(id) = &request.target_id {
            return self.target(id)?.emulate(request);
        }
        if request.frame.is_some()
            || request.code_length.is_some()
            || !request.core_memory.is_empty()
        {
            return Err(crate::Diagnostic::new(
                "INVALID_ARGUMENT",
                "Core state requires a target_id",
                None,
            )
            .into());
        }
        Ok(serde_json::to_value(crate::code::emulate(request)?)?)
    }

    pub fn search_memory(&self, request: crate::rpc::SearchMemoryRequest) -> Result<Value> {
        self.target(&request.target_id)?.search_memory(&request)
    }

    pub fn inspect_core(&self, request: crate::rpc::InspectRequest) -> Result<Value> {
        self.target(request.target_id.as_deref().unwrap_or_default())?
            .inspect_request(request)
    }

    pub fn read_memory(&self, request: crate::rpc::ReadMemoryRequest) -> Result<Value> {
        self.query_target(0, request.target_id.as_deref())?
            .read_memory(&request)
    }

    pub fn observe_threads(&self, request: crate::script_observation::Request) -> Result<Value> {
        let target = self.query_target(0, request.target_id.as_deref())?;
        target.observe_threads(request)
    }

    pub fn pointer_chain(&self, request: crate::rpc::PointerChainRequest) -> Result<Value> {
        self.target(&request.target_id)?
            .pointer_chain(request.base, request.offsets)
    }

    fn query_target(&self, pid: i32, id: Option<&str>) -> Result<Arc<Target>> {
        let id = id.filter(|id| pid == 0 && !id.is_empty()).ok_or_else(|| {
            crate::Diagnostic::new(
                "INVALID_ARGUMENT",
                "Specify exactly one positive pid or a target_id",
                None,
            )
        })?;
        self.target(id)
    }

    fn compile(
        &self,
        source: &str,
        mode: Mode,
        target: Option<&Target>,
        emit: bool,
    ) -> Result<(CheckResult, Option<(String, u64)>)> {
        if source.len() > MAX_SOURCE_BYTES {
            return Err(crate::Diagnostic::new(
                "INVALID_ARGUMENT",
                "script source exceeds 64 KiB",
                None,
            )
            .into());
        }
        let started = Instant::now();
        let (compiler, declarations) = match mode {
            Mode::Offline => (&self.compiler, DECLARATIONS),
            Mode::Breakpoint => (&self.rules_compiler, RULE_DECLARATIONS),
            Mode::Live => (&self.live_compiler, LIVE_DECLARATIONS),
            Mode::Signal => (&self.signals_compiler, SIGNAL_DECLARATIONS),
        };
        let mut guard = compiler
            .lock()
            .map_err(|_| error("script compiler unavailable"))?;
        let compiler = guard.get_or_insert_with(|| Compiler::new(declarations));
        let (diagnostics, expressions) =
            compiler.check(source, target, matches!(mode, Mode::Offline))?;
        let failed = diagnostics.iter().any(Diagnostic::is_error);
        let checked = CheckResult {
            status: if failed { "failed" } else { "complete" },
            diagnostics,
            warnings: target.map_or_else(Vec::new, |target| target.warnings.clone()),
            expressions,
            check_us: elapsed_us(started),
        };
        let emitted = if emit && !failed {
            let started = Instant::now();
            let js = compiler.emit()?;
            Some((js, elapsed_us(started)))
        } else {
            None
        };
        Ok((checked, emitted))
    }

    pub fn check(&self, request: CheckRequest) -> Result<CheckResult> {
        if !matches!(request.mode, Mode::Offline) && request.target_id.is_some() {
            let mode = match request.mode {
                Mode::Breakpoint => "breakpoint",
                Mode::Signal => "signal",
                Mode::Live => "live",
                Mode::Offline => unreachable!(),
            };
            return Err(error(format!(
                "{mode} script checks do not take an offline target ID"
            )));
        }
        let target = request
            .target_id
            .as_deref()
            .map(|id| self.target(id))
            .transpose()?;
        if matches!(request.mode, Mode::Offline | Mode::Live) {
            self.compile_program(&request.source, request.mode, target.as_deref(), false)
        } else {
            self.compile(&request.source, request.mode, target.as_deref(), false)
        }
        .map(|(checked, _)| checked)
    }

    /// Compile the callback before sending it to the target's tracer thread.
    pub fn compile_breakpoint(&self, source: &str) -> Result<String> {
        self.compile_handler(source, Mode::Breakpoint)
    }

    pub fn compile_live(&self, source: &str) -> Result<String> {
        let (check, emitted) = self.compile_program(source, Mode::Live, None, true)?;
        emitted.map(|(js, _)| js).ok_or_else(|| {
            error(
                serde_json::to_string(&check).unwrap_or_else(|_| "TypeScript check failed".into()),
            )
        })
    }

    pub fn compile_signal(&self, source: &str) -> Result<String> {
        self.compile_handler(source, Mode::Signal)
    }

    fn compile_handler(&self, source: &str, mode: Mode) -> Result<String> {
        let (check, emitted) = self.compile(source, mode, None, true)?;
        emitted.map(|(js, _)| js).ok_or_else(|| {
            error(
                serde_json::to_string(&check).unwrap_or_else(|_| "TypeScript check failed".into()),
            )
        })
    }

    fn compile_program(
        &self,
        source: &str,
        mode: Mode,
        target: Option<&Target>,
        emit: bool,
    ) -> Result<(CheckResult, Option<(String, u64)>)> {
        let checked = self.compile(source, mode.clone(), target, emit)?;
        if !checked
            .0
            .diagnostics
            .iter()
            .any(|issue| issue.code == "1108")
        {
            return Ok(checked);
        }
        let body = "export default async function main() {\n";
        let wrapped = format!("{body}{source}\n}}");
        let (mut checked, emitted) = self.compile(&wrapped, mode, target, emit)?;
        for range in checked
            .diagnostics
            .iter_mut()
            .filter_map(|issue| issue.range.as_mut())
            .chain(
                checked
                    .expressions
                    .iter_mut()
                    .map(|expression| &mut expression.range),
            )
        {
            range.start = range.start.saturating_sub(body.len() as u32);
            range.end = range.end.saturating_sub(body.len() as u32);
            range.line = range.line.saturating_sub(1).max(1);
            range.end_line = range.end_line.saturating_sub(1).max(1);
        }
        Ok((checked, emitted))
    }

    pub fn run(&self, request: RunRequest) -> Result<RunResult> {
        let budget = request.budget()?;
        let target = self.target(
            request
                .target_id
                .as_deref()
                .ok_or_else(|| error("provide target_id"))?,
        )?;
        let (check, emitted) =
            self.compile_program(&request.source, Mode::Offline, Some(&target), true)?;
        let mut result = RunResult {
            stop_reason: "check_failed",
            output: Vec::new(),
            return_value: Value::Null,
            check,
            emit_us: None,
            execute_us: None,
        };
        if let Some((js, emit_us)) = emitted {
            let started = Instant::now();
            let execution = runtime::execute(js, target, budget)?;
            result.stop_reason = execution.stop_reason;
            result.output = execution.output;
            result.return_value = execution.return_value;
            result.emit_us = Some(emit_us);
            result.execute_us = Some(elapsed_us(started));
            if let Some(message) = execution.issue {
                result.check.status = "failed";
                result.check.diagnostics.push(Diagnostic {
                    source: "quickjs",
                    code: execution.stop_reason.to_owned(),
                    severity: "error",
                    message,
                    file: None,
                    range: None,
                });
            }
        }
        Ok(result)
    }
}

fn elapsed_us(start: Instant) -> u64 {
    start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}
