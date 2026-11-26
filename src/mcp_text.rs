use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::fmt::Write;

const TEXT_BUDGET: usize = 32 * 1024;
const STRUCTURED_BUDGET: usize = 2 * 1024 * 1024;

fn clip(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let end = text.floor_char_boundary(limit);
    text[..end]
        .rsplit_once('\n')
        .map_or(&text[..end], |(lines, _)| lines)
}

fn limited_blocks(blocks: Vec<String>, limit: usize) -> (String, bool) {
    let mut text = String::new();
    for block in blocks {
        let separator = usize::from(!text.is_empty() && !text.ends_with('\n'));
        let left = limit.saturating_sub(text.len() + separator);
        if block.len() > left {
            let fragment = clip(&block, left);
            if !fragment.is_empty() {
                if separator > 0 {
                    text.push('\n');
                }
                text.push_str(fragment);
            }
            return (text, true);
        }
        if separator > 0 && !block.is_empty() {
            text.push('\n');
        }
        text.push_str(&block);
    }
    (text, false)
}

fn limited_text(ordinary: Vec<String>, critical: Vec<String>) -> String {
    const NOTICE: &str = "* Output truncated for display.";
    let budget = TEXT_BUDGET - NOTICE.len() - 4;
    let (important, important_clipped) = limited_blocks(critical, budget);
    let (text, clipped) = limited_blocks(ordinary, budget.saturating_sub(important.len() + 2));
    let mut parts = vec![text.as_str(), important.as_str()];
    if clipped || important_clipped {
        parts.push(NOTICE);
    }
    parts
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn structured_fits(value: &Value) -> bool {
    struct Limit(usize);
    impl std::io::Write for Limit {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("structured output limit reached"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Limit(STRUCTURED_BUDGET), value).is_ok()
}

pub fn document(data: Value) -> CallToolResult {
    let mut reply = CallToolResult::success(Vec::new());
    reply.structured_content = Some(data);
    reply
}

pub fn document_error(data: Value) -> CallToolResult {
    let mut reply = CallToolResult::error(Vec::new());
    reply.structured_content = Some(data);
    reply
}

pub fn error(text: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(limited_text(
        vec![text.into()],
        vec![],
    ))])
}

#[derive(Default)]
pub struct Presentation {
    asynchronous: BTreeSet<u64>,
    stopped: Value,
    target: Value,
    last_event: Option<u64>,
}

impl Presentation {
    pub fn render(
        &mut self,
        mut reply: CallToolResult,
        tool: &str,
        source: Option<&str>,
        path: Option<&str>,
        structured: bool,
    ) -> CallToolResult {
        let Some(data) = reply.structured_content.take() else {
            return reply;
        };
        if tool == "docs" {
            if structured {
                return if reply.is_error == Some(true) {
                    document_error(data)
                } else {
                    document(data)
                };
            }
            let content = vec![ContentBlock::text(
                data["text"].as_str().unwrap_or_default(),
            )];
            return if reply.is_error == Some(true) {
                CallToolResult::error(content)
            } else {
                CallToolResult::success(content)
            };
        }
        let structured_overflow = structured && !structured_fits(&data);
        let mut failed = reply.is_error.unwrap_or(false);
        let result = &data["result"];
        let id = result["script_id"].as_u64();
        let status = result["status"].as_str().unwrap_or_default();
        failed |= matches!(status, "check_failed" | "failed");
        if let Some(id) = id
            && rows(&data["output"])
                .iter()
                .any(|row| row["script_id"] == id && row["value"]["kind"] == "script_error")
        {
            failed = true;
        }
        if structured && !structured_overflow {
            return if failed {
                document_error(data)
            } else {
                document(data)
            };
        }

        let output = rows(&data["output"]);
        let session = output
            .iter()
            .find_map(|row| {
                (row["value"]["kind"] == "session_presentation").then_some(&row["value"])
            })
            .unwrap_or(&Value::Null);
        let full = tool == "status";
        let mut blocks = Vec::new();
        let mut ordinary = Vec::new();
        if structured_overflow {
            failed = true;
            blocks.push(
                "* Structured output exceeded 2 MiB. Request a smaller scope or page.".into(),
            );
        }

        if let Some(message) = data["error"].as_str() {
            blocks.push(message.to_owned());
        }
        let target = &session["target"];
        let launch = if tool == "run" {
            result
        } else {
            &result["run"]
        };
        if let Some(pid) = launch["pid"].as_i64() {
            let path = path.map(|path| format!(": {path}")).unwrap_or_default();
            blocks.push(format!(
                "Started process {pid}{path}\nState: {}",
                state(target, launch)
            ));
            if let Some(warning) = launch["scratchpad_error"].as_str() {
                blocks.push(format!("* Scratchpad unavailable: {warning}"));
            }
        } else if tool == "attach"
            && let Some(pid) = result["pid"].as_i64()
        {
            blocks.push(format!(
                "Attached to PID {pid}.\nState: {}",
                state(target, result)
            ));
            if let Some(warning) = result["scratchpad_error"].as_str() {
                blocks.push(format!("* Scratchpad unavailable: {warning}"));
            }
        }

        let released = if launch["pid"].is_number() {
            &launch["released"]
        } else {
            &result["released"]
        };
        if !rows(released).is_empty() {
            let pids = rows(released)
                .iter()
                .map(scalar)
                .collect::<Vec<_>>()
                .join(", ");
            blocks.push(format!("* Released previous target PID(s): {pids}."));
        }

        match tool {
            "connect" if !failed => {
                *self = Self::default();
                blocks.push(format!(
                    "Connected to {}.\nSession: {}",
                    data["socket"]
                        .as_str()
                        .or(data["endpoint"].as_str())
                        .unwrap_or("aidbg-server"),
                    scalar(&data["session"])
                ));
            }
            "script_run" | "script_wait" | "gdb" => {}
            "run" | "attach" => {}
            "send_input" | "interrupt_input" if result["handler"].is_string() => {
                let verb = if tool == "send_input" {
                    "Answered"
                } else {
                    "Interrupted"
                };
                blocks.push(format!("{verb} {}.", scalar(&result["handler"])));
            }
            "ps" | "syscall_table" if !result.is_null() => {
                ordinary.push(table(result, tool));
            }
            "snapshot" => ordinary.push(snapshot_text(result)),
            _ if !result.is_null() => ordinary.push(readable(result, true)),
            _ => {}
        }

        if status == "check_failed" {
            blocks.push(diagnostics(id, rows(&result["diagnostics"]), source));
        }

        let running: BTreeSet<_> = rows(&data["running_scripts"])
            .iter()
            .filter_map(Value::as_u64)
            .collect();
        let mut participants = self.asynchronous.clone();
        participants.extend(running.iter().copied());
        participants.extend(id);
        let mut terminal = HashSet::new();
        let mut summarized = HashSet::new();
        let mut summarized_threads = HashSet::new();
        for row in output {
            let value = &row["value"];
            if matches!(
                value["kind"].as_str(),
                Some("console" | "fmt" | "operation_result" | "script_error")
            ) {
                participants.extend(row["script_id"].as_u64());
            }
        }
        let mut group = None;
        for row in output {
            let value = &row["value"];
            let script = row["script_id"].as_u64().unwrap_or_default();
            let kind = value["kind"].as_str().unwrap_or_default();
            match kind {
                "session_presentation" => continue,
                "console" | "fmt" => {
                    if participants.len() > 1 && group != Some(script) {
                        ordinary.push(format!("[Script #{script}]"));
                        group = Some(script);
                    }
                    if let Some(text) = value["text"].as_str() {
                        ordinary.push(text.to_owned());
                    } else {
                        ordinary.push(
                            rows(&value["values"])
                                .iter()
                                .map(|value| readable(value, false))
                                .collect::<Vec<_>>()
                                .join(" "),
                        );
                    }
                    continue;
                }
                "operation_result" => {
                    if let Some(text) = value["text"].as_str() {
                        blocks.push(text.to_owned());
                    }
                }
                "script_complete" | "script_cancelled" | "script_error" => {
                    terminal.insert(script);
                    let was_async = self.asynchronous.remove(&script)
                        || tool == "script_wait" && id == Some(script);
                    match kind {
                        "script_complete" if was_async => {
                            blocks.push(format!("* Script #{script} completed."))
                        }
                        "script_cancelled" => blocks.push(format!("* Script #{script} cancelled.")),
                        "script_error" => {
                            if id == Some(script) {
                                failed = true;
                            }
                            let heading =
                                if was_async || participants.len() > 1 || id != Some(script) {
                                    format!("* Script #{script} failed")
                                } else {
                                    String::from("Script failed")
                                };
                            blocks.push(runtime_error(&heading, value));
                        }
                        _ => continue,
                    }
                }
                "callback_error" => blocks.push(runtime_error("* Debugger callback failed", value)),
                "stop_summary" => {
                    if let Some(seq) = value["sequence"].as_u64() {
                        summarized.insert(seq);
                    }
                    if let Some(tid) = value["tid"].as_i64() {
                        summarized_threads.insert(tid);
                    }
                    blocks.push(format!("* {}", scalar(&value["text"])));
                }
                _ => {
                    if let Some(text) = value["text"].as_str() {
                        blocks.push(format!("* {text}"));
                    } else {
                        blocks.push(format!("* {}", readable(value, true)));
                    }
                }
            }
        }

        if let Some(script) = id
            && !terminal.contains(&script)
        {
            match status {
                "completed" if tool == "script_wait" || self.asynchronous.remove(&script) => {
                    blocks.push(format!("* Script #{script} completed."))
                }
                "cancelled" => {
                    self.asynchronous.remove(&script);
                    blocks.push(format!("* Script #{script} cancelled."));
                }
                "failed" => {
                    self.asynchronous.remove(&script);
                    blocks.push(format!("* Script #{script} failed."));
                }
                "accepted" | "wait_timeout" if !running.contains(&script) && session.is_null() => {
                    blocks.push(format!("Script #{script} submitted."))
                }
                _ => {}
            }
        }

        for input in rows(&data["waiting_inputs"]) {
            let handler = scalar(&input["handler"]);
            let script = session["inputScripts"]
                .get(&handler)
                .and_then(Value::as_u64);
            let heading = script
                .map(|id| format!("Script #{id} awaiting input"))
                .unwrap_or_else(|| "Awaiting input".into());
            let payload = readable(&input["payload"], false);
            let excerpt = clip(&payload, 1536);
            let note = if excerpt.len() < payload.len() {
                " <request preview truncated>"
            } else {
                ""
            };
            blocks.push(format!(
                "* {heading}\n  Request {handler}: {excerpt}{note}\n  Reply with send_input."
            ));
        }
        for wait in rows(&data["waiting_events"]) {
            let heading = wait["scriptId"]
                .as_u64()
                .map(|id| format!("Script #{id} waiting"))
                .unwrap_or_else(|| "Waiting".into());
            let event = match wait["kind"].as_str() {
                Some("hit") => "a breakpoint or watchpoint hit",
                Some("thread_exit") => "thread exit",
                Some("process_exit") => "process exit",
                _ => "a target stop",
            };
            let thread = wait["tid"]
                .as_i64()
                .map(|tid| format!(" on thread {tid}"))
                .unwrap_or_default();
            blocks.push(format!("* {heading} for {event}{thread}."));
        }
        for &script in &running {
            let awaiting = rows(&data["waiting_events"])
                .iter()
                .any(|wait| wait["scriptId"] == script)
                || session["inputScripts"]
                    .as_object()
                    .is_some_and(|inputs| inputs.values().any(|v| v == script));
            if !awaiting
                && (!full || result.as_str().is_none())
                && (Some(script) == id || !self.asynchronous.contains(&script))
            {
                let timeout =
                    if Some(script) == id && tool == "script_wait" && status == "wait_timeout" {
                        " Completion wait timed out."
                    } else {
                        ""
                    };
                blocks.push(format!("Script #{script} running.{timeout}"));
            }
        }
        if !full {
            let previous: Vec<_> = self.asynchronous.iter().copied().collect();
            for script in previous {
                let key = script.to_string();
                if let Some(outcome) = session["outcomes"][&key].as_str() {
                    self.asynchronous.remove(&script);
                    blocks.push(format!("* Script #{script} {outcome}."));
                }
            }
        }
        self.asynchronous.extend(
            running
                .into_iter()
                .filter(|id| session["outcomes"][id.to_string()].is_null()),
        );

        let mut events: Vec<_> = rows(&session["events"])
            .iter()
            .chain(rows(&data["signals"]))
            .collect();
        events.sort_by_key(|row| row["sequence"].as_u64());
        let mut newest = self.last_event;
        if full && !events.is_empty() {
            blocks.push("Pending event details".into());
        }
        for event in events {
            let sequence = event["sequence"].as_u64();
            if full || sequence.is_none_or(|seq| newest.is_none_or(|last| seq > last)) {
                if full || sequence.is_none_or(|seq| !summarized.contains(&seq)) {
                    blocks.push(event_text(event, full));
                }
                if let Some(tid) = event["tid"].as_i64() {
                    summarized_threads.insert(tid);
                }
                newest = newest.max(sequence);
            }
        }
        if !full {
            self.last_event = newest;
        }

        if !full {
            let stops = &data["paused_stops"];
            if stops.is_array() && stops != &self.stopped {
                for stop in rows(stops) {
                    if !rows(&self.stopped).contains(stop)
                        && stop["tid"]
                            .as_i64()
                            .is_none_or(|tid| !summarized_threads.contains(&tid))
                        && !matches!(stop["reason"].as_str(), Some("attach" | "exec"))
                    {
                        blocks.push(event_text(stop, false));
                    }
                }
                if (tool == "attach" || launch["pid"].is_number())
                    && !rows(&data["paused_threads"]).is_empty()
                {
                    let tids = rows(&data["paused_threads"])
                        .iter()
                        .map(scalar)
                        .collect::<Vec<_>>()
                        .join(", ");
                    blocks.push(format!("Stopped threads: {tids}"));
                }
                self.stopped = stops.clone();
            }
            if !session.is_null() && target != &self.target {
                if launch["pid"].is_null()
                    && tool != "attach"
                    && tool != "core_open"
                    && !target.is_null()
                {
                    blocks.push(format!(
                        "* Target PID {}: {}.",
                        scalar(&target["pid"]),
                        scalar(&target["state"])
                    ));
                }
                self.target = target.clone();
            }
        }

        let process = &data["process_output"];
        for process in rows(&process["released"])
            .iter()
            .chain(std::iter::once(process))
        {
            append_process_output(process, &mut ordinary, &mut blocks);
        }
        if data["output_dropped"] == true || full && session["outputDropped"] == true {
            blocks.push("* Script output was dropped from its buffer.".into());
        }
        if session["moreOutput"] == true {
            blocks.push(
                "* More script output is buffered. Use another collecting call to read it.".into(),
            );
        }
        if data["event_queue_full"] == true {
            blocks.push(
                "* Event queue full. Use dbg.waitStops() to consume pending events and resume collection.".into(),
            );
        }
        if let Some(message) = data["target_error"].as_str() {
            blocks.push(format!("* Target error: {message}"));
        }
        let text = if blocks.is_empty() && ordinary.is_empty() {
            String::from("OK")
        } else {
            limited_text(ordinary, blocks)
        };
        let content = vec![ContentBlock::text(text)];
        if failed {
            CallToolResult::error(content)
        } else {
            CallToolResult::success(content)
        }
    }
}

fn append_process_output(process: &Value, ordinary: &mut Vec<String>, blocks: &mut Vec<String>) {
    if process["pid"].is_null() {
        return;
    }
    let pid = scalar(&process["pid"]);
    if process["truncated"] == true {
        let bytes = process["dropped_bytes"].as_u64().filter(|&bytes| bytes > 0);
        blocks.push(match bytes {
            Some(bytes) => {
                format!("* Process {pid} output was dropped from its buffer ({bytes} bytes).")
            }
            None => format!("* Process {pid} output was dropped from its buffer."),
        });
    }
    for chunk in rows(&process["chunks"]) {
        ordinary.push(format!(
            "Process {pid} {}\n{}",
            scalar(&chunk[0]),
            scalar(&chunk[1])
        ));
    }
    // Earlier servers send one string per stream.
    for stream in ["stdout", "stderr"] {
        if let Some(text) = process[stream].as_str().filter(|s| !s.is_empty()) {
            ordinary.push(format!("Process {pid} {stream}\n{text}"));
        }
    }
    if process["more"] == true {
        let bytes = process["more_bytes"]
            .as_u64()
            .map(|n| format!(" ({n} bytes)"))
            .unwrap_or_default();
        blocks.push(format!(
            "* More output is buffered for process {pid}{bytes}. Use another collecting call to read it."
        ));
    }
}

fn rows(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or_default()
}

fn scalar(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn state<'a>(target: &'a Value, result: &'a Value) -> &'a str {
    target["state"]
        .as_str()
        .or(result["state"].as_str())
        .unwrap_or("unknown")
}

fn runtime_error(heading: &str, value: &Value) -> String {
    let mut text = format!(
        "{heading}:\n{}",
        value["message"]
            .as_str()
            .or(value["error"].as_str())
            .unwrap_or("Unknown error")
    );
    if let Some(stack) = value["stack"].as_str().filter(|s| !s.is_empty()) {
        write!(text, "\n{stack}").unwrap();
    }
    text
}

fn diagnostics(script: Option<u64>, rows: &[Value], source: Option<&str>) -> String {
    let mut text = script
        .map(|id| format!("Script #{id}: compilation failed"))
        .unwrap_or_else(|| "Compilation failed".into());
    let mut seen = HashSet::new();
    let mut ordered: Vec<_> = rows.iter().collect();
    ordered.sort_by_key(|row| (row["file"].as_str(), row["range"]["start"].as_u64()));
    for row in ordered {
        let file = row["file"].as_str().unwrap_or("script.ts");
        let file = file.strip_prefix("/aidbg/").unwrap_or(file);
        let message = row["message"].as_str().unwrap_or("Unknown diagnostic");
        let code = row["code"].as_str().unwrap_or_default();
        let code_prefix =
            if row["source"] == "typescript" && code.bytes().all(|n| n.is_ascii_digit()) {
                "TS"
            } else {
                ""
            };
        let severity = row["severity"].as_str().unwrap_or("error");
        let range = &row["range"];
        let location = range["line"].as_u64().zip(range["column"].as_u64());
        if !seen.insert((file, location, code, message)) {
            continue;
        }
        let location_text = location
            .map(|(line, col)| format!(":{line}:{col}"))
            .unwrap_or_default();
        write!(
            text,
            "\n{file}{location_text}: {severity} {code_prefix}{code}: {message}"
        )
        .unwrap();
        if let Some((line, col)) = location
            && (file == "script.ts" || file.ends_with("/script.ts"))
            && let Some(excerpt) = source.and_then(|src| {
                line.checked_sub(1)
                    .and_then(|i| src.lines().nth(i as usize))
            })
        {
            let prefix: String = excerpt
                .chars()
                .scan(col.saturating_sub(1), |left, ch| {
                    if *left == 0 {
                        return None;
                    }
                    *left = left.saturating_sub(ch.len_utf16() as u64);
                    Some(if ch == '\t' { '\t' } else { ' ' })
                })
                .collect();
            let width = if range["end_line"] == line {
                range["end_column"]
                    .as_u64()
                    .unwrap_or(col)
                    .saturating_sub(col)
            } else {
                1
            };
            let available = excerpt
                .chars()
                .count()
                .saturating_sub(prefix.chars().count());
            write!(
                text,
                "\n  {excerpt}\n  {prefix}{}",
                "^".repeat((width as usize).min(available).max(1))
            )
            .unwrap();
        }
    }
    text
}

fn event_text(event: &Value, full: bool) -> String {
    let tid = scalar(&event["tid"]);
    let kind = event["kind"]
        .as_str()
        .or(event["reason"].as_str())
        .unwrap_or("stop");
    let detail = event["signalName"].as_str().unwrap_or(kind);
    let mut text = match kind {
        "exit" => {
            let subject = if event["scope"] == "process" {
                "Process"
            } else {
                "Thread"
            };
            let reason = event["code"]
                .as_i64()
                .map(|code| format!(" with code {code}"))
                .or_else(|| {
                    event["signal"]
                        .as_i64()
                        .map(|signal| format!(" from signal {signal}"))
                })
                .unwrap_or_default();
            format!("* {subject} {tid} exited{reason}.")
        }
        "fork" => format!(
            "* Process {} forked child {tid}.",
            scalar(&event["parentPid"])
        ),
        "exec" => format!("* Thread {tid} executed {}.", scalar(&event["executable"])),
        _ => {
            let id = event["breakpointId"]
                .as_u64()
                .map(|id| format!(" #{id}"))
                .unwrap_or_default();
            let verb = if event["paused"] == false {
                "reported"
            } else {
                "stopped"
            };
            format!("* Thread {tid} {verb}: {detail}{id}")
        }
    };
    for (key, label) in [
        ("address", "Address"),
        ("faultAddress", "Fault address"),
        ("before", "Old value"),
        ("after", "New value"),
        ("name", "Syscall"),
        ("phase", "Phase"),
    ] {
        if !event[key].is_null() {
            write!(text, "\n  {label}: {}", scalar(&event[key])).unwrap();
        }
    }
    if full && let Some(sequence) = event["sequence"].as_u64() {
        write!(text, " [event {sequence}]").unwrap();
    }
    text
}

fn readable(value: &Value, management: bool) -> String {
    struct Text(String);
    impl Write for Text {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let left = (TEXT_BUDGET / 2).saturating_sub(self.0.len());
            self.0.push_str(clip(text, left));
            if text.len() > left {
                Err(std::fmt::Error)
            } else {
                Ok(())
            }
        }
    }
    fn render(value: &Value, management: bool, depth: usize, out: &mut Text) -> std::fmt::Result {
        match value {
            Value::Object(map) => {
                let indent = "  ".repeat(depth);
                for (key, value) in map {
                    if management
                        && (value.is_null()
                            || (value == false
                                && matches!(
                                    key.as_str(),
                                    "truncated"
                                        | "output_dropped"
                                        | "event_queue_full"
                                        | "timedOut"
                                ))
                            || value.as_array().is_some_and(Vec::is_empty)
                            || value.as_object().is_some_and(serde_json::Map::is_empty))
                    {
                        continue;
                    }
                    write!(out, "{indent}{key}:")?;
                    if value.is_object()
                        || value.is_array() && rows(value).iter().any(Value::is_object)
                    {
                        out.write_char('\n')?;
                        render(value, management, depth + 1, out)?;
                    } else {
                        out.write_char(' ')?;
                        render(value, management, depth + 1, out)?;
                        out.write_char('\n')?;
                    }
                }
                if map.is_empty() && !management {
                    out.write_str("{}")?;
                }
            }
            Value::Array(values) if values.iter().any(|v| v.is_object() || v.is_array()) => {
                let indent = "  ".repeat(depth);
                for value in values {
                    writeln!(out, "{indent}-")?;
                    render(value, management, depth + 1, out)?;
                    if !out.0.ends_with('\n') {
                        out.write_char('\n')?;
                    }
                }
            }
            Value::Array(values) => {
                out.write_char('[')?;
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        out.write_str(", ")?;
                    }
                    render(value, management, depth + 1, out)?;
                }
                out.write_char(']')?;
            }
            Value::String(text) => out.write_str(text)?,
            _ => out.write_str(&scalar(value))?,
        }
        Ok(())
    }
    let mut text = Text(String::new());
    let clipped = render(value, management, 0, &mut text).is_err();
    let mut text = text.0;
    text.truncate(text.trim_end_matches('\n').len());
    if clipped {
        text.push_str("\n* Output truncated for display.");
    }
    text
}

fn snapshot_text(result: &Value) -> String {
    let threads = rows(&result["threads"]);
    if !result["threads"].is_array() {
        return readable(result, true);
    }
    let total = result["threadCount"]
        .as_u64()
        .unwrap_or(threads.len() as u64);
    let mut text = format!(
        "Snapshot ({})\nThreads: {total}",
        scalar(&result["consistency"])
    );
    let mut shown = 0;
    for thread in threads {
        let mut line = readable(thread, true);
        if result["frameLimit"].as_u64() == Some(rows(&thread["frames"]).len() as u64) {
            line.push_str("\n* Frame capture limit reached for this thread.");
        }
        if text.len() + line.len() + 2 > TEXT_BUDGET / 2 {
            if shown == 0 {
                write!(text, "\n{}", clip(&line, TEXT_BUDGET / 3)).unwrap();
                text.push_str("\n* First thread details truncated.");
                shown += 1;
            }
            break;
        }
        write!(text, "\n{line}").unwrap();
        shown += 1;
    }
    let omitted =
        threads.len() as u64 - shown + result["threadsOmitted"].as_u64().unwrap_or_default();
    if omitted > 0 {
        write!(text, "\n* Output truncated: {omitted} more threads.").unwrap();
    }
    for key in ["incomplete", "context", "mappings"] {
        if let Some(value) = result.get(key) {
            let section = readable(value, true);
            write!(text, "\n{key}: {}", clip(&section, 2048)).unwrap();
            if section.len() > 2048 {
                text.push_str("\n* Section truncated for display.");
            }
        }
    }
    text
}

fn table(result: &Value, tool: &str) -> String {
    let rows = if tool == "ps" {
        rows(&result["items"])
    } else {
        rows(&result["syscalls"])
    };
    if rows.is_empty() {
        return if tool == "ps" {
            "No matching processes."
        } else {
            "No matching syscalls."
        }
        .into();
    }
    let preferred = if tool == "ps" {
        &["pid", "ppid", "tid", "name", "threads", "args"][..]
    } else {
        &["id", "name", "parameters"][..]
    };
    let fields: Vec<_> = preferred
        .iter()
        .copied()
        .filter(|field| rows.iter().any(|row| row.get(field).is_some()))
        .collect();
    if fields.is_empty()
        || rows.iter().any(|row| {
            row.as_object()
                .is_none_or(|map| map.keys().any(|k| !fields.contains(&k.as_str())))
        })
    {
        return readable(result, true);
    }
    let mut text = fields.join("  ").to_uppercase();
    for (index, row) in rows.iter().enumerate() {
        let cells: Vec<_> = fields
            .iter()
            .map(|field| {
                let value = &row[field];
                if value.is_null() {
                    return String::from("-");
                }
                if *field == "args" {
                    return value
                        .as_array()
                        .map(|args| {
                            args.iter()
                                .map(Value::to_string)
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_else(|| scalar(value));
                }
                readable(value, false)
            })
            .collect();
        let line = cells.join("  ");
        if text.len() + line.len() + 1 > TEXT_BUDGET / 2 {
            let next = result["offset"].as_u64().unwrap_or_default() + index as u64;
            if index == 0 {
                write!(
                    text,
                    "\n{}\n* Row truncated for display.",
                    clip(&line, 2048)
                )
                .unwrap();
            }
            write!(
                text,
                "\n* Output truncated: {} more rows.",
                result["total"]
                    .as_u64()
                    .map(|total| total.saturating_sub(next + u64::from(index == 0)))
                    .unwrap_or((rows.len() - index - usize::from(index == 0)) as u64)
            )
            .unwrap();
            if tool == "ps" {
                write!(
                    text,
                    "\nMore results at offset {}.",
                    next + u64::from(index == 0)
                )
                .unwrap();
            }
            return text;
        }
        write!(text, "\n{line}").unwrap();
    }
    if let Some(next) = result["next_offset"].as_u64() {
        write!(text, "\nMore results at offset {next}.").unwrap();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn global_budget_preserves_stop_and_reports_utf8_clipping() {
        let reply = document(json!({
            "output": [
                {"value":{"kind":"console", "text":"火".repeat(TEXT_BUDGET)}},
                {"value":{"kind":"session_presentation","moreOutput":true,
                    "events":[{"sequence":1,"kind":"signal","tid":10,"paused":true,
                        "name":"SIGSEGV","faultAddress":"0x18"}]}}
            ],
            "process_output":{"pid":10,"chunks":[["stdout","more"]],"more":true,"truncated":true}
        }));
        let result = Presentation::default().render(reply, "script_run", None, None, false);
        let text = &result.content[0].as_text().unwrap().text;
        assert!(text.len() <= TEXT_BUDGET);
        assert!(text.contains("Output truncated for display"));
        assert!(text.contains("Fault address: 0x18"));
        assert!(text.contains("output is buffered") && text.contains("dropped from its buffer"));
        assert!(result.structured_content.is_none());
    }

    #[test]
    fn structured_output_has_a_resource_limit() {
        let reply = document(json!({
            "result":"x".repeat(STRUCTURED_BUDGET),
            "paused_stops":[{"tid":9,"reason":"signal","signalName":"SIGSEGV"}],
        }));
        let result = Presentation::default().render(reply, "script_run", None, None, true);
        let text = &result.content[0].as_text().unwrap().text;
        assert_eq!(result.is_error, Some(true));
        assert!(result.structured_content.is_none());
        assert!(text.contains("Structured output exceeded 2 MiB"));
        assert!(text.contains("SIGSEGV"));
        assert!(text.len() <= TEXT_BUDGET);
    }

    #[test]
    fn snapshot_reports_omitted_threads_and_frame_limits() {
        let frame = json!({"pc":"0x1000","symbol":"f"});
        let thread = json!({"tid":1, "frames": vec![frame; 13]});
        let snapshot = json!({
            "threadCount":256,"threadsOmitted":224,
            "frameLimit":13,"threads":vec![thread; 32], "consistency":"all-stopped"
        });
        let output = snapshot_text(&snapshot);
        assert!(output.contains("Threads: 256") && output.contains("more threads"));
        assert!(output.contains("Frame capture limit reached"));
        assert!(output.len() < TEXT_BUDGET);
    }

    #[test]
    fn full_queue_warning_preserves_all_pending_events_and_status_can_show_them_again() {
        let mut presentation = Presentation::default();
        let reply = || {
            document(json!({
                "event_queue_full": true,
                "output": [{
                    "script_id": 0,
                    "value": {"kind":"session_presentation","events":[
                        {"sequence":5,"kind":"breakpoint","breakpointId":1,"tid":42,"paused":true},
                        {"sequence":6,"kind":"watchpoint","breakpointId":2,"tid":42,"paused":true}
                    ]}
                }]
            }))
        };
        let ordinary = presentation.render(reply(), "ps", None, None, false);
        let text = &ordinary.content[0].as_text().unwrap().text;
        assert!(text.contains("Event queue full"));
        assert!(text.contains("breakpoint #1") && text.contains("watchpoint #2"));
        let repeat = presentation.render(reply(), "ps", None, None, false);
        assert!(
            !repeat.content[0]
                .as_text()
                .unwrap()
                .text
                .contains("breakpoint #1")
        );
        let status = presentation.render(reply(), "status", None, None, false);
        let text = &status.content[0].as_text().unwrap().text;
        assert!(text.contains("[event 5]") && text.contains("[event 6]"));
        assert!(!status.is_error.unwrap());
    }
}
