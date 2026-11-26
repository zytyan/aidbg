use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::fmt::Write;

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
    CallToolResult::error(vec![ContentBlock::text(text)])
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
        if structured {
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
            "docs" => blocks.push(format!(
                "{}\n\n{}\n\n{}\n\nFull API: {}",
                scalar(&data["instructions"]),
                scalar(&data["declarations"]),
                scalar(&data["modules"]),
                scalar(&data["full_api"])
            )),
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
                blocks.push(table(result, tool));
            }
            _ if !result.is_null() => blocks.push(readable(result, true)),
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
                "console" | "fmt" | "operation_result" => {
                    if participants.len() > 1 && group != Some(script) {
                        blocks.push(format!("[Script #{script}]"));
                        group = Some(script);
                    }
                    if let Some(text) = value["text"].as_str() {
                        blocks.push(text.to_owned());
                    } else {
                        blocks.push(
                            rows(&value["values"])
                                .iter()
                                .map(|value| readable(value, false))
                                .collect::<Vec<_>>()
                                .join(" "),
                        );
                    }
                    continue;
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
            blocks.push(format!(
                "* {heading}\n  Request {handler}: {}\n  Reply with send_input.",
                readable(&input["payload"], false)
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
            append_process_output(process, &mut blocks);
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
        let text = if blocks.is_empty() {
            String::from("OK")
        } else {
            join_blocks(blocks)
        };
        let content = vec![ContentBlock::text(text)];
        if failed {
            CallToolResult::error(content)
        } else {
            CallToolResult::success(content)
        }
    }
}

fn append_process_output(process: &Value, blocks: &mut Vec<String>) {
    if process["pid"].is_null() {
        return;
    }
    let pid = scalar(&process["pid"]);
    if process["truncated"] == true {
        blocks.push(format!(
            "* Process {pid} output was dropped from its buffer."
        ));
    }
    for chunk in rows(&process["chunks"]) {
        blocks.push(format!(
            "Process {pid} {}\n{}",
            scalar(&chunk[0]),
            scalar(&chunk[1])
        ));
    }
    // Earlier servers send one string per stream.
    for stream in ["stdout", "stderr"] {
        if let Some(text) = process[stream].as_str().filter(|s| !s.is_empty()) {
            blocks.push(format!("Process {pid} {stream}\n{text}"));
        }
    }
    if process["more"] == true {
        blocks.push(format!(
            "* More output is buffered for process {pid}. Use another collecting call to read it."
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

fn join_blocks(blocks: Vec<String>) -> String {
    let mut out = String::new();
    for (index, block) in blocks.into_iter().enumerate() {
        if index > 0 && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&block);
    }
    out
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
    fn render(value: &Value, management: bool, depth: usize, out: &mut String) {
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
                    write!(out, "{indent}{key}:").unwrap();
                    if value.is_object()
                        || value.is_array() && rows(value).iter().any(Value::is_object)
                    {
                        out.push('\n');
                        render(value, management, depth + 1, out);
                    } else {
                        out.push(' ');
                        render(value, management, depth + 1, out);
                        out.push('\n');
                    }
                }
                if map.is_empty() && !management {
                    out.push_str("{}");
                }
            }
            Value::Array(values) if values.iter().any(|v| v.is_object() || v.is_array()) => {
                let indent = "  ".repeat(depth);
                for value in values {
                    writeln!(out, "{indent}-").unwrap();
                    render(value, management, depth + 1, out);
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
            }
            Value::Array(values) => {
                out.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&scalar(value));
                }
                out.push(']');
            }
            _ => out.push_str(&scalar(value)),
        }
    }
    if let Some(text) = value.as_str() {
        return text.to_owned();
    }
    let mut text = String::new();
    render(value, management, 0, &mut text);
    text.truncate(text.trim_end_matches('\n').len());
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
    for row in rows {
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
        write!(text, "\n{}", cells.join("  ")).unwrap();
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
