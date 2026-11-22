use super::{Store, internal, script_error};
use aidbg::breakpoint::{
    CallbackSource, Capture, Control, Event, Kind, Location, Publish, Scope, WeakControl, Worker,
};
use aidbg::rpc::{
    BreakpointEventsRequest, BreakpointKind, CaptureScope, InstallBreakpointRequest,
    UpdateBreakpointRequest, install_breakpoint_request,
};
use aidbg::selection::Filter;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use tonic::Status;

const EVENT_CAPACITY: usize = 512;
const SAVE_QUEUE: usize = 16;
const MAX_SESSIONS: usize = 32;
const MAX_RULES: usize = 128;

#[derive(Serialize)]
struct EventRow {
    event_id: u64,
    #[serde(flatten)]
    event: Event,
    snapshot_id: Option<String>,
    snapshot_status: &'static str,
    snapshot_error: Option<String>,
}

#[derive(Default)]
struct Events {
    next_id: u64,
    rows: VecDeque<EventRow>,
}

#[derive(Default)]
struct Sessions {
    workers: BTreeMap<i32, Worker>,
    owners: BTreeMap<u64, (Weak<()>, WeakControl)>,
}

impl Sessions {
    fn register(&mut self, id: u64, active: Weak<()>, owner: WeakControl) {
        self.owners
            .retain(|_, (active, _)| active.strong_count() != 0);
        self.owners.insert(id, (active, owner));
    }
}

#[derive(Default)]
struct Rules {
    next_id: u64,
    named: BTreeMap<u64, NamedRule>,
}

struct NamedRule {
    name: String,
    callback: CallbackSource,
    exports: BTreeSet<String>,
    owned_exports: BTreeSet<String>,
}

impl NamedRule {
    fn document(&self) -> serde_json::Value {
        let mut document = serde_json::json!({
            "rule_id": self.callback.id(),
            "name": self.name,
            "revision": self.callback.revision(),
            "hits": self.callback.hits(),
        });
        if self.callback.exports() {
            document["mode"] = "exports".into();
            document["exports"] = serde_json::json!(self.exports);
        }
        document
    }
}

fn missing_rule(id: u64) -> Status {
    script_error(
        aidbg::Diagnostic::new("RULE_NOT_FOUND", format!("rule {id} does not exist"), None).into(),
    )
}

#[derive(Clone)]
pub(super) struct Breakpoints {
    sessions: Arc<Mutex<Sessions>>,
    ids: Arc<AtomicU64>,
    rules: Arc<Mutex<Rules>>,
    events: Arc<Mutex<Events>>,
    queue: mpsc::SyncSender<(u64, Capture)>,
}

impl Breakpoints {
    pub fn new(store: Arc<Store>) -> aidbg::Result<(Self, std::thread::JoinHandle<()>)> {
        let events = Arc::new(Mutex::new(Events::default()));
        let (queue, receiver) = mpsc::sync_channel::<(_, Capture)>(SAVE_QUEUE);
        let journal = Arc::clone(&events);
        let saver = std::thread::Builder::new()
            .name("aidbg-event-store".into())
            .spawn(move || {
                let filter = || Filter::parse(None).expect("no filter");
                for (event_id, capture) in receiver {
                    let snapshot = store.save(capture.into_snapshot(), filter());
                    let mut events = journal.lock().unwrap();
                    if let Some(row) = events
                        .rows
                        .iter_mut()
                        .find(|event| event.event_id == event_id)
                    {
                        match snapshot {
                            Ok(reply) => {
                                row.snapshot_id = Some(reply.snapshot_id);
                                row.snapshot_status = "saved";
                            }
                            Err(e) => {
                                row.snapshot_status = "failed";
                                row.snapshot_error = Some(e.to_string());
                            }
                        }
                    }
                }
            })?;
        Ok((
            Self {
                sessions: Arc::default(),
                ids: Arc::default(),
                rules: Arc::default(),
                events,
                queue,
            },
            saver,
        ))
    }

    pub fn contains(&self, pid: i32) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .workers
            .get(&pid)
            .is_some_and(|w| !w.is_finished())
    }

    pub fn define_rule(
        &self,
        name: String,
        js: String,
        source: String,
        exports: Option<Vec<String>>,
    ) -> Result<serde_json::Value, Status> {
        let mut rules = self.rules.lock().unwrap();
        if rules.named.len() >= MAX_RULES {
            return Err(Status::resource_exhausted(
                "too many named breakpoint rules",
            ));
        }
        let names: BTreeSet<_> = exports.unwrap_or_default().into_iter().collect();
        Self::validate_names(&rules, None, &names)?;
        rules.next_id += 1;
        let id = rules.next_id;
        let callback = if names.is_empty() {
            CallbackSource::new(id, js, source)
        } else {
            CallbackSource::new_exports(id, js, source)
        };
        let rule = NamedRule {
            name,
            callback,
            owned_exports: names.clone(),
            exports: names,
        };
        let document = rule.document();
        rules.named.insert(id, rule);
        Ok(document)
    }

    pub fn list_rules(&self) -> serde_json::Value {
        let rules = self.rules.lock().unwrap();
        let rows: Vec<_> = rules.named.values().map(NamedRule::document).collect();
        serde_json::json!({ "rules": rows })
    }

    pub fn rule_exports(&self, id: u64) -> Result<bool, Status> {
        let rules = self.rules.lock().unwrap();
        rules
            .named
            .get(&id)
            .map(|rule| rule.callback.exports())
            .ok_or_else(|| missing_rule(id))
    }

    fn validate_names(
        rules: &Rules,
        owner: Option<u64>,
        names: &BTreeSet<String>,
    ) -> Result<(), Status> {
        for (&id, rule) in &rules.named {
            if Some(id) != owner
                && let Some(name) = names.intersection(&rule.owned_exports).next()
            {
                return Err(Status::already_exists(format!(
                    "callback export $.{name} is already registered"
                )));
            }
        }
        Ok(())
    }

    pub fn update_rule(
        &self,
        id: u64,
        js: String,
        source: String,
        exports: Option<Vec<String>>,
    ) -> Result<serde_json::Value, Status> {
        let mut rules = self.rules.lock().unwrap();
        let names: BTreeSet<_> = exports.unwrap_or_default().into_iter().collect();
        Self::validate_names(&rules, Some(id), &names)?;
        let rule = rules.named.get_mut(&id).ok_or_else(|| missing_rule(id))?;
        rule.callback.update(js, source).map_err(script_error)?;
        rule.owned_exports.extend(names.iter().cloned());
        rule.exports = names;
        Ok(rule.document())
    }

    pub fn script_run(
        &self,
        control: Control,
        js: String,
        source: String,
        replay_points: Vec<aidbg::script::LiveReplayPoint>,
        budget: std::time::Duration,
    ) -> Result<aidbg::script::LiveRunResult, Status> {
        let result = control
            .script_run(js, source, replay_points, budget, Arc::clone(&self.ids))
            .map_err(script_error)?;
        let mut sessions = self.sessions.lock().unwrap();
        for (id, active) in &result.active {
            sessions.register(*id, active.clone(), control.downgrade());
        }
        Ok(result)
    }

    pub fn remove_rule(&self, id: u64) -> Result<serde_json::Value, Status> {
        let mut rules = self.rules.lock().unwrap();
        let Some(rule) = rules.named.get(&id) else {
            return Ok(
                serde_json::json!({"rule_id": id, "removed": false, "status": "already_removed"}),
            );
        };
        if rule.callback.in_use() {
            return Err(script_error(
                aidbg::Diagnostic::new(
                    "RULE_IN_USE",
                    format!("rule {id} is attached to a breakpoint"),
                    Some("Remove the referencing breakpoints first."),
                )
                .into(),
            ));
        }
        rules.named.remove(&id);
        Ok(serde_json::json!({ "rule_id": id, "removed": true }))
    }

    fn callback(
        &self,
        id: Option<u64>,
        inline: Option<(String, String, Option<String>)>,
        handler: Option<String>,
    ) -> Result<Option<CallbackSource>, Status> {
        if id.is_none() && inline.is_none() && handler.is_none() {
            return Ok(None);
        }
        let mut rules = self.rules.lock().unwrap();
        if let Some(handler) = handler {
            let name = handler
                .strip_prefix("$.")
                .filter(|name| !name.is_empty())
                .ok_or_else(|| Status::invalid_argument("handler must have the form $.name"))?;
            return rules
                .named
                .values()
                .find(|rule| rule.exports.contains(name))
                .map(|rule| Some(rule.callback.select(name.to_owned())))
                .ok_or_else(|| {
                    Status::not_found(format!("callback export {handler} is not registered"))
                });
        }
        if let Some(id) = id {
            let rule = rules.named.get(&id).ok_or_else(|| missing_rule(id))?;
            if rule.callback.exports() {
                return Err(Status::invalid_argument(
                    "use handler to select a named export",
                ));
            }
            return Ok(Some(rule.callback.clone()));
        }
        rules.next_id += 1;
        Ok(inline.map(|(js, source, export)| match export {
            Some(export) => CallbackSource::new_exports(rules.next_id, js, source).select(export),
            None => CallbackSource::new(rules.next_id, js, source),
        }))
    }

    pub fn install(
        &self,
        req: InstallBreakpointRequest,
        callback_js: Option<(String, String, Option<String>)>,
        run: Option<Control>,
    ) -> Result<impl Serialize, Status> {
        let mode = BreakpointKind::try_from(req.kind)
            .map_err(|_| Status::invalid_argument("unknown breakpoint kind"))?;
        let execution = matches!(mode, BreakpointKind::Hardware | BreakpointKind::Software);
        let location = match req.location {
            Some(install_breakpoint_request::Location::Address(address)) if address != 0 => {
                Location::Address(address)
            }
            Some(install_breakpoint_request::Location::Symbol(symbol))
                if !symbol.module.is_empty() && !symbol.symbol.is_empty() =>
            {
                if execution && symbol.offset.is_none() {
                    Location::Symbol {
                        module: symbol.module,
                        symbol: symbol.symbol,
                        instance: symbol.instance,
                    }
                } else {
                    Location::ModuleOffset {
                        module: symbol.module,
                        offset: symbol.offset.unwrap_or_default(),
                        execution,
                        instance: symbol.instance,
                        symbol: Some(symbol.symbol),
                    }
                }
            }
            Some(install_breakpoint_request::Location::Source(source))
                if !source.file.is_empty() && source.line > 0 =>
            {
                Location::Source {
                    file: source.file.into(),
                    line: source.line,
                    module: source.module,
                    instance: source.instance,
                }
            }
            Some(install_breakpoint_request::Location::ModuleOffset(location))
                if !location.module.is_empty() && location.module.len() <= 4096 =>
            {
                Location::ModuleOffset {
                    module: location.module,
                    offset: location.offset,
                    execution,
                    instance: location.instance,
                    symbol: None,
                }
            }
            _ => {
                return Err(Status::invalid_argument(
                    "provide an address, module with symbol or offset, or file and line",
                ));
            }
        };
        let kind = match (mode, req.length) {
            (BreakpointKind::Hardware, None) => Kind::Hardware,
            (BreakpointKind::Software, None) => Kind::Software,
            (
                mode @ (BreakpointKind::Read | BreakpointKind::Write | BreakpointKind::ReadWrite),
                Some(length @ (1 | 2 | 4 | 8)),
            ) if matches!(
                location,
                Location::Address(_) | Location::ModuleOffset { .. }
            ) =>
            {
                Kind::Watch {
                    length: length as usize,
                    access: match mode {
                        BreakpointKind::Read => aidbg::breakpoint::WatchAccess::Read,
                        BreakpointKind::Write => aidbg::breakpoint::WatchAccess::Write,
                        _ => aidbg::breakpoint::WatchAccess::ReadWrite,
                    },
                }
            }
            (BreakpointKind::Hardware | BreakpointKind::Software, Some(_)) => {
                return Err(Status::invalid_argument(
                    "length is only valid for watchpoints",
                ));
            }
            _ => {
                return Err(Status::invalid_argument(
                    "watchpoints require an address or module location and length 1, 2, 4, or 8",
                ));
            }
        };
        let scope = match CaptureScope::try_from(req.scope) {
            Ok(CaptureScope::Thread) => Scope::Thread,
            Ok(CaptureScope::Process) => Scope::Process,
            Err(_) => return Err(Status::invalid_argument("unknown capture scope")),
        };
        let budget = req.timeout_ms.unwrap_or(100);
        if !(1..=500).contains(&budget) {
            return Err(Status::invalid_argument("timeout_ms must be in 1..=500"));
        }

        let callback = self.callback(req.rule_id, callback_js, req.handler)?;
        let id = self.ids.fetch_add(1, Ordering::Relaxed) + 1;
        let (result, owner) = if let Some(run) = run {
            (
                run.install(
                    req.pid, id, location, scope, budget, kind, req.tid, callback,
                ),
                run.downgrade(),
            )
        } else {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.workers.retain(|_, worker| !worker.is_finished());
            let new_worker = !sessions.workers.contains_key(&req.pid);
            if new_worker {
                if sessions.workers.len() >= MAX_SESSIONS {
                    return Err(Status::resource_exhausted("too many breakpoint sessions"));
                }
                let worker = Worker::start(req.pid, self.publisher()).map_err(internal)?;
                sessions.workers.insert(req.pid, worker);
            }
            let control = sessions.workers[&req.pid].control();
            let owner = control.downgrade();
            let result = control.install(
                req.pid, id, location, scope, budget, kind, req.tid, callback,
            );
            if new_worker && result.is_err() {
                sessions.workers.remove(&req.pid);
            }
            (result, owner)
        };
        let installed = result.map_err(|e| {
            let message = e.to_string();
            if message.contains("slots exhausted") {
                Status::resource_exhausted(message)
            } else {
                script_error(e)
            }
        })?;
        self.sessions
            .lock()
            .unwrap()
            .register(id, installed.active.clone(), owner);
        Ok(installed)
    }

    pub fn update(&self, req: UpdateBreakpointRequest) -> Result<impl Serialize, Status> {
        if req.breakpoint_id == 0
            || req.address == Some(0)
            || (req.address.is_none() && req.rule_id.is_none())
        {
            return Err(Status::invalid_argument(
                "provide a breakpoint ID and a nonzero address or rule ID",
            ));
        }
        let id = req.breakpoint_id;
        let control = self
            .sessions
            .lock()
            .unwrap()
            .owners
            .get(&id)
            .filter(|(active, _)| active.strong_count() != 0)
            .and_then(|(_, owner)| owner.upgrade())
            .ok_or_else(|| {
                script_error(
                    aidbg::Diagnostic::new("BREAKPOINT_NOT_FOUND", "breakpoint ID not found", None)
                        .into(),
                )
            })?;
        let callback = self.callback(req.rule_id, None, None)?;
        control
            .update(id, req.address, callback)
            .map_err(script_error)
    }

    pub fn publisher(&self) -> Publish {
        let events = Arc::clone(&self.events);
        let queue = self.queue.clone();
        Arc::new(move |event: Event, capture: Option<Capture>| {
            let mut journal = events.lock().unwrap();
            journal.next_id += 1;
            let event_id = journal.next_id;
            let (status, error) = match capture {
                Some(capture) => match queue.try_send((event_id, capture)) {
                    Ok(()) => ("pending", None),
                    Err(error) => ("failed", Some(error.to_string())),
                },
                None => ("not_requested", None),
            };
            if journal.rows.len() == EVENT_CAPACITY {
                journal.rows.pop_front();
            }
            journal.rows.push_back(EventRow {
                event_id,
                event,
                snapshot_id: None,
                snapshot_status: status,
                snapshot_error: error,
            });
        })
    }

    pub fn inspect_control(&self, pid: i32) -> Option<Control> {
        self.sessions
            .lock()
            .unwrap()
            .workers
            .get(&pid)
            .filter(|worker| !worker.is_finished())
            .map(|worker| worker.control().clone())
    }

    pub fn live_controls(&self) -> Vec<(i32, Control)> {
        self.sessions
            .lock()
            .unwrap()
            .workers
            .iter()
            .filter(|(_, worker)| !worker.is_finished())
            .map(|(&pid, worker)| (pid, worker.control().clone()))
            .collect()
    }

    pub fn remove(
        &self,
        pid: i32,
        id: u64,
        run: Option<Control>,
    ) -> Result<impl Serialize, Status> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.workers.retain(|_, worker| !worker.is_finished());
        let absent = || serde_json::json!({"breakpoint_id": id, "status": "already_removed", "cleanup": null});
        let Some(control) = run
            .as_ref()
            .or_else(|| sessions.workers.get(&pid).map(Worker::control))
        else {
            return Ok(absent());
        };
        let cleanup = match control.remove(id) {
            Ok(cleanup) => cleanup,
            Err(issue)
                if matches!(
                    issue.to_string().as_str(),
                    "breakpoint ID not found"
                        | "debugger session has ended"
                        | "breakpoint session ended during removal"
                ) =>
            {
                return Ok(absent());
            }
            Err(issue) => return Err(internal(issue)),
        };
        sessions.owners.remove(&id);
        let status = if let Some(cleanup) = &cleanup {
            sessions.workers.remove(&pid);
            if cleanup.ok() {
                "detached"
            } else {
                "cleanup_failed"
            }
        } else {
            "removed"
        };
        Ok(serde_json::json!({"breakpoint_id": id, "status": status, "cleanup": cleanup}))
    }

    pub fn snapshot_id(&self, event_id: u64) -> Result<String, Status> {
        let journal = self.events.lock().unwrap();
        let event = journal
            .rows
            .iter()
            .find(|row| row.event_id == event_id)
            .ok_or_else(|| Status::not_found("breakpoint event not found"))?;
        match event.snapshot_status {
            "pending" => Err(Status::unavailable("snapshot is still being saved")),
            "not_requested" => Err(Status::failed_precondition(
                "callback did not request a snapshot",
            )),
            "failed" => Err(Status::failed_precondition(
                event
                    .snapshot_error
                    .as_deref()
                    .unwrap_or("could not save snapshot"),
            )),
            _ => event
                .snapshot_id
                .clone()
                .ok_or_else(|| Status::internal("snapshot ID missing")),
        }
    }

    pub fn events(&self, req: BreakpointEventsRequest) -> serde_json::Value {
        let journal = self.events.lock().unwrap();
        let oldest = journal.rows.front().map(|row| row.event_id);
        let events: Vec<_> = journal
            .rows
            .iter()
            .filter(|row| {
                row.event_id > req.after_event_id
                    && req
                        .breakpoint_id
                        .is_none_or(|id| row.event.breakpoint_id == id)
            })
            .collect();
        let mut accesses = BTreeMap::new();
        for row in &events {
            let event = &row.event;
            if let Some(watch) = &event.watch {
                let access = match watch.write_observed {
                    Some(true) => "write",
                    Some(false) => "read",
                    None => "unknown",
                };
                let key = (
                    event.pid,
                    event.tid,
                    &event.address,
                    &event.instruction_pc,
                    event.pc_relation,
                    access,
                );
                *accesses.entry(key).or_insert(0_u64) += 1;
            }
        }
        let accesses: Vec<_> = accesses
            .into_iter()
            .map(|((pid, tid, address, pc, relation, access), count)| {
                serde_json::json!({"pid": pid, "tid": tid, "address": address, "instruction_pc": pc,
                "pc_relation": relation, "access": access, "count": count})
            })
            .collect();
        serde_json::json!({
            "events": events,
            "accesses": accesses,
            "oldest_event_id": oldest,
            "latest_event_id": journal.next_id,
            "history_truncated": oldest.is_some_and(|id| id.saturating_sub(1) > req.after_event_id),
        })
    }

    pub fn stop(self) {
        self.sessions.lock().unwrap().workers.clear();
    }
}
