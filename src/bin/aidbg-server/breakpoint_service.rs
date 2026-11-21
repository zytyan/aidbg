use super::{Store, internal};
use aidbg::breakpoint::{Capture, Event, Kind, Location, Scope, Worker};
use aidbg::rpc::{
    BreakpointEventsRequest, BreakpointKind, CaptureScope, InstallBreakpointRequest,
    install_breakpoint_request,
};
use aidbg::selection::Filter;
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, mpsc};
use tonic::Status;

const EVENT_CAPACITY: usize = 512;
const SAVE_QUEUE: usize = 16;
const MAX_SESSIONS: usize = 32;

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
    next_id: u64,
    workers: BTreeMap<i32, Worker>,
}

#[derive(Clone)]
pub(super) struct Breakpoints {
    sessions: Arc<Mutex<Sessions>>,
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

    pub fn install(&self, req: InstallBreakpointRequest) -> Result<impl Serialize, Status> {
        let location = match req.location {
            Some(install_breakpoint_request::Location::Address(address)) if address != 0 => {
                Location::Address(address)
            }
            Some(install_breakpoint_request::Location::Symbol(symbol))
                if !symbol.module.is_empty() && !symbol.symbol.is_empty() =>
            {
                Location::Symbol {
                    module: symbol.module,
                    symbol: symbol.symbol,
                    instance: symbol.instance,
                }
            }
            _ => {
                return Err(Status::invalid_argument(
                    "provide a nonzero address or a module and symbol",
                ));
            }
        };
        let mode = BreakpointKind::try_from(req.kind)
            .map_err(|_| Status::invalid_argument("unknown breakpoint kind"))?;
        let kind = match (mode, req.length) {
            (BreakpointKind::Hardware, None) => Kind::Hardware,
            (BreakpointKind::Software, None) => Kind::Software,
            (
                mode @ (BreakpointKind::Write | BreakpointKind::ReadWrite),
                Some(length @ (1 | 2 | 4 | 8)),
            ) if matches!(location, Location::Address(_)) => Kind::Watch {
                length: length as usize,
                read_write: mode == BreakpointKind::ReadWrite,
            },
            (BreakpointKind::Hardware | BreakpointKind::Software, Some(_)) => {
                return Err(Status::invalid_argument(
                    "length is only valid for watchpoints",
                ));
            }
            _ => {
                return Err(Status::invalid_argument(
                    "watchpoints require an absolute address and length 1, 2, 4, or 8",
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

        let mut sessions = self.sessions.lock().unwrap();
        sessions.workers.retain(|_, worker| !worker.is_finished());
        let new_worker = !sessions.workers.contains_key(&req.pid);
        if new_worker {
            if sessions.workers.len() >= MAX_SESSIONS {
                return Err(Status::resource_exhausted("too many breakpoint sessions"));
            }
            let events = Arc::clone(&self.events);
            let queue = self.queue.clone();
            let publish = Arc::new(move |event: Event, capture: Capture| {
                let mut journal = events.lock().unwrap();
                journal.next_id += 1;
                let event_id = journal.next_id;
                let error = queue
                    .try_send((event_id, capture))
                    .err()
                    .map(|e| e.to_string());
                if journal.rows.len() == EVENT_CAPACITY {
                    journal.rows.pop_front();
                }
                journal.rows.push_back(EventRow {
                    event_id,
                    event,
                    snapshot_id: None,
                    snapshot_status: if error.is_some() { "failed" } else { "pending" },
                    snapshot_error: error,
                });
            });
            let worker = Worker::start(req.pid, publish).map_err(internal)?;
            sessions.workers.insert(req.pid, worker);
        }
        sessions.next_id += 1;
        let id = sessions.next_id;
        let worker = &sessions.workers[&req.pid];
        let result = worker.install(id, location, scope, budget, kind);
        if new_worker && result.is_err() {
            sessions.workers.remove(&req.pid);
        }
        result.map_err(|e| {
            let message = e.to_string();
            if message.contains("slots exhausted") {
                Status::resource_exhausted(message)
            } else {
                Status::failed_precondition(message)
            }
        })
    }

    pub fn remove(&self, pid: i32, id: u64) -> Result<impl Serialize, Status> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.workers.retain(|_, worker| !worker.is_finished());
        let worker = sessions
            .workers
            .get(&pid)
            .ok_or_else(|| Status::not_found("breakpoint session not found"))?;
        let cleanup = worker.remove(id).map_err(|e| {
            if e.to_string() == "breakpoint ID not found" {
                Status::not_found(e.to_string())
            } else {
                internal(e)
            }
        })?;
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
        serde_json::json!({
            "events": events,
            "oldest_event_id": oldest,
            "latest_event_id": journal.next_id,
            "history_truncated": oldest.is_some_and(|id| id.saturating_sub(1) > req.after_event_id),
        })
    }

    pub fn stop(self) {
        self.sessions.lock().unwrap().workers.clear();
    }
}
