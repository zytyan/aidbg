use crate::{Result, error};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

pub(super) const QUEUE_LIMIT: usize = 4096;
pub(super) const DEFAULT_TIMEOUT_MS: u64 = 180_000;
const MAX_WAITERS: usize = 64;
const MAX_BATCH: usize = 64;

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Stop,
    Hit,
    ThreadExit,
    ProcessExit,
    Batch,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Request {
    pub kind: Kind,
    pub tid: Option<i32>,
    pub timeout_ms: Option<u64>,
    pub resume: Option<bool>,
    pub fresh: Option<bool>,
    pub paused_only: Option<bool>,
    pub limit: Option<usize>,
}

struct Wait {
    kind: Kind,
    paused_only: bool,
    tid: Option<i32>,
    after: u64,
    deadline: Instant,
    limit: usize,
}

impl Wait {
    fn deliverable(&self, event: &Entry, held: &impl Fn(i32, u64) -> bool) -> bool {
        self.matches(event)
            && (!self.paused_only
                || !event.ready
                || event.row["kind"] == "exit"
                || is_held(&event.row, held))
    }

    fn matches(&self, event: &Entry) -> bool {
        let row = &event.row;
        let terminal = row["kind"] == "exit";
        let process = terminal && row["scope"] == "process";
        let tid_matches = self.tid.is_none_or(|tid| row["tid"] == tid);
        if row["sequence"].as_u64().unwrap() <= self.after {
            return false;
        }
        match self.kind {
            Kind::ProcessExit => process,
            Kind::ThreadExit => terminal && tid_matches,
            Kind::Hit => {
                process
                    || (tid_matches
                        && (terminal || row["kind"] == "breakpoint" || row["kind"] == "watchpoint"))
            }
            Kind::Batch | Kind::Stop => process || row["kind"] == "fork" || tid_matches,
        }
    }
}

struct Entry {
    row: Value,
    ready: bool,
}

#[derive(Default)]
pub(super) struct Queue {
    sequence: u64,
    next_wait: u64,
    events: VecDeque<Entry>,
    waiters: BTreeMap<u64, Wait>,
    terminal: bool,
    exited: BTreeMap<i32, u64>,
}

impl Queue {
    pub fn reset(&mut self) {
        self.events.clear();
        self.waiters.clear();
        self.terminal = false;
        self.exited.clear();
    }

    pub fn follow_fork(&mut self, old_threads: Vec<i32>) {
        self.events.clear();
        self.terminal = false;
        self.exited.clear();
        self.exited
            .extend(old_threads.into_iter().map(|tid| (tid, self.sequence)));
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn push(&mut self, mut row: Value, ready: bool) -> u64 {
        self.sequence += 1;
        row["sequence"] = json!(self.sequence);
        if row["kind"] == "exit" {
            if row["scope"] == "process" {
                self.terminal = true;
            } else if let Some(tid) = row["tid"].as_i64() {
                self.exited.insert(tid as i32, self.sequence);
            }
        }
        self.events.push_back(Entry { row, ready });
        self.sequence
    }

    pub fn resurrect(&mut self, tids: impl IntoIterator<Item = i32>) {
        for tid in tids {
            self.exited.remove(&tid);
        }
    }

    pub fn complete(&mut self, sequence: u64, paused: bool, hit_count: Option<u64>) {
        if let Some(entry) = self
            .events
            .iter_mut()
            .find(|entry| entry.row["sequence"] == sequence)
        {
            entry.row["paused"] = json!(paused);
            if let Some(count) = hit_count {
                entry.row["hitCount"] = json!(count);
            }
            entry.ready = true;
        }
    }

    pub fn is_breakpoint(&self, sequence: u64) -> bool {
        self.events
            .iter()
            .find(|entry| entry.row["sequence"] == sequence)
            .is_some_and(|entry| {
                entry.row["kind"] == "breakpoint" || entry.row["kind"] == "watchpoint"
            })
    }

    pub fn interested(&self, sequence: u64) -> bool {
        self.events
            .iter()
            .find(|entry| entry.row["sequence"] == sequence)
            .is_some_and(|entry| self.waiters.values().any(|wait| wait.matches(entry)))
    }

    pub fn register(
        &mut self,
        request: &Request,
        held: impl Fn(i32, u64) -> bool,
    ) -> Result<(u64, bool)> {
        if self.waiters.len() == MAX_WAITERS {
            return Err(error("too many active event waits"));
        }
        let timeout = request.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        if timeout > 86_400_000 {
            return Err(error("timeoutMs must be between 0 and 86400000"));
        }
        let limit = request
            .limit
            .unwrap_or(if request.tid.is_some() { 1 } else { 16 });
        if !(1..=MAX_BATCH).contains(&limit) {
            return Err(error("event batch limit must be in 1..=64"));
        }
        let wait = Wait {
            kind: request.kind,
            paused_only: request.paused_only == Some(true),
            tid: request.tid,
            after: if request.fresh == Some(true) {
                self.sequence
            } else {
                0
            },
            deadline: Instant::now() + Duration::from_millis(timeout),
            limit,
        };
        let resume = request.resume == Some(true)
            && !self.ended(&wait)
            && !self
                .events
                .iter()
                .any(|entry| wait.deliverable(entry, &held));
        self.next_wait += 1;
        self.waiters.insert(self.next_wait, wait);
        Ok((self.next_wait, resume))
    }

    pub fn remove(&mut self, id: u64) {
        self.waiters.remove(&id);
    }

    fn ended(&self, wait: &Wait) -> bool {
        self.terminal || wait.tid.is_some_and(|tid| self.exited.contains_key(&tid))
    }

    pub fn poll(&mut self, now: Instant, held: impl Fn(i32, u64) -> bool) -> Vec<(u64, Value)> {
        let mut results = Vec::new();
        let mut completed = Vec::new();
        for (&id, wait) in &self.waiters {
            let first = self
                .events
                .iter()
                .position(|entry| wait.deliverable(entry, &held));
            let mut result = None;
            if let Some(index) = first
                && self.events[index].ready
            {
                let mut row = self.events.remove(index).unwrap().row;
                refresh_paused(&mut row, &held);
                if wait.kind == Kind::Batch && row["kind"] != "exit" {
                    let mut batch = vec![row];
                    let mut index = index;
                    while index < self.events.len() && batch.len() < wait.limit {
                        let next = &self.events[index];
                        if !wait.matches(next) {
                            index += 1;
                            continue;
                        }
                        if !next.ready || next.row["kind"] == "exit" {
                            break;
                        }
                        let mut row = self.events.remove(index).unwrap().row;
                        refresh_paused(&mut row, &held);
                        batch.push(row);
                    }
                    result = Some(json!({"kind":"stops", "events":batch}));
                } else {
                    result = Some(row);
                }
            } else if first.is_none() && self.ended(wait) {
                result = Some(json!({"kind":"ended"}));
            } else if now >= wait.deadline {
                result = Some(json!({"kind":"timeout"}));
            }
            if let Some(result) = result {
                completed.push(id);
                results.push((id, result));
            }
        }
        for id in completed {
            self.waiters.remove(&id);
        }
        results
    }

    pub fn status(&self) -> Vec<Value> {
        self.waiters
            .iter()
            .map(|(&id, wait)| {
                let kind = match wait.kind {
                    Kind::Stop => "stop",
                    Kind::Hit => "hit",
                    Kind::ThreadExit => "thread_exit",
                    Kind::ProcessExit => "process_exit",
                    Kind::Batch => "stops",
                };
                json!({"id":id, "kind":kind, "tid":wait.tid})
            })
            .collect()
    }
}

fn is_held(row: &Value, held: &impl Fn(i32, u64) -> bool) -> bool {
    row["paused"] == true
        && row["tid"]
            .as_i64()
            .is_some_and(|tid| held(tid as i32, row["sequence"].as_u64().unwrap()))
}

fn refresh_paused(row: &mut Value, held: &impl Fn(i32, u64) -> bool) {
    if row["paused"] == true {
        row["paused"] = json!(is_held(row, held));
    }
}
