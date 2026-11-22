use crate::script_observation::Request;
use crate::{Diagnostic, Result, hex};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Serialize, PartialEq)]
pub(super) struct ThreadState {
    pub tid: i32,
    pub state: String,
    pub wait_channel: Option<String>,
    pub pc: Option<String>,
    pub futex: Option<u64>,
}

struct Observation {
    samples: u32,
    interval: Duration,
    locks: BTreeMap<u64, u32>,
    waits: Vec<(i32, u64)>,
}

fn invalid(message: &str) -> Diagnostic {
    Diagnostic::new("INVALID_ARGUMENT", message, None)
}

fn address(value: &str) -> Result<u64> {
    let parsed = match value.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse(),
    };
    parsed.map_err(|_| invalid("expected a decimal or hexadecimal address").into())
}

impl Observation {
    fn new(request: Request, live: bool) -> Result<Self> {
        let samples = request.samples.unwrap_or(if live { 10 } else { 1 });
        let interval = request.interval_ms.unwrap_or(25);
        if !(1..=128).contains(&samples)
            || (!live && samples != 1)
            || !(1..=1000).contains(&interval)
            || samples.saturating_sub(1) * interval > 5000
            || request.locks.len() > 128
            || request.waits.len() > 256
        {
            return Err(invalid("provide up to 128 samples within five seconds and up to 128 locks; cores have one sample").into());
        }
        let mut locks = BTreeMap::new();
        for lock in request.locks {
            let addr = address(&lock.address)?;
            let offset = lock.owner_offset.unwrap_or(8);
            if addr == 0
                || offset > 4096
                || addr.checked_add(u64::from(offset) + 4).is_none()
                || locks.insert(addr, offset).is_some()
            {
                return Err(invalid("invalid or repeated lock address/owner_offset").into());
            }
        }
        let mut waits = Vec::new();
        for wait in request.waits {
            let addr = address(&wait.address)?;
            if wait.tid <= 0 || !locks.contains_key(&addr) {
                return Err(invalid(
                    "each supplied wait must name a positive TID and a listed lock",
                )
                .into());
            }
            waits.push((wait.tid, addr));
        }
        Ok(Self {
            samples,
            interval: Duration::from_millis(u64::from(interval)),
            locks,
            waits,
        })
    }

    fn collect(
        self,
        source: &str,
        mut threads: impl FnMut() -> Result<Vec<ThreadState>>,
        mut owner: impl FnMut(u64) -> Result<u64>,
    ) -> Result<Value> {
        let start = Instant::now();
        let mut timeline = Vec::new();
        let mut timeline_truncated = false;
        let mut append = |row: Value| {
            if timeline.len() < 4096 {
                timeline.push(row);
            } else {
                timeline_truncated = true;
            }
        };
        let mut previous = BTreeMap::new();
        let mut graph = Value::Null;
        let mut samples = 0;
        for i in 0..self.samples {
            std::thread::sleep(
                (start + self.interval * i).saturating_duration_since(Instant::now()),
            );
            let ms = start.elapsed().as_millis() as u64;
            let current: BTreeMap<_, _> = threads()?
                .into_iter()
                .map(|thread| (thread.tid, thread))
                .collect();
            let mut readable = BTreeMap::new();
            let mut lock_rows = Vec::new();
            for (&addr, &offset) in &self.locks {
                let result = owner(addr + u64::from(offset)).map(|raw| raw as i32);
                if let Ok(tid) = result.as_ref()
                    && *tid > 0
                    && current.contains_key(tid)
                {
                    readable.insert(addr, *tid);
                }
                lock_rows.push(json!({
                    "address": hex(addr), "owner_tid": result.as_ref().ok(),
                    "issue": result.err().map(|err| err.to_string())
                }));
            }
            let mut edges = BTreeMap::new();
            for thread in current.values() {
                if let Some(addr) = thread.futex
                    && let Some(&owner) = readable.get(&addr)
                {
                    edges.insert((thread.tid, owner, addr), "futex_wait");
                }
                if previous.get(&thread.tid) != Some(thread) {
                    let mut row = serde_json::to_value(thread)?;
                    row["elapsed_ms"] = json!(ms);
                    row["futex"] = json!(thread.futex.map(hex));
                    append(row);
                }
            }
            for &tid in previous.keys() {
                if !current.contains_key(&tid) {
                    append(json!({"tid": tid, "state": "exited", "elapsed_ms": ms}));
                }
            }
            for &(tid, addr) in &self.waits {
                if current.contains_key(&tid)
                    && let Some(&owner) = readable.get(&addr)
                {
                    edges.entry((tid, owner, addr)).or_insert("supplied");
                }
            }
            let cycles = cycles(edges.keys().map(|&(waiter, owner, _)| (waiter, owner)));
            let edges: Vec<_> = edges.into_iter().map(|((waiter, owner, addr), evidence)| {
                json!({"waiter_tid": waiter, "owner_tid": owner, "address": hex(addr), "evidence": evidence})
            }).collect();
            graph = json!({"elapsed_ms": ms, "locks": lock_rows, "edges": edges, "cycles": cycles});
            previous = current;
            samples += 1;
            if previous.is_empty() {
                break;
            }
        }
        Ok(
            json!({"source": source, "samples": samples, "timeline": timeline, "timeline_truncated": timeline_truncated, "lock_graph": graph}),
        )
    }
}

fn cycles(edges: impl Iterator<Item = (i32, i32)>) -> Vec<Vec<i32>> {
    let mut graph = BTreeMap::<i32, Vec<i32>>::new();
    for (waiter, owner) in edges {
        graph.entry(waiter).or_default().push(owner);
    }
    let reachable = |root: i32| {
        let mut pending = graph.get(&root).cloned().unwrap_or_default();
        let mut seen = BTreeSet::new();
        while let Some(tid) = pending.pop() {
            if seen.insert(tid)
                && let Some(next) = graph.get(&tid)
            {
                pending.extend(next);
            }
        }
        seen
    };
    let mut groups = Vec::new();
    let mut assigned = BTreeSet::new();
    for &tid in graph.keys() {
        if assigned.contains(&tid) {
            continue;
        }
        let forward = reachable(tid);
        if forward.contains(&tid) {
            let component: Vec<_> = forward
                .into_iter()
                .filter(|&other| reachable(other).contains(&tid))
                .collect();
            assigned.extend(component.iter().copied());
            groups.push(component);
        }
    }
    groups
}

fn proc_thread(tid: i32, path: &Path) -> Option<ThreadState> {
    let status = fs::read_to_string(path.join("status")).ok()?;
    let state = status
        .lines()
        .find_map(|line| line.strip_prefix("State:"))?
        .trim()
        .to_owned();
    let wchan = fs::read_to_string(path.join("wchan"))
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| text != "0" && !text.is_empty());
    let syscall = fs::read_to_string(path.join("syscall")).ok();
    let mut words = syscall
        .as_deref()
        .unwrap_or_default()
        .split_ascii_whitespace();
    let number = words.next().and_then(|n| n.parse::<i64>().ok());
    let futex = if state.starts_with(['S', 'D']) && number == Some(nix::libc::SYS_futex) {
        let location = words.next().and_then(|word| address(word).ok());
        let op = words.next().and_then(|word| address(word).ok());
        location.filter(|_| op.is_some_and(|op| matches!(op & 127, 0 | 6 | 9 | 11 | 13)))
    } else {
        None
    };
    let pc = number
        .and_then(|_| syscall.as_deref()?.split_ascii_whitespace().last())
        .filter(|word| word.starts_with("0x"))
        .map(str::to_owned);
    Some(ThreadState {
        tid,
        state,
        wait_channel: wchan,
        pc,
        futex,
    })
}

pub fn live(pid: i32, request: Request) -> Result<Value> {
    let start = crate::coredump::target_identity(pid)?;
    let task = format!("/proc/{pid}/task");
    Observation::new(request, true)?.collect(
        "live",
        || {
            if crate::coredump::target_identity(pid).ok() != Some(start) {
                return Ok(Vec::new());
            }
            let entries = match fs::read_dir(&task) {
                Ok(entries) => entries,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(err) => return Err(err.into()),
            };
            Ok(entries
                .flatten()
                .filter_map(|entry| {
                    proc_thread(entry.file_name().to_str()?.parse().ok()?, &entry.path())
                })
                .take(512)
                .collect())
        },
        |addr| crate::trace::read_process_word(pid, addr, 4),
    )
}

pub(super) fn core(
    request: Request,
    threads: impl FnMut() -> Result<Vec<ThreadState>>,
    owner: impl FnMut(u64) -> Result<u64>,
) -> Result<Value> {
    Observation::new(request, false)?.collect("core", threads, owner)
}
