use crate::procfs::{Status, start_ticks, task_ids, task_path};
use crate::{Result, error};
use nix::errno::Errno;
use nix::libc;
use nix::sys::{
    ptrace,
    signal::Signal,
    uio,
    wait::{WaitPidFlag, WaitStatus, waitpid},
};
use nix::unistd::Pid;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::IoSliceMut;
use std::marker::PhantomData;
use std::path::Path;
use std::rc::Rc;
use std::thread::sleep;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub enum Stop {
    Interrupt,
    Group(Signal),
    Delivery(Signal),
    Event(Signal, i32),
}

#[derive(Serialize)]
pub struct StopInfo {
    pub kind: &'static str,
    pub signal: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<i32>,
}

impl Stop {
    pub fn info(self) -> StopInfo {
        match self {
            Self::Interrupt => StopInfo {
                kind: "snapshot_interrupt",
                signal: libc::SIGTRAP,
                event: None,
            },
            Self::Group(sig) => StopInfo {
                kind: "group_stop",
                signal: sig as i32,
                event: None,
            },
            Self::Delivery(sig) => StopInfo {
                kind: "signal_delivery",
                signal: sig as i32,
                event: None,
            },
            Self::Event(sig, event) => StopInfo {
                kind: "ptrace_event",
                signal: sig as i32,
                event: Some(event),
            },
        }
    }
}

pub struct Thread {
    pub before: Option<Status>,
    pub stop: Option<Stop>,
    requested: bool,
}

#[derive(Serialize)]
pub struct CleanupThread {
    pub tid: i32,
    pub outcome: &'static str,
    pub group_stop_before_detach: bool,
    pub preserved_group_stop: bool,
    pub state_after_detach: Option<String>,
    pub forwarded_signal: Option<i32>,
    pub detail: Option<String>,
}

#[derive(Default, Serialize)]
pub struct Cleanup {
    pub threads: Vec<CleanupThread>,
}

impl Cleanup {
    pub fn ok(&self) -> bool {
        self.threads.iter().all(|t| t.outcome != "failed")
    }
}

pub struct Trace<'a> {
    pub threads: BTreeMap<i32, Thread>,
    pub observed: BTreeMap<i32, Option<Status>>,
    pub started: Option<Instant>,
    pid: Pid,
    root: &'a Path,
    start_ticks: u64,
    _same_thread: PhantomData<Rc<()>>,
}

impl<'a> Trace<'a> {
    pub fn new(pid: i32, root: &'a Path, start_ticks: u64) -> Self {
        Self {
            threads: BTreeMap::new(),
            observed: BTreeMap::new(),
            started: None,
            pid: Pid::from_raw(pid),
            root,
            start_ticks,
            _same_thread: PhantomData,
        }
    }

    pub fn freeze(&mut self, deadline: Instant) -> Result<()> {
        for _ in 0..8 {
            if Instant::now() >= deadline {
                return Err(error("thread freeze deadline"));
            }
            if start_ticks(self.root)? != self.start_ticks {
                return Err(error("target identity changed"));
            }
            let ids = task_ids(self.root)?;
            for tid in ids {
                if self.threads.contains_key(&tid) {
                    continue;
                }
                if Instant::now() >= deadline {
                    return Err(error("thread freeze deadline"));
                }
                let task = task_path(self.root, tid);
                let before = Status::read(&task).ok();
                self.observed.insert(tid, before);
                // Do not seize a recycled TID that no longer belongs to this process.
                if !task.is_dir() {
                    continue;
                }
                match ptrace::seize(Pid::from_raw(tid), ptrace::Options::empty()) {
                    Ok(()) => {
                        self.started.get_or_insert_with(Instant::now);
                        self.threads.insert(
                            tid,
                            Thread {
                                before: self.observed.remove(&tid).flatten(),
                                stop: None,
                                requested: false,
                            },
                        );
                    }
                    Err(Errno::ESRCH) if !task.is_dir() => continue,
                    Err(e) => return Err(error(format!("PTRACE_SEIZE {tid}: {e}"))),
                }
            }
            self.request_stops()?;
            self.wait_for_stops(deadline)?;
            let after = task_ids(self.root)?;
            if !after.is_empty()
                && after.len() == self.threads.len()
                && after
                    .iter()
                    .all(|tid| self.threads.get(tid).is_some_and(|t| t.stop.is_some()))
            {
                if start_ticks(self.root)? != self.start_ticks {
                    return Err(error("target identity changed"));
                }
                return Ok(());
            }
        }
        Err(error("thread set did not stabilize"))
    }

    fn request_stops(&mut self) -> Result<()> {
        let mut failure = None;
        for (&tid, thread) in &mut self.threads {
            if thread.stop.is_some() || thread.requested {
                continue;
            }
            match ptrace::interrupt(Pid::from_raw(tid)) {
                Ok(()) | Err(Errno::ESRCH) => thread.requested = true,
                Err(e) => {
                    failure.get_or_insert_with(|| error(format!("PTRACE_INTERRUPT {tid}: {e}")));
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn wait_for_stops(&mut self, deadline: Instant) -> Result<()> {
        loop {
            let mut pending = false;
            let mut exited = Vec::new();
            let mut failure = None;
            for (&tid, thread) in &mut self.threads {
                if thread.stop.is_some() {
                    continue;
                }
                let status = waitpid(
                    Pid::from_raw(tid),
                    Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG),
                );
                thread.stop = match status {
                    Ok(WaitStatus::PtraceEvent(_, sig, libc::PTRACE_EVENT_STOP)) => {
                        Some(if sig == Signal::SIGTRAP {
                            Stop::Interrupt
                        } else {
                            Stop::Group(sig)
                        })
                    }
                    Ok(WaitStatus::PtraceEvent(_, sig, event)) => Some(Stop::Event(sig, event)),
                    Ok(WaitStatus::Stopped(_, sig)) => Some(Stop::Delivery(sig)),
                    Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => {
                        exited.push(tid);
                        None
                    }
                    Err(Errno::ECHILD | Errno::ESRCH) if !task_path(self.root, tid).is_dir() => {
                        exited.push(tid);
                        None
                    }
                    Ok(_) | Err(Errno::EINTR) => {
                        pending = true;
                        None
                    }
                    Err(e) => {
                        failure.get_or_insert_with(|| error(format!("waitpid {tid}: {e}")));
                        None
                    }
                };
            }
            for tid in exited {
                if let Some(t) = self.threads.remove(&tid) {
                    self.observed.insert(tid, t.before);
                }
            }
            if let Some(e) = failure {
                return Err(e);
            }
            if !pending {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(error("timed out waiting for ptrace stop"));
            }
            sleep(Duration::from_millis(1));
        }
    }

    pub fn read_word(&self, addr: u64, size: usize) -> Result<u64> {
        if !(1..=8).contains(&size) || addr.checked_add(size as u64).is_none() {
            return Err(error("invalid remote read range"));
        }
        let mut buf = [0_u8; 8];
        let local = &mut [IoSliceMut::new(&mut buf[..size])];
        let remote = [uio::RemoteIoVec {
            base: usize::try_from(addr)?,
            len: size,
        }];
        let got = uio::process_vm_readv(self.pid, local, &remote)?;
        if got != size {
            return Err(error(format!("short remote read: {got}/{size}")));
        }
        Ok(u64::from_le_bytes(buf))
    }

    pub fn close(&mut self) -> Cleanup {
        let before: Vec<_> = self.threads.keys().copied().collect();
        let mut cleanup = Cleanup {
            threads: Vec::new(),
        };
        // Release threads already in a ptrace stop before waiting for any
        // uninterruptible thread. Detach forwards real signal-delivery stops.
        self.detach_stopped(&mut cleanup);
        if !self.threads.is_empty() {
            let interrupt = self.request_stops().err();
            let wait = self
                .wait_for_stops(Instant::now() + Duration::from_millis(250))
                .err();
            self.detach_stopped(&mut cleanup);
            for (tid, _) in std::mem::take(&mut self.threads) {
                cleanup.threads.push(CleanupThread {
                    tid,
                    outcome: "failed",
                    group_stop_before_detach: false,
                    preserved_group_stop: false,
                    state_after_detach: None,
                    forwarded_signal: None,
                    detail: Some(wait.as_ref().or(interrupt.as_ref()).map_or_else(
                        || "thread did not reach a detachable stop".to_owned(),
                        ToString::to_string,
                    )),
                });
            }
        }
        for tid in before {
            if !cleanup.threads.iter().any(|row| row.tid == tid) {
                cleanup.threads.push(CleanupThread {
                    tid,
                    outcome: "exited",
                    group_stop_before_detach: false,
                    preserved_group_stop: false,
                    state_after_detach: None,
                    forwarded_signal: None,
                    detail: None,
                });
            }
        }
        // A detached task can briefly be runnable as it returns through the
        // kernel's group-stop path. Observe after every thread was detached.
        let deadline = Instant::now() + Duration::from_millis(25);
        loop {
            let mut pending_group_stop = false;
            for row in &mut cleanup.threads {
                if row.outcome != "detached" || row.preserved_group_stop {
                    continue;
                }
                row.state_after_detach = Status::read(&task_path(self.root, row.tid))
                    .ok()
                    .and_then(|s| s.state());
                row.preserved_group_stop =
                    row.group_stop_before_detach && row.state_after_detach.as_deref() == Some("T");
                pending_group_stop |= row.group_stop_before_detach && !row.preserved_group_stop;
            }
            if !pending_group_stop || Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_millis(1));
        }
        cleanup.threads.sort_unstable_by_key(|row| row.tid);
        cleanup
    }

    fn detach_stopped(&mut self, result: &mut Cleanup) {
        let tids: Vec<_> = self
            .threads
            .iter()
            .filter_map(|(&tid, t)| t.stop.map(|_| tid))
            .rev()
            .collect();
        for tid in tids {
            let Some(thread) = self.threads.remove(&tid) else {
                continue;
            };
            let stop = thread.stop.expect("selected stopped thread");
            let signal = match stop {
                Stop::Delivery(sig) => Some(sig),
                _ => None,
            };
            let (outcome, detail) = match ptrace::detach(Pid::from_raw(tid), signal) {
                Ok(()) => ("detached", None),
                Err(Errno::ESRCH) if !task_path(self.root, tid).is_dir() => ("exited", None),
                Err(e) => ("failed", Some(format!("PTRACE_DETACH: {e}"))),
            };
            result.threads.push(CleanupThread {
                tid,
                outcome,
                detail,
                group_stop_before_detach: matches!(stop, Stop::Group(_)),
                preserved_group_stop: false,
                state_after_detach: None,
                forwarded_signal: (outcome == "detached")
                    .then_some(signal)
                    .flatten()
                    .map(|s| s as i32),
            });
        }
    }
}

impl Drop for Trace<'_> {
    fn drop(&mut self) {
        self.close();
    }
}
