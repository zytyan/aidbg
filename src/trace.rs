use crate::procfs::{Status, epoch_ms, start_ticks, task_ids, task_path};
use crate::{Result, error, modules, software_breakpoint as software};
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
    Breakpoint {
        slots: u64,
        observed: Instant,
        unix_ms: u64,
    },
    Software {
        address: u64,
        observed: Instant,
        unix_ms: u64,
    },
    Step,
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
            Self::Software { .. } => StopInfo {
                kind: "software_breakpoint",
                signal: libc::SIGTRAP,
                event: None,
            },
            Self::Step => StopInfo {
                kind: "single_step",
                signal: libc::SIGTRAP,
                event: None,
            },
            Self::Breakpoint { .. } => StopInfo {
                kind: "hardware_breakpoint",
                signal: libc::SIGTRAP,
                event: None,
            },
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
    pub newborn: bool,
    stepping: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_restore_error: Option<String>,
}

impl Cleanup {
    pub fn ok(&self) -> bool {
        self.software_restore_error.is_none() && self.threads.iter().all(|t| t.outcome != "failed")
    }
}

pub struct Trace<'a> {
    pub threads: BTreeMap<i32, Thread>,
    pub observed: BTreeMap<i32, Option<Status>>,
    pub started: Option<Instant>,
    pid: Pid,
    root: &'a Path,
    start_ticks: u64,
    monitored: bool,
    patches: BTreeMap<u64, Patch>,
    pub foreign_software: bool,
    _same_thread: PhantomData<Rc<()>>,
}

struct Patch {
    original: u8,
    mapping: modules::CodeMapping,
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
            monitored: false,
            patches: BTreeMap::new(),
            foreign_software: false,
            _same_thread: PhantomData,
        }
    }

    pub fn monitor(&mut self) {
        self.monitored = true;
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
                let options = if self.monitored {
                    ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEEXEC
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK
                } else {
                    ptrace::Options::empty()
                };
                match ptrace::seize(Pid::from_raw(tid), options) {
                    Ok(()) => {
                        self.started.get_or_insert_with(Instant::now);
                        self.threads.insert(
                            tid,
                            Thread {
                                before: self.observed.remove(&tid).flatten(),
                                stop: None,
                                requested: false,
                                newborn: false,
                                stepping: false,
                            },
                        );
                    }
                    Err(Errno::ESRCH) if !task.is_dir() => continue,
                    // A clone event may already have attached this thread.
                    Err(Errno::EPERM)
                        if self.monitored
                            && Status::read(&task).ok().is_some_and(|s| {
                                s.field("TracerPid").and_then(|t| t.parse::<i32>().ok())
                                    == Some(unsafe { libc::gettid() })
                            }) =>
                    {
                        continue;
                    }
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
            if thread.stop.is_some() || thread.requested || thread.newborn {
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
            self.poll()?;
            self.detach_foreign_children()?;
            let pending = self.threads.values().any(|thread| thread.stop.is_none());
            if !pending {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(error("timed out waiting for ptrace stop"));
            }
            sleep(Duration::from_millis(1));
        }
    }

    pub fn poll(&mut self) -> Result<()> {
        let mut children = Vec::new();
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
                Ok(WaitStatus::PtraceEvent(_, sig, event)) => {
                    if matches!(
                        event,
                        libc::PTRACE_EVENT_CLONE
                            | libc::PTRACE_EVENT_FORK
                            | libc::PTRACE_EVENT_VFORK
                    ) {
                        match ptrace::getevent(Pid::from_raw(tid)) {
                            Ok(child) => children.push(child as i32),
                            Err(e) => {
                                failure.get_or_insert_with(|| error(e.to_string()));
                            }
                        }
                    }
                    Some(Stop::Event(sig, event))
                }
                Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) if self.monitored => {
                    let code = ptrace::getsiginfo(Pid::from_raw(tid))
                        .ok()
                        .map(|info| info.si_code);
                    let observed = Instant::now();
                    let unix_ms = epoch_ms();
                    match code {
                        Some(libc::TRAP_TRACE | libc::TRAP_HWBKPT)
                            if thread.stepping || code == Some(libc::TRAP_HWBKPT) =>
                        {
                            match crate::breakpoint::triggered(tid) {
                                Ok(0) if thread.stepping => Some(Stop::Step),
                                Ok(slots) => Some(Stop::Breakpoint {
                                    slots,
                                    observed,
                                    unix_ms,
                                }),
                                Err(e) => {
                                    failure.get_or_insert(e);
                                    Some(Stop::Breakpoint {
                                        slots: 0,
                                        observed,
                                        unix_ms,
                                    })
                                }
                            }
                        }
                        Some(libc::SI_KERNEL | libc::TRAP_BRKPT) => software::pc(tid)
                            .ok()
                            .and_then(|pc| pc.checked_sub(1))
                            .filter(|address| self.patches.contains_key(address))
                            .map(|address| Stop::Software {
                                address,
                                observed,
                                unix_ms,
                            })
                            .or(Some(Stop::Delivery(Signal::SIGTRAP))),
                        _ => Some(Stop::Delivery(Signal::SIGTRAP)),
                    }
                }
                Ok(WaitStatus::Stopped(_, sig)) => Some(Stop::Delivery(sig)),
                Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => {
                    exited.push(tid);
                    None
                }
                Err(Errno::ECHILD | Errno::ESRCH) if !task_path(self.root, tid).is_dir() => {
                    exited.push(tid);
                    None
                }
                Ok(_) | Err(Errno::EINTR) => None,
                Err(e) => {
                    failure.get_or_insert_with(|| error(format!("waitpid {tid}: {e}")));
                    None
                }
            };
            if thread.stop.is_some() {
                thread.requested = false;
                thread.stepping = false;
            }
        }
        for tid in children {
            self.threads.entry(tid).or_insert_with(|| Thread {
                before: Status::read(&task_path(self.root, tid)).ok(),
                stop: None,
                requested: false,
                newborn: true,
                stepping: false,
            });
        }
        for tid in exited {
            if let Some(t) = self.threads.remove(&tid)
                && !self.monitored
            {
                self.observed.insert(tid, t.before);
            }
        }
        if let Some(e) = failure {
            return Err(e);
        }
        Ok(())
    }

    pub fn resume(&mut self, tid: i32) -> Result<()> {
        let thread = self.threads.get_mut(&tid).expect("known thread");
        let stop = thread.stop.expect("stopped thread");
        let pid = Pid::from_raw(tid);
        let result = match stop {
            Stop::Group(_) => {
                Errno::result(unsafe { libc::ptrace(libc::PTRACE_LISTEN, tid, 0_usize, 0_usize) })
                    .map(|_| ())
            }
            Stop::Delivery(signal) => ptrace::cont(pid, Some(signal)),
            _ => ptrace::cont(pid, None),
        };
        match result {
            Ok(()) => {
                thread.stop = None;
                thread.newborn = false;
                Ok(())
            }
            Err(Errno::ESRCH) => {
                // An exiting task can remain visible in procfs until reaped.
                thread.stop = None;
                thread.newborn = false;
                Ok(())
            }
            Err(e) => Err(error(format!("resume {tid}: {e}"))),
        }
    }

    pub fn detach_foreign_children(&mut self) -> Result<()> {
        let mut foreign = Vec::new();
        for (&tid, thread) in &self.threads {
            if thread.newborn && thread.stop.is_some() && !task_path(self.root, tid).is_dir() {
                if !self.patches.is_empty() {
                    // A fork can inherit patched bytes. vfork or a foreign
                    // CLONE_VM task can also share the parent's address space.
                    self.foreign_software = true;
                    self.restore_bytes(tid, Path::new(&format!("/proc/{tid}")))?;
                }
                match ptrace::detach(Pid::from_raw(tid), None) {
                    Ok(()) | Err(Errno::ESRCH) => foreign.push(tid),
                    Err(e) => return Err(error(format!("detach cloned process {tid}: {e}"))),
                }
            }
        }
        for tid in foreign {
            self.threads.remove(&tid);
        }
        Ok(())
    }

    fn stopped_tid(&self) -> Result<i32> {
        self.threads
            .iter()
            .find_map(|(&tid, thread)| {
                (thread.stop.is_some() && task_path(self.root, tid).is_dir()).then_some(tid)
            })
            .ok_or_else(|| error("no stopped thread for software breakpoint"))
    }

    pub fn patch(&mut self, address: u64) -> Result<()> {
        let tid = self.stopped_tid()?;
        let mapping = modules::private_code_mapping(self.root, address, true)?
            .ok_or_else(|| error("software breakpoints require a private executable mapping"))?;
        let original = software::read_byte(tid, address)?;
        if original == software::TRAP {
            return Err(error("software breakpoint address already contains INT3"));
        }
        software::write_byte(tid, address, software::TRAP)?;
        self.patches.insert(address, Patch { original, mapping });
        Ok(())
    }

    pub fn unpatch(&mut self, address: u64) -> Result<()> {
        let tid = self.stopped_tid()?;
        self.restore_byte(tid, address, &self.patches[&address], self.root)?;
        self.patches.remove(&address);
        Ok(())
    }

    fn restore_byte(&self, tid: i32, address: u64, patch: &Patch, root: &Path) -> Result<()> {
        if modules::private_code_mapping(root, address, false)?.as_ref() == Some(&patch.mapping)
            && software::read_byte(tid, address)? == software::TRAP
        {
            software::write_byte(tid, address, patch.original)?;
        }
        Ok(())
    }

    fn restore_bytes(&self, tid: i32, root: &Path) -> Result<()> {
        let mut failure = None;
        for (&address, patch) in &self.patches {
            if let Err(e) = self.restore_byte(tid, address, patch, root) {
                failure.get_or_insert(e);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    pub fn rewind_software_stops(&self) -> Result<()> {
        for (&tid, t) in &self.threads {
            if let Some(Stop::Software { address, .. }) = t.stop {
                software::set_pc(tid, address)?;
            }
        }
        Ok(())
    }

    pub fn step_software(&mut self, tid: i32, address: u64, deadline: Instant) -> Result<()> {
        let patch = &self.patches[&address];
        self.restore_byte(tid, address, patch, self.root)?;
        software::set_pc(tid, address)?;
        loop {
            ptrace::step(Pid::from_raw(tid), None)?;
            let thread = self.threads.get_mut(&tid).expect("known thread");
            thread.stop = None;
            thread.stepping = true;
            self.wait_for_stops(deadline)?;
            if !self
                .threads
                .get(&tid)
                .is_some_and(|thread| matches!(thread.stop, Some(Stop::Interrupt)))
                || software::pc(tid)? != address
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(error("software single-step interrupted after its deadline"));
            }
        }
        if self.foreign_software || self.exec_observed() {
            return Err(error(
                "target address space changed during software single-step",
            ));
        }
        if let Ok(tid) = self.stopped_tid() {
            // The old instruction may have unmapped or changed its own page.
            let patch = &self.patches[&address];
            if modules::private_code_mapping(self.root, address, true)?.as_ref()
                != Some(&patch.mapping)
                || software::read_byte(tid, address)? != patch.original
            {
                return Err(error(
                    "software breakpoint instruction changed during single-step",
                ));
            }
            software::write_byte(tid, address, software::TRAP)?;
        }
        Ok(())
    }

    pub fn exec_observed(&self) -> bool {
        self.threads
            .values()
            .any(|t| matches!(t.stop, Some(Stop::Event(_, libc::PTRACE_EVENT_EXEC))))
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
        let mut cleanup = Cleanup::default();
        // Release threads already in a ptrace stop before waiting for any
        // uninterruptible thread. Detach forwards real signal-delivery stops.
        if !self.monitored {
            self.detach_stopped(&mut cleanup);
        }
        if !self.threads.is_empty() {
            let interrupt = self.request_stops().err();
            let wait = self
                .wait_for_stops(Instant::now() + Duration::from_millis(250))
                .err();
            if !self.patches.is_empty() && !self.exec_observed() && !self.threads.is_empty() {
                cleanup.software_restore_error = self
                    .stopped_tid()
                    .and_then(|tid| self.restore_bytes(tid, self.root))
                    .err()
                    .map(|e| format!("restore software breakpoints: {e}"));
            }
            self.detach_stopped(&mut cleanup);
            self.patches.clear();
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
            let rewind = if let Stop::Software { address, .. } = stop {
                software::set_pc(tid, address).err()
            } else {
                None
            };
            // On x86 PTRACE_DETACH does not clear DR7 in the tracee.
            let disarm =
                if self.monitored && !matches!(stop, Stop::Event(_, libc::PTRACE_EVENT_EXEC)) {
                    crate::breakpoint::disarm(tid).err()
                } else {
                    None
                };
            let foreign_cleanup = if thread.newborn
                && !self.patches.is_empty()
                && !task_path(self.root, tid).is_dir()
            {
                self.restore_bytes(tid, Path::new(&format!("/proc/{tid}")))
                    .err()
            } else {
                None
            };
            let recovery = rewind.or(disarm).or(foreign_cleanup);
            let (outcome, detail) = match ptrace::detach(Pid::from_raw(tid), signal) {
                Ok(()) if recovery.is_none() => ("detached", None),
                Ok(()) => (
                    "failed",
                    recovery.map(|e| format!("detached after breakpoint recovery failed: {e}")),
                ),
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
