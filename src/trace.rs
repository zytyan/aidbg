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
use std::io::{IoSlice, IoSliceMut};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::thread::sleep;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub enum Stop {
    Interrupt,
    ExecBoundary,
    Group(Signal),
    Delivery(Signal),
    UnnamedDelivery(i32),
    Event(Signal, i32),
    Breakpoint {
        slots: u64,
        address: Option<u64>,
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
            Self::ExecBoundary => StopInfo {
                kind: "exec_boundary",
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
            Self::UnnamedDelivery(signal) => StopInfo {
                kind: "signal_delivery",
                signal,
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

fn next_thread_identity() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub struct Thread {
    pub(crate) identity: u64,
    pub before: Option<Status>,
    pub stop: Option<Stop>,
    requested: bool,
    pub newborn: bool,
    private_fork: bool,
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

pub struct Trace {
    pub threads: BTreeMap<i32, Thread>,
    pub observed: BTreeMap<i32, Option<Status>>,
    pub started: Option<Instant>,
    pid: Pid,
    root: PathBuf,
    start_ticks: u64,
    monitored: bool,
    launched: bool,
    pub(crate) exit: Option<LaunchExit>,
    pub(crate) retired: Option<Vec<(i32, Option<LaunchExit>)>>,
    pub(crate) follow_fork: bool,
    follow_child: Option<i32>,
    patches: BTreeMap<u64, Patch>,
    pub foreign_software: bool,
    _same_thread: PhantomData<Rc<()>>,
}

#[derive(Clone, Copy)]
pub(crate) enum LaunchExit {
    Code(i32),
    Signal(i32),
}

enum Wait {
    Named(WaitStatus),
    Delivery(i32),
    Terminated(i32),
}

fn wait_for_task(tid: i32, launched: bool) -> nix::Result<Wait> {
    let flags = WaitPidFlag::__WALL | WaitPidFlag::WNOHANG;
    let pid = Pid::from_raw(tid);
    if !launched {
        return waitpid(pid, Some(flags)).map(Wait::Named);
    }
    let mut raw = 0;
    if Errno::result(unsafe { libc::waitpid(tid, &mut raw, flags.bits()) })? == 0 {
        return Ok(Wait::Named(WaitStatus::StillAlive));
    }
    // Nix only represents standard signals. Pass real-time signals through.
    match WaitStatus::from_raw(pid, raw) {
        Err(Errno::EINVAL) if libc::WIFSTOPPED(raw) => Ok(Wait::Delivery(libc::WSTOPSIG(raw))),
        Err(Errno::EINVAL) if libc::WIFSIGNALED(raw) => Ok(Wait::Terminated(libc::WTERMSIG(raw))),
        result => result.map(Wait::Named),
    }
}

fn forward_signal(request: libc::c_uint, tid: i32, signal: i32) -> nix::Result<()> {
    Errno::result(unsafe { libc::ptrace(request as _, tid, 0_usize, signal as usize) }).map(|_| ())
}

fn fork_copies_vm(tid: i32) -> bool {
    let Ok(regs) = ptrace::getregs(Pid::from_raw(tid)) else {
        return false;
    };
    #[cfg(target_arch = "x86_64")]
    let (syscall, argument) = (regs.orig_rax, regs.rdi);
    #[cfg(target_arch = "aarch64")]
    let (syscall, argument) = (regs.regs[8], regs.regs[0]);
    #[cfg(target_arch = "x86_64")]
    if syscall == libc::SYS_fork as u64 {
        return true;
    }
    let flags = match syscall as libc::c_long {
        libc::SYS_clone => Some(argument),
        libc::SYS_clone3 => read_process_word(tid, argument, 8).ok(),
        _ => None,
    };
    flags.is_some_and(|flags| flags & libc::CLONE_VM as u64 == 0)
}

struct Patch {
    original: u32,
    mapping: modules::CodeMapping,
}

impl Trace {
    pub fn new(pid: i32, root: &Path, start_ticks: u64) -> Self {
        Self {
            threads: BTreeMap::new(),
            observed: BTreeMap::new(),
            started: None,
            pid: Pid::from_raw(pid),
            root: root.to_path_buf(),
            start_ticks,
            monitored: false,
            launched: false,
            exit: None,
            retired: None,
            follow_fork: false,
            follow_child: None,
            patches: BTreeMap::new(),
            foreign_software: false,
            _same_thread: PhantomData,
        }
    }

    pub fn monitor(&mut self) {
        self.monitored = true;
    }

    pub(crate) fn seize_launched(&mut self, trace_exit: bool) -> Result<()> {
        ptrace::seize(
            self.pid,
            ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_EXITKILL
                | if trace_exit {
                    ptrace::Options::PTRACE_O_TRACEEXIT
                } else {
                    ptrace::Options::empty()
                },
        )?;
        self.monitored = true;
        self.launched = true;
        self.threads.insert(
            self.pid.as_raw(),
            Thread {
                identity: next_thread_identity(),
                before: Status::read(&self.root).ok(),
                stop: None,
                requested: false,
                newborn: false,
                private_fork: false,
                stepping: false,
            },
        );
        Ok(())
    }

    pub fn freeze(&mut self, deadline: Instant) -> Result<()> {
        self.freeze_checked(deadline, &|| Ok(()))
    }

    pub(crate) fn freeze_checked(
        &mut self,
        deadline: Instant,
        check: &impl Fn() -> Result<()>,
    ) -> Result<()> {
        for _ in 0..8 {
            check()?;
            if Instant::now() >= deadline {
                return Err(error("thread freeze deadline"));
            }
            if start_ticks(&self.root)? != self.start_ticks {
                return Err(error("target identity changed"));
            }
            let ids = task_ids(&self.root)?;
            for tid in ids {
                check()?;
                if self.threads.contains_key(&tid) {
                    continue;
                }
                if Instant::now() >= deadline {
                    return Err(error("thread freeze deadline"));
                }
                let task = task_path(&self.root, tid);
                let before = Status::read(&task).ok();
                self.observed.insert(tid, before);
                // Do not seize a recycled TID that no longer belongs to this process.
                if !task.is_dir() {
                    continue;
                }
                let options = if self.launched {
                    ptrace::Options::PTRACE_O_TRACEEXEC
                        | ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK
                        | ptrace::Options::PTRACE_O_EXITKILL
                } else if self.monitored {
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
                                identity: next_thread_identity(),
                                before: self.observed.remove(&tid).flatten(),
                                stop: None,
                                requested: false,
                                newborn: false,
                                private_fork: false,
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
            self.wait_for_stops_checked(deadline, check)?;
            let after = task_ids(&self.root)?;
            if !after.is_empty()
                && after.len() == self.threads.len()
                && after
                    .iter()
                    .all(|tid| self.threads.get(tid).is_some_and(|t| t.stop.is_some()))
            {
                if start_ticks(&self.root)? != self.start_ticks {
                    return Err(error("target identity changed"));
                }
                return Ok(());
            }
        }
        Err(error("thread set did not stabilize"))
    }

    pub(crate) fn stop_thread(&mut self, tid: i32, deadline: Instant) -> Result<()> {
        let thread = self
            .threads
            .get_mut(&tid)
            .ok_or_else(|| error("thread no longer exists"))?;
        if thread.stop.is_none() && !thread.requested && !thread.newborn {
            ptrace::interrupt(Pid::from_raw(tid))?;
            thread.requested = true;
        }
        loop {
            self.poll()?;
            self.detach_foreign_children()?;
            match self.threads.get(&tid) {
                Some(thread) if thread.stop.is_some() => return Ok(()),
                None => return Err(error("thread no longer exists")),
                _ if Instant::now() >= deadline => {
                    return Err(error("timed out waiting for thread"));
                }
                _ => sleep(Duration::from_millis(1)),
            }
        }
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
        self.wait_for_stops_checked(deadline, &|| Ok(()))
    }

    fn wait_for_stops_checked(
        &mut self,
        deadline: Instant,
        check: &impl Fn() -> Result<()>,
    ) -> Result<()> {
        loop {
            check()?;
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
            if thread.stop.is_some() && self.retired.is_none() {
                continue;
            }
            let status = wait_for_task(tid, self.launched || self.retired.is_some());
            // SIGKILL can retire a task even while it is held in a ptrace stop.
            if matches!(
                status,
                Ok(Wait::Named(WaitStatus::StillAlive)) | Err(Errno::EINTR)
            ) {
                continue;
            }
            thread.stop = match status {
                Ok(Wait::Named(WaitStatus::PtraceEvent(_, sig, libc::PTRACE_EVENT_STOP))) => Some(
                    if sig == Signal::SIGTRAP || (self.launched && thread.newborn) {
                        Stop::Interrupt
                    } else {
                        Stop::Group(sig)
                    },
                ),
                Ok(Wait::Named(WaitStatus::PtraceEvent(_, sig, event))) => {
                    if matches!(
                        event,
                        libc::PTRACE_EVENT_CLONE
                            | libc::PTRACE_EVENT_FORK
                            | libc::PTRACE_EVENT_VFORK
                    ) {
                        match ptrace::getevent(Pid::from_raw(tid)) {
                            Ok(child) => {
                                let private_fork =
                                    event == libc::PTRACE_EVENT_FORK && fork_copies_vm(tid);
                                children.push((child as i32, private_fork));
                                if self.follow_fork && private_fork {
                                    self.follow_child.get_or_insert(child as i32);
                                }
                            }
                            Err(e) => {
                                failure.get_or_insert_with(|| error(e.to_string()));
                            }
                        }
                    }
                    Some(Stop::Event(sig, event))
                }
                Ok(Wait::Named(WaitStatus::Stopped(_, Signal::SIGTRAP)))
                    if self.monitored || thread.stepping =>
                {
                    let info = ptrace::getsiginfo(Pid::from_raw(tid)).ok();
                    let code = info.as_ref().map(|info| info.si_code);
                    let observed = Instant::now();
                    let unix_ms = epoch_ms();
                    match code {
                        Some(libc::TRAP_TRACE) if thread.stepping && !self.monitored => {
                            Some(Stop::Step)
                        }
                        Some(libc::TRAP_TRACE | libc::TRAP_HWBKPT)
                            if thread.stepping || code == Some(libc::TRAP_HWBKPT) =>
                        {
                            match crate::breakpoint::triggered(tid) {
                                Ok(0)
                                    if thread.stepping
                                        && (cfg!(target_arch = "x86_64")
                                            || code == Some(libc::TRAP_TRACE)) =>
                                {
                                    Some(Stop::Step)
                                }
                                Ok(slots) => Some(Stop::Breakpoint {
                                    slots,
                                    address: info
                                        .as_ref()
                                        .map(|info| unsafe { info.si_addr() } as u64),
                                    observed,
                                    unix_ms,
                                }),
                                Err(e) => {
                                    failure.get_or_insert(e);
                                    Some(Stop::Breakpoint {
                                        slots: 0,
                                        address: None,
                                        observed,
                                        unix_ms,
                                    })
                                }
                            }
                        }
                        Some(libc::SI_KERNEL | libc::TRAP_BRKPT) => software::trap_address(tid)
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
                Ok(Wait::Named(WaitStatus::Stopped(_, sig))) => Some(Stop::Delivery(sig)),
                Ok(Wait::Delivery(sig)) => Some(Stop::UnnamedDelivery(sig)),
                Ok(
                    status @ (Wait::Named(WaitStatus::Exited(..) | WaitStatus::Signaled(..))
                    | Wait::Terminated(_)),
                ) => {
                    let outcome = match status {
                        Wait::Named(WaitStatus::Exited(_, code)) => LaunchExit::Code(code),
                        Wait::Named(WaitStatus::Signaled(_, signal, _)) => {
                            LaunchExit::Signal(signal as i32)
                        }
                        Wait::Terminated(signal) => LaunchExit::Signal(signal),
                        _ => unreachable!(),
                    };
                    if (self.launched || self.retired.is_some()) && tid == self.pid.as_raw() {
                        self.exit = Some(outcome);
                    }
                    if let Some(retired) = &mut self.retired {
                        retired.push((tid, Some(outcome)));
                    }
                    exited.push(tid);
                    None
                }
                Err(Errno::ECHILD | Errno::ESRCH) if !task_path(&self.root, tid).is_dir() => {
                    if let Some(retired) = &mut self.retired {
                        retired.push((tid, None));
                    }
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
        for tid in exited {
            if self.follow_child == Some(tid) {
                self.follow_child = None;
            }
            if let Some(t) = self.threads.remove(&tid)
                && !self.monitored
            {
                self.observed.insert(tid, t.before);
            }
        }
        for (tid, private_fork) in children {
            self.threads.entry(tid).or_insert_with(|| Thread {
                identity: next_thread_identity(),
                before: Status::read(&task_path(&self.root, tid)).ok(),
                stop: None,
                requested: false,
                newborn: true,
                private_fork,
                stepping: false,
            });
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
            Stop::UnnamedDelivery(signal) => forward_signal(libc::PTRACE_CONT as _, tid, signal),
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
            if self.follow_child != Some(tid)
                && thread.newborn
                && thread.stop.is_some()
                && !task_path(&self.root, tid).is_dir()
            {
                if !self.patches.is_empty() {
                    // A fork can inherit patched bytes. vfork or a foreign
                    // CLONE_VM task can also share the parent's address space.
                    self.foreign_software |= !thread.private_fork;
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

    pub(crate) fn awaiting_fork(&self) -> bool {
        self.follow_child.is_some()
    }

    pub(crate) fn take_fork_child(&mut self) -> Result<Option<(i32, u64, PathBuf, Self)>> {
        let Some(pid) = self.follow_child else {
            return Ok(None);
        };
        if self
            .threads
            .get(&pid)
            .is_none_or(|thread| thread.stop.is_none())
        {
            return Ok(None);
        }
        let root = PathBuf::from(format!("/proc/{pid}"));
        let start = start_ticks(&root)?;
        self.restore_bytes(pid, &root)?;
        crate::breakpoint::disarm(pid)?;
        ptrace::setoptions(
            Pid::from_raw(pid),
            ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK,
        )?;
        let mut thread = self.threads.remove(&pid).unwrap();
        thread.stop = Some(Stop::Interrupt);
        thread.newborn = false;
        self.follow_child = None;
        let mut child = Self::new(pid, &root, start);
        child.monitor();
        child.follow_fork = self.follow_fork;
        child.threads.insert(pid, thread);
        Ok(Some((pid, start, root, child)))
    }

    fn stopped_tid(&self) -> Result<i32> {
        self.threads
            .iter()
            .find_map(|(&tid, thread)| {
                (thread.stop.is_some() && task_path(&self.root, tid).is_dir()).then_some(tid)
            })
            .ok_or_else(|| error("no stopped thread for software breakpoint"))
    }

    pub(crate) fn clear_patches(&mut self) {
        self.patches.clear();
        self.foreign_software = false;
    }

    pub fn patch(&mut self, address: u64) -> Result<()> {
        let tid = self.stopped_tid()?;
        let mapping = modules::private_code_mapping(&self.root, address, true)?
            .ok_or_else(|| error("software breakpoints require a private executable mapping"))?;
        let original = software::read_instruction(tid, address)?;
        if original == software::TRAP {
            return Err(error(
                "software breakpoint address already contains the trap instruction",
            ));
        }
        software::write_instruction(tid, address, software::TRAP)?;
        self.patches.insert(address, Patch { original, mapping });
        Ok(())
    }

    pub fn unpatch(&mut self, address: u64) -> Result<()> {
        let tid = self.stopped_tid()?;
        self.restore_byte(tid, address, &self.patches[&address], &self.root)?;
        self.patches.remove(&address);
        Ok(())
    }

    pub(crate) fn with_unpatched<T>(
        &mut self,
        capture: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let mut restored = Vec::new();
        let result = (|| {
            if !self.patches.is_empty() {
                let tid = self.stopped_tid()?;
                for (&address, patch) in &self.patches {
                    self.restore_byte(tid, address, patch, &self.root)?;
                    restored.push(address);
                }
            }
            capture(self)
        })();
        let mut failure = None;
        for address in restored {
            if let Err(issue) = self.rearm_software(address) {
                failure.get_or_insert(issue);
            }
        }
        if let Some(issue) = failure {
            self.close();
            return Err(error(format!(
                "failed to restore software breakpoints after coredump: {issue}"
            )));
        }
        result
    }

    fn restore_byte(&self, tid: i32, address: u64, patch: &Patch, root: &Path) -> Result<()> {
        if modules::private_code_mapping(root, address, false)?.as_ref() == Some(&patch.mapping)
            && software::read_instruction(tid, address)? == software::TRAP
        {
            software::write_instruction(tid, address, patch.original)?;
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

    pub fn step_software(&mut self, tid: i32, address: u64, deadline: Instant) -> Result<bool> {
        let patch = &self.patches[&address];
        self.restore_byte(tid, address, patch, &self.root)?;
        software::set_pc(tid, address)?;
        loop {
            self.step_one(tid, deadline)?;
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
        // AArch64 watchpoints can interrupt the original instruction before it
        // executes. Leave its bytes in place while the session handles that hit.
        if cfg!(target_arch = "aarch64")
            && self
                .threads
                .get(&tid)
                .is_some_and(|t| matches!(t.stop, Some(Stop::Breakpoint { .. })))
            && software::pc(tid)? == address
        {
            return Ok(true);
        }
        self.rearm_software(address)?;
        Ok(false)
    }

    pub fn rearm_software(&self, address: u64) -> Result<()> {
        if let Ok(tid) = self.stopped_tid() {
            // The old instruction may have unmapped or changed its own page.
            let patch = &self.patches[&address];
            if modules::private_code_mapping(&self.root, address, true)?.as_ref()
                != Some(&patch.mapping)
                || software::read_instruction(tid, address)? != patch.original
            {
                return Err(error(
                    "software breakpoint instruction changed during single-step",
                ));
            }
            software::write_instruction(tid, address, software::TRAP)?;
        }
        Ok(())
    }

    pub(crate) fn stepping(&self, tid: i32) -> bool {
        self.threads.get(&tid).is_some_and(|thread| thread.stepping)
    }

    pub fn step_one(&mut self, tid: i32, deadline: Instant) -> Result<Option<Stop>> {
        if Instant::now() >= deadline {
            return Err(error("single-step deadline reached"));
        }
        let thread = self
            .threads
            .get_mut(&tid)
            .ok_or_else(|| error("unknown thread"))?;
        if !matches!(
            thread.stop,
            Some(
                Stop::Interrupt
                    | Stop::ExecBoundary
                    | Stop::Step
                    | Stop::Software { .. }
                    | Stop::Breakpoint { .. }
            )
        ) {
            return Err(error(
                "thread has no debugger stop eligible for single-step",
            ));
        }
        let exec_pc = matches!(thread.stop, Some(Stop::ExecBoundary))
            .then(|| software::pc(tid))
            .transpose()?;
        ptrace::step(Pid::from_raw(tid), None)?;
        thread.stop = None;
        thread.stepping = true;
        loop {
            self.poll()?;
            self.detach_foreign_children()?;
            if self
                .threads
                .get(&tid)
                .is_none_or(|thread| thread.stop.is_some())
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(error("single-step deadline reached"));
            }
            sleep(Duration::from_millis(1));
        }
        let stop = self.threads.get(&tid).and_then(|thread| thread.stop);
        // Some kernels first report the synthetic trap from completing exec.
        // User-directed traps and traps from executed instructions are retained.
        if let Some(pc) = exec_pc
            && matches!(stop, Some(Stop::Delivery(Signal::SIGTRAP)))
            && software::pc(tid)? == pc
            && ptrace::getsiginfo(Pid::from_raw(tid)).is_ok_and(|info| {
                matches!(info.si_code, libc::TRAP_BRKPT | libc::SI_KERNEL)
                    || (info.si_code == libc::SI_USER && unsafe { info.si_pid() } == 0)
            })
        {
            self.threads.get_mut(&tid).unwrap().stop = Some(Stop::Interrupt);
            return self.step_one(tid, deadline);
        }
        Ok(stop)
    }

    pub fn exec_observed(&self) -> bool {
        self.threads
            .values()
            .any(|t| matches!(t.stop, Some(Stop::Event(_, libc::PTRACE_EVENT_EXEC))))
    }

    pub fn read_word(&self, addr: u64, size: usize) -> Result<u64> {
        read_process_word(self.pid.as_raw(), addr, size)
    }

    pub(crate) fn read_code_prefix(&self, address: u64, bytes: &mut [u8]) -> Result<usize> {
        let count = read_process_prefix(self.pid.as_raw(), address, bytes, || true)?;
        let width = if cfg!(target_arch = "aarch64") { 4 } else { 1 };
        let end = address.saturating_add(count as u64);
        for (&site, patch) in self.patches.range(address.saturating_sub(width - 1)..end) {
            if modules::private_code_mapping(&self.root, site, false)?.as_ref()
                != Some(&patch.mapping)
            {
                continue;
            }
            for (offset, byte) in patch.original.to_le_bytes()[..width as usize]
                .iter()
                .enumerate()
            {
                if let Some(index) = (site + offset as u64).checked_sub(address)
                    && index < count as u64
                {
                    let expected = software::TRAP.to_le_bytes()[offset];
                    if bytes[index as usize] == expected {
                        bytes[index as usize] = *byte;
                    }
                }
            }
        }
        Ok(count)
    }

    pub fn read_memory(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        read_process_memory_exact(self.pid.as_raw(), addr, buf)
    }

    pub fn write_memory(&self, addr: u64, buf: &[u8]) -> Result<()> {
        let len = buf.len();
        addr.checked_add(len as u64)
            .ok_or_else(|| error("invalid remote write range"))?;
        let remote = [uio::RemoteIoVec {
            base: usize::try_from(addr)?,
            len,
        }];
        let got = uio::process_vm_writev(self.pid, &[IoSlice::new(buf)], &remote)?;
        if got != len {
            return Err(error(format!("short remote write: {got}/{len}")));
        }
        Ok(())
    }

    pub fn close(&mut self) -> Cleanup {
        self.close_with_signal_delivery(true)
    }

    pub(crate) fn close_with_signal_delivery(&mut self, deliver_signals: bool) -> Cleanup {
        self.follow_fork = false;
        self.follow_child = None;
        let before: Vec<_> = self.threads.keys().copied().collect();
        let mut cleanup = Cleanup::default();
        // Release threads already in a ptrace stop before waiting for any
        // uninterruptible thread. Detach forwards real signal-delivery stops.
        if !self.monitored {
            self.detach_stopped(&mut cleanup, deliver_signals);
        }
        if !self.threads.is_empty() {
            let interrupt = self.request_stops().err();
            let wait = self
                .wait_for_stops(Instant::now() + Duration::from_millis(250))
                .err();
            if !self.patches.is_empty() && !self.exec_observed() && !self.threads.is_empty() {
                if let Err(error) = self.rewind_software_stops() {
                    cleanup.software_restore_error = Some(error.to_string());
                }
                let restore_error = self
                    .stopped_tid()
                    .and_then(|tid| self.restore_bytes(tid, &self.root))
                    .err()
                    .map(|e| format!("restore software breakpoints: {e}"));
                cleanup.software_restore_error = restore_error.or(cleanup.software_restore_error);
            }
            self.detach_stopped(&mut cleanup, deliver_signals);
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
                row.state_after_detach = Status::read(&task_path(&self.root, row.tid))
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

    fn detach_stopped(&mut self, result: &mut Cleanup, deliver_signals: bool) {
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
                Stop::Delivery(sig) if deliver_signals => Some(sig as i32),
                Stop::UnnamedDelivery(sig) if deliver_signals => Some(sig),
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
                && !task_path(&self.root, tid).is_dir()
            {
                self.restore_bytes(tid, Path::new(&format!("/proc/{tid}")))
                    .err()
            } else {
                None
            };
            let recovery = rewind.or(disarm).or(foreign_cleanup);
            let (outcome, detail) =
                match forward_signal(libc::PTRACE_DETACH as _, tid, signal.unwrap_or(0)) {
                    Ok(()) if recovery.is_none() => ("detached", None),
                    Ok(()) => (
                        "failed",
                        recovery.map(|e| format!("detached after breakpoint recovery failed: {e}")),
                    ),
                    Err(Errno::ESRCH) if !task_path(&self.root, tid).is_dir() => ("exited", None),
                    Err(e) => ("failed", Some(format!("PTRACE_DETACH: {e}"))),
                };
            result.threads.push(CleanupThread {
                tid,
                outcome,
                detail,
                group_stop_before_detach: matches!(stop, Stop::Group(_)),
                preserved_group_stop: false,
                state_after_detach: None,
                forwarded_signal: (outcome == "detached").then_some(signal).flatten(),
            });
        }
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) fn read_process_word(pid: i32, address: u64, size: usize) -> Result<u64> {
    if !(1..=8).contains(&size) {
        return Err(error("invalid remote read range"));
    }
    let mut bytes = [0; 8];
    read_process_memory_exact(pid, address, &mut bytes[..size])?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_process_memory_exact(pid: i32, address: u64, bytes: &mut [u8]) -> Result<()> {
    let got = read_process_memory(pid, address, bytes)?;
    if got != bytes.len() {
        return Err(error(format!("short remote read: {got}/{}", bytes.len())));
    }
    Ok(())
}

pub(crate) fn read_process_memory(pid: i32, address: u64, bytes: &mut [u8]) -> Result<usize> {
    let size = bytes.len();
    if address.checked_add(size as u64).is_none() {
        return Err(error("invalid remote read range"));
    }
    let local = &mut [IoSliceMut::new(bytes)];
    let remote = [uio::RemoteIoVec {
        base: usize::try_from(address)?,
        len: size,
    }];
    Ok(uio::process_vm_readv(Pid::from_raw(pid), local, &remote)?)
}

pub(crate) fn read_process_prefix(
    pid: i32,
    address: u64,
    bytes: &mut [u8],
    allowed: impl Fn() -> bool,
) -> Result<usize> {
    if address.checked_add(bytes.len() as u64).is_none() {
        return Err(error("invalid remote read range"));
    }
    let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .ok()
        .filter(|size| *size > 0)
        .unwrap_or(4096);
    let mut offset = 0;
    while offset < bytes.len() && allowed() {
        let current = address + offset as u64;
        let end = bytes
            .len()
            .min(offset + (page_size - current % page_size) as usize);
        let got = match read_process_memory(pid, current, &mut bytes[offset..end]) {
            Ok(got) => got,
            Err(issue) if issue.downcast_ref::<Errno>() == Some(&Errno::EFAULT) || offset > 0 => {
                break;
            }
            Err(issue) => return Err(issue),
        };
        offset += got;
        if offset != end {
            break;
        }
    }
    Ok(offset)
}
