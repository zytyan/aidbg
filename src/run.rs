use crate::{
    Result,
    breakpoint::{Commands, Publish, Session},
    coredump::{self, CaptureOptions, Dump},
    error,
    procfs::start_ticks,
    rpc::CoreMode,
    script::signal::{Handlers, SignalEvent},
    trace::{LaunchExit, Stop, Trace},
};
use nix::{
    errno::Errno,
    libc,
    sys::{
        ptrace,
        signal::Signal,
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    ffi::CString,
    io::{self, PipeReader, Read, Seek, Write},
    os::{
        fd::AsRawFd,
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: usize = 64 * 1024;
const MAX_EVENTS: usize = 32;
const DEFAULT_TIMEOUT_MS: u32 = 30_000;
const MAX_TIMEOUT_MS: u32 = 300_000;

mod request;
pub use request::{RunId, RunRequest};

#[derive(Serialize)]
pub struct RunResult {
    pid: i32,
    stop_reason: &'static str,
    exit_code: Option<i32>,
    exit_signal: Option<i32>,
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    signals: Vec<Event>,
    signals_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_coredump: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_coredump_issue: Option<String>,
}

#[derive(Serialize)]
struct Event {
    tid: i32,
    signal: i32,
    name: &'static str,
    code: Option<i32>,
    fault_address: Option<String>,
    coredump: Option<Value>,
    issue: Option<String>,
}

struct Child {
    pid: Pid,
    reaped: bool,
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.reaped {
            match self.poll() {
                Err(Errno::ECHILD) => return,
                Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => (),
                // Only signal a child whose death has not been reported.
                _ => self.kill(),
            }
            self.reap();
            if !self.reaped {
                let pid = self.pid;
                // The run worker has finished tracing, but the kernel may
                // still be completing the thread group's exit.
                let _ = thread::Builder::new()
                    .name(format!("aidbg-reap-{pid}"))
                    .spawn(move || {
                        while matches!(waitpid(pid, Some(WaitPidFlag::__WALL)), Err(Errno::EINTR)) {
                        }
                    });
            }
        }
    }
}

impl Child {
    fn poll(&self) -> nix::Result<WaitStatus> {
        waitpid(
            self.pid,
            Some(WaitPidFlag::__WALL | WaitPidFlag::__WNOTHREAD | WaitPidFlag::WNOHANG),
        )
    }

    fn kill(&self) {
        let _ = nix::sys::signal::kill(self.pid, Signal::SIGKILL);
    }

    fn reap(&mut self) -> Option<WaitStatus> {
        let deadline = Instant::now() + Duration::from_millis(250);
        let mut exit = None;
        loop {
            match self.poll() {
                Ok(status @ (WaitStatus::Exited(..) | WaitStatus::Signaled(..))) => {
                    // A traced thread-group leader can report its ptrace exit
                    // before the ordinary parent wait can reap the process.
                    exit = Some(status);
                }
                Err(Errno::ECHILD) => {
                    self.reaped = true;
                    return exit;
                }
                _ if Instant::now() >= deadline => return exit,
                _ => thread::sleep(Duration::from_millis(1)),
            }
        }
    }
}

struct Output {
    pipe: PipeReader,
    bytes: Vec<u8>,
    truncated: bool,
}

impl Output {
    fn new(pipe: PipeReader) -> Result<Self> {
        Errno::result(unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;
        Ok(Self {
            pipe,
            bytes: Vec::new(),
            truncated: false,
        })
    }

    fn drain(&mut self) -> Result<()> {
        let mut buffer = [0; 8192];
        for _ in 0..(OUTPUT_LIMIT / buffer.len()) {
            match self.pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let keep = n.min(OUTPUT_LIMIT - self.bytes.len());
                    self.bytes.extend_from_slice(&buffer[..keep]);
                    self.truncated |= keep != n;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

pub enum RunObservation {
    Snapshot {
        mode: crate::rpc::FreezeMode,
        reply: tokio::sync::oneshot::Sender<crate::Snapshot>,
    },
    SetPaused {
        paused: bool,
        reply: tokio::sync::oneshot::Sender<Result<()>>,
    },
}

pub struct RunControl {
    pub observations: std::sync::mpsc::Receiver<RunObservation>,
    pub breakpoints: Commands,
    pub paused: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Spawn and trace a single process, including its threads, on this OS thread.
pub fn execute(
    request: RunRequest,
    js: Option<&str>,
    cancelled: &(dyn Fn() -> bool + Sync),
    launched: impl FnOnce(i32, bool),
    control: Option<RunControl>,
    publish: Publish,
    mut save: impl FnMut(i32, &mut dyn FnMut(&Path) -> Result<Dump>) -> Result<Value>,
) -> Result<RunResult> {
    let timeout = request.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout) {
        return Err(error("run timeout must be in 1..=300000 milliseconds"));
    }
    if !request.executable.is_absolute()
        || request.cwd.as_ref().is_some_and(|cwd| !cwd.is_absolute())
    {
        return Err(error(
            "executable and cwd must be absolute paths on the server",
        ));
    }
    let executable = CString::new(request.executable.as_os_str().as_bytes())?;
    let cwd = request
        .cwd
        .map(|path| CString::new(path.as_os_str().as_bytes()))
        .transpose()?;
    let arguments = request
        .arguments
        .into_iter()
        .map(CString::new)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let argv = std::iter::once(executable.as_ptr())
        .chain(arguments.iter().map(|arg| arg.as_ptr()))
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    let mut env = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
    for (name, value) in request.env {
        if name.is_empty() || name.contains('=') {
            return Err(error(
                "environment variable names must be nonempty and cannot contain '='",
            ));
        }
        env.insert(name.into(), value.into());
    }
    let environment = env
        .into_iter()
        .map(|(name, value)| {
            let mut entry = name.into_vec();
            entry.push(b'=');
            entry.extend(value.into_vec());
            CString::new(entry)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let envp = environment
        .iter()
        .map(|entry| entry.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    let mut handlers = js.map(Handlers::load).transpose()?;
    if cancelled() {
        return Err(
            crate::Diagnostic::new("RUN_CANCELLED", "Run cancelled before launch", None).into(),
        );
    }

    let (gate, mut release) = io::pipe()?;
    let (mut exec_error, exec_error_writer) = io::pipe()?;
    let (stdout, stdout_writer) = io::pipe()?;
    let (stderr, stderr_writer) = io::pipe()?;
    let mut stdout = Output::new(stdout)?;
    let mut stderr = Output::new(stderr)?;
    let stdin = if let Some(input) = request.stdin {
        if input.len() > OUTPUT_LIMIT {
            return Err(error("stdin must be at most 65536 bytes"));
        }
        let mut file = tempfile::tempfile()?;
        file.write_all(input.as_bytes())?;
        file.rewind()?;
        file
    } else {
        std::fs::File::open("/dev/null")?
    };
    // The child uses only async-signal-safe libc calls until exec.
    let pid = Errno::result(unsafe { libc::fork() })?;
    if pid == 0 {
        unsafe {
            let input = gate.as_raw_fd();
            let report = exec_error_writer.as_raw_fd();
            libc::close(release.as_raw_fd());
            let mut token = 0u8;
            if libc::read(input, (&mut token as *mut u8).cast(), 1) != 1 || token != 1 {
                libc::_exit(127);
            }
            if libc::dup2(stdin.as_raw_fd(), libc::STDIN_FILENO) >= 0
                && libc::dup2(stdout_writer.as_raw_fd(), libc::STDOUT_FILENO) >= 0
                && libc::dup2(stderr_writer.as_raw_fd(), libc::STDERR_FILENO) >= 0
                && cwd
                    .as_ref()
                    .is_none_or(|path| libc::chdir(path.as_ptr()) == 0)
            {
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                libc::execve(executable.as_ptr(), argv.as_ptr(), envp.as_ptr());
            }
            let errno = Errno::last_raw().to_ne_bytes();
            libc::write(report, errno.as_ptr().cast(), errno.len());
            libc::_exit(127);
        }
    }
    let mut child = Child {
        pid: Pid::from_raw(pid),
        reaped: false,
    };
    drop((gate, exec_error_writer, stdout_writer, stderr_writer));
    let root = PathBuf::from(format!("/proc/{pid}"));
    let start = start_ticks(&root)?;
    let mut trace = Trace::new(pid, &root, start);
    trace.seize_launched(request.exit_coredump)?;
    release.write_all(&[1])?;
    drop(release);
    let mut launched = Some(launched);
    let mut session = Session::new(pid, &root, start, trace, publish, true);
    if let Some(control) = &control {
        session.track_pause_state(control.paused.clone());
    }

    let deadline = Instant::now() + Duration::from_millis(timeout.into());
    let expired = || Instant::now() >= deadline || cancelled();
    let mut events = Vec::new();
    let mut signals_truncated = false;
    let mut exec_observed = false;
    let mut stopped_by_budget = None;
    let mut exit_coredump = None;
    let mut exit_coredump_issue = None;
    let mut exit = loop {
        stdout.drain()?;
        stderr.drain()?;
        session.trace.poll()?;
        session.trace.detach_foreign_children()?;
        if let Some(control) = &control {
            session.finish_live_script(&control.paused, expired() && session.trace.exit.is_none());
        }
        if let Some(exit) = session.trace.exit
            && session.trace.threads.is_empty()
        {
            break Some(exit);
        }
        if expired() {
            stopped_by_budget = Some(if cancelled() {
                "cancelled"
            } else {
                "timed_out"
            });
            break None;
        }
        if session.trace.exec_observed() {
            if exec_observed {
                session.reset_address_space()?;
                crate::symbols::inspect::warm_dwarf(pid);
                if let Some(thread) = session.trace.threads.get_mut(&pid) {
                    thread.stop = Some(Stop::ExecBoundary);
                }
            } else {
                exec_observed = true;
                crate::symbols::inspect::warm_dwarf(pid);
                session.paused = request.pause_at_entry;
                // The initial exec establishes the address space used by all subsequent commands.
                if let Some(thread) = session.trace.threads.get_mut(&pid) {
                    thread.stop = Some(Stop::ExecBoundary);
                }
                if let Some(launched) = launched.take() {
                    launched(pid, session.paused);
                }
            }
        }
        if request.exit_coredump
            && exec_observed
            && exit_coredump.is_none()
            && exit_coredump_issue.is_none()
            && matches!(
                session
                    .trace
                    .threads
                    .get(&pid)
                    .and_then(|thread| thread.stop),
                Some(Stop::Event(_, libc::PTRACE_EVENT_EXIT))
            )
        {
            let result = save(pid, &mut |path| {
                let remaining = u32::try_from(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                )?;
                let options = CaptureOptions::new(CoreMode::CoreFull, remaining, None, None)?
                    .for_process(start);
                session.trace.freeze(deadline)?;
                session.trace.rewind_software_stops()?;
                session.trace.with_unpatched(|trace| {
                    coredump::prepare_with_trace(
                        pid,
                        CoreMode::CoreFull,
                        options,
                        path,
                        &expired,
                        || {},
                        Some((trace, None)),
                    )
                })
            });
            match result {
                Ok(dump) => exit_coredump = Some(dump),
                Err(issue) => exit_coredump_issue = Some(issue.to_string()),
            }
        }
        if session.trace.foreign_software {
            session.retire_inherited_patches()?;
        }
        if exec_observed && let Some(control) = &control {
            if let Ok(observation) = control.observations.try_recv() {
                match observation {
                    RunObservation::Snapshot { mode, reply } if !reply.is_closed() => {
                        let snapshot = crate::Snapshot::from_run(
                            pid,
                            mode,
                            &root,
                            &mut session.trace,
                            deadline,
                        );
                        let _ = reply.send(snapshot);
                    }
                    RunObservation::SetPaused { paused, reply } if !reply.is_closed() => {
                        let result = if paused && !session.paused {
                            session
                                .trace
                                .freeze(deadline.min(Instant::now() + Duration::from_millis(500)))
                        } else {
                            Ok(())
                        };
                        if result.is_ok() {
                            session.set_paused(paused);
                        }
                        let _ = reply.send(result);
                    }
                    _ => {}
                }
            }
            session.service(&control.breakpoints, &control.paused);
            if session.trace.exec_observed() || session.trace.foreign_software {
                continue;
            }
        }
        if session.paused {
            thread::sleep(Duration::from_millis(1));
            continue;
        }
        let trace = &mut session.trace;
        let stopped = trace
            .threads
            .iter()
            .filter_map(|(&tid, thread)| thread.stop.map(|stop| (tid, stop)))
            .collect::<Vec<_>>();
        if stopped.is_empty() {
            thread::sleep(Duration::from_millis(1));
        }
        for &(tid, stop) in &stopped {
            if let Stop::Delivery(signal) = stop
                && exec_observed
                && let Some(handlers) = handlers
                    .as_mut()
                    .filter(|handlers| handlers.contains(signal))
            {
                if events.len() == MAX_EVENTS {
                    signals_truncated = true;
                } else {
                    let info = ptrace::getsiginfo(Pid::from_raw(tid));
                    let code = info.as_ref().ok().map(|info| info.si_code);
                    let fault_address = info
                        .as_ref()
                        .ok()
                        .filter(|info| {
                            info.si_code > 0
                                && matches!(
                                    signal,
                                    Signal::SIGSEGV
                                        | Signal::SIGBUS
                                        | Signal::SIGILL
                                        | Signal::SIGFPE
                                )
                        })
                        .map(|info| unsafe { info.si_addr() } as u64);
                    let mut event = Event {
                        tid,
                        signal: signal as i32,
                        name: signal.as_str(),
                        code,
                        fault_address: fault_address.map(crate::hex),
                        coredump: None,
                        issue: None,
                    };
                    let outcome = match code {
                        None => Err(error("could not read ptrace signal information")),
                        Some(code) => handlers
                            .invoke(
                                SignalEvent {
                                    pid,
                                    tid,
                                    signal,
                                    code,
                                    fault_address,
                                },
                                deadline,
                            )
                            .and_then(|dump| {
                                if !dump {
                                    return Ok(None);
                                }
                                let remaining = u32::try_from(
                                    deadline
                                        .saturating_duration_since(Instant::now())
                                        .as_millis(),
                                )?;
                                save(pid, &mut |path| {
                                    let options = CaptureOptions::new(
                                        CoreMode::CoreFull,
                                        remaining,
                                        None,
                                        None,
                                    )?
                                    .for_process(start_ticks(&root)?);
                                    coredump::prepare_with_trace(
                                        pid,
                                        CoreMode::CoreFull,
                                        options,
                                        path,
                                        &expired,
                                        || {},
                                        Some((trace, Some(tid))),
                                    )
                                })
                                .map(Some)
                            }),
                    };
                    match outcome {
                        Ok(dump) => event.coredump = dump,
                        Err(issue) => event.issue = Some(issue.to_string()),
                    }
                    events.push(event);
                }
            }
        }
        if session.empty() {
            for (tid, _) in stopped {
                if session.trace.threads.contains_key(&tid) {
                    session.trace.resume(tid)?;
                }
            }
        } else {
            let handled = session.handle_stops();
            if session.trace.exec_observed() || session.trace.foreign_software {
                continue;
            }
            handled?;
            if let Some(control) = &control {
                control
                    .paused
                    .store(session.paused, std::sync::atomic::Ordering::Relaxed);
            }
            if !session.paused {
                session.remove_exhausted()?;
            }
        }
    };

    if exit.is_none() {
        child.kill();
        // Close detaches any stopped tasks and forwards pending signals.
        session.trace.close();
        exit = session.trace.exit;
    }
    let reaped = child.reap().and_then(|status| match status {
        WaitStatus::Exited(_, code) => Some(LaunchExit::Code(code)),
        WaitStatus::Signaled(_, signal, _) => Some(LaunchExit::Signal(signal as i32)),
        _ => None,
    });
    exit = exit.or(reaped);
    if !child.reaped {
        return Err(error("run exited before its child could be reaped"));
    }
    if !exec_observed && child.reaped {
        let mut errno = [0; std::mem::size_of::<i32>()];
        if exec_error.read_exact(&mut errno).is_ok() {
            return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(errno)).into());
        }
    }
    stdout.drain()?;
    stderr.drain()?;
    let (stop_reason, exit_code, exit_signal) = match exit {
        Some(LaunchExit::Code(code)) => ("exited", Some(code), None),
        Some(LaunchExit::Signal(signal)) => ("signaled", None, Some(signal)),
        _ => ("unavailable", None, None),
    };
    Ok(RunResult {
        pid,
        stop_reason: stopped_by_budget.unwrap_or(stop_reason),
        exit_code,
        exit_signal,
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        signals: events,
        signals_truncated,
        exit_coredump,
        exit_coredump_issue,
    })
}
