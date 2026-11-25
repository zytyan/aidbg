use crate::{Result, error, hex};
use nix::{errno::Errno, libc};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub(super) struct Catch {
    id: u64,
    entry: bool,
    exit: bool,
}

impl Catch {
    pub(super) fn parse(args: &Value) -> Result<Self> {
        let id = args["catchId"]
            .as_u64()
            .ok_or_else(|| error("expected syscall catch ID"))?;
        let (entry, exit) = match args["phase"].as_str() {
            Some("entry") => (true, false),
            Some("exit") => (false, true),
            Some("both") => (true, true),
            _ => return Err(error("expected entry, exit, or both")),
        };
        Ok(Self { id, entry, exit })
    }
}

pub(super) struct Entry {
    number: u64,
    arch: u32,
    args: [u64; 6],
    pathname: Option<String>,
}

// Linux UAPI for PTRACE_GET_SYSCALL_INFO. libc exposes this only for glibc.
#[repr(C)]
#[derive(Default)]
struct SyscallInfo {
    op: u8,
    reserved: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: [u64; 8],
}

fn syscall_info(tid: i32) -> nix::Result<(SyscallInfo, usize)> {
    const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
    let mut info = SyscallInfo::default();
    let length = Errno::result(unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO as _,
            tid,
            std::mem::size_of_val(&info),
            &mut info,
        )
    })?;
    Ok((info, length as usize))
}

pub(super) fn verify_supported(tid: i32) -> Result<()> {
    match syscall_info(tid) {
        Ok(_) => Ok(()),
        Err(Errno::EIO | Errno::EINVAL) => Err(error(
            "NotSupport: syscall capture requires Linux PTRACE_GET_SYSCALL_INFO",
        )),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn read_stop(
    tid: i32,
    entries: &mut BTreeMap<i32, Entry>,
    catches: [Option<&Catch>; 2],
) -> Result<Vec<Value>> {
    if catches.iter().all(Option::is_none) {
        return Ok(Vec::new());
    }
    let (info, length) = match syscall_info(tid) {
        Err(Errno::ESRCH) => return Ok(Vec::new()),
        result => result?,
    };
    match info.op {
        1 if length >= 80 => {
            let number = info.data[0];
            let args: [u64; 6] = info.data[1..7].try_into().unwrap();
            let pathname = native_signature(info.arch, number)
                .and_then(|(_, names)| names.iter().position(|&name| name == "pathname"))
                .and_then(|index| read_pathname(tid, args[index]));
            let entry = Entry {
                number,
                arch: info.arch,
                args,
                pathname,
            };
            let result = rows(tid, &entry, None, catches);
            entries.insert(tid, entry);
            Ok(result)
        }
        2 if length >= 33 => {
            let Some(entry) = entries.remove(&tid) else {
                return Ok(Vec::new());
            };
            let value = info.data[0] as i64;
            let failed = info.data[1].to_ne_bytes()[0] != 0;
            Ok(rows(tid, &entry, Some((value, failed)), catches))
        }
        _ => Ok(Vec::new()),
    }
}

fn read_pathname(tid: i32, address: u64) -> Option<String> {
    if address == 0 {
        return None;
    }
    let mut bytes = [0; 4096];
    let len = crate::trace::read_process_prefix(tid, address, &mut bytes, || true).ok()?;
    let end = bytes[..len].iter().position(|&byte| byte == 0)?;
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn rows(
    tid: i32,
    entry: &Entry,
    result: Option<(i64, bool)>,
    catches: [Option<&Catch>; 2],
) -> Vec<Value> {
    let signature = native_signature(entry.arch, entry.number);
    catches
        .into_iter()
        .flatten()
        .filter(|catch| {
            if result.is_some() {
                catch.exit
            } else {
                catch.entry
            }
        })
        .map(|catch| {
            json!({
                "kind":"syscall", "tid":tid, "paused":true, "catchId":catch.id,
                "phase":if result.is_some() {"exit"} else {"entry"},
                "number":entry.number, "abi":entry.arch,
                "name":signature.map(|(name, _)| name),
                "parameterNames":signature.map(|(_, params)| params),
                "args":entry.args.map(hex),
                "pathname":entry.pathname,
                "result":result.map(|(value, _)| value.to_string()),
                "failed":result.map(|(_, failed)| failed),
            })
        })
        .collect()
}

fn native_signature(arch: u32, number: u64) -> Option<(&'static str, &'static [&'static str])> {
    #[cfg(target_arch = "x86_64")]
    let native = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    let native = 0xc000_00b7;
    if arch != native {
        return None;
    }
    macro_rules! signatures {
        ($($sys:ident => $name:literal [$($arg:literal),*]),* $(,)?) => {
            $(if number == libc::$sys as u64 { return Some(($name, &[$($arg),*])); })*
        };
    }
    #[cfg(target_arch = "x86_64")]
    signatures! {
        SYS_open => "open" ["pathname", "flags", "mode"],
        SYS_clone => "clone" ["flags", "stack", "parent_tid", "child_tid", "tls"],
        SYS_fork => "fork" [],
        SYS_vfork => "vfork" [],
    }
    #[cfg(target_arch = "aarch64")]
    signatures! {
        SYS_clone => "clone" ["flags", "stack", "parent_tid", "tls", "child_tid"],
    }
    signatures! {
        SYS_read => "read" ["fd", "buf", "count"],
        SYS_write => "write" ["fd", "buf", "count"],
        SYS_openat => "openat" ["dirfd", "pathname", "flags", "mode"],
        SYS_openat2 => "openat2" ["dirfd", "pathname", "how", "size"],
        SYS_faccessat => "faccessat" ["dirfd", "pathname", "mode"],
        SYS_faccessat2 => "faccessat2" ["dirfd", "pathname", "mode", "flags"],
        SYS_readlinkat => "readlinkat" ["dirfd", "pathname", "buf", "bufsiz"],
        SYS_unlinkat => "unlinkat" ["dirfd", "pathname", "flags"],
        SYS_mkdirat => "mkdirat" ["dirfd", "pathname", "mode"],
        SYS_statx => "statx" ["dirfd", "pathname", "flags", "mask", "statxbuf"],
        SYS_fstat => "fstat" ["fd", "statbuf"],
        SYS_close => "close" ["fd"],
        SYS_lseek => "lseek" ["fd", "offset", "whence"],
        SYS_pread64 => "pread64" ["fd", "buf", "count", "offset"],
        SYS_pwrite64 => "pwrite64" ["fd", "buf", "count", "offset"],
        SYS_readv => "readv" ["fd", "iov", "iovcnt"],
        SYS_writev => "writev" ["fd", "iov", "iovcnt"],
        SYS_getdents64 => "getdents64" ["fd", "dirp", "count"],
        SYS_mmap => "mmap" ["addr", "length", "prot", "flags", "fd", "offset"],
        SYS_mprotect => "mprotect" ["addr", "length", "prot"],
        SYS_munmap => "munmap" ["addr", "length"],
        SYS_brk => "brk" ["addr"],
        SYS_ioctl => "ioctl" ["fd", "request", "arg"],

        SYS_execve => "execve" ["pathname", "argv", "envp"],
        SYS_execveat => "execveat" ["dirfd", "pathname", "argv", "envp", "flags"],
        SYS_exit => "exit" ["status"],
        SYS_exit_group => "exit_group" ["status"],
        SYS_getpid => "getpid" [],
        SYS_gettid => "gettid" [],
        SYS_getppid => "getppid" [],
        SYS_getrandom => "getrandom" ["buf", "buflen", "flags"],
        SYS_clock_gettime => "clock_gettime" ["clockid", "tp"],
        SYS_nanosleep => "nanosleep" ["duration", "remaining"],
        SYS_rt_sigaction => "rt_sigaction" ["sig", "act", "oldact", "sigsetsize"],
        SYS_rt_sigprocmask => "rt_sigprocmask" ["how", "set", "oldset", "sigsetsize"],
        SYS_kill => "kill" ["pid", "sig"],
        SYS_tgkill => "tgkill" ["tgid", "tid", "sig"],
        SYS_wait4 => "wait4" ["pid", "status", "options", "rusage"],
        SYS_clone3 => "clone3" ["args", "size"],
        SYS_prlimit64 => "prlimit64" ["pid", "resource", "new_limit", "old_limit"],
        SYS_set_tid_address => "set_tid_address" ["tidptr"],
        SYS_set_robust_list => "set_robust_list" ["head", "len"],
        SYS_futex => "futex" ["uaddr", "op", "val", "timeout", "uaddr2", "val3"],
        SYS_socket => "socket" ["domain", "type", "protocol"],
        SYS_connect => "connect" ["sockfd", "addr", "addrlen"],
        SYS_bind => "bind" ["sockfd", "addr", "addrlen"],
        SYS_listen => "listen" ["sockfd", "backlog"],
        SYS_accept4 => "accept4" ["sockfd", "addr", "addrlen", "flags"],
        SYS_sendto => "sendto" ["sockfd", "buf", "len", "flags", "addr", "addrlen"],
        SYS_recvfrom => "recvfrom" ["sockfd", "buf", "len", "flags", "addr", "addrlen"],
    }
    None
}
