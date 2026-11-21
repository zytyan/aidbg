use super::{Capture, CaptureLimit, Coverage, memory};
use crate::modules::{Backing, Mapping};
use crate::procfs::{Status, task_path};
use crate::{Result, error};
use nix::{errno::Errno, libc};
use object::elf::*;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::Path;
const NT_PRSTATUS: u32 = libc::NT_PRSTATUS as u32;
const NT_FPREGSET: u32 = libc::NT_FPREGSET as u32;
const NT_PRPSINFO: u32 = 3;
const NT_AUXV: u32 = 6;
const NT_FILE: u32 = 0x4649_4c45;

#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = EM_X86_64.0;
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = EM_AARCH64.0;
#[cfg(target_arch = "x86_64")]
const GENERAL_SIZE: usize = 27 * 8;
#[cfg(target_arch = "aarch64")]
const GENERAL_SIZE: usize = 34 * 8;
#[cfg(target_arch = "x86_64")]
const SP_OFFSET: usize = 19 * 8;
#[cfg(target_arch = "aarch64")]
const SP_OFFSET: usize = 31 * 8;

#[cfg(target_arch = "x86_64")]
const REGSETS: &[(u32, usize)] = &[(0x201, 8192), (0x202, 256 * 1024), (0x204, 8)];
#[cfg(target_arch = "aarch64")]
const REGSETS: &[(u32, usize)] = &[
    (0x401, 16),
    (0x402, 264),
    (0x403, 264),
    (0x404, 4),
    (0x405, 256 * 1024),
    (0x406, 16),
    (0x407, 64),
    (0x408, 16),
    (0x409, 8),
    (0x40a, 8),
    (0x40b, 256 * 1024),
    (0x40c, 256 * 1024),
    (0x40d, 64),
    (0x40e, 8),
    (0x40f, 8),
    (0x410, 24),
];

fn register_bytes(tid: i32, kind: u32, buffer: &mut [u8]) -> std::result::Result<usize, Errno> {
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    Errno::result(unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET as _,
            tid,
            kind as usize,
            &mut iov as *mut libc::iovec,
        )
    })?;
    Ok(iov.iov_len)
}

fn note(notes: &mut Vec<u8>, owner: &[u8], kind: u32, data: &[u8]) -> Result<()> {
    notes.extend(u32::try_from(owner.len() + 1)?.to_le_bytes());
    notes.extend(u32::try_from(data.len())?.to_le_bytes());
    notes.extend(kind.to_le_bytes());
    notes.extend(owner);
    notes.resize((notes.len() + 1).next_multiple_of(4), 0);
    notes.extend(data);
    notes.resize(notes.len().next_multiple_of(4), 0);
    Ok(())
}

fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn proc_stat(root: &Path) -> Vec<u64> {
    fs::read_to_string(root.join("stat"))
        .ok()
        .and_then(|stat| {
            Some(
                stat.rsplit_once(')')?
                    .1
                    .split_whitespace()
                    .skip(1)
                    .map(|part| part.parse().unwrap_or(0))
                    .collect(),
            )
        })
        .unwrap_or_default()
}

fn process_info(root: &Path, pid: i32) -> [u8; 136] {
    let mut data = [0; 136];
    let stat = proc_stat(root);
    let field = |n| stat.get(n).copied().unwrap_or(0);
    put64(&mut data, 8, field(5));
    put32(&mut data, 24, pid as u32);
    for n in 0..3 {
        put32(&mut data, 28 + 4 * n, field(n) as u32);
    }
    if let Ok(status) = Status::read(root) {
        for (key, offset) in [("Uid", 16), ("Gid", 20)] {
            if let Some(value) = status
                .field(key)
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse().ok())
            {
                put32(&mut data, offset, value);
            }
        }
        if let Some(name) = status.name() {
            let n = name.len().min(15);
            data[40..40 + n].copy_from_slice(&name.as_bytes()[..n]);
            data[56..56 + n].copy_from_slice(&name.as_bytes()[..n]);
        }
    }
    data
}

pub(super) fn thread_notes(
    root: &Path,
    pid: i32,
    trace: &crate::trace::Trace<'_>,
    coverage: &mut Coverage,
    limit: &CaptureLimit<'_>,
) -> Result<(Vec<u8>, Vec<(i32, u64)>)> {
    let mut notes = Vec::new();
    note(&mut notes, b"CORE", NT_PRPSINFO, &process_info(root, pid))?;
    match fs::read(root.join("auxv")) {
        Ok(auxv) if !auxv.is_empty() => note(&mut notes, b"CORE", NT_AUXV, &auxv)?,
        _ => coverage.issues.push("NT_AUXV unavailable".into()),
    }
    let mut stacks = Vec::new();
    let mut optional = vec![0; REGSETS.iter().map(|&(_, size)| size).max().unwrap_or(0)];
    let mut fp = [0; 1024];
    for &tid in trace.threads.keys() {
        limit.check()?;
        let mut general = [0; GENERAL_SIZE];
        let size = register_bytes(tid, NT_PRSTATUS, &mut general)
            .map_err(|e| error(format!("tid {tid}: NT_PRSTATUS: {e}")))?;
        if size != GENERAL_SIZE {
            return Err(error(format!(
                "tid {tid}: unsupported register ABI ({size} bytes)"
            )));
        }
        stacks.push((
            tid,
            u64::from_le_bytes(general[SP_OFFSET..SP_OFFSET + 8].try_into()?),
        ));
        let mut status = [0; (112 + GENERAL_SIZE + 4).next_multiple_of(8)];
        let task = task_path(root, tid);
        let stat = proc_stat(&task);
        put32(&mut status, 32, tid as u32);
        for (i, &value) in stat.iter().take(3).enumerate() {
            put32(&mut status, 36 + 4 * i, value as u32);
        }
        if let Ok(task_status) = Status::read(&task) {
            for (key, offset) in [("SigPnd", 16), ("SigBlk", 24)] {
                if let Some(bits) = task_status
                    .field(key)
                    .and_then(|v| u64::from_str_radix(v, 16).ok())
                {
                    put64(&mut status, offset, bits);
                }
            }
        }
        let fp_len = match register_bytes(tid, NT_FPREGSET, &mut fp) {
            Ok(n) if n != 0 && n <= fp.len() => n,
            result => {
                coverage
                    .issues
                    .push(format!("tid {tid}: NT_FPREGSET: {result:?}"));
                0
            }
        };
        status[112..112 + GENERAL_SIZE].copy_from_slice(&general);
        put32(&mut status, 112 + GENERAL_SIZE, u32::from(fp_len != 0));
        note(&mut notes, b"CORE", NT_PRSTATUS, &status)?;
        if fp_len != 0 {
            note(&mut notes, b"CORE", NT_FPREGSET, &fp[..fp_len])?;
        }
        for &(kind, capacity) in REGSETS {
            match register_bytes(tid, kind, &mut optional[..capacity]) {
                Ok(n) if n != 0 && n <= capacity => {
                    note(&mut notes, b"LINUX", kind, &optional[..n])?;
                }
                Ok(0)
                | Err(
                    Errno::EINVAL
                    | Errno::ENODEV
                    | Errno::ENODATA
                    | Errno::ENXIO
                    | Errno::EOPNOTSUPP,
                ) => {}
                result => coverage
                    .issues
                    .push(format!("tid {tid}: regset {kind:#x}: {result:?}")),
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            // Linux exposes native x86 debug registers through PEEKUSER.
            let base = std::mem::offset_of!(libc::user, u_debugreg);
            let mut data = Vec::from(tid.to_le_bytes());
            for index in [0, 1, 2, 3, 6, 7] {
                let offset = base + index * size_of::<libc::c_ulonglong>();
                match nix::sys::ptrace::read_user(nix::unistd::Pid::from_raw(tid), offset as _) {
                    Ok(value) => data.extend(value.to_le_bytes()),
                    Err(e) => {
                        coverage.issues.push(format!("tid {tid}: DR{index}: {e}"));
                        data.clear();
                        break;
                    }
                }
            }
            if !data.is_empty() {
                note(&mut notes, b"AIDBG", 2, &data)?;
            }
        }
    }
    Ok((notes, stacks))
}

pub(super) fn mapping_notes(
    notes: &mut Vec<u8>,
    mode: crate::rpc::CoreMode,
    maps: &[(Backing, Mapping)],
    modules: &[memory::Image],
    coverage: &Coverage,
    page: u64,
) -> Result<()> {
    let mut files = Vec::new();
    let mut names = Vec::new();
    let mut count = 0_u64;
    for (backing, map) in maps {
        if backing.inode == 0 || backing.path.is_empty() {
            continue;
        }
        count += 1;
        files.extend(map.start.to_le_bytes());
        files.extend(map.end.to_le_bytes());
        files.extend((map.offset / page).to_le_bytes());
        names.extend_from_slice(&backing.path);
        names.push(0);
    }
    if count != 0 {
        let mut data = Vec::from(count.to_le_bytes());
        data.extend(page.to_le_bytes());
        data.extend(files);
        data.extend(names);
        note(notes, b"CORE", NT_FILE, &data)?;
    }

    let mappings: Vec<_> = maps
        .iter()
        .map(|(backing, map)| {
            json!({
                "start": map.start, "end": map.end, "offset": map.offset, "permissions": map.perms,
                "device": [backing.major, backing.minor], "inode": backing.inode,
                "path": String::from_utf8_lossy(&backing.path),
                "path_bytes": std::str::from_utf8(&backing.path).is_err().then_some(&backing.path),
            })
        })
        .collect();
    let metadata = serde_json::to_vec(&json!({
        "version": 1, "mode": mode.name(), "mappings": mappings,
        "modules": modules, "coverage": coverage,
    }))?;
    note(notes, b"AIDBG", 1, &metadata)
}

struct Segment {
    flags: u32,
    start: u64,
    end: u64,
    offset: Option<u64>,
}

pub(super) fn write_header(writer: &mut impl Write, capture: &Capture) -> Result<()> {
    let mut loads = Vec::new();
    for (_, map) in &capture.maps {
        let mut cursor = map.start;
        let perms = map.perms.as_bytes();
        let flags = (u32::from(perms.first() == Some(&b'r')) * PF_R.0)
            | (u32::from(perms.get(1) == Some(&b'w')) * PF_W.0)
            | (u32::from(map.executable()) * PF_X.0);
        let first = capture
            .stored
            .partition_point(|saved| saved.end <= map.start);
        for saved in &capture.stored[first..] {
            if saved.start >= map.end {
                break;
            }
            let start = saved.start.max(map.start);
            if cursor < start {
                loads.push(Segment {
                    flags,
                    start: cursor,
                    end: start,
                    offset: None,
                });
            }
            let end = saved.end.min(map.end);
            loads.push(Segment {
                flags,
                start,
                end,
                offset: Some(saved.offset + start - saved.start),
            });
            cursor = end;
        }
        if cursor < map.end {
            loads.push(Segment {
                flags,
                start: cursor,
                end: map.end,
                offset: None,
            });
        }
    }

    const EH_SIZE: u64 = 64;
    const PH_SIZE: u64 = 56;
    const SH_SIZE: u64 = 64;
    const PN_XNUM: u32 = 0xffff;
    let phnum = u32::try_from(1 + loads.len())?;
    let extended = phnum >= PN_XNUM;
    let shoff = EH_SIZE + u64::from(phnum) * PH_SIZE;
    let notes_at = shoff + if extended { SH_SIZE } else { 0 };
    let data_at = notes_at + capture.notes.len() as u64;
    let mut header = [0; EH_SIZE as usize];
    header[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', ELFCLASS64.0, ELFDATA2LSB.0, 1]);
    header[16..18].copy_from_slice(&ET_CORE.0.to_le_bytes());
    header[18..20].copy_from_slice(&MACHINE.to_le_bytes());
    put32(&mut header, 20, 1);
    put64(&mut header, 32, EH_SIZE);
    header[52..54].copy_from_slice(&(EH_SIZE as u16).to_le_bytes());
    header[54..56].copy_from_slice(&(PH_SIZE as u16).to_le_bytes());
    header[56..58].copy_from_slice(&(phnum.min(PN_XNUM) as u16).to_le_bytes());
    if extended {
        put64(&mut header, 40, shoff);
        header[58..60].copy_from_slice(&(SH_SIZE as u16).to_le_bytes());
        header[60..62].copy_from_slice(&1_u16.to_le_bytes());
    }
    writer.write_all(&header)?;

    let mut note = [0; PH_SIZE as usize];
    put32(&mut note, 0, PT_NOTE.0);
    put64(&mut note, 8, notes_at);
    put64(&mut note, 32, capture.notes.len() as u64);
    put64(&mut note, 48, 4);
    writer.write_all(&note)?;
    for segment in loads {
        let mut load = [0; PH_SIZE as usize];
        put32(&mut load, 0, PT_LOAD.0);
        put32(&mut load, 4, segment.flags);
        put64(&mut load, 16, segment.start);
        let len = segment.end - segment.start;
        if let Some(offset) = segment.offset {
            put64(&mut load, 8, data_at + offset);
            put64(&mut load, 32, len);
        }
        put64(&mut load, 40, len);
        // Stack windows may start at an unaligned SP and packed data may follow holes.
        put64(&mut load, 48, 1);
        writer.write_all(&load)?;
    }
    if extended {
        let mut section = [0; SH_SIZE as usize];
        put32(&mut section, 44, phnum);
        writer.write_all(&section)?;
    }
    writer.write_all(&capture.notes)?;
    Ok(())
}
