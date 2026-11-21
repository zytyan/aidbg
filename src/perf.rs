use crate::procfs::{Status, epoch_ms, task_ids, task_path};
use crate::regs::{self, Registers, SP};
use crate::unwind::{Images, UnwindMemory};
use crate::{Result, error, hex, machine, modules};
use gimli::Register;
use nix::libc;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering, fence};
use std::time::{Duration, Instant};

const STACK_BYTES: usize = 8192;
const MAX_THREADS: usize = 64;
const PERF_RECORD_LOST: u32 = 2;
const PERF_RECORD_SAMPLE: u32 = 9;
const PERF_RECORD_LOST_SAMPLES: u32 = 13;
const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u32 = 0x2401;

#[cfg(target_arch = "x86_64")]
const REG_MASK: u64 = 0xff01ff;
#[cfg(target_arch = "x86_64")]
const DWARF_REGISTER_ORDER: &[u16] = &[0, 3, 2, 1, 4, 5, 6, 7, 16, 8, 9, 10, 11, 12, 13, 14, 15];
#[cfg(target_arch = "aarch64")]
const REG_MASK: u64 = (1 << 33) - 1;

// Linux perf_event_attr version 3, including PERF_SAMPLE_STACK_USER.
#[repr(C)]
struct Attr {
    event_type: u32,
    size: u32,
    config: u64,
    frequency: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    regs: u64,
    stack_size: u32,
    clock_id: i32,
}

struct Ring {
    fd: OwnedFd,
    base: *mut u8,
    len: usize,
    offset: usize,
    size: usize,
    tail: u64,
}

impl Drop for Ring {
    fn drop(&mut self) {
        // The mapping and descriptor are owned exclusively by this sampler.
        unsafe { libc::munmap(self.base.cast(), self.len) };
    }
}

impl Ring {
    fn open(tid: i32, frequency: u32, stack: bool) -> io::Result<Self> {
        let attr = Attr {
            event_type: 1, // PERF_TYPE_SOFTWARE
            size: size_of::<Attr>() as u32,
            config: 0, // PERF_COUNT_SW_CPU_CLOCK
            frequency: u64::from(frequency),
            sample_type: 3 | if stack { (1 << 12) | (1 << 13) } else { 0 },
            read_format: 0,
            flags: 1 | (1 << 5) | (1 << 6) | (1 << 10), // disabled, user space, freq
            wakeup_events: 1,
            bp_type: 0,
            config1: 0,
            config2: 0,
            branch_sample_type: 0,
            regs: if stack { REG_MASK } else { 0 },
            stack_size: if stack { STACK_BYTES as u32 } else { 0 },
            clock_id: 0,
        };
        // A per-thread event follows the scheduler. CLOEXEC closes it on server exec.
        let fd =
            unsafe { libc::syscall(libc::SYS_perf_event_open, &attr, tid, -1_i32, -1_i32, 8_u64) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(io::Error::other("could not determine page size"));
        }
        let page = page as usize;
        let len = page * if stack { 17 } else { 3 };
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mut ring = Self {
            fd,
            base: base.cast(),
            len,
            offset: 0,
            size: 0,
            tail: 0,
        };
        ring.offset = ring.metadata(1040).load(Ordering::Relaxed) as usize;
        ring.size = ring.metadata(1048).load(Ordering::Relaxed) as usize;
        if ring.offset < page
            || !ring.size.is_power_of_two()
            || ring
                .offset
                .checked_add(ring.size)
                .is_none_or(|end| end > len)
        {
            return Err(io::Error::other("invalid perf ring layout"));
        }
        Ok(ring)
    }

    fn configure(&self, command: u32) -> io::Result<()> {
        let result = unsafe { libc::ioctl(self.fd.as_raw_fd(), command as _, 0) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn metadata(&self, offset: usize) -> &AtomicU64 {
        // The perf metadata page uses aligned u64 fields at these ABI offsets.
        unsafe { &*self.base.add(offset).cast() }
    }

    fn copy_at(&self, at: u64, bytes: &mut [u8]) {
        let start = at as usize & (self.size - 1);
        let first = bytes.len().min(self.size - start);
        // The head is acquired before reading, and the tail is published after
        // the copy. The kernel will not overwrite these committed records.
        unsafe {
            let data = self.base.add(self.offset);
            std::ptr::copy_nonoverlapping(data.add(start), bytes.as_mut_ptr(), first);
            std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr().add(first), bytes.len() - first);
        }
    }

    fn drain(&mut self, mut record: impl FnMut(u32, &[u8])) -> io::Result<()> {
        let head = self.metadata(1024).load(Ordering::Acquire);
        let result = (|| {
            if head.wrapping_sub(self.tail) > self.size as u64 {
                return Err(io::Error::other("perf ring overrun"));
            }
            let mut payload = Vec::new();
            while self.tail != head {
                let mut header = [0; 8];
                let remaining = head.wrapping_sub(self.tail);
                if remaining < header.len() as u64 {
                    return Err(io::Error::other("incomplete perf record header"));
                }
                self.copy_at(self.tail, &mut header);
                let kind = u32::from_ne_bytes(header[..4].try_into().unwrap());
                let len = u16::from_ne_bytes(header[6..].try_into().unwrap()) as usize;
                if len < header.len() || len as u64 > remaining {
                    return Err(io::Error::other("invalid perf record size"));
                }
                payload.resize(len - header.len(), 0);
                self.copy_at(self.tail.wrapping_add(header.len() as u64), &mut payload);
                record(kind, &payload);
                self.tail = self.tail.wrapping_add(len as u64);
            }
            Ok(())
        })();
        self.tail = head;
        fence(Ordering::SeqCst);
        self.metadata(1032).store(head, Ordering::Relaxed);
        result
    }
}

struct StackBytes {
    start: u64,
    bytes: Vec<u8>,
}

impl UnwindMemory for StackBytes {
    fn read_word(&self, address: u64, size: usize) -> Result<u64> {
        let start = address
            .checked_sub(self.start)
            .and_then(|n| usize::try_from(n).ok());
        let data = start
            .and_then(|start| self.bytes.get(start..start.checked_add(size)?))
            .filter(|_| (1..=8).contains(&size))
            .ok_or_else(|| error("read outside sampled stack bytes"))?;
        let mut word = [0; 8];
        word[..data.len()].copy_from_slice(data);
        Ok(u64::from_le_bytes(word))
    }
}

struct Sample {
    pc: u64,
    stack: Option<(Registers, StackBytes)>,
}

fn take_word(bytes: &mut &[u8]) -> io::Result<u64> {
    let (word, rest) = bytes
        .split_at_checked(8)
        .ok_or_else(|| io::Error::other("short perf sample"))?;
    *bytes = rest;
    Ok(u64::from_ne_bytes(word.try_into().unwrap()))
}

impl Sample {
    fn parse(mut bytes: &[u8], stack: bool, pid: i32, tid: i32) -> Result<Self> {
        let pc = take_word(&mut bytes)?;
        if pc == 0 {
            return Err(error("perf sample has no userspace PC"));
        }
        let ids = take_word(&mut bytes)?;
        if ids as u32 != pid as u32 || (ids >> 32) as u32 != tid as u32 {
            return Err(error(
                "perf sample belongs to a different process or thread",
            ));
        }
        let mut sample = Self { pc, stack: None };
        if !stack {
            return Ok(sample);
        }
        let abi = take_word(&mut bytes)?;
        if abi != 2 {
            return Ok(sample);
        }
        let mut registers = Registers::empty();
        #[cfg(target_arch = "x86_64")]
        let dwarf_order = DWARF_REGISTER_ORDER.iter().copied();
        #[cfg(target_arch = "aarch64")]
        let dwarf_order = 0..REG_MASK.count_ones() as u16;
        for dwarf in dwarf_order {
            registers.set(Register(dwarf), Some(take_word(&mut bytes)?));
        }
        let size = usize::try_from(take_word(&mut bytes)?)?;
        if size == 0 {
            return Ok(sample);
        }
        let (data, mut rest) = bytes
            .split_at_checked(size)
            .ok_or_else(|| error("short perf stack sample"))?;
        let valid = usize::try_from(take_word(&mut rest)?)?;
        if valid > data.len() || data.len() > STACK_BYTES {
            return Err(error("invalid sampled stack size"));
        }
        let start = registers.get(SP)?;
        sample.stack = Some((
            registers,
            StackBytes {
                start,
                bytes: data[..valid].to_vec(),
            },
        ));
        Ok(sample)
    }
}

#[derive(Serialize)]
struct Thread {
    tid: i32,
    sampled: bool,
    samples: u64,
    issue: Option<String>,
}

fn perf_error(stage: &str, cause: &io::Error) -> String {
    let hint = match cause.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => {
            " (check perf_event_paranoid, ptrace permissions or CAP_PERFMON)"
        }
        Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::ENOENT | libc::EINVAL) => {
            " (kernel perf sampling or requested sample format may be unavailable)"
        }
        _ => "",
    };
    format!("{stage}: {cause}{hint}")
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize)]
struct Location {
    module: Option<String>,
    symbol: Option<String>,
    start: String,
}

struct Address {
    location: Location,
    offset: u64,
}

fn location(
    pc: u64,
    images: &mut Images,
    maps: &[modules::Module],
    root: &Path,
    exe: Option<&fs::Metadata>,
) -> Address {
    let (module, symbol, start, offset) = match images.profile_location(pc, maps, root, exe) {
        Some((id, offset, Some((symbol, delta)))) => (
            Some(maps[id].path().to_string_lossy().into_owned()),
            Some(symbol),
            offset - delta,
            delta,
        ),
        Some((id, offset, None)) => (
            Some(maps[id].path().to_string_lossy().into_owned()),
            None,
            offset & !15,
            offset,
        ),
        None => (None, None, pc & !15, pc),
    };
    Address {
        location: Location {
            module,
            symbol,
            start: hex(start),
        },
        offset,
    }
}

#[derive(Serialize)]
struct Hotspot {
    #[serde(flatten)]
    location: Location,
    first: String,
    last: String,
    display: String,
    samples: u64,
    percent: f64,
}

fn finish_hotspots(grouped: BTreeMap<Location, BTreeMap<u64, u64>>, total: u64) -> Vec<Hotspot> {
    let mut rows = Vec::new();
    for (location, addresses) in grouped {
        let label = location
            .symbol
            .as_deref()
            .or_else(|| Path::new(location.module.as_deref()?).file_name()?.to_str());
        let format_offset = |offset| match label {
            Some(label) => format!("{label}+{}", hex(offset)),
            None => hex(offset),
        };
        let mut addresses = addresses.into_iter().peekable();
        while let Some((first, mut count)) = addresses.next() {
            let mut last = first;
            while addresses.peek().is_some_and(|(next, _)| next - last <= 16) {
                let (next, samples) = addresses.next().expect("just peeked");
                last = next;
                count += samples;
            }
            let display = if last == first {
                format_offset(first)
            } else {
                format!("{}~{}", format_offset(first), format_offset(last))
            };
            rows.push(Hotspot {
                location: location.clone(),
                first: hex(first),
                last: hex(last),
                display,
                samples: count,
                percent: percent(count, total),
            });
        }
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.samples));
    rows
}

#[derive(Default)]
struct CountTree {
    count: u64,
    children: BTreeMap<Location, CountTree>,
}

#[derive(Serialize)]
struct Tree {
    #[serde(flatten)]
    location: Location,
    samples: u64,
    percent: f64,
    percent_of_parent: f64,
    children: Vec<Tree>,
}

impl CountTree {
    fn finish(self, total: u64) -> Vec<Tree> {
        let mut rows: Vec<_> = self
            .children
            .into_iter()
            .map(|(location, node)| Tree {
                location,
                samples: node.count,
                percent: percent(node.count, total),
                percent_of_parent: percent(node.count, self.count),
                children: node.finish(total),
            })
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.samples));
        rows
    }
}

fn percent(count: u64, total: u64) -> f64 {
    100.0 * count as f64 / total.max(1) as f64
}

#[derive(Serialize)]
pub struct Report {
    status: &'static str,
    pid: i32,
    mode: &'static str,
    scope: &'static str,
    duration_ms: u32,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    frequency_hz: u32,
    samples: u64,
    kernel_lost_samples: u64,
    discarded_samples: u64,
    ring_errors: u64,
    threads: Vec<Thread>,
    threads_seen_after_start: Vec<i32>,
    issues: Vec<String>,
    hotspots: Vec<Hotspot>,
    stacks: Vec<Tree>,
    truncated_stacks: BTreeMap<String, u64>,
    recovered_frames: BTreeMap<&'static str, u64>,
}

pub fn run(
    pid: i32,
    stack: bool,
    duration_ms: u32,
    frequency: u32,
    selected_tid: Option<i32>,
) -> Result<Report> {
    let directory = File::open(format!("/proc/{pid}"))?;
    let path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let root = Path::new(&path);
    let expected_pid = pid.to_string();
    if Status::read(root)?.field("Tgid") != Some(&expected_pid) {
        return Err(error("pass the process ID (thread-group leader)"));
    }
    if machine(root)? != regs::ARCH {
        return Err(error("target ABI does not match the sampling server"));
    }
    let exe = fs::metadata(root.join("exe")).ok();
    let maps = modules::read(root)?;
    let mut tids = task_ids(root)?;
    if let Some(tid) = selected_tid {
        tids.retain(|&id| id == tid);
        if tids.is_empty() {
            return Err(error("selected thread does not belong to target process"));
        }
    }
    let mut threads = Vec::new();
    let mut rings = Vec::new();
    let mut issues = Vec::new();
    for (index, &tid) in tids.iter().enumerate() {
        let mut thread = Thread {
            tid,
            sampled: false,
            samples: 0,
            issue: None,
        };
        if index >= MAX_THREADS {
            thread.issue = Some("thread limit exceeded".into());
        } else if !task_path(root, tid).is_dir() {
            thread.issue = Some("thread exited before perf event could be opened".into());
        } else {
            match Ring::open(tid, frequency, stack) {
                Ok(ring) => rings.push((index, ring)),
                Err(e) => thread.issue = Some(perf_error("perf_event_open or mmap", &e)),
            }
        }
        threads.push(thread);
    }
    rings.retain(|(index, ring)| {
        let thread = &mut threads[*index];
        match ring.configure(PERF_EVENT_IOC_ENABLE) {
            Ok(()) => thread.sampled = true,
            Err(e) => thread.issue = Some(perf_error("enable perf event", &e)),
        }
        thread.sampled
    });

    let started_unix_ms = epoch_ms();
    let deadline = Instant::now() + Duration::from_millis(u64::from(duration_ms));
    let mut samples = Vec::new();
    let sample_limit = if stack { 1024 } else { 16_384 };
    let mut kernel_lost_samples: u64 = 0;
    let mut discarded_samples = 0;
    let mut ring_errors = 0;
    while !rings.is_empty() {
        let finished = Instant::now() >= deadline;
        for (index, ring) in &mut rings {
            let thread = &mut threads[*index];
            if finished && let Err(e) = ring.configure(PERF_EVENT_IOC_DISABLE) {
                thread.issue = Some(perf_error("disable perf event", &e));
            }
            if let Err(e) = ring.drain(|kind, mut data| match kind {
                PERF_RECORD_SAMPLE => {
                    if samples.len() >= sample_limit {
                        discarded_samples += 1;
                    } else if let Ok(sample) = Sample::parse(data, stack, pid, thread.tid) {
                        samples.push(sample);
                        thread.samples += 1;
                    } else {
                        discarded_samples += 1;
                    }
                }
                PERF_RECORD_LOST | PERF_RECORD_LOST_SAMPLES => {
                    if kind == PERF_RECORD_LOST {
                        let _ = take_word(&mut data);
                    }
                    if let Ok(lost) = take_word(&mut data) {
                        kernel_lost_samples = kernel_lost_samples.saturating_add(lost);
                    } else {
                        ring_errors += 1;
                    }
                }
                _ => {}
            }) {
                ring_errors += 1;
                thread.issue = Some(perf_error("read perf records", &e));
            }
        }
        if finished {
            break;
        }
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(10)),
        );
    }
    drop(rings);
    let finished_unix_ms = epoch_ms();
    let threads_seen_after_start = if selected_tid.is_none() {
        match task_ids(root) {
            Ok(after) => after
                .into_iter()
                .filter(|tid| tids.binary_search(tid).is_err())
                .collect(),
            Err(e) => {
                issues.push(format!("could not inspect threads after collection: {e}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    if threads.iter().any(|thread| thread.sampled) {
        verify_image(root, &maps, exe.as_ref(), &mut issues);
    }
    let total = samples.len() as u64;
    let mut images = Images::new();
    let mut locations = BTreeMap::new();
    let mut grouped = BTreeMap::<Location, BTreeMap<u64, u64>>::new();
    let mut tree = CountTree::default();
    let mut truncated_stacks = BTreeMap::new();
    let mut recovered_frames = BTreeMap::new();
    for sample in samples {
        if stack {
            let (mut path, reason) = if let Some((registers, memory)) = sample.stack {
                let stack = images.walk(
                    &memory,
                    registers,
                    &maps,
                    root,
                    exe.as_ref(),
                    Instant::now() + Duration::from_millis(50),
                );
                for frame in stack.frames.iter().skip(1) {
                    *recovered_frames.entry(frame.method).or_insert(0) += 1;
                }
                let pcs = stack
                    .frames
                    .iter()
                    .map(|frame| frame.lookup_address)
                    .collect::<Vec<_>>();
                (pcs, (!stack.complete).then_some(stack.stop_reason))
            } else {
                (
                    Vec::new(),
                    Some("sampled registers or stack unavailable".into()),
                )
            };
            if let Some(reason) = reason {
                *truncated_stacks.entry(reason).or_insert(0) += 1;
            }
            if path.is_empty() {
                path.push(sample.pc);
            }
            let mut node = &mut tree;
            node.count += 1;
            for pc in path.into_iter().rev() {
                let address = locations
                    .entry(pc)
                    .or_insert_with(|| location(pc, &mut images, &maps, root, exe.as_ref()));
                node = node.children.entry(address.location.clone()).or_default();
                node.count += 1;
            }
        } else {
            let address = locations
                .entry(sample.pc)
                .or_insert_with(|| location(sample.pc, &mut images, &maps, root, exe.as_ref()));
            *grouped
                .entry(address.location.clone())
                .or_default()
                .entry(address.offset)
                .or_default() += 1;
        }
    }
    let hotspots = finish_hotspots(grouped, total);
    let status = if !threads.iter().any(|thread| thread.sampled) {
        "unavailable"
    } else if threads.iter().any(|thread| thread.issue.is_some())
        || !threads_seen_after_start.is_empty()
        || !issues.is_empty()
        || kernel_lost_samples != 0
        || discarded_samples != 0
        || ring_errors != 0
        || !truncated_stacks.is_empty()
    {
        "partial"
    } else {
        "complete"
    };
    Ok(Report {
        status,
        pid,
        mode: if stack { "stack" } else { "hotspot" },
        scope: if selected_tid.is_some() {
            "thread"
        } else {
            "initial_threads"
        },
        duration_ms,
        started_unix_ms,
        finished_unix_ms,
        frequency_hz: frequency,
        samples: total,
        kernel_lost_samples,
        discarded_samples,
        ring_errors,
        threads,
        threads_seen_after_start,
        issues,
        hotspots,
        stacks: tree.finish(total),
        truncated_stacks,
        recovered_frames,
    })
}

fn verify_image(
    root: &Path,
    before: &[modules::Module],
    exe: Option<&fs::Metadata>,
    issues: &mut Vec<String>,
) {
    use std::os::unix::fs::MetadataExt;
    let after_exe = fs::metadata(root.join("exe"));
    if exe
        .zip(after_exe.as_ref().ok())
        .is_none_or(|(a, b)| (a.dev(), a.ino()) != (b.dev(), b.ino()))
    {
        issues.push("target executable became unavailable or changed during sampling".into());
        return;
    }
    let compare = |a: &modules::Module, b: &modules::Module| {
        a.backing == b.backing
            && a.maps
                .iter()
                .map(|m| (m.start, m.end, m.offset, &m.perms))
                .eq(b.maps.iter().map(|m| (m.start, m.end, m.offset, &m.perms)))
    };
    if modules::read(root).ok().is_none_or(|after| {
        before.len() != after.len() || !before.iter().zip(&after).all(|(a, b)| compare(a, b))
    }) {
        issues.push(
            "file-backed mappings changed during sampling; attribution uses the initial mappings"
                .into(),
        );
    }
}
