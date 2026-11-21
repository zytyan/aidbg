use super::{CaptureLimit, CaptureTimings, Coverage};
use crate::modules::{self, Backing, Layout, Mapping, Module};
use crate::rpc::CoreMode;
use crate::trace::Trace;
use crate::{Result, error};
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::unistd::Pid;
use object::{Object, ObjectSegment, SegmentFlags, read::ReadCache};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::IoSliceMut;
use std::ops::Range;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::time::Instant;

#[derive(Serialize)]
pub(super) struct Image {
    #[serde(flatten)]
    identity: modules::ModuleIdentity,
    #[serde(skip)]
    data: Vec<Range<u64>>,
    #[serde(skip)]
    headers: Vec<Range<u64>>,
}

#[derive(PartialEq, Eq)]
struct FileVersion {
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileVersion {
    fn read(file: &File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

struct ElfImage {
    build_id: Option<Vec<u8>>,
    loads: Vec<modules::LoadSegment>,
    writable: Vec<(u64, u64)>,
}

struct PreparedImage {
    file: File,
    version: FileVersion,
    elf: Option<ElfImage>,
}

impl PreparedImage {
    fn read(file: File, mode: CoreMode) -> Result<Self> {
        let version = FileVersion::read(&file)?;
        let cache = ReadCache::new(&file);
        let elf = object::File::parse(&cache)
            .ok()
            .filter(modules::is_executable_module)
            .map(|elf| ElfImage {
                build_id: elf.build_id().ok().flatten().map(<[u8]>::to_vec),
                loads: if mode.includes_data() {
                    modules::load_segments(&elf).collect()
                } else {
                    Vec::new()
                },
                writable: if mode.includes_data() {
                    elf.segments()
                        .filter(|segment| {
                            matches!(segment.flags(), SegmentFlags::Elf { p_flags, .. }
                            if (p_flags & object::elf::PF_W).0 != 0)
                        })
                        .map(|segment| (segment.address(), segment.size()))
                        .collect()
                } else {
                    Vec::new()
                },
            });
        if FileVersion::read(&file)? != version {
            return Err(error("ELF file changed while reading it"));
        }
        Ok(Self { file, version, elf })
    }
}

#[derive(Default)]
pub(super) struct ImageCache(BTreeMap<Backing, PreparedImage>);

pub(super) fn prepare_images(
    root: &Path,
    mode: CoreMode,
    limit: &CaptureLimit<'_>,
) -> Result<ImageCache> {
    let Ok(space) = modules::address_space(root) else {
        return Ok(ImageCache::default());
    };
    let exe = fs::metadata(root.join("exe")).ok();
    let mut images = BTreeMap::new();
    for module in space.modules {
        limit.check()?;
        let is_main = exe
            .as_ref()
            .is_some_and(|metadata| module.matches(metadata));
        if let Ok(file) = module.open(root, is_main)
            && let Ok(image) = PreparedImage::read(file, mode)
        {
            images.insert(module.backing, image);
        }
    }
    Ok(ImageCache(images))
}

impl ImageCache {
    pub(super) fn resolve(
        mut self,
        root: &Path,
        mode: CoreMode,
        page: u64,
        maps: &[(Backing, Mapping)],
        coverage: &mut Coverage,
        check: impl Fn() -> Result<()>,
    ) -> Result<(Vec<Image>, usize)> {
        let exe = mode
            .needs_elf_memory()
            .then(|| fs::metadata(root.join("exe")).ok())
            .flatten();
        let space = modules::group_mappings(maps.iter().cloned());
        let mut result = Vec::new();
        let mut hits = 0;
        for module in space.modules {
            check()?;
            let mut image = Image {
                identity: module.identity(None),
                data: Vec::new(),
                headers: Vec::new(),
            };
            // Match the frozen maps by backing identity. Recheck the open file so
            // in-place changes during preflight cannot reuse stale ELF metadata.
            let cached = self.0.remove(&module.backing).filter(|cached| {
                FileVersion::read(&cached.file).is_ok_and(|current| current == cached.version)
            });
            let prepared = if let Some(cached) = cached {
                hits += 1;
                Ok(cached)
            } else if mode.needs_elf_memory() {
                let is_main = exe
                    .as_ref()
                    .is_some_and(|metadata| module.matches(metadata));
                module
                    .open(root, is_main)
                    .and_then(|file| PreparedImage::read(file, mode))
            } else {
                // Metadata-only resolution happens after detach. A new or
                // changed image cannot be trusted to match the frozen bytes.
                result.push(image);
                continue;
            };
            match prepared {
                Ok(PreparedImage { elf: Some(elf), .. }) => {
                    image.identity = module.identity(elf.build_id.as_deref());
                    if mode.needs_elf_memory() {
                        image.headers.extend(
                            module
                                .maps
                                .iter()
                                .filter(|map| map.offset == 0 && map.perms.starts_with('r'))
                                .map(|map| map.start..map.start.saturating_add(page).min(map.end)),
                        );
                    }
                    if mode.includes_data() {
                        select_elf_data(&mut image, elf, &module, page, coverage);
                    }
                }
                Err(error)
                    if mode.includes_data()
                        && module.backing.inode != 0
                        && !shared_memory(&module.backing) =>
                {
                    coverage.issues.push(format!(
                        "ELF data layout for {}: {error}",
                        module.path().display()
                    ));
                }
                _ => {}
            }
            result.push(image);
        }
        Ok((result, hits))
    }
}

fn select_elf_data(
    image: &mut Image,
    elf: ElfImage,
    module: &Module,
    page: u64,
    coverage: &mut Coverage,
) {
    let layout = match Layout::from_segments(elf.loads, module, page) {
        Ok(layout) if !layout.instances.is_empty() => layout,
        _ => {
            coverage.issues.push(format!(
                "ELF load instance unavailable for {}",
                module.path().display()
            ));
            return;
        }
    };
    for (start, size) in elf.writable {
        let Some(end) = start.checked_add(size) else {
            coverage.issues.push(format!(
                "invalid ELF load segment range for {}",
                module.path().display()
            ));
            continue;
        };
        image.data.extend(
            layout
                .instances
                .iter()
                .filter_map(|instance| instance.relocate(start).zip(instance.relocate(end)))
                .filter(|(start, end)| start < end)
                .map(|(start, end)| start..end),
        );
    }
}

#[derive(Default)]
struct Smaps {
    private_dirty: Option<u64>,
    shared_dirty: Option<u64>,
    unsafe_to_read: bool,
}

fn smaps(root: &Path) -> BTreeMap<u64, Smaps> {
    let mut result = BTreeMap::<u64, Smaps>::new();
    let mut row = None;
    let Ok(data) = fs::read(root.join("smaps")) else {
        return result;
    };
    for line in data.split(|&byte| byte == b'\n') {
        if let Some(start) = line
            .split(|&byte| byte == b'-' || byte == b' ')
            .next()
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| u64::from_str_radix(s, 16).ok())
        {
            row = Some(result.entry(start).or_default());
        } else if let Some(info) = row.as_deref_mut() {
            let kb = |value: &[u8]| {
                std::str::from_utf8(value)
                    .ok()?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            };
            if let Some(value) = line.strip_prefix(b"Private_Dirty:") {
                info.private_dirty = kb(value);
            } else if let Some(value) = line.strip_prefix(b"Shared_Dirty:") {
                info.shared_dirty = kb(value);
            } else if let Some(flags) = line.strip_prefix(b"VmFlags:") {
                // Faulting a missing userfaultfd page can wait for a frozen handler.
                info.unsafe_to_read = flags
                    .split(u8::is_ascii_whitespace)
                    .any(|flag| matches!(flag, b"io" | b"pf" | b"um" | b"ui"));
            }
        }
    }
    result
}

fn shared_memory(backing: &Backing) -> bool {
    backing.inode == 0
        || backing.path.starts_with(b"[anon_shmem:")
        || backing.path.starts_with(b"/memfd:")
        || backing.path.starts_with(b"/SYSV")
        || backing.path.starts_with(b"/dev/shm/")
        || backing.path == b"/dev/zero (deleted)"
}

fn push_range(list: &mut Vec<Range<u64>>, range: Range<u64>) {
    if let Some(last) = list.last_mut()
        && last.end >= range.start
    {
        last.end = last.end.max(range.end);
    } else {
        list.push(range);
    }
}

fn union(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    ranges.sort_unstable_by_key(|range| range.start);
    let mut output = Vec::with_capacity(ranges.len());
    for range in ranges {
        push_range(&mut output, range);
    }
    output
}

// A mapped copy can still contain valid data on the partial page at EOF.
fn private_file_pages(
    pagemap: &File,
    map: &Mapping,
    page: u64,
    file_len: u64,
    scratch: &mut [u8],
    limit: &CaptureLimit<'_>,
) -> Result<Vec<Range<u64>>> {
    let mut selected = Vec::new();
    let mut start = map.start;
    while start < map.end {
        limit.check()?;
        let count = ((map.end - start).div_ceil(page)).min((scratch.len() / 8) as u64);
        let entries = &mut scratch[..count as usize * 8];
        pagemap.read_exact_at(entries, (start / page) * 8)?;
        for entry in entries.chunks_exact(8) {
            let bits = u64::from_ne_bytes(entry.try_into()?);
            let end = (start + page).min(map.end);
            let offset = map.offset.checked_add(end - map.start);
            let cow = bits & (1 << 63) != 0 && bits & (1 << 61) == 0;
            let swapped = bits & (1 << 62) != 0;
            if cow || swapped || offset.is_none_or(|offset| offset > file_len) {
                push_range(&mut selected, start..end);
            }
            start = end;
        }
    }
    Ok(selected)
}

struct Plan {
    read: Vec<Range<u64>>,
    omitted: Vec<Range<u64>>,
}

fn plan(
    trace: &Trace<'_>,
    root: &Path,
    mode: CoreMode,
    page: u64,
    maps: &[(Backing, Mapping)],
    stacks: &[(i32, u64)],
    modules: &[Image],
    smaps: &BTreeMap<u64, Smaps>,
    coverage: &mut Coverage,
    limit: &CaptureLimit<'_>,
) -> Result<Plan> {
    let pagemap = mode
        .includes_data()
        .then(|| File::open(root.join("pagemap")).ok())
        .flatten();
    let mut scratch = vec![0; 64 * 1024];
    let mut file_lengths = BTreeMap::new();
    let data = union(
        modules
            .iter()
            .flat_map(|image| image.data.iter().cloned())
            .collect(),
    );
    let mut selected = if mode == CoreMode::CoreFull {
        Vec::new()
    } else {
        modules
            .iter()
            .flat_map(|image| image.headers.iter().cloned())
            .collect()
    };
    if mode != CoreMode::CoreFull {
        let read = |address: u64, buffer: &mut [u8]| -> Result<()> {
            let end = address
                .checked_add(buffer.len() as u64)
                .ok_or_else(|| error("invalid dynamic linker range"))?;
            let i = maps.partition_point(|(_, map)| map.end <= address);
            let Some((_, map)) = maps.get(i).filter(|(_, map)| {
                map.contains(address) && end <= map.end && map.perms.starts_with('r')
            }) else {
                return Err(error("dynamic linker range is unmapped"));
            };
            if smaps
                .get(&map.start)
                .is_some_and(|info| info.unsafe_to_read)
            {
                return Err(error("dynamic linker range cannot be read safely"));
            }
            trace.read_memory(address, buffer)
        };
        match super::loader::ranges(root, page, read, limit) {
            Ok(ranges) => selected.extend(ranges),
            Err(error) => {
                limit.check()?;
                coverage
                    .issues
                    .push(format!("dynamic linker metadata: {error}"));
            }
        }
    }
    for &(tid, sp) in stacks {
        let i = maps.partition_point(|(_, map)| map.end <= sp);
        match maps.get(i).filter(|(_, map)| map.contains(sp)) {
            Some((_, map)) if mode == CoreMode::CoreStack4k => {
                selected.push(sp..sp.saturating_add(4096).min(map.end));
            }
            Some((_, map)) => selected.push(map.start..map.end),
            None => coverage
                .issues
                .push(format!("tid {tid}: SP {sp:#x} outside every mapping")),
        }
    }
    let selected = union(selected);
    let mut read = Vec::new();
    let mut omitted = Vec::new();
    for (backing, map) in maps {
        limit.check()?;
        let whole = map.start..map.end;
        let usage = smaps.get(&map.start);
        let shared = map.perms.as_bytes().get(3) == Some(&b's');
        let ipc = shared && shared_memory(backing);
        let writable = map.perms.as_bytes().get(1) == Some(&b'w');
        let include_heap = backing.path == b"[heap]"
            || (backing.inode == 0
                && !shared
                && writable
                && (backing.path.is_empty() || backing.path.starts_with(b"[anon:")));
        let whole_mapping = mode == CoreMode::CoreFull
            || backing.path == b"[vdso]"
            || mode != CoreMode::CoreStack4k && backing.path == b"[stack]"
            || mode == CoreMode::CoreExtended
                && (include_heap || ipc && map.perms.starts_with('r'));
        let ranges = if whole_mapping {
            vec![whole]
        } else {
            let mut ranges = Vec::new();
            let intersect = |ranges: &[Range<u64>], output: &mut Vec<Range<u64>>| {
                let first = ranges.partition_point(|range| range.end <= map.start);
                output.extend(
                    ranges[first..]
                        .iter()
                        .take_while(|range| range.start < map.end)
                        .map(|range| range.start.max(map.start)..range.end.min(map.end)),
                );
            };
            intersect(&selected, &mut ranges);
            if mode.includes_data() {
                intersect(&data, &mut ranges);
                if backing.inode != 0 && !ipc {
                    let length = *file_lengths.entry(backing.clone()).or_insert_with(|| {
                        if backing.path.ends_with(b" (deleted)") {
                            return None;
                        }
                        let file = Module {
                            backing: backing.clone(),
                            maps: vec![map.clone()],
                        };
                        file.open(root, false)
                            .ok()?
                            .metadata()
                            .ok()
                            .map(|m| m.len())
                    });
                    let extent = map.offset.checked_add(map.end - map.start);
                    if shared {
                        let clean = usage.is_some_and(|s| {
                            s.private_dirty == Some(0) && s.shared_dirty == Some(0)
                        });
                        if !clean || length.is_none() {
                            coverage.conservative_shared_mappings += 1;
                            ranges.push(whole);
                        } else if let Some(length) = length
                            && extent.is_none_or(|end| end > length)
                        {
                            let available = length.saturating_sub(map.offset) / page * page;
                            ranges.push(map.start + available..map.end);
                        }
                    } else if let (Some(pagemap), Some(length)) = (&pagemap, length) {
                        match private_file_pages(pagemap, map, page, length, &mut scratch, limit) {
                            Ok(pages) => ranges.extend(pages),
                            Err(_) => {
                                limit.check()?;
                                ranges.push(whole);
                            }
                        }
                    } else {
                        ranges.push(whole);
                    }
                }
            }
            union(ranges)
        };
        if usage.is_some_and(|s| s.unsafe_to_read) {
            omitted.extend(ranges);
        } else {
            read.extend(ranges);
        }
    }
    Ok(Plan { read, omitted })
}

pub(super) struct Stored {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
}

#[derive(Default)]
pub(super) struct Captured {
    pub stored: Vec<Stored>,
    pub bytes: u64,
}

impl Captured {
    fn record(&mut self, start: u64, len: usize) {
        let end = start + len as u64;
        if let Some(last) = self.stored.last_mut()
            && last.end == start
        {
            last.end = end;
        } else {
            self.stored.push(Stored {
                start,
                end,
                offset: self.bytes,
            });
        }
        self.bytes += len as u64;
    }
}

fn read_batch(
    pid: Pid,
    page: u64,
    mem: &mut Option<Option<File>>,
    root: &Path,
    remote: &mut [RemoteIoVec],
    buffer: &mut [u8],
    captured: &mut Captured,
    coverage: &mut Coverage,
    limit: &CaptureLimit<'_>,
) -> Result<usize> {
    let mut first = 0;
    let mut filled = 0;
    let mut remaining = buffer.len();
    while first < remote.len() {
        limit.check()?;
        let transfer = process_vm_readv(
            pid,
            &mut [IoSliceMut::new(&mut buffer[filled..])],
            &remote[first..],
        );
        let mut n = match transfer {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ESRCH) => return Err(error("target exited during coredump")),
            Err(_) => 0,
        };
        let short = n < remaining;
        remaining -= n;
        while n != 0 {
            let range = &mut remote[first];
            let consumed = range.len.min(n);
            captured.record(range.base as u64, consumed);
            range.base += consumed;
            range.len -= consumed;
            filled += consumed;
            n -= consumed;
            first += usize::from(range.len == 0);
        }
        if short {
            let range = &mut remote[first];
            let address = range.base as u64;
            let remainder = range.len.min((page - address % page) as usize);
            let fallback = mem.get_or_insert_with(|| File::open(root.join("mem")).ok());
            let got = fallback
                .as_ref()
                .and_then(|file| {
                    file.read_at(&mut buffer[filled..filled + remainder], address)
                        .ok()
                })
                .unwrap_or(0);
            if got != 0 {
                captured.record(address, got);
                filled += got;
            }
            if got < remainder {
                coverage.missing(
                    address + got as u64,
                    address + remainder as u64,
                    "unreadable",
                );
            }
            range.base += remainder;
            range.len -= remainder;
            remaining -= remainder;
            first += usize::from(range.len == 0);
        }
    }
    Ok(filled)
}

pub(super) fn capture(
    trace: &Trace<'_>,
    pid: i32,
    root: &Path,
    mode: CoreMode,
    page: u64,
    maps: &[(Backing, Mapping)],
    stacks: &[(i32, u64)],
    modules: &[Image],
    coverage: &mut Coverage,
    limit: &CaptureLimit<'_>,
    mut buffer: Vec<u8>,
    sink: &mut dyn FnMut(Vec<u8>) -> Result<Vec<u8>>,
    timings: &mut CaptureTimings,
) -> Result<Captured> {
    let started = Instant::now();
    let smaps = smaps(root);
    timings.smaps = super::micros(started);
    let started = Instant::now();
    let plan = plan(
        trace, root, mode, page, maps, stacks, modules, &smaps, coverage, limit,
    )?;
    timings.selection = super::micros(started);
    let mut captured = Captured::default();
    let block_bytes = buffer.len();
    let mut batch = Vec::with_capacity(64);
    let mut mem = None;
    let pid = Pid::from_raw(pid);
    let mut ranges = plan.read.into_iter().peekable();
    while ranges.peek().is_some() {
        limit.check()?;
        let mut size = 0;
        batch.clear();
        while size < block_bytes && batch.len() < 64 {
            let Some(range) = ranges.peek_mut() else {
                break;
            };
            let n = (range.end - range.start).min((block_bytes - size) as u64);
            let end = range.start + n;
            batch.push(RemoteIoVec {
                base: range.start as usize,
                len: n as usize,
            });
            size += n as usize;
            range.start = end;
            if range.start == range.end {
                ranges.next();
            }
        }
        let started = Instant::now();
        buffer.resize(size, 0);
        let read = read_batch(
            pid,
            page,
            &mut mem,
            root,
            &mut batch,
            &mut buffer,
            &mut captured,
            coverage,
            limit,
        )?;
        timings.memory_read += super::micros(started);
        buffer.truncate(read);
        if !buffer.is_empty() {
            let started = Instant::now();
            buffer = sink(buffer)?;
            timings.buffering += super::micros(started);
        }
    }
    for range in plan.omitted {
        coverage.missing(range.start, range.end, "unsafe_to_fault");
    }
    coverage.missing.sort_unstable_by_key(|gap| gap.start);
    Ok(captured)
}
