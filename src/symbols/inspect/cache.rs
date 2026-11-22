use super::*;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::sync::{
    Arc, Mutex, OnceLock, Weak,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

const CACHE_BYTES: usize = 128 * 1024 * 1024;
const MAX_INDEX_DIES: usize = 2_000_000;
const INDEX_BYTES: usize = 8 * 1024 * 1024;

enum Work {
    Index(Weak<Data>),
    Warm(File),
}

fn queue(work: Work) -> bool {
    static WORKER: OnceLock<Option<mpsc::SyncSender<Work>>> = OnceLock::new();
    if let Some(sender) = WORKER.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel(16);
        std::thread::Builder::new()
            .name("aidbg-dwarf".into())
            .spawn(move || {
                while let Ok(work) = receiver.recv() {
                    match work {
                        Work::Index(data) => {
                            if let Some(data) = data.upgrade() {
                                let _ = data.index.set(Index::build(&data.borrow()).ok());
                            }
                        }
                        Work::Warm(process) => {
                            use std::os::fd::AsRawFd;
                            let root =
                                PathBuf::from(format!("/proc/self/fd/{}", process.as_raw_fd()));
                            let Ok(exe) = fs::metadata(root.join("exe")) else {
                                continue;
                            };
                            let Ok(modules) = modules::read(&root) else {
                                continue;
                            };
                            if let Some(module) = modules.iter().find(|module| module.matches(&exe))
                            {
                                let _ = live_image(&root, module, Some(&exe));
                            }
                        }
                    }
                }
            })
            .ok()
            .map(|_| sender)
    }) {
        sender.try_send(work).is_ok()
    } else {
        false
    }
}

pub(crate) fn warm(pid: i32) {
    if let Ok(process) = File::open(format!("/proc/{pid}")) {
        queue(Work::Warm(process));
    }
}

type UnitId = gimli::DebugInfoOffset<usize>;
type Function = (UnitId, Offset);

#[derive(Default)]
struct Index {
    functions: Vec<(gimli::Range, Function)>,
    max_ends: Vec<u64>,
    globals: BTreeMap<String, Vec<(UnitId, Offset)>>,
}

impl Index {
    fn build(dwarf: &Dwarf<Reader<'_>>) -> Result<Self> {
        let mut index = Self::default();
        let mut units = dwarf.units();
        let mut ranges_budget = ScanBudget {
            scanned: 0,
            limit: MAX_INDEX_DIES,
            deadline: None,
        };
        let mut global_budget = ScanBudget {
            scanned: 0,
            limit: MAX_INDEX_DIES,
            deadline: None,
        };
        let mut bytes = 0;
        while let Some(header) = units.next()? {
            let Some(id) = gimli::UnitOffset(0).to_debug_info_offset(&header) else {
                continue;
            };
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                ranges_budget.entry()?;
                if entry.tag() == gimli::DW_TAG_subprogram {
                    let mut ranges = dwarf.die_ranges(&unit, entry)?;
                    while let Some(range) = ranges.next()? {
                        bytes += std::mem::size_of::<(gimli::Range, Function)>()
                            + std::mem::size_of::<u64>();
                        if bytes > INDEX_BYTES {
                            return Err(error("DWARF index range budget exceeded"));
                        }
                        index.functions.push((range, (id, entry.offset())));
                    }
                }
            }
            find_variable(
                dwarf,
                &unit,
                "",
                None,
                &mut global_budget,
                None,
                Some(&mut |name, _, _, candidate| {
                    let entries = index.globals.entry(name.to_owned()).or_insert_with(|| {
                        bytes += name.len() + 128;
                        Vec::new()
                    });
                    bytes += 2 * std::mem::size_of::<(UnitId, Offset)>();
                    entries.push((id, candidate.offset));
                    bytes <= INDEX_BYTES
                }),
                false,
                None,
            )?;
            if bytes > INDEX_BYTES {
                return Err(error("DWARF index name budget exceeded"));
            }
        }
        index
            .functions
            .sort_unstable_by_key(|(range, _)| range.begin);
        let mut max_end = 0;
        index.max_ends = index
            .functions
            .iter()
            .map(|(range, _)| {
                max_end = max_end.max(range.end);
                max_end
            })
            .collect();
        Ok(index)
    }
}

pub(super) struct Data {
    sections: DwarfSections<Vec<u8>>,
    index: OnceLock<Option<Index>>,
    index_queued: AtomicBool,
    section_bytes: usize,
}

impl Data {
    pub fn load(obj: &object::File<'_>) -> Result<Arc<Self>> {
        let section_bytes = std::cell::Cell::new(0);
        let sections = load_sections(obj, |bytes| {
            section_bytes.set(section_bytes.get() + bytes.len());
            bytes.into_owned()
        })?;
        let data = Arc::new(Self {
            sections,
            index: OnceLock::new(),
            index_queued: AtomicBool::new(false),
            section_bytes: section_bytes.get(),
        });
        data.schedule();
        Ok(data)
    }

    pub fn schedule(self: &Arc<Self>) {
        if !self.index_queued.swap(true, Ordering::AcqRel)
            && !queue(Work::Index(Arc::downgrade(self)))
        {
            self.index_queued.store(false, Ordering::Release);
        }
    }

    pub fn borrow(&self) -> Dwarf<Reader<'_>> {
        self.sections
            .borrow(|bytes| EndianSlice::new(bytes, LittleEndian))
    }

    pub fn functions(&self, pc: u64) -> Option<Vec<Function>> {
        let index = self.index.get()?.as_ref()?;
        let end = index
            .functions
            .partition_point(|(range, _)| range.begin <= pc);
        let start = index.max_ends[..end].partition_point(|&max| max <= pc);
        let functions: BTreeSet<_> = index.functions[start..end]
            .iter()
            .filter_map(|(range, function)| (pc < range.end).then_some(*function))
            .collect();
        Some(functions.into_iter().collect())
    }

    pub fn lookup<'a, T>(
        &self,
        dwarf: &Dwarf<Reader<'a>>,
        target: &str,
        pc: Option<u64>,
        mut shadow: Option<&mut bool>,
        deadline: Instant,
        mut evaluate: impl FnMut(&Dwarf<Reader<'a>>, &Unit<Reader<'a>>, Candidate<'a>) -> Result<T>,
    ) -> Result<Option<(usize, Result<T>)>> {
        let mut budget = ScanBudget::foreground(deadline);
        let mut best = None;
        let index = self
            .index
            .get()
            .and_then(Option::as_ref)
            .filter(|_| shadow.is_none());
        let mut scan =
            |best: &mut Option<(usize, Result<T>)>, header, pc, function| -> Result<()> {
                if Instant::now() >= deadline {
                    return Err(failure(
                        "limit_reached",
                        "DWARF variable lookup exceeded its capture budget",
                    ));
                }
                let unit = dwarf.unit(header)?;
                let Some(candidate) = find_variable(
                    dwarf,
                    &unit,
                    target,
                    pc,
                    &mut budget,
                    shadow.as_deref_mut(),
                    None,
                    false,
                    function,
                )?
                else {
                    return Ok(());
                };
                match best.as_ref() {
                    Some((priority, _)) if *priority > candidate.priority => {}
                    Some((priority, _)) if *priority == candidate.priority => {
                        *best = Some((
                            *priority,
                            Err(failure(
                                "ambiguous",
                                "multiple compilation units define the variable",
                            )),
                        ));
                    }
                    _ => {
                        let priority = candidate.priority;
                        *best = Some((priority, evaluate(dwarf, &unit, candidate)));
                    }
                }
                Ok(())
            };
        if let Some(index) = index {
            if let Some(functions) = pc.and_then(|pc| self.functions(pc)) {
                for (unit, function) in functions {
                    scan(&mut best, dwarf.unit_header(unit)?, pc, Some(function))?;
                }
            }
            if best.is_none() {
                let name = target.strip_prefix("::").unwrap_or(target);
                if let Some(globals) = index.globals.get(name) {
                    best = match globals.as_slice() {
                        [(id, offset)] => {
                            let unit = dwarf.unit(dwarf.unit_header(*id)?)?;
                            let candidate = Candidate {
                                offset: *offset,
                                priority: 0,
                                concrete: true,
                                active: true,
                                ranges: Arc::from([]),
                                prologue: false,
                                frame_base: None,
                            };
                            Some((0, evaluate(dwarf, &unit, candidate)))
                        }
                        _ => Some((
                            0,
                            Err(failure(
                                "ambiguous",
                                "multiple DWARF variables match this global name",
                            )),
                        )),
                    };
                }
            }
        } else {
            let mut units = dwarf.units();
            while let Some(header) = units.next()? {
                scan(&mut best, header, pc, None)?;
            }
        }
        Ok(best)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Stamp(u64, u64, u64, i64, i64, i64, i64);

impl From<&fs::Metadata> for Stamp {
    fn from(info: &fs::Metadata) -> Self {
        Self(
            info.dev(),
            info.ino(),
            info.len(),
            info.mtime(),
            info.mtime_nsec(),
            info.ctime(),
            info.ctime_nsec(),
        )
    }
}

pub(super) struct LiveImage {
    pub bytes: Arc<Vec<u8>>,
    pub primary: Option<Arc<Data>>,
    pub separate: Option<Arc<Data>>,
    loaded: Instant,
}

struct Entry {
    stamp: Stamp,
    namespace: Option<(u64, u64)>,
    path: PathBuf,
    image: Arc<LiveImage>,
    size: usize,
}

pub(super) fn live_image(
    root: &Path,
    module: &Module,
    exe: Option<&fs::Metadata>,
) -> Result<Arc<LiveImage>> {
    static CACHE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
    let mut file = module.open(root, exe.is_some_and(|exe| module.matches(exe)))?;
    let stamp = Stamp::from(&file.metadata()?);
    let namespace = fs::metadata(root.join("ns/mnt"))
        .ok()
        .map(|stat| (stat.dev(), stat.ino()));
    let path = module.path();
    let matched =
        |entry: &Entry| entry.stamp == stamp && entry.namespace == namespace && entry.path == path;
    {
        let mut cache = CACHE.lock().unwrap_or_else(|lock| lock.into_inner());
        if let Some(index) = cache.iter().position(matched) {
            let entry = cache.remove(index);
            // Refresh negative lookups so newly installed separate debug info is picked up.
            if (entry.image.separate.is_some() || entry.image.primary.is_some())
                || entry.image.loaded.elapsed() < Duration::from_secs(30)
            {
                let image = entry.image.clone();
                for data in image.separate.iter().chain(&image.primary) {
                    data.schedule();
                }
                cache.push(entry);
                return Ok(image);
            }
        }
    }
    if stamp.2 > IMAGE_LIMIT {
        return Err(error("module exceeds image byte budget"));
    }
    let mut bytes = Vec::new();
    (&mut file).take(IMAGE_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > IMAGE_LIMIT || Stamp::from(&file.metadata()?) != stamp {
        return Err(error("module changed during image read"));
    }
    let object = object::File::parse(&*bytes)?;
    let debug = DebugFile::discover(root, module, &object);
    let separate = debug.as_ref().and_then(DebugFile::parse);
    let load = |object: &object::File<'_>| {
        if object.section_by_name(".debug_info").is_some() {
            Data::load(object).map(Some)
        } else {
            Ok(None)
        }
    };
    let separate = separate.as_ref().map(load).transpose()?.flatten();
    let primary = load(&object)?;
    let size = bytes.len()
        + separate
            .iter()
            .chain(&primary)
            .map(|data| data.section_bytes + INDEX_BYTES)
            .sum::<usize>();
    let image = Arc::new(LiveImage {
        bytes: Arc::new(bytes),
        primary,
        separate,
        loaded: Instant::now(),
    });
    let mut cache = CACHE.lock().unwrap_or_else(|lock| lock.into_inner());
    if let Some(entry) = cache.iter().find(|entry| matched(entry)) {
        return Ok(entry.image.clone());
    }
    if size <= CACHE_BYTES {
        let mut used: usize = cache.iter().map(|entry| entry.size).sum();
        while used + size > CACHE_BYTES || cache.len() >= 32 {
            used -= cache.remove(0).size;
        }
        cache.push(Entry {
            stamp,
            namespace,
            path,
            image: image.clone(),
            size,
        });
    }
    Ok(image)
}
