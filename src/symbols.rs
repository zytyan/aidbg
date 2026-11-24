use crate::modules::{self, Backing, Layout, Mapping, Module, ModuleIdentity, id_hex, signed_hex};
use crate::procfs::Status;
use crate::rpc::SymbolMatch;
use crate::{Diagnostic, Result, error, hex};
use gimli::{ColumnType, DwarfSections, EndianSlice, LittleEndian};
use nix::libc;
use object::ObjectSegment;
use object::{Object, ObjectSection, ObjectSymbol, SymbolFlags, SymbolKind};
use serde::Serialize;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

pub(crate) mod inspect;
mod overrides;
pub(crate) mod script_page;
pub use inspect::{Report as InspectReport, inspect};
pub use overrides::{Overrides, Rule as OverrideRule};

const IMAGE_LIMIT: u64 = 128 * 1024 * 1024;
const DEBUG_LIMIT: u64 = 256 * 1024 * 1024;
const MAX_RESULTS: u32 = 4096;

struct Process {
    _dir: File,
    root: PathBuf,
    exe: Option<fs::Metadata>,
    modules: Vec<Module>,
    anonymous: Vec<Mapping>,
}

impl Process {
    fn open(pid: i32) -> Result<Self> {
        let dir = File::open(format!("/proc/{pid}"))?;
        let root = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
        if Status::read(&root)?.field("Tgid") != Some(&pid.to_string()) {
            return Err(error("pass the process ID (thread-group leader)"));
        }
        let space = modules::address_space(&root)?;
        let exe = fs::metadata(root.join("exe")).ok();
        Ok(Self {
            _dir: dir,
            root,
            exe,
            modules: space.modules,
            anonymous: space.anonymous,
        })
    }
}

pub(crate) fn path_matches(module: &Module, filter: &str) -> bool {
    let path = module.path();
    path == Path::new(filter) || path.file_name() == Some(OsStr::new(filter))
}

fn module_matches(module: &Module, filter: &str, build_id: Option<&[u8]>) -> bool {
    path_matches(module, filter)
        || build_id.is_some_and(|id| id_hex(id).eq_ignore_ascii_case(filter))
}

pub(crate) fn may_be_build_id(filter: &str) -> bool {
    filter.len() >= 2
        && filter.len().is_multiple_of(2)
        && filter.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) struct DebugFile {
    pub(crate) path: PathBuf,
    pub(crate) bytes: Vec<u8>,
}

fn debug_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(error("invalid or oversized external debug file"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(error("external debug file exceeds byte limit"));
    }
    Ok(bytes)
}

pub(crate) fn installed_debug_symbols(build_id: &str) -> Option<PathBuf> {
    if build_id.len() < 4 || !build_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let (prefix, suffix) = build_id.split_at(2);
    let path = PathBuf::from(format!("/usr/lib/debug/.build-id/{prefix}/{suffix}.debug"));
    path.is_file().then_some(path)
}

pub(crate) fn debuglink_paths(path: &Path, link: &[u8]) -> Vec<PathBuf> {
    let name = Path::new(OsStr::from_bytes(link));
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    if name.file_name() != Some(name.as_os_str()) {
        return Vec::new();
    }
    let mut paths = vec![parent.join(name), parent.join(".debug").join(name)];
    if let Ok(relative) = parent.strip_prefix("/") {
        paths.push(Path::new("/usr/lib/debug").join(relative).join(name));
    }
    paths
}

pub(crate) fn external_debug(
    root: &Path,
    module: &Module,
    obj: &object::File<'_>,
) -> Option<(PathBuf, Vec<u8>)> {
    find_external_debug(Some(&root.join("root")), &module.path(), obj, DEBUG_LIMIT)
}

pub(crate) fn find_external_debug(
    target_root: Option<&Path>,
    module_path: &Path,
    obj: &object::File<'_>,
    limit: u64,
) -> Option<(PathBuf, Vec<u8>)> {
    let build_id = obj.build_id().ok().flatten();
    let debuglink = obj.gnu_debuglink().ok().flatten().filter(|(name, _)| {
        let name = Path::new(OsStr::from_bytes(name));
        name.file_name()
            .is_some_and(|basename| name.as_os_str() == basename)
    });
    let target_debug = target_root.map(|root| root.join("usr/lib/debug"));
    let host_debug = Path::new("/usr/lib/debug");
    let mut candidates = Vec::new();
    if let Some(id) = build_id.filter(|id| !id.is_empty()) {
        let id = id_hex(id);
        let relative = format!(".build-id/{}/{}.debug", &id[..2], &id[2..]);
        if let Some(target_debug) = &target_debug {
            candidates.push((target_debug.join(&relative), None));
        }
        candidates.push((host_debug.join(relative), None));
    }
    if let Some((name, crc)) = debuglink
        && let Ok(relative) = module_path.strip_prefix("/")
        && let Some(dir) = relative.parent()
    {
        let name = OsStr::from_bytes(name);
        if let Some(root) = target_root {
            candidates.push((root.join(dir).join(name), Some(crc)));
            candidates.push((root.join(dir).join(".debug").join(name), Some(crc)));
            candidates.push((root.join("usr/lib/debug").join(dir).join(name), Some(crc)));
            candidates.push((host_debug.join(dir).join(name), Some(crc)));
        } else {
            candidates.extend(
                debuglink_paths(module_path, name.as_bytes())
                    .into_iter()
                    .map(|path| (path, Some(crc))),
            );
        }
    }
    for (path, crc) in candidates {
        let Ok(bytes) = debug_bytes(&path, limit) else {
            continue;
        };
        if crc.is_some_and(|expected| crc32fast::hash(&bytes) != expected) {
            continue;
        }
        let Ok(debug) = object::File::parse(&*bytes) else {
            continue;
        };
        if !modules::is_executable_module(&debug)
            || debug.architecture() != obj.architecture()
            || (debug.symbol_table().is_none() && !debug.has_debug_symbols())
        {
            continue;
        }
        let Ok(found_id) = debug.build_id() else {
            continue;
        };
        let identity_ok = match (crc, build_id, found_id) {
            (_, Some(expected), Some(found)) => expected == found,
            (Some(_), _, _) => true,
            _ => false,
        };
        if identity_ok {
            let display = target_root
                .and_then(|root| path.strip_prefix(root).ok())
                .map(|p| Path::new("/").join(p))
                .unwrap_or(path);
            return Some((display, bytes));
        }
    }
    None
}

impl DebugFile {
    fn discover(root: &Path, module: &Module, obj: &object::File<'_>) -> Option<Self> {
        let (path, bytes) = external_debug(root, module, obj)?;
        Some(Self { path, bytes })
    }

    pub(crate) fn parse(&self) -> Option<object::File<'_>> {
        object::File::parse(&*self.bytes).ok()
    }

    fn display_path(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct Source {
    table: &'static str,
    debug_file: Option<String>,
}

#[derive(Clone, Serialize)]
struct Symbol {
    #[serde(flatten)]
    names: crate::cpp_names::Names,
    name: String,
    elf_address: String,
    size: u64,
    kind: String,
    binding: &'static str,
    visibility: &'static str,
    elf_type: u8,
    sources: Vec<Source>,
}

#[derive(Clone, Serialize)]
struct Match {
    module: ModuleIdentity,
    instance: String,
    load_bias: String,
    runtime_address: String,
    module_offset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol_override: Option<OverrideRule>,
    #[serde(flatten)]
    symbol: Symbol,
}

fn symbol_record<'a>(sym: impl ObjectSymbol<'a>, name: &str, source: Source) -> Symbol {
    let (elf_type, binding, visibility) = match sym.flags() {
        SymbolFlags::Elf { st_info, st_other } => {
            let binding = match st_info.0 >> 4 {
                0 => "local",
                1 => "global",
                2 => "weak",
                10 => "gnu_unique",
                _ => "other",
            };
            let visibility = match st_other.0 & 3 {
                0 => "default",
                1 => "internal",
                2 => "hidden",
                _ => "protected",
            };
            (st_info.0 & 15, binding, visibility)
        }
        _ => (0, "other", "other"),
    };
    Symbol {
        names: crate::cpp_names::names(name),
        name: name.to_owned(),
        elf_address: hex(sym.address()),
        size: sym.size(),
        kind: format!("{:?}", sym.kind()).to_ascii_lowercase(),
        binding,
        visibility,
        elf_type,
        sources: vec![source],
    }
}

fn has_elf_address<'a>(symbol: &impl ObjectSymbol<'a>) -> bool {
    symbol.is_definition()
        || (symbol.section_index().is_some()
            && matches!(symbol.flags(), SymbolFlags::Elf { st_info, .. }
                if st_info.0 & 15 == object::elf::STT_GNU_IFUNC.0))
}

fn symbol_entries<'a>(
    image: &'a object::File<'a>,
    debug: Option<&'a object::File<'a>>,
) -> impl Iterator<Item = (object::Symbol<'a, 'a>, &'static str, bool)> + 'a {
    image
        .symbols()
        .map(|s| (s, ".symtab", false))
        .chain(image.dynamic_symbols().map(|s| (s, ".dynsym", false)))
        .chain(
            debug
                .into_iter()
                .flat_map(|obj| obj.symbols().map(|s| (s, ".symtab", true))),
        )
}

fn find_symbols(
    image: &object::File<'_>,
    debug: Option<&DebugFile>,
    matches: impl Fn(&str) -> bool,
    limit: usize,
) -> (BTreeMap<(u64, String, u8), Symbol>, bool) {
    let parsed = debug.and_then(DebugFile::parse);
    let mut results: BTreeMap<_, Symbol> = BTreeMap::new();
    let debug_path = debug.map(DebugFile::display_path);
    let mut truncated = false;
    for (sym, table, external) in symbol_entries(image, parsed.as_ref()) {
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() || !matches(name) || !has_elf_address(&sym) {
            continue;
        }
        let address = sym.address();
        let row = symbol_record(
            sym,
            name,
            Source {
                table,
                debug_file: if external { debug_path.clone() } else { None },
            },
        );
        let key = (address, row.name.clone(), row.elf_type);
        if let Some(existing) = results.get_mut(&key) {
            for source in row.sources {
                if !existing.sources.contains(&source) {
                    existing.sources.push(source);
                }
            }
        } else if results.len() < limit {
            results.insert(key, row);
        } else {
            truncated = true;
        }
    }
    (results, truncated)
}

enum Matcher<'a> {
    Exact(&'a str),
    Glob(glob::Pattern),
    Regex(regex::Regex),
}

impl<'a> Matcher<'a> {
    fn new(mode: SymbolMatch, pattern: &'a str) -> Result<Self> {
        if pattern.is_empty() || pattern.len() > 1024 {
            return Err(error("symbol pattern must contain 1–1024 bytes"));
        }
        Ok(match mode {
            SymbolMatch::Exact => Self::Exact(pattern),
            SymbolMatch::Glob => Self::Glob(glob::Pattern::new(pattern)?),
            SymbolMatch::Regex => Self::Regex(
                regex::RegexBuilder::new(pattern)
                    .size_limit(1024 * 1024)
                    .build()?,
            ),
        })
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(pattern) => name == *pattern,
            Self::Glob(pattern) => pattern.matches(name),
            Self::Regex(pattern) => pattern.is_match(name),
        }
    }
}

pub(crate) fn validate_search(request: &crate::rpc::SearchSymbolsRequest) -> Result<()> {
    if !(1..=MAX_RESULTS).contains(&request.limit.unwrap_or(256)) {
        return Err(error("symbol result limit must be in 1..=4096"));
    }
    Matcher::new(SymbolMatch::try_from(request.match_mode)?, &request.pattern)?;
    Ok(())
}

pub(crate) fn search_core(
    image: &object::File<'_>,
    debug: Option<&DebugFile>,
    bias: i128,
    module: &Module,
    request: &crate::rpc::SearchSymbolsRequest,
) -> Result<Search> {
    let limit = request.limit.unwrap_or(256);
    let mode = SymbolMatch::try_from(request.match_mode)?;
    let matcher = Matcher::new(mode, &request.pattern)?;
    let mut result = Search {
        matches: Vec::new(),
        truncated: false,
        issues: Vec::new(),
    };
    let build_id = image.build_id()?;
    if request
        .module
        .as_deref()
        .is_some_and(|filter| !module_matches(module, filter, build_id))
    {
        return Ok(result);
    }
    let (symbols, truncated) =
        find_symbols(image, debug, |name| matcher.matches(name), limit as usize);
    let base = image
        .segments()
        .map(|segment| segment.address())
        .min()
        .unwrap_or(0);
    let identity = module.identity(build_id);
    result.truncated = truncated;
    result
        .matches
        .extend(symbols.into_iter().filter_map(|((link, _, _), symbol)| {
            let runtime = u64::try_from(bias + i128::from(link)).ok()?;
            Some(Match {
                module: identity.clone(),
                instance: hex(u64::try_from(bias + i128::from(base)).ok()?),
                load_bias: signed_hex(bias),
                runtime_address: hex(runtime),
                module_offset: hex(link.checked_sub(base)?),
                symbol,
                symbol_override: None,
            })
        }));
    Ok(result)
}

#[derive(Serialize)]
struct SearchIssue {
    module: ModuleIdentity,
    error: String,
}

#[derive(Default, Serialize)]
pub struct Search {
    matches: Vec<Match>,
    truncated: bool,
    issues: Vec<SearchIssue>,
}

impl Search {
    pub(crate) fn merge(&mut self, other: Self, limit: usize) {
        let available = limit - self.matches.len();
        self.truncated |= other.truncated || other.matches.len() > available;
        self.matches
            .extend(other.matches.into_iter().take(available));
        self.issues.extend(other.issues);
    }
}

pub fn search(
    pid: i32,
    pattern: &str,
    mode: SymbolMatch,
    filter: Option<&str>,
    limit: u32,
    overrides: &[OverrideRule],
) -> Result<Search> {
    if !(1..=MAX_RESULTS).contains(&limit) {
        return Err(error("symbol result limit must be in 1..=4096"));
    }
    let matcher = Matcher::new(mode, pattern)?;
    let process = Process::open(pid)?;
    let start_ticks = crate::procfs::start_ticks(&process.root).ok();
    let mut results = Search {
        matches: Vec::new(),
        truncated: false,
        issues: Vec::new(),
    };
    for module in &process.modules {
        if filter.is_some_and(|f| !path_matches(module, f) && !may_be_build_id(f)) {
            continue;
        }
        let bytes = match module.read_image(&process.root, process.exe.as_ref(), IMAGE_LIMIT) {
            Ok(bytes) => bytes,
            Err(e) => {
                if filter.is_none_or(|f| path_matches(module, f)) {
                    results.issues.push(SearchIssue {
                        module: module.identity(None),
                        error: e.to_string(),
                    });
                }
                continue;
            }
        };
        let Ok(image) = object::File::parse(&*bytes) else {
            continue;
        };
        if !modules::is_executable_module(&image) {
            continue;
        }
        let build_id = image.build_id().ok().flatten();
        if filter.is_some_and(|f| !module_matches(module, f, build_id)) {
            continue;
        }
        let layout = Layout::new(&image, module)?;
        if layout.instances.is_empty() {
            results.issues.push(SearchIssue {
                module: module.identity(build_id),
                error: "could not match ELF load segments to executable mappings".into(),
            });
            continue;
        }
        let identity = module.identity(build_id);
        let debug = DebugFile::discover(&process.root, module, &image);
        let (symbols, truncated) = find_symbols(
            &image,
            debug.as_ref(),
            |name| matcher.matches(name),
            limit as usize + 1,
        );
        results.truncated |= truncated;
        for instance in &layout.instances {
            for rule in overrides.iter().filter(|rule| {
                matcher.matches(rule.name())
                    && rule.matches(pid, start_ticks, &identity, instance.base)
            }) {
                let Some(link) = layout.elf_base.checked_add(rule.offset()) else {
                    continue;
                };
                let Some(runtime) = layout.runtime(*instance, link, module, &process.anonymous)
                else {
                    continue;
                };
                if results.matches.len() == limit as usize {
                    results.truncated = true;
                    return Ok(results);
                }
                results.matches.push(Match {
                    module: identity.clone(),
                    instance: hex(instance.base),
                    load_bias: signed_hex(instance.bias),
                    runtime_address: hex(runtime),
                    module_offset: hex(rule.offset()),
                    symbol: rule.symbol(link, module.executable_at(runtime).is_some()),
                    symbol_override: Some(rule.clone()),
                });
            }
            for ((elf_address, _, _), symbol) in &symbols {
                let Some(runtime) =
                    layout.runtime(*instance, *elf_address, module, &process.anonymous)
                else {
                    continue;
                };
                if results.matches.len() == limit as usize {
                    results.truncated = true;
                    return Ok(results);
                }
                results.matches.push(Match {
                    module: identity.clone(),
                    instance: hex(instance.base),
                    load_bias: signed_hex(instance.bias),
                    runtime_address: hex(runtime),
                    module_offset: hex(elf_address - layout.elf_base),
                    symbol: symbol.clone(),
                    symbol_override: None,
                });
            }
        }
    }
    Ok(results)
}

pub(crate) struct BreakpointSite {
    pub address: u64,
    pub size: u64,
    pub(crate) build_id: Option<String>,
    pub(crate) symbols: Vec<String>,
    backing: Backing,
    file_offset: u64,
}

impl BreakpointSite {
    pub fn still_mapped(&self, root: &Path) -> Result<bool> {
        Ok(modules::read(root)?.iter().any(|module| {
            module.backing == self.backing
                && module
                    .executable_at(self.address)
                    .is_some_and(|map| map.file_offset(self.address) == Some(self.file_offset))
        }))
    }
}

pub(crate) fn unique_breakpoint_location(
    pid: i32,
    root: &Path,
    module: Option<&str>,
    symbol: &str,
    instance: Option<u64>,
    offset: u64,
    execution: bool,
    overrides: &[OverrideRule],
) -> Result<(u64, Option<BreakpointSite>)> {
    let report = search(
        pid,
        symbol,
        SymbolMatch::Exact,
        module,
        MAX_RESULTS,
        overrides,
    )?;
    let parse = |value: &str| u64::from_str_radix(value.trim_start_matches("0x"), 16);
    let mut matches = report.matches.iter().filter(|item| {
        instance.is_none_or(|base| parse(&item.instance).ok() == Some(base))
            && (!execution || item.symbol.kind == "text")
    });
    let first = matches.next();
    if report.truncated || matches.next().is_some() {
        return Err(Diagnostic::new(
            "AMBIGUOUS_SYMBOL",
            format!("symbol {symbol} is ambiguous across loaded locations"),
            Some("Specify module or instance."),
        )
        .into());
    }
    let found = first.ok_or_else(|| {
        Diagnostic::new(
            "SYMBOL_NOT_FOUND",
            format!("symbol {symbol} is unavailable"),
            None,
        )
    })?;
    let invalid = || {
        Diagnostic::new(
            "INVALID_ARGUMENT",
            "symbol address plus offset overflows",
            None,
        )
    };
    let address = if offset == 0 {
        parse(&found.runtime_address)?
    } else {
        let offset = parse(&found.module_offset)?
            .checked_add(offset)
            .ok_or_else(invalid)?;
        resolve_module_offset(
            root,
            &found.module.path,
            offset,
            execution,
            Some(parse(&found.instance)?),
        )?
    };
    if !execution {
        return Ok((address, None));
    }
    let (backing, mapping) = modules::map_entries(root)?
        .into_iter()
        .find(|(_, mapping)| mapping.contains(address) && mapping.executable())
        .ok_or_else(|| error("symbol is outside executable mappings"))?;
    let file_offset = mapping
        .file_offset(address)
        .ok_or_else(|| error("invalid symbol mapping offset"))?;
    Ok((
        address,
        Some(BreakpointSite {
            address,
            size: found.symbol.size,
            build_id: found.module.build_id.clone(),
            symbols: vec![found.symbol.name.clone()],
            backing,
            file_offset,
        }),
    ))
}

pub(crate) fn breakpoint_site_matching(
    root: &Path,
    filter: &str,
    base: Option<u64>,
    matches: impl Fn(&str) -> bool,
) -> Result<BreakpointSite> {
    if filter.len() > 4096 {
        return Err(error("module or symbol name exceeds length limit"));
    }
    let exe = fs::metadata(root.join("exe")).ok();
    let mut found = None;
    for module in modules::read(root)? {
        if !path_matches(&module, filter) && !may_be_build_id(filter) {
            continue;
        }
        let bytes = match module.read_image(root, exe.as_ref(), IMAGE_LIMIT) {
            Ok(bytes) => bytes,
            Err(e) if path_matches(&module, filter) => return Err(e),
            Err(_) => continue,
        };
        let Ok(image) = object::File::parse(&*bytes) else {
            continue;
        };
        if !modules::is_executable_module(&image)
            || !module_matches(&module, filter, image.build_id().ok().flatten())
        {
            continue;
        }
        let layout = Layout::new(&image, &module)?;
        let debug = DebugFile::discover(root, &module, &image);
        let parsed = debug.as_ref().and_then(DebugFile::parse);
        let mut addresses = BTreeMap::<u64, (u64, Vec<String>)>::new();
        for (symbol, _, _) in symbol_entries(&image, parsed.as_ref()) {
            if symbol.kind() == SymbolKind::Text
                && has_elf_address(&symbol)
                && let Ok(name) = symbol.name()
                && matches(name)
            {
                let (size, names) = addresses.entry(symbol.address()).or_default();
                *size = (*size).max(symbol.size());
                if !names.iter().any(|existing| existing == name) {
                    names.push(name.to_owned());
                }
            }
        }
        for &instance in layout
            .instances
            .iter()
            .filter(|i| base.is_none_or(|base| i.base == base))
        {
            for (&elf_address, (size, symbols)) in &addresses {
                let Some(address) = layout.runtime(instance, elf_address, &module, &[]) else {
                    continue;
                };
                let Some(map) = module.executable_at(address) else {
                    continue;
                };
                let file_offset = map
                    .file_offset(address)
                    .ok_or_else(|| error("invalid map offset"))?;
                if found.is_some() {
                    return Err(error(
                        "ambiguous module or symbol; specify a full module path and load instance",
                    ));
                }
                found = Some(BreakpointSite {
                    address,
                    size: *size,
                    build_id: image.build_id()?.map(id_hex),
                    symbols: symbols.clone(),
                    backing: module.backing.clone(),
                    file_offset,
                });
            }
        }
    }
    found.ok_or_else(|| error("executable symbol not found in a loaded module instance"))
}

#[derive(Serialize)]
pub(crate) struct Line {
    pub(crate) file: PathBuf,
    pub(crate) line: Option<u64>,
    pub(crate) column: Option<u64>,
    source: Option<String>,
}

fn line_sections<'a>(obj: &object::File<'a>) -> Result<DwarfSections<Cow<'a, [u8]>>> {
    let mut total = 0;
    DwarfSections::load(|id: gimli::SectionId| -> Result<_> {
        let Some(section) = obj.section_by_name(id.name()) else {
            return Ok(std::borrow::Cow::Borrowed(&[][..]));
        };
        let length = section.compressed_data()?.uncompressed_size;
        if length > DEBUG_LIMIT - total {
            return Err(error("DWARF decompression exceeds byte limit"));
        }
        total += length;
        Ok(section.uncompressed_data()?)
    })
}

pub(crate) fn dwarf_line(obj: &object::File<'_>, pc: u64) -> Result<Option<Line>> {
    let sections = line_sections(obj)?;
    let dwarf = sections.borrow(|s| EndianSlice::new(s, LittleEndian));
    line_for_pc(&dwarf, pc)
}

type LineReader<'a> = EndianSlice<'a, LittleEndian>;

fn source_path(
    dwarf: &gimli::Dwarf<LineReader<'_>>,
    unit: &gimli::Unit<LineReader<'_>>,
    header: &gimli::LineProgramHeader<LineReader<'_>>,
    file: &gimli::FileEntry<LineReader<'_>>,
) -> Result<PathBuf> {
    let mut path = PathBuf::new();
    if let Some(dir) = &unit.comp_dir {
        path.push(dir.to_string_lossy().as_ref());
    }
    if let Some(dir) = file.directory(header) {
        path.push(dwarf.attr_string(unit, dir)?.to_string_lossy().as_ref());
    }
    path.push(
        dwarf
            .attr_string(unit, file.path_name())?
            .to_string_lossy()
            .as_ref(),
    );
    Ok(path)
}

fn source_addresses(
    obj: &object::File<'_>,
    wanted: &Path,
    line: u64,
) -> Result<(BTreeSet<u64>, BTreeSet<u64>)> {
    let sections = line_sections(obj)?;
    let dwarf = sections.borrow(|s| EndianSlice::new(s, LittleEndian));
    let mut units = dwarf.units();
    let mut statements = BTreeSet::new();
    let mut declarations = BTreeSet::new();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let Some(program) = unit.line_program.clone() else {
            continue;
        };
        let header = program.header();
        let files = header
            .file_names()
            .iter()
            .enumerate()
            .filter_map(|(i, _)| {
                let index = i as u64 + u64::from(header.version() < 5);
                header.file(index).map(|file| (index, file))
            })
            .map(|(index, file)| Ok((index, source_path(&dwarf, &unit, header, file)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let matches = |index: u64| files.get(&index).is_some_and(|path| path.ends_with(wanted));
        if !files.values().any(|path| path.ends_with(wanted)) {
            continue;
        }
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs()? {
            if entry.tag() == gimli::DW_TAG_subprogram
                && matches!(entry.attr_value(gimli::DW_AT_decl_file), Some(gimli::AttributeValue::FileIndex(index)) if matches(index))
                && entry
                    .attr_value(gimli::DW_AT_decl_line)
                    .and_then(|value| value.udata_value())
                    == Some(line)
                && let Some(gimli::AttributeValue::Addr(address)) =
                    entry.attr_value(gimli::DW_AT_low_pc)
            {
                declarations.insert(address);
            }
        }
        let mut rows = program.rows();
        while let Some((_, row)) = rows.next_row()? {
            if !row.end_sequence()
                && row.is_stmt()
                && row.line().map(|n| n.get()) == Some(line)
                && matches(row.file_index())
            {
                statements.insert(row.address());
            }
        }
    }
    Ok((statements, declarations))
}

pub(crate) fn breakpoint_line(
    root: &Path,
    file: &Path,
    line: u64,
    filter: Option<&str>,
    base: Option<u64>,
) -> Result<BreakpointSite> {
    let unavailable = |message| -> Box<dyn std::error::Error + Send + Sync> {
        Diagnostic::new(
            "LINE_UNAVAILABLE",
            message,
            Some("Use an executable source line, a fuller path, or select a module instance."),
        )
        .into()
    };
    if file.as_os_str().len() > 4096 || filter.is_some_and(|filter| filter.len() > 4096) {
        return Err(unavailable("source path or module exceeds length limit"));
    }
    let exe = fs::metadata(root.join("exe")).ok();
    let mut statements = BTreeMap::new();
    let mut declarations = BTreeMap::new();
    for module in modules::read(root)? {
        if filter.is_some_and(|f| !path_matches(&module, f) && !may_be_build_id(f)) {
            continue;
        }
        let Ok(bytes) = module.read_image(root, exe.as_ref(), IMAGE_LIMIT) else {
            continue;
        };
        let Ok(image) = object::File::parse(&*bytes) else {
            continue;
        };
        let build_id = image.build_id()?;
        if !modules::is_executable_module(&image)
            || filter.is_some_and(|f| !module_matches(&module, f, build_id))
        {
            continue;
        }
        let layout = Layout::new(&image, &module)?;
        let debug = DebugFile::discover(root, &module, &image);
        let parsed = debug.as_ref().and_then(DebugFile::parse);
        let Ok((lines, functions)) =
            source_addresses(parsed.as_ref().unwrap_or(&image), file, line)
        else {
            continue;
        };
        for &instance in layout
            .instances
            .iter()
            .filter(|i| base.is_none_or(|base| i.base == base))
        {
            for (offsets, candidates) in
                [(&lines, &mut statements), (&functions, &mut declarations)]
            {
                for &offset in offsets {
                    let Some(address) = layout.runtime(instance, offset, &module, &[]) else {
                        continue;
                    };
                    let Some(file_offset) = module
                        .executable_at(address)
                        .and_then(|map| map.file_offset(address))
                    else {
                        continue;
                    };
                    candidates.insert(
                        address,
                        BreakpointSite {
                            address,
                            size: 0,
                            build_id: build_id.map(id_hex),
                            symbols: Vec::new(),
                            backing: module.backing.clone(),
                            file_offset,
                        },
                    );
                }
            }
        }
    }
    let candidates = if statements.is_empty() {
        declarations
    } else {
        statements
    };
    match candidates.len() {
        1 => Ok(candidates.into_values().next().unwrap()),
        0 => Err(unavailable("source line has no executable address")),
        _ => Err(unavailable(
            "source line resolves to multiple executable addresses",
        )),
    }
}

pub(crate) fn line_for_pc(
    dwarf: &gimli::Dwarf<gimli::EndianSlice<'_, LittleEndian>>,
    pc: u64,
) -> Result<Option<Line>> {
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let Some(program) = unit.line_program.clone() else {
            continue;
        };
        let mut ranges = dwarf.unit_ranges(&unit)?;
        let mut contains = false;
        let mut had_ranges = false;
        while let Some(range) = ranges.next()? {
            had_ranges = true;
            if (range.begin..range.end).contains(&pc) {
                contains = true;
                break;
            }
        }
        if had_ranges && !contains {
            continue;
        }
        let (program, sequences) = program.sequences()?;
        for sequence in sequences.iter().filter(|s| (s.start..s.end).contains(&pc)) {
            let mut rows = program.resume_from(sequence);
            let mut line = None;
            while let Some((header, row)) = rows.next_row()? {
                if row.end_sequence() || row.address() > pc {
                    break;
                }
                let Some(file) = row.file(header) else {
                    continue;
                };
                line = Some(Line {
                    file: source_path(dwarf, &unit, header, file)?,
                    line: row.line().map(|n| n.get()),
                    column: match row.column() {
                        ColumnType::LeftEdge => None,
                        ColumnType::Column(n) => Some(n.get()),
                    },
                    source: None,
                });
            }
            if line.is_some() {
                return Ok(line);
            }
        }
    }
    Ok(None)
}

#[derive(Serialize)]
pub struct ResolvedAddress {
    runtime_address: String,
    module: Option<ModuleIdentity>,
    instance: Option<String>,
    elf_address: Option<String>,
    module_offset: Option<String>,
    file_offset: Option<String>,
    display: Option<String>,
    symbol: Option<Symbol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol_override: Option<OverrideRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_symbol: Option<Symbol>,
    source_line: Option<Line>,
    issues: Vec<String>,
}

impl ResolvedAddress {
    pub(crate) fn replay_location(&self) -> serde_json::Value {
        serde_json::json!({
            "module": self.module,
            "module_offset": self.module_offset,
        })
    }
}

pub(crate) fn resolve_module_offset(
    root: &Path,
    filter: &str,
    offset: u64,
    execution: bool,
    base: Option<u64>,
) -> Result<u64> {
    let exe = fs::metadata(root.join("exe")).ok();
    let space = modules::address_space(root)?;
    let mut addresses = BTreeSet::new();
    for module in &space.modules {
        if !path_matches(module, filter) && !may_be_build_id(filter) {
            continue;
        }
        let Ok(bytes) = module.read_image(root, exe.as_ref(), IMAGE_LIMIT) else {
            continue;
        };
        let Ok(image) = object::File::parse(&*bytes) else {
            continue;
        };
        if !modules::is_executable_module(&image)
            || !module_matches(module, filter, image.build_id()?)
        {
            continue;
        }
        let layout = Layout::new(&image, module)?;
        let Some(link) = layout.elf_base.checked_add(offset) else {
            continue;
        };
        for instance in layout
            .instances
            .iter()
            .copied()
            .filter(|instance| base.is_none_or(|base| instance.base == base))
        {
            if let Some(address) = layout.runtime(instance, link, module, &space.anonymous)
                && (!execution || module.executable_at(address).is_some())
            {
                addresses.insert(address);
            }
        }
    }
    if addresses.len() == 1 {
        return Ok(addresses.into_iter().next().unwrap());
    }
    Err(Diagnostic::new(
        "MODULE_OFFSET_UNAVAILABLE",
        if addresses.is_empty() {
            "Module offset is not mapped"
        } else {
            "Module offset matches multiple load instances"
        },
        Some("Use a target with one matching module instance."),
    )
    .into())
}

pub(crate) fn symbol_module_offset(
    pid: i32,
    module: &str,
    symbol: &str,
    base: Option<u64>,
    offset: u64,
) -> Result<(u64, u64)> {
    let found = search(
        pid,
        symbol,
        SymbolMatch::Exact,
        Some(module),
        MAX_RESULTS,
        &[],
    )?;
    let parse = |hex: &str| u64::from_str_radix(hex.trim_start_matches("0x"), 16);
    let sites = found
        .matches
        .iter()
        .filter_map(|item| {
            let instance = parse(&item.instance).ok()?;
            let address = parse(&item.module_offset).ok()?.checked_add(offset)?;
            base.is_none_or(|base| instance == base)
                .then_some((instance, address))
        })
        .collect::<BTreeSet<_>>();
    if found.truncated || sites.len() != 1 {
        return Err(Diagnostic::new(
            "SYMBOL_OFFSET_UNAVAILABLE",
            "Symbol and offset must identify one loaded address",
            Some("Use an exact module path or build ID and a load instance."),
        )
        .into());
    }
    Ok(sites.into_iter().next().unwrap())
}

impl ResolvedAddress {
    pub(crate) fn symbol_location(&self) -> Option<serde_json::Value> {
        let symbol = self.symbol.as_ref()?;
        let parse = |address: &str| u64::from_str_radix(address.trim_start_matches("0x"), 16).ok();
        let offset =
            parse(self.elf_address.as_deref()?)?.checked_sub(parse(&symbol.elf_address)?)?;
        Some(serde_json::json!({
            "address": self.runtime_address,
            "name": symbol.name,
            "offset": offset,
            "display": self.display,
            "module": self.module,
        }))
    }

    pub(crate) fn stop_site(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.runtime_address,
            "symbol": self.symbol_location(),
            "function": self.symbol.as_ref().map(|symbol| {
                symbol.names.demangled_name.as_ref().unwrap_or(&symbol.names.display_name)
            }),
            "source_line": self.source_line,
        })
    }
}

pub fn resolve(pid: i32, address: u64, overrides: &[OverrideRule]) -> Result<ResolvedAddress> {
    let process = Process::open(pid)?;
    let mut result = ResolvedAddress {
        runtime_address: hex(address),
        module: None,
        instance: None,
        elf_address: None,
        module_offset: None,
        file_offset: None,
        display: None,
        symbol: None,
        symbol_override: None,
        original_symbol: None,
        source_line: None,
        issues: Vec::new(),
    };
    let file_mapping = process
        .modules
        .iter()
        .find_map(|module| module.mapping_at(address).map(|map| (module, map)));
    let anonymous_mapping = || {
        let map = process.anonymous.iter().find(|map| map.contains(address))?;
        let module = process
            .modules
            .iter()
            .find(|module| module.maps.iter().any(|file_map| file_map.end == map.start))?;
        Some((module, map))
    };
    let Some((module, map)) = file_mapping.or_else(anonymous_mapping) else {
        return Ok(result);
    };
    let name = module
        .path()
        .file_name()
        .map(OsStr::to_string_lossy)
        .unwrap_or_default()
        .into_owned();
    if file_mapping.is_some() {
        result.module = Some(module.identity(None));
        if let Some(offset) = map.file_offset(address) {
            result.display = Some(format!("{name}+{} (file offset)", hex(offset)));
            result.file_offset = Some(hex(offset));
        }
    }
    let bytes = match module.read_image(&process.root, process.exe.as_ref(), IMAGE_LIMIT) {
        Ok(bytes) => bytes,
        Err(e) => {
            result.issues.push(e.to_string());
            return Ok(result);
        }
    };
    let image = match object::File::parse(&*bytes) {
        Ok(image) if modules::is_executable_module(&image) => image,
        Ok(_) => return Ok(result),
        Err(e) => {
            result.issues.push(e.to_string());
            return Ok(result);
        }
    };
    let layout = Layout::new(&image, module)?;
    let relocated = if file_mapping.is_some() {
        layout.for_address(map, address)
    } else {
        layout.zerofill_address(map, address, module)
    };
    let Some((instance, link)) = relocated else {
        if file_mapping.is_some() {
            result
                .issues
                .push("address does not match a loaded ELF segment".into());
        }
        return Ok(result);
    };
    result.module = Some(module.identity(image.build_id().ok().flatten()));
    result.instance = Some(hex(instance.base));
    result.elf_address = Some(hex(link));
    result.module_offset = Some(hex(link - layout.elf_base));
    result.display = Some(format!("{name}+{}", hex(link - layout.elf_base)));
    let debug = DebugFile::discover(&process.root, module, &image);
    let debug_image = debug.as_ref().and_then(DebugFile::parse);
    let is_exec = map.executable();
    let mut best = None;
    for (sym, table, external) in symbol_entries(&image, debug_image.as_ref()) {
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() || !has_elf_address(&sym) || (is_exec && sym.kind() != SymbolKind::Text)
        {
            continue;
        }
        let Some(delta) = link.checked_sub(sym.address()) else {
            continue;
        };
        if delta >= sym.size().max(1) {
            continue;
        }
        if best.is_none_or(|best| delta < best) {
            best = Some(delta);
            result.display = Some(if delta == 0 {
                name.into()
            } else {
                format!("{name}+{}", hex(delta))
            });
            result.symbol = Some(symbol_record(
                sym,
                name,
                Source {
                    table,
                    debug_file: external
                        .then(|| debug.as_ref().expect("parsed debug image").display_path()),
                },
            ));
        }
    }
    if let (Some(file), Some(obj)) = (debug.as_ref(), debug_image.as_ref()) {
        match dwarf_line(obj, link) {
            Ok(line) => {
                result.source_line = line.map(|mut line| {
                    line.source = Some(file.display_path());
                    line
                })
            }
            Err(e) => result.issues.push(e.to_string()),
        }
    }
    if result.source_line.is_none() {
        match dwarf_line(&image, link) {
            Ok(line) => result.source_line = line,
            Err(e) => result.issues.push(e.to_string()),
        }
    }
    if !overrides.is_empty() {
        let offset = link - layout.elf_base;
        let identity = result.module.as_ref().expect("resolved module identity");
        let start_ticks = crate::procfs::start_ticks(&process.root).ok();
        if let Some(rule) = overrides.iter().find(|rule| {
            rule.covers(offset) && rule.matches(pid, start_ticks, identity, instance.base)
        }) {
            let delta = offset - rule.offset();
            result.original_symbol = result.symbol.take();
            result.symbol = Some(rule.symbol(link - delta, is_exec));
            result.symbol_override = Some(rule.clone());
            result.display = Some(if delta == 0 {
                rule.name().into()
            } else {
                format!("{}+{}", rule.name(), hex(delta))
            });
        }
    }
    Ok(result)
}

pub(crate) fn code_start(root: &Path, address: u64) -> Option<u64> {
    let exe = fs::metadata(root.join("exe")).ok();
    let modules = modules::read(root).ok()?;
    let (module, map) = modules
        .iter()
        .find_map(|m| m.executable_at(address).map(|map| (m, map)))?;
    let bytes = module.read_image(root, exe.as_ref(), IMAGE_LIMIT).ok()?;
    let image = object::File::parse(&*bytes).ok()?;
    let layout = Layout::new(&image, module).ok()?;
    let (instance, link) = layout.for_address(map, address)?;
    let find = |obj: &object::File<'_>| {
        obj.symbols()
            .chain(obj.dynamic_symbols())
            .filter(|sym| sym.kind() == SymbolKind::Text && has_elf_address(sym))
            .filter(|sym| {
                link.checked_sub(sym.address())
                    .is_some_and(|delta| delta < sym.size().max(1))
            })
            .map(|sym| sym.address())
            .max()
    };
    let entry = find(&image).or_else(|| {
        let debug = DebugFile::discover(root, module, &image)?;
        find(&debug.parse()?)
    })?;
    let runtime = instance.relocate(entry)?;
    map.contains(runtime).then_some(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_and_verifies_build_id_debug_files() -> Result<()> {
        let path = std::env::current_exe()?;
        let bytes = fs::read(&path)?;
        let image = object::File::parse(&*bytes)?;
        let id = image
            .build_id()?
            .ok_or_else(|| error("test executable lacks a build ID"))?;
        let module = modules::read(Path::new("/proc/self"))?
            .into_iter()
            .find(|module| module.path() == path)
            .ok_or_else(|| error("test executable is missing from proc maps"))?;
        let root = tempfile::tempdir()?;
        let hex = id_hex(id);
        let candidate = PathBuf::from(format!(
            "usr/lib/debug/.build-id/{}/{}.debug",
            &hex[..2],
            &hex[2..]
        ));
        let file = root.path().join("root").join(&candidate);
        fs::create_dir_all(file.parent().expect("debug file directory"))?;

        let note = image
            .section_by_name(".note.gnu.build-id")
            .expect("GNU build ID note");
        let (offset, _) = note.file_range().expect("build ID note file offset");
        let position = note
            .data()?
            .windows(id.len())
            .position(|window| window == id)
            .expect("build ID in GNU note");
        let discover = || {
            find_external_debug(
                Some(&root.path().join("root")),
                &module.path(),
                &image,
                bytes.len() as u64,
            )
        };
        let mut mismatch = bytes.clone();
        mismatch[usize::try_from(offset)? + position] ^= 1;
        fs::write(&file, &mismatch)?;
        assert!(discover().is_none());
        drop(mismatch);

        fs::write(&file, &bytes)?;
        let (found_path, found) =
            discover().ok_or_else(|| error("verified debug file was not discovered"))?;
        assert_eq!(found_path, Path::new("/").join(candidate));
        assert_eq!(object::File::parse(&*found)?.build_id()?, Some(id));
        Ok(())
    }
}
