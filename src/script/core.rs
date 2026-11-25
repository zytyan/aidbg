mod images;
pub(super) mod memory;

use super::CoreSymbols;
use crate::{
    Diagnostic, Result,
    coredump::{Coverage, ExecutableMetadata, Missing},
    error, hex,
    modules::{Backing, Mapping, Module},
    regs::{self, Registers},
    symbols::inspect::offline::{DwarfImage, Validation},
    unwind::{MissingMemory, OfflineFrame, OfflineImage, UnwindMemory, offline_frames},
};
use object::{Object, ObjectSection, ObjectSegment, elf};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::Path,
    sync::{Mutex, OnceLock},
    time::Instant,
};

const MAX_CORE: u64 = 32 * 1024 * 1024 * 1024;
const MAX_IMAGE: u64 = 128 * 1024 * 1024;
const MAX_NOTES: u64 = 64 * 1024 * 1024;

#[derive(Serialize)]
pub struct CoreInfo {
    pub target_id: String,
    pub architecture: &'static str,
    pub threads: usize,
    pub captured_bytes: String,
    pub mapped_bytes: String,
    pub symbol_match: &'static str,
    pub dwarf_available: bool,
    executable: Option<ExecutableMetadata>,
    missing_range_details: Vec<Missing>,
    pub warnings: Vec<Diagnostic>,
}

#[derive(Default, Deserialize)]
struct CoreMetadata {
    #[serde(default)]
    modules: Vec<Value>,
    #[serde(default)]
    coverage: Coverage,
    executable: Option<ExecutableMetadata>,
}

struct Segment {
    start: u64,
    end: u64,
    offset: u64,
    size: u64,
    executable: bool,
    flags: u32,
}

struct Thread {
    stop_signal: u16,
    regs: Registers,
    flags: u64,
    general: std::collections::BTreeMap<String, String>,
    fp: Option<Vec<u8>>,
    frames: OnceLock<Vec<OfflineFrame>>,
    frame_metadata: OnceLock<Vec<Value>>,
}

pub(super) struct Target {
    id: String,
    pid: Option<i32>,
    file: File,
    segments: Vec<Segment>,
    threads: BTreeMap<i32, Thread>,
    image: Option<OfflineImage>,
    dwarf: Option<DwarfImage>,
    architecture: &'static str,
    executable: Option<ExecutableMetadata>,
    debug_image: Option<crate::symbols::DebugFile>,
    modules: Vec<Value>,
    file_modules: Vec<Module>,
    file_page: u64,
    entry: Option<u64>,
    use_recorded_symbols: bool,
    shared_images: Mutex<images::SharedImages>,
    pub(super) warnings: Vec<Diagnostic>,
}

fn uint(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut word = [0; 8];
    word[..width].copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(word)
}

pub(super) fn decompress(source: impl Read) -> Result<File> {
    let mut decoder = zstd::stream::read::Decoder::new(source)?;
    decoder.window_log_max(27)?;
    let mut output = tempfile::tempfile()?;
    if io::copy(&mut decoder.take(MAX_CORE + 1), &mut output)? > MAX_CORE {
        return Err(error("uncompressed ELF core exceeds the size limit"));
    }
    Ok(output)
}

pub(super) fn open_path(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(error("expected a regular ELF core file"));
    }
    let mut magic = [0; 4];
    file.read_exact_at(&mut magic, 0)?;
    if magic == *b"\x7fELF" {
        Ok(file)
    } else {
        decompress(file)
    }
}

fn image_bytes(path: &Path) -> Result<Vec<u8>> {
    read_image_bytes(path, MAX_IMAGE)
}

fn read_image_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(error("expected a regular executable or debug symbol file"));
    }
    if metadata.len() > limit {
        return Err(error("ELF image exceeds the available byte budget"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(error(
            "executable or debug symbol file exceeds the size limit",
        ));
    }
    Ok(bytes)
}

fn load_debug_image(
    path: std::path::PathBuf,
    build_id: &[u8],
    architecture: object::Architecture,
    crc: Option<u32>,
) -> Result<crate::symbols::DebugFile> {
    let bytes = image_bytes(&path)?;
    let debug = object::File::parse(&*bytes)?;
    if debug.build_id()? != Some(build_id)
        || debug.architecture() != architecture
        || !debug.is_little_endian()
        || crc.is_some_and(|expected| crc32fast::hash(&bytes) != expected)
    {
        return Err(Diagnostic::new(
            "SYMBOL_ID_MISMATCH",
            "The debug symbol file does not match the executable build ID or debuglink checksum",
            None,
        )
        .into());
    }
    Ok(crate::symbols::DebugFile { path, bytes })
}

impl Target {
    pub fn open(
        id: String,
        file: File,
        symbols: CoreSymbols,
        use_recorded_symbols: bool,
    ) -> Result<(Self, CoreInfo)> {
        let file_len = file.metadata()?.len();
        let mut header = [0; 64];
        file.read_exact_at(&mut header, 0)?;
        if &header[..7] != b"\x7fELF\x02\x01\x01"
            || uint(&header, 16, 2) != u64::from(elf::ET_CORE.0)
        {
            return Err(error("expected a little-endian 64-bit ELF core"));
        }
        let machine = elf::Machine(uint(&header, 18, 2) as u16);
        let (architecture, object_arch) = match machine {
            elf::EM_X86_64 => ("x86_64", object::Architecture::X86_64),
            elf::EM_AARCH64 => ("aarch64", object::Architecture::Aarch64),
            _ => return Err(error("unsupported ELF core architecture")),
        };
        if architecture != regs::ARCH {
            return Err(error(format!(
                "open this {architecture} core with the {architecture} debugger"
            )));
        }
        let phoff = uint(&header, 32, 8);
        let phsize = uint(&header, 54, 2);
        let mut phnum = uint(&header, 56, 2);
        if phnum == u64::from(elf::PN_XNUM) {
            let mut sh0 = [0; 64];
            file.read_exact_at(&mut sh0, uint(&header, 40, 8))?;
            phnum = uint(&sh0, 44, 4);
        }
        if file_len > MAX_CORE
            || phsize != 56
            || phnum > 262_144
            || phoff
                .checked_add(phsize * phnum)
                .is_none_or(|end| end > file_len)
        {
            return Err(error("invalid or oversized ELF core program header table"));
        }
        let mut target = Self {
            id: id.clone(),
            pid: None,
            file,
            segments: Vec::new(),
            threads: BTreeMap::new(),
            image: None,
            dwarf: None,
            architecture,
            executable: None,
            debug_image: None,
            modules: Vec::new(),
            file_modules: Vec::new(),
            file_page: 4096,
            entry: None,
            use_recorded_symbols,
            shared_images: Mutex::default(),
            warnings: Vec::new(),
        };
        let mut entry = None;
        let mut metadata = None;
        let mut note_tid = None;
        let mut notes_remaining = MAX_NOTES;
        let mut headers = vec![0; (phsize * phnum) as usize];
        target.file.read_exact_at(&mut headers, phoff)?;
        for row in headers.chunks_exact(56) {
            let kind = elf::ProgramType(uint(row, 0, 4) as u32);
            let offset = uint(row, 8, 8);
            let size = uint(row, 32, 8);
            if size != 0 && offset.checked_add(size).is_none_or(|end| end > file_len) {
                return Err(error("truncated ELF core segment"));
            }
            match kind {
                elf::PT_LOAD => {
                    let start = uint(row, 16, 8);
                    let mapped = uint(row, 40, 8);
                    let end = start
                        .checked_add(mapped)
                        .ok_or_else(|| error("ELF core mapping overflows"))?;
                    if size > mapped {
                        return Err(error("ELF core segment exceeds its virtual mapping"));
                    }
                    if mapped != 0 {
                        target.segments.push(Segment {
                            start,
                            end,
                            offset,
                            size,
                            executable: uint(row, 4, 4) & 1 != 0,
                            flags: uint(row, 4, 4) as u32,
                        });
                    }
                }
                elf::PT_NOTE => {
                    notes_remaining = notes_remaining
                        .checked_sub(size)
                        .ok_or_else(|| error("ELF core notes exceed the size limit"))?;
                    let mut notes = vec![0; size as usize];
                    target.file.read_exact_at(&mut notes, offset)?;
                    target.read_notes(&notes, &mut entry, &mut metadata, &mut note_tid)?;
                }
                _ => {}
            }
        }
        target.segments.sort_unstable_by_key(|s| s.start);
        if target
            .segments
            .windows(2)
            .any(|pair| pair[0].end > pair[1].start)
        {
            return Err(error("ELF core contains overlapping memory mappings"));
        }
        if target.threads.is_empty() {
            return Err(error("ELF core has no NT_PRSTATUS thread registers"));
        }
        target.entry = entry;
        for module in &mut target.file_modules {
            for mapping in &mut module.maps {
                let first = target
                    .segments
                    .partition_point(|segment| segment.end <= mapping.start);
                if target.segments[first..]
                    .iter()
                    .take_while(|segment| segment.start < mapping.end)
                    .any(|segment| segment.executable)
                {
                    mapping.perms = "r-x".into();
                }
            }
        }
        let recorded_coverage = metadata.is_some();
        let mut metadata = metadata.unwrap_or_default();
        if !recorded_coverage {
            for segment in &target.segments {
                if segment.start + segment.size < segment.end {
                    metadata.coverage.missing(
                        segment.start + segment.size,
                        segment.end,
                        "not_stored",
                    );
                }
            }
        }
        if !metadata.modules.is_empty() {
            for mut item in metadata.modules {
                if let Some(original) = target
                    .modules
                    .iter_mut()
                    .find(|original| original["path"] == item["path"])
                {
                    item["mappings"] = original["mappings"].take();
                    *original = item;
                } else {
                    target.modules.push(item);
                }
            }
        }
        if use_recorded_symbols
            && metadata.executable.is_none()
            && let Some((module, _)) = entry.and_then(|entry| target.mapped_file(entry))
            && let Some(path) = module
                .path()
                .to_str()
                .filter(|path| Path::new(path).is_absolute())
        {
            let build_id = target
                .modules
                .iter()
                .find(|info| info["path"].as_str() == Some(path))
                .and_then(|info| info["build_id"].as_str())
                .map(str::to_owned);
            metadata.executable = Some(ExecutableMetadata {
                path: path.into(),
                build_id,
                debug_symbols: None,
            });
        }
        let mut warnings = metadata.coverage.warnings();
        let mut symbol_match = "not_provided";
        if let Some(path) = symbols.executable {
            target.load_symbols(
                path,
                symbols.debug_symbols,
                entry,
                object_arch,
                None,
                &mut warnings,
            )?;
            symbol_match = "matched";
        } else if use_recorded_symbols && let Some(executable) = &metadata.executable {
            match target.load_symbols(
                executable.path.clone(),
                symbols.debug_symbols.clone(),
                entry,
                object_arch,
                Some(executable),
                &mut warnings,
            ) {
                Ok(()) => symbol_match = "matched",
                Err(error) if symbols.debug_symbols.is_none() => {
                    symbol_match = "unavailable";
                    warnings.push(Diagnostic::new(
                        "EXECUTABLE_UNAVAILABLE",
                        error.to_string(),
                        Some("Supply a matching executable to core_open."),
                    ));
                }
                Err(error) => return Err(error),
            }
        } else if symbols.debug_symbols.is_some() {
            return Err(error(
                "a verified executable is required for separate debug symbols",
            ));
        }
        if target.dwarf.is_none() {
            warnings.push(Diagnostic::new(
                "NO_DWARF",
                "No verified DWARF image is available",
                Some("Open the core with a matching executable and debug symbols."),
            ));
        }
        target.warnings = warnings.clone();
        let info = CoreInfo {
            target_id: id,
            architecture,
            threads: target.threads.len(),
            captured_bytes: target
                .segments
                .iter()
                .map(|s| u128::from(s.size))
                .sum::<u128>()
                .to_string(),
            mapped_bytes: target
                .segments
                .iter()
                .map(|s| u128::from(s.end - s.start))
                .sum::<u128>()
                .to_string(),
            symbol_match,
            dwarf_available: target.dwarf.is_some(),
            executable: target.executable.clone().or(metadata.executable),
            missing_range_details: metadata.coverage.missing,
            warnings,
        };
        Ok((target, info))
    }

    fn load_symbols(
        &mut self,
        path: std::path::PathBuf,
        debug_symbols: Option<std::path::PathBuf>,
        entry: Option<u64>,
        object_arch: object::Architecture,
        recorded: Option<&ExecutableMetadata>,
        warnings: &mut Vec<Diagnostic>,
    ) -> Result<()> {
        let bytes = image_bytes(&path)?;
        let obj = object::File::parse(&*bytes)?;
        if obj.architecture() != object_arch
            || !obj.is_little_endian()
            || !crate::modules::is_executable_module(&obj)
        {
            return Err(error("executable ELF is incompatible with the core"));
        }
        let at_entry =
            entry.ok_or_else(|| error("core has no AT_ENTRY for executable verification"))?;
        let bias = at_entry
            .checked_sub(obj.entry())
            .ok_or_else(|| error("executable entry does not match the core"))?;
        let note = obj
            .section_by_name(".note.gnu.build-id")
            .filter(|note| note.address() != 0)
            .ok_or_else(|| error("executable has no mapped GNU build ID note"))?;
        let build_id = obj
            .build_id()?
            .ok_or_else(|| error("executable has no GNU build ID"))?;
        let build_id_hex = crate::modules::id_hex(build_id);
        let recorded_id = recorded.and_then(|image| image.build_id.as_deref());
        if recorded_id.is_some_and(|recorded| recorded != build_id_hex) {
            return Err(Diagnostic::new(
                "SYMBOL_ID_MISMATCH",
                "Executable GNU build ID does not match the saved core",
                None,
            )
            .into());
        }
        let note_address = bias
            .checked_add(note.address())
            .ok_or_else(|| error("build ID address overflow"))?;
        let expected = note.data()?;
        if expected.is_empty() || expected.len() > 4096 {
            return Err(error("invalid GNU build ID note length"));
        }
        let mut observed = vec![0; expected.len()];
        match self.read_at(note_address, &mut observed) {
            Ok(()) if observed == expected => {}
            Ok(()) => {
                return Err(Diagnostic::new(
                    "SYMBOL_ID_MISMATCH",
                    "Executable GNU build ID does not match the core",
                    None,
                )
                .into());
            }
            Err(error)
                if error.is::<MissingMemory>() && recorded_id == Some(build_id_hex.as_str()) =>
            {
                warnings.push(Diagnostic::new("BUILD_ID_FROM_CAPTURE", "Executable identity matched the capture metadata. The core does not contain the in-memory build ID note.", None));
            }
            Err(_) => {
                return Err(error(
                    "core does not contain the executable GNU build ID note",
                ));
            }
        }

        let mut dwarf = DwarfImage::load(&obj, bias, path.clone())?;
        let debug = if let Some(path) = debug_symbols {
            let debug = load_debug_image(path, build_id, object_arch, None)?;
            dwarf = DwarfImage::load(
                &object::File::parse(&*debug.bytes)?,
                bias,
                debug.path.clone(),
            )?;
            Some(debug)
        } else if dwarf.is_none() {
            let mut candidates = Vec::new();
            if let Some(path) = crate::symbols::installed_debug_symbols(&build_id_hex) {
                candidates.push((path, None));
            }
            if let Some((link, crc)) = obj.gnu_debuglink()? {
                candidates.extend(
                    crate::symbols::debuglink_paths(&path, link)
                        .into_iter()
                        .map(|path| (path, Some(crc))),
                );
            }
            let debug = candidates
                .into_iter()
                .find_map(|(path, crc)| load_debug_image(path, build_id, object_arch, crc).ok());
            if let Some(debug) = &debug {
                dwarf = DwarfImage::load(
                    &object::File::parse(&*debug.bytes)?,
                    bias,
                    debug.path.clone(),
                )?;
            }
            debug
        } else {
            None
        };
        self.image = Some(OfflineImage::new(bytes, bias)?);
        self.executable = Some(ExecutableMetadata {
            path,
            build_id: Some(build_id_hex),
            debug_symbols: debug.as_ref().map(|file| file.path.clone()),
        });
        self.dwarf = dwarf;
        self.debug_image = debug;
        Ok(())
    }

    fn read_notes(
        &mut self,
        mut notes: &[u8],
        entry: &mut Option<u64>,
        metadata: &mut Option<CoreMetadata>,
        note_tid: &mut Option<i32>,
    ) -> Result<()> {
        while notes.len() >= 12 {
            let name_len = uint(notes, 0, 4) as usize;
            let desc_len = uint(notes, 4, 4) as usize;
            let kind = elf::NoteType(uint(notes, 8, 4) as u32);
            let offset = 12 + name_len.next_multiple_of(4);
            let next = offset + desc_len.next_multiple_of(4);
            if next > notes.len() {
                return Err(error("truncated ELF core note"));
            }
            let desc = &notes[offset..offset + desc_len];
            let owner = notes.get(12..12 + name_len);
            if owner == Some(b"AIDBG\0") && kind.0 == 1 && metadata.is_none() {
                *metadata = Some(serde_json::from_slice(desc)?);
            }
            if owner == Some(b"CORE\0") {
                match kind {
                    elf::NT_FILE => self.read_file_note(desc)?,
                    elf::NT_PRPSINFO if desc.len() >= 28 => {
                        self.pid = Some(uint(desc, 24, 4) as i32);
                    }
                    elf::NT_FPREGSET if desc.len() <= 4096 => {
                        if let Some(thread) = note_tid.and_then(|tid| self.threads.get_mut(&tid)) {
                            thread.fp = Some(desc.to_vec());
                        }
                    }
                    elf::NT_PRSTATUS => {
                        let tid = uint(
                            desc.get(..36)
                                .ok_or_else(|| error("truncated NT_PRSTATUS note"))?,
                            32,
                            4,
                        ) as i32;
                        let regs = core_registers(desc)?;
                        let flags = core_flags(desc)?;
                        if tid <= 0
                            || self.threads.len() >= 4096
                            || self
                                .threads
                                .insert(
                                    tid,
                                    Thread {
                                        stop_signal: uint(desc, 12, 2) as u16,
                                        regs,
                                        flags,
                                        general: regs::general_from_bytes(&desc[112..])?,
                                        fp: None,
                                        frames: OnceLock::new(),
                                        frame_metadata: OnceLock::new(),
                                    },
                                )
                                .is_some()
                        {
                            return Err(error("invalid or oversized set of core thread IDs"));
                        }
                        *note_tid = Some(tid);
                    }
                    elf::NT_AUXV => {
                        for pair in desc.chunks_exact(16) {
                            match uint(pair, 0, 8) {
                                0 => break,
                                9 => {
                                    *entry = Some(uint(pair, 8, 8));
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            if self.architecture == "aarch64"
                && owner == Some(b"LINUX\0")
                && kind.0 == regs::NT_ARM_PAC_MASK
                && desc.len() == 16
                && let Some(thread) = note_tid.and_then(|tid| self.threads.get_mut(&tid))
            {
                thread.regs.set_instruction_pac_mask(uint(desc, 8, 8));
            }
            notes = &notes[next..];
        }
        Ok(())
    }

    fn read_file_note(&mut self, note: &[u8]) -> Result<()> {
        if note.len() < 16 {
            return Err(error("truncated NT_FILE metadata"));
        }
        let count = usize::try_from(uint(note, 0, 8))?;
        let page = uint(note, 8, 8);
        let (records, paths) = note[16..]
            .split_at_checked(
                count
                    .checked_mul(24)
                    .ok_or_else(|| error("invalid NT_FILE count"))?,
            )
            .ok_or_else(|| error("truncated NT_FILE table"))?;
        if !page.is_power_of_two() || page > 2 * 1024 * 1024 {
            return Err(error("invalid NT_FILE page size"));
        }
        self.file_page = page;
        let mut names: BTreeMap<&[u8], Vec<Mapping>> = BTreeMap::new();
        for (record, path) in records.chunks_exact(24).zip(paths.split(|byte| *byte == 0)) {
            let start = uint(record, 0, 8);
            let end = uint(record, 8, 8);
            let offset = uint(record, 16, 8).checked_mul(page);
            if let Some(offset) = offset.filter(|_| start < end && !path.is_empty()) {
                names.entry(path).or_default().push(Mapping {
                    start,
                    end,
                    offset,
                    perms: "r--".into(),
                });
            }
        }
        for (path, maps) in names {
            self.modules.push(json!({
                "path": String::from_utf8_lossy(path),
                "mappings": maps.iter().map(|map| json!({
                    "start": hex(map.start), "end": hex(map.end), "offset": hex(map.offset),
                })).collect::<Vec<_>>(),
            }));
            self.file_modules.push(Module {
                backing: Backing {
                    major: 0,
                    minor: 0,
                    inode: 0,
                    path: path.to_vec(),
                },
                maps,
            });
        }
        Ok(())
    }

    pub(super) fn read_at(&self, mut address: u64, mut output: &mut [u8]) -> Result<()> {
        while !output.is_empty() {
            let index = self
                .segments
                .partition_point(|segment| segment.start <= address);
            let mapping = index
                .checked_sub(1)
                .and_then(|index| self.segments.get(index));
            let Some(segment) = mapping.filter(|m| address - m.start < m.size) else {
                return Err(Box::new(MissingMemory(address)));
            };
            let delta = address - segment.start;
            let count = (segment.size - delta).min(output.len() as u64) as usize;
            self.file
                .read_exact_at(&mut output[..count], segment.offset + delta)?;
            address += count as u64;
            output = &mut output[count..];
        }
        Ok(())
    }

    fn frames_for(&self, tid: i32) -> Option<&[OfflineFrame]> {
        let thread = self.threads.get(&tid)?;
        Some(thread.frames.get_or_init(|| {
            let maps = self
                .segments
                .iter()
                .filter(|s| s.executable)
                .map(|s| Mapping {
                    start: s.start,
                    end: s.end,
                    offset: 0,
                    perms: "r-x".into(),
                })
                .collect();
            let module = Module {
                backing: Backing {
                    major: 0,
                    minor: 0,
                    inode: 0,
                    path: Vec::new(),
                },
                maps,
            };
            offline_frames(
                self,
                |lookup| {
                    let image = self.image_at(lookup)?;
                    let link = image.link(lookup)?;
                    Some((image, link))
                },
                thread.regs,
                &[module],
            )
        }))
    }

    fn frame(&self, handle: &str) -> Option<&OfflineFrame> {
        let (id, location) = handle.split_once(':')?;
        if id != self.id {
            return None;
        }
        let (tid, index) = location.split_once(':')?;
        self.frames_for(tid.parse().ok()?)?
            .get(index.parse::<usize>().ok()?)
    }

    pub(super) fn session_types(
        &self,
        pattern: &str,
        exact: bool,
        offset: usize,
        limit: usize,
        deadline: Instant,
    ) -> Result<Vec<(String, crate::symbols::inspect::type_graph::Graph)>> {
        let mut result = Vec::new();
        let mut skip = offset;
        let main = self
            .entry
            .and_then(|entry| self.mapped_file(entry).map(|(module, _)| module));
        let mut images = self.dwarf.iter().cloned().collect::<Vec<_>>();
        for module in &self.file_modules {
            if self.dwarf.is_some() && main.is_some_and(|main| std::ptr::eq(main, module)) {
                continue;
            }
            if let Some(address) = module.maps.first().map(|map| map.start)
                && let Some(image) = self.image_at(address)
                && let Some(dwarf) = image.dwarf(self)?
            {
                images.push(dwarf);
            }
        }
        for dwarf in images {
            let (rows, matched) = dwarf.type_graphs(
                pattern,
                exact,
                skip,
                limit.saturating_sub(result.len()),
                deadline,
            )?;
            skip = skip.saturating_sub(matched);
            for row in rows {
                if !result.contains(&row) {
                    result.push(row);
                }
            }
            if result.len() >= limit || (exact && !result.is_empty()) {
                break;
            }
        }
        Ok(result)
    }

    pub(super) fn session_pid(&self) -> i32 {
        self.pid.or_else(|| self.default_tid()).unwrap_or_default()
    }

    pub(super) fn session_registers(&self, tid: i32, full: bool) -> Result<Value> {
        let thread = self
            .threads
            .get(&tid)
            .ok_or_else(|| error("thread no longer exists"))?;
        let mut registers = serde_json::to_value(&thread.general)?;
        if full {
            regs::add_vectors(
                &mut registers,
                thread.fp.as_deref().ok_or_else(|| {
                    error("NotSupport: core has no floating-point registers for this thread")
                })?,
            )?;
        }
        Ok(registers)
    }

    pub(super) fn session_frames(&self, tid: i32, limit: usize) -> Result<Value> {
        let frames = self
            .frames_for(tid)
            .ok_or_else(|| error("thread no longer exists"))?;
        let metadata = self.frame_metadata(tid)?;
        let deadline = Instant::now() + std::time::Duration::from_millis(750);
        Ok(json!(
            frames
                .iter()
                .zip(metadata)
                .take(limit)
                .map(|(frame, site)| {
                    let values = self.session_frame_values(frame, deadline).unwrap_or(Value::Null);
                    json!({"pc":hex(frame.pc), "lookupPc":hex(frame.lookup_pc),
                        "sp":frame.regs.get(regs::SP).ok().map(hex), "fp":frame.regs.get(regs::FP).ok().map(hex),
                        "symbol":site["function"], "file":site["file"], "line":site["line"],
                        "locals":values["locals"], "parameters":values["parameters"]})
                })
                .collect::<Vec<_>>()
        ))
    }

    fn session_frame_values(&self, frame: &OfflineFrame, deadline: Instant) -> Result<Value> {
        if Instant::now() >= deadline {
            return Err(error("frame inspection deadline"));
        }
        self.frame_dwarf(frame)?
            .frame_values(self, frame, 64, deadline)
    }

    pub(super) fn session_variable_type(
        &self,
        tid: i32,
        name: &str,
        deadline: Instant,
    ) -> Result<Option<crate::symbols::inspect::type_graph::Graph>> {
        let Some(frame) = self.frames_for(tid).and_then(|frames| frames.first()) else {
            return Ok(None);
        };
        let Ok(dwarf) = self.frame_dwarf(frame) else {
            return Ok(None);
        };
        dwarf.variable_type_graph(name, frame.link, deadline)
    }

    pub(super) fn session_top_values(&self, tid: i32, deadline: Instant) -> Result<Value> {
        let frame = self
            .frames_for(tid)
            .and_then(|frames| frames.first())
            .ok_or_else(|| error("thread has no captured frame"))?;
        self.session_frame_values(frame, deadline)
    }

    pub(super) fn session_mappings(&self) -> Value {
        json!(
            self.segments
                .iter()
                .map(|segment| {
                    let named = self.mapped_file(segment.start);
                    let mut prot = String::new();
                    for (flag, character) in [(4, 'r'), (2, 'w'), (1, 'x')] {
                        prot.push(if segment.flags & flag != 0 {
                            character
                        } else {
                            '-'
                        });
                    }
                    prot.push('p');
                    json!({"start":hex(segment.start), "end":hex(segment.end),
                "offset":hex(named.map_or(0, |(_, map)| map.offset + (segment.start - map.start))),
                "prot":prot, "name":named.map(|(module, _)| module.path()).unwrap_or_default()})
                })
                .collect::<Vec<_>>()
        )
    }

    pub fn threads(&self) -> Value {
        Value::Array(self.threads.keys().map(|tid| json!({"tid": tid})).collect())
    }

    pub(super) fn observe_threads(
        &self,
        request: crate::script_observation::Request,
    ) -> Result<Value> {
        use super::synchronization::{self, ThreadState};
        synchronization::core(
            request,
            || {
                Ok(self
                    .threads
                    .iter()
                    .map(|(&tid, thread)| ThreadState {
                        tid,
                        state: "captured".into(),
                        wait_channel: None,
                        pc: thread.regs.get(crate::regs::PC).ok().map(hex),
                        futex: None,
                    })
                    .collect())
            },
            |address| self.read_word(address, 4),
        )
    }

    fn frame_metadata(&self, tid: i32) -> Result<&[Value]> {
        let frames = self
            .frames_for(tid)
            .ok_or_else(|| error("TID is absent from the core"))?;
        let metadata = self.threads[&tid].frame_metadata.get_or_init(|| {
            frames
                .iter()
                .enumerate()
                .map(|(index, frame)| {
                    let lookup = frame.lookup_pc;
                    let image = self.image_at(lookup);
                    let source = image
                        .as_ref()
                        .and_then(|image| image.line(self, image.link(lookup)?).ok().flatten());
                    let function = (|| {
                        let image = image.as_ref()?;
                        let link = image.link(lookup)?;
                        image
                            .debug(self)
                            .and_then(|debug| object::File::parse(&*debug.bytes).ok())
                            .and_then(|debug| crate::modules::text_symbol(&debug, link))
                            .or_else(|| {
                                let obj = object::File::parse(image.bytes()).ok()?;
                                crate::modules::text_symbol(&obj, link)
                            })
                            .map(|(name, _)| name.to_owned())
                    })();
                    json!({
                        "handle": format!("{}:{tid}:{index}", self.id),
                        "pc": hex(frame.pc), "function": function,
                        "file": source.as_ref().map(|line| &line.file),
                        "line": source.as_ref().and_then(|line| line.line),
                        "column": source.as_ref().and_then(|line| line.column),
                    })
                })
                .collect()
        });
        Ok(metadata)
    }

    pub fn frames(&self, tid: i32, deadline: Instant) -> Result<Value> {
        let mut metadata = self.frame_metadata(tid)?.to_vec();
        if let Some(first) = metadata.first_mut()
            && let Some(frame) = self.frames_for(tid).and_then(|frames| frames.first())
        {
            first["args"] = self.frame_arguments(frame, deadline);
        }
        Ok(Value::Array(metadata))
    }

    pub fn modules(&self) -> Value {
        Value::Array(self.modules.clone())
    }

    fn dwarf(&self) -> Result<&DwarfImage> {
        self.dwarf.as_ref().ok_or_else(|| {
            Diagnostic::new(
                "NO_DWARF",
                "No verified DWARF image is available",
                Some("Supply a matching executable and debug symbols."),
            )
            .into()
        })
    }

    fn frame_dwarf(&self, frame: &OfflineFrame) -> Result<DwarfImage> {
        if let Some(image) = self.image_at(frame.lookup_pc)
            && let Some(dwarf) = image.dwarf(self)?
        {
            return Ok(dwarf);
        }
        Err(Diagnostic::new(
            "NO_DWARF",
            "No verified DWARF image for this core frame",
            Some("Supply matching debug information for the frame's module."),
        )
        .into())
    }

    pub fn locals(
        &self,
        handle: &str,
        offset: usize,
        limit: usize,
        deadline: Instant,
    ) -> Result<Value> {
        let frame = self
            .frame(handle)
            .filter(|frame| frame.link.is_some())
            .ok_or_else(|| {
                Diagnostic::new(
                    "NO_FRAME_CONTEXT",
                    "Frame is absent or its PC has no verified image",
                    Some("Select a current frame from dbg.frames(tid)."),
                )
            })?;
        self.frame_dwarf(frame)?
            .variables(self, Some(frame), "*", offset, limit, deadline)
    }

    pub fn globals(
        &self,
        pattern: &str,
        offset: usize,
        limit: usize,
        deadline: Instant,
    ) -> Result<Value> {
        self.dwarf()?
            .variables(self, None, pattern, offset, limit, deadline)
    }

    pub fn types(
        &self,
        pattern: &str,
        offset: usize,
        limit: usize,
        deadline: Instant,
    ) -> Result<Value> {
        self.dwarf()?.types(pattern, offset, limit, deadline)
    }

    pub fn into_images(self) -> Result<Vec<(String, Vec<u8>)>> {
        self.image()?;
        let mut images = vec![("executable".to_owned(), self.image.unwrap().into_bytes())];
        if let Some(debug) = self.debug_image {
            images.push(("executable.debug".to_owned(), debug.bytes));
        }
        Ok(images)
    }

    fn image(&self) -> Result<&OfflineImage> {
        self.image.as_ref().ok_or_else(|| {
            Diagnostic::new(
                "NO_SYMBOL_IMAGE",
                "No verified executable is available",
                Some("Open the core with its executable."),
            )
            .into()
        })
    }

    fn missing_memory(&self, address: u64) -> Diagnostic {
        Diagnostic::new(
            "CORE_MEMORY_MISSING",
            format!("Core has no bytes at {}", hex(address)),
            None,
        )
    }

    pub fn resolve(&self, address: u64) -> Result<Value> {
        let mapped = self.mapped_file(address);
        let mut warnings = self.warnings.clone();
        let Some(image) = self.image_at(address) else {
            let module = mapped.map(|(module, _)| module.identity(None));
            let file_offset = mapped
                .and_then(|(_, mapping)| mapping.file_offset(address))
                .map(hex);
            warnings.push(Diagnostic::new(
                "NO_SYMBOL_IMAGE",
                "No verified ELF covers this address",
                None,
            ));
            return Ok(json!({
                "runtime_address": hex(address), "module": module, "file_offset": file_offset,
                "elf_address": null, "symbol": null, "source_line": null, "warnings": warnings,
            }));
        };
        let obj = object::File::parse(image.bytes())?;
        let link = image
            .link(address)
            .ok_or_else(|| error("ELF address overflows"))?;
        let source = image.line(self, link)?;
        if source.is_none() {
            if image.debug(self).is_none() && !obj.has_debug_symbols() {
                warnings.push(Diagnostic::new(
                    "NO_DEBUG_FILE",
                    "No matching debug file is available for this module",
                    None,
                ));
            }
            warnings.push(Diagnostic::new(
                "NO_SOURCE_LINE",
                "No source line covers this address",
                None,
            ));
        }
        let debug_symbol = || {
            image
                .debug(self)
                .and_then(|debug| object::File::parse(&*debug.bytes).ok())
                .as_ref()
                .and_then(|debug| crate::modules::text_symbol(debug, link))
        };
        let image_symbol = || crate::modules::text_symbol(&obj, link);
        let symbol = match image {
            images::Image::Main(_) => debug_symbol().or_else(image_symbol),
            images::Image::Shared(_, _) => image_symbol().or_else(debug_symbol),
        }
        .map(|(name, start)| json!({"name": name, "elf_address": hex(start)}));
        let module = mapped
            .map(|(module, _)| serde_json::to_value(module.identity(obj.build_id().ok().flatten())))
            .transpose()?
            .unwrap_or(serde_json::to_value(&self.executable)?);
        Ok(json!({
            "runtime_address": hex(address), "elf_address": hex(link),
            "file_offset": mapped.and_then(|(_, mapping)| mapping.file_offset(address)).map(hex),
            "module": module, "display": symbol.as_ref().and_then(|value| value["name"].as_str()),
            "symbol": symbol, "source_line": source, "warnings": warnings,
        }))
    }

    pub fn disassemble(
        &self,
        request: &crate::rpc::DisassembleRequest,
    ) -> Result<crate::disassembly::Window> {
        let address = request.address;
        let image = self.image_at(address);
        let object = image
            .as_ref()
            .map(|image| object::File::parse(image.bytes()))
            .transpose()?;
        let link = image.as_ref().and_then(|image| image.link(address));
        let entry =
            image
                .as_ref()
                .zip(object.as_ref())
                .zip(link)
                .and_then(|((image, object), link)| {
                    let (_, start) = crate::modules::text_symbol(object, link)?;
                    image.runtime(start)
                });
        let before = request.before.unwrap_or(4);
        let after = request.after.unwrap_or(8);
        if let Some(segment) = self.segments.iter().find(|segment| {
            segment.executable && address >= segment.start && address - segment.start < segment.size
        }) {
            let mapping = Mapping {
                start: segment.start,
                end: segment.end,
                offset: 0,
                perms: "r-x".into(),
            };
            return crate::disassembly::decode_window(
                self.architecture,
                address,
                before,
                after,
                request.start,
                &mapping,
                entry,
                "core",
                |anchor, buffer| {
                    let count =
                        (segment.size - (anchor - segment.start)).min(buffer.len() as u64) as usize;
                    self.read_at(anchor, &mut buffer[..count])?;
                    Ok(count)
                },
            );
        }
        if let Some(image) = image.as_ref()
            && let Some(link) = link
            && let Some(obj) = object.as_ref()
            && let Some(segment) = obj.segments().find(|segment| {
                matches!(segment.flags(), object::SegmentFlags::Elf { p_flags, .. } if (p_flags & elf::PF_X).0 != 0)
                    && link.checked_sub(segment.address()).is_some_and(|offset| offset < segment.file_range().1)
            }) {
            let start = image.runtime(segment.address()).ok_or_else(|| error("code address overflow"))?;
            let end = start.checked_add(segment.file_range().1).ok_or_else(|| error("code range overflow"))?;
            let mapping = Mapping {
                start, end, offset: segment.file_range().0, perms: "r-x".into(),
            };
            return crate::disassembly::decode_window(self.architecture, address, before, after, request.start, &mapping, entry, "executable", |anchor, buffer| {
                let data = segment.data()?;
                let offset = usize::try_from(anchor - mapping.start)?;
                let count = (data.len() - offset).min(buffer.len());
                buffer[..count].copy_from_slice(&data[offset..offset + count]);
                Ok(count)
            });
        }
        Err(self.missing_memory(address).into())
    }

    fn address_symbol(&self, address: u64) -> Option<Value> {
        let image = self.image_at(address)?;
        let link = image.link(address)?;
        let find = |obj: &object::File<'_>| {
            crate::modules::text_symbol(obj, link)
                .or_else(|| crate::modules::data_symbol(obj, link))
                .map(|(name, start)| (name.to_owned(), start))
        };
        let primary = object::File::parse(image.bytes()).ok()?;
        let (name, start) = image
            .debug(self)
            .and_then(|debug| object::File::parse(&*debug.bytes).ok())
            .and_then(|debug| find(&debug))
            .or_else(|| find(&primary))?;
        let offset = link.checked_sub(start)?;
        let display = if offset == 0 {
            name.clone()
        } else {
            format!("{name}+{offset}")
        };
        Some(json!({"address": hex(address), "name": name, "offset": offset, "display": display}))
    }

    fn frame_arguments(&self, frame: &OfflineFrame, deadline: Instant) -> Value {
        let args = self.frame_dwarf(frame).and_then(|dwarf| {
            if frame.link.is_none() {
                return Err(Diagnostic::new(
                    "NO_FRAME_CONTEXT",
                    "No DWARF image for this frame",
                    None,
                )
                .into());
            }
            if Instant::now() >= deadline {
                return Err(Diagnostic::new(
                    "LIMIT_REACHED",
                    "Argument capture deadline reached",
                    None,
                )
                .into());
            }
            dwarf.parameters(self, frame, 8, deadline)
        });
        crate::symbols::inspect::enrich_arguments(args, deadline, |address| {
            self.address_symbol(address)
        })
    }

    fn default_tid(&self) -> Option<i32> {
        if self.threads.len() == 1 {
            return self.threads.keys().next().copied();
        }
        let mut signaled = self
            .threads
            .iter()
            .filter(|(_, thread)| thread.stop_signal != 0);
        let tid = *signaled.next()?.0;
        signaled.next().is_none().then_some(tid)
    }

    fn default_frame_handle(&self) -> Result<String> {
        let tid = self.default_tid().ok_or_else(|| {
            Diagnostic::new(
                "THREAD_REQUIRED",
                "Select a core frame when the captured thread is ambiguous",
                None,
            )
        })?;
        Ok(format!("{}:{tid}:0", self.id))
    }

    pub fn inspect_request(&self, request: crate::rpc::InspectRequest) -> Result<Value> {
        let invalid = |message| Diagnostic::new("INVALID_ARGUMENT", message, None);
        if request.pid != 0
            || request.run_id.is_some()
            || request.module.is_some()
            || request.instance.is_some()
        {
            return Err(invalid("Select core frames with target_id, tid and frame_index").into());
        }
        let batch = !request.expressions.is_empty();
        if batch && (!request.expression.is_empty() || request.expressions.len() > 16) {
            return Err(invalid("Supply a single expression or at most 16 expressions").into());
        }
        let timeout = request.timeout_ms.unwrap_or(1000);
        if !(1..=5000).contains(&timeout) {
            return Err(invalid("timeout_ms must be between 1 and 5000").into());
        }
        let deadline = Instant::now() + std::time::Duration::from_millis(u64::from(timeout));
        let tid = request.tid.or_else(|| self.default_tid()).ok_or_else(|| {
            Diagnostic::new(
                "THREAD_REQUIRED",
                "Select the thread to inspect in this core",
                None,
            )
        })?;
        let index = request.frame_index.unwrap_or_default();
        let handle = format!("{}:{tid}:{index}", self.id);
        let frame = self.frame(&handle).ok_or_else(|| {
            Diagnostic::new(
                "NO_FRAME_CONTEXT",
                "Thread or frame is absent from this core target",
                None,
            )
        })?;
        let mut value = crate::symbols::inspect::inspect_batch(&request, |text| {
            self.inspect(text, &handle, deadline, request.expand.clone())
        });
        let mut metadata = self.frame_metadata(tid)?[index as usize].clone();
        metadata["args"] = self.frame_arguments(frame, deadline);
        metadata["tid"] = json!(tid);
        metadata["index"] = json!(index);
        value["frame"] = metadata;
        Ok(value)
    }

    pub fn inspect(
        &self,
        text: &str,
        handle: &str,
        deadline: Instant,
        expand: Option<crate::rpc::InspectExpansion>,
    ) -> Value {
        if Instant::now() >= deadline {
            return json!({"status": "limit_reached", "result": null, "code": "LIMIT_REACHED",
                "issue": "Core inspection deadline reached"});
        }
        let Some(frame) = self.frame(handle) else {
            return json!({"status": "invalid_frame", "result": null, "issue": "frame is absent from this core target", "code": "NO_FRAME_CONTEXT", "hint": "Select a current frame from dbg.frames(tid)."});
        };
        let mut result = self.frame_dwarf(frame).map(|dwarf| {
            dwarf.inspect(
                text,
                self,
                frame.regs,
                frame.link,
                frame.cfa,
                deadline,
                expand.clone(),
            )
        });
        if let Some(main) = &self.dwarf
            && (result.is_err()
                || result
                    .as_ref()
                    .is_ok_and(|report| report["status"] == "not_found"))
            && !matches!(self.image_at(frame.lookup_pc), Some(images::Image::Main(_)))
        {
            result = Ok(main.inspect(text, self, frame.regs, None, None, deadline, expand));
        }
        let mut report = result.unwrap_or_else(|error| json!({"status": "no_dwarf", "result": null, "issue": error.to_string(), "code": "NO_DWARF", "hint": "Supply matching executable and debug symbols."}));
        let value = &mut report["result"];
        if Instant::now() < deadline
            && value["type"]["kind"] == "pointer"
            && let Some(address) = value["value"].as_str()
            && let Ok(address) = u64::from_str_radix(address.trim_start_matches("0x"), 16)
            && address != 0
            && let Some(symbol) = self.address_symbol(address)
        {
            value["symbol"] = symbol;
        }
        report
    }

    pub fn preflight(&self, text: &str, handle: Option<&str>) -> Validation {
        if let Some(handle) = handle {
            let Some(frame) = self.frame(handle) else {
                return Validation::unchecked("UNKNOWN_FRAME");
            };
            return self.frame_dwarf(frame).map_or_else(
                |_| Validation::unchecked("NO_DWARF"),
                |dwarf| dwarf.preflight(text, self, frame.link),
            );
        }
        self.dwarf.as_ref().map_or_else(
            || Validation::unchecked("NO_DWARF"),
            |dwarf| dwarf.preflight(text, self, None),
        )
    }
}

impl super::debugger::Debugger for Target {
    fn threads(&self) -> Result<Value> {
        Ok(self.threads())
    }

    fn frames(&self, tid: i32, deadline: Instant) -> Result<Value> {
        self.frames(tid, deadline)
    }

    fn modules(&self) -> Result<Value> {
        Ok(self.modules())
    }

    fn read_prefix(&self, address: u64, bytes: &mut [u8]) -> Result<usize> {
        self.read_prefix(address, bytes)
    }

    fn discover(
        &self,
        kind: crate::symbols::inspect::Discovery,
        frame: Option<&str>,
        pattern: &str,
        (offset, limit): (usize, usize),
        deadline: Instant,
    ) -> Result<Value> {
        use crate::symbols::inspect::Discovery;
        match kind {
            Discovery::Locals => {
                let handle = frame
                    .map(str::to_owned)
                    .map_or_else(|| self.default_frame_handle(), Ok)?;
                self.locals(&handle, offset, limit, deadline)
            }
            Discovery::Globals => self.globals(pattern, offset, limit, deadline),
            Discovery::Types => self.types(pattern, offset, limit, deadline),
            Discovery::Parameters => unreachable!("parameters are exposed through frames"),
        }
    }

    fn inspect(
        &self,
        expression: String,
        frame: Option<&str>,
        expand: Option<crate::rpc::InspectExpansion>,
        deadline: Instant,
    ) -> Result<Value> {
        let handle = match frame
            .map(str::to_owned)
            .map_or_else(|| self.default_frame_handle(), Ok)
        {
            Ok(handle) => handle,
            Err(error) => {
                return Ok(json!({
                    "status": "invalid_frame", "result": null, "code": "THREAD_REQUIRED", "issue": error.to_string(),
                }));
            }
        };
        Ok(self.inspect(&expression, &handle, deadline, expand))
    }
}

impl UnwindMemory for Target {
    fn read_word(&self, address: u64, size: usize) -> Result<u64> {
        let mut bytes = [0; 8];
        let output = bytes
            .get_mut(..size)
            .filter(|b| !b.is_empty())
            .ok_or_else(|| error("invalid memory word size"))?;
        self.read_at(address, output)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

fn core_registers(desc: &[u8]) -> Result<Registers> {
    #[cfg(target_arch = "x86_64")]
    let order = [10, 12, 11, 5, 13, 14, 4, 19, 9, 8, 7, 6, 3, 2, 1, 0, 16];
    #[cfg(target_arch = "aarch64")]
    let order = std::array::from_fn::<_, 33, _>(|index| index);
    let mut registers = Registers::empty();
    for (dwarf, index) in order.into_iter().enumerate() {
        let offset = 112 + index * 8;
        let bytes = desc
            .get(offset..offset + 8)
            .ok_or_else(|| error("truncated NT_PRSTATUS registers"))?;
        registers.set(gimli::Register(dwarf as u16), Some(uint(bytes, 0, 8)));
    }
    Ok(registers)
}

fn core_flags(desc: &[u8]) -> Result<u64> {
    #[cfg(target_arch = "x86_64")]
    let index = 18;
    #[cfg(target_arch = "aarch64")]
    let index = 33;
    let start = 112 + index * 8;
    let bytes = desc
        .get(start..start + 8)
        .ok_or_else(|| error("truncated NT_PRSTATUS flags"))?;
    let flags = uint(bytes, 0, 8);
    #[cfg(target_arch = "aarch64")]
    let flags = flags & 0xf000_0000;
    Ok(flags)
}
