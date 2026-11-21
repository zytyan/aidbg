use crate::{Result, error, hex};
use nix::libc;
use object::{Object, ObjectKind, ObjectSegment, ObjectSymbol, SegmentFlags, SymbolKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub perms: String,
}

impl Mapping {
    pub fn executable(&self) -> bool {
        self.perms.as_bytes().get(2) == Some(&b'x')
    }

    pub fn contains(&self, address: u64) -> bool {
        (self.start..self.end).contains(&address)
    }

    pub fn file_offset(&self, address: u64) -> Option<u64> {
        self.contains(address)
            .then(|| self.offset.checked_add(address - self.start))
            .flatten()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Backing {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) inode: u64,
    pub(crate) path: Vec<u8>,
}

pub struct Module {
    pub(crate) backing: Backing,
    pub maps: Vec<Mapping>,
}

#[derive(Serialize)]
pub struct ModuleInfo {
    id: usize,
    kind: &'static str,
    #[serde(flatten)]
    identity: ModuleIdentity,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    load_instances: Vec<LoadInstanceInfo>,
    mappings: Vec<MappingInfo>,
}

#[derive(Clone, Serialize)]
pub(crate) struct ModuleIdentity {
    path: String,
    device: String,
    inode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_id: Option<String>,
}

pub(crate) fn id_hex(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Serialize)]
struct LoadInstanceInfo {
    base: String,
    load_bias: String,
}

#[derive(Serialize)]
struct MappingInfo {
    start: String,
    end: String,
    offset: String,
    permissions: String,
}

fn field<'a>(rest: &mut &'a [u8]) -> Result<&'a str> {
    *rest = rest.trim_ascii_start();
    let n = rest
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(rest.len());
    let answer = std::str::from_utf8(&rest[..n])?;
    *rest = &rest[n..];
    Ok(answer)
}

pub(crate) fn map_entries(base: &Path) -> Result<Vec<(Backing, Mapping)>> {
    let data = fs::read(base.join("maps"))?;
    data.split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|line| {
            let mut rest = line;
            let (start, end) = field(&mut rest)?
                .split_once('-')
                .ok_or_else(|| error("invalid maps range"))?;
            let perms = field(&mut rest)?.to_owned();
            let offset = u64::from_str_radix(field(&mut rest)?, 16)?;
            let (major, minor) = field(&mut rest)?
                .split_once(':')
                .ok_or_else(|| error("invalid maps device"))?;
            let inode = field(&mut rest)?.parse::<u64>()?;
            Ok((
                Backing {
                    major: u32::from_str_radix(major, 16)?,
                    minor: u32::from_str_radix(minor, 16)?,
                    inode,
                    path: rest.trim_ascii_start().to_vec(),
                },
                Mapping {
                    start: u64::from_str_radix(start, 16)?,
                    end: u64::from_str_radix(end, 16)?,
                    offset,
                    perms,
                },
            ))
        })
        .collect()
}

pub fn mapping_at(root: &Path, address: u64) -> Result<Option<Mapping>> {
    Ok(map_entries(root)?
        .into_iter()
        .map(|(_, map)| map)
        .find(|map| map.contains(address)))
}

pub(crate) fn private_code_mapping(
    root: &Path,
    address: u64,
    executable: bool,
) -> Result<Option<CodeMapping>> {
    let Some((backing, map)) = map_entries(root)?.into_iter().find(|(_, map)| {
        map.contains(address)
            && (!executable || map.executable())
            && map.perms.as_bytes().get(3) == Some(&b'p')
    }) else {
        return Ok(None);
    };
    Ok(Some(match backing.inode {
        0 => CodeMapping::Anonymous {
            start: map.start,
            end: map.end,
            name: backing.path,
        },
        inode => CodeMapping::File {
            major: backing.major,
            minor: backing.minor,
            inode,
            offset: map
                .file_offset(address)
                .ok_or_else(|| error("invalid mapping offset"))?,
        },
    }))
}

#[derive(PartialEq, Eq)]
pub(crate) enum CodeMapping {
    File {
        major: u32,
        minor: u32,
        inode: u64,
        offset: u64,
    },
    Anonymous {
        start: u64,
        end: u64,
        name: Vec<u8>,
    },
}

pub fn is_executable_address(root: &Path, address: u64) -> Result<bool> {
    // Absolute breakpoints can also point to anonymous executable mappings.
    Ok(map_entries(root)?
        .iter()
        .any(|(_, map)| map.executable() && map.contains(address)))
}

pub struct AddressSpace {
    pub modules: Vec<Module>,
    pub anonymous: Vec<Mapping>,
}

pub fn address_space(base: &Path) -> Result<AddressSpace> {
    Ok(group_mappings(map_entries(base)?))
}

pub(crate) fn group_mappings(
    entries: impl IntoIterator<Item = (Backing, Mapping)>,
) -> AddressSpace {
    let mut files = BTreeMap::<Backing, Vec<Mapping>>::new();
    let mut loaded = BTreeSet::new();
    let mut anonymous = Vec::new();
    for (backing, map) in entries {
        if backing.inode == 0 && backing.path != b"[vdso]" {
            if backing.path.is_empty() || backing.path.starts_with(b"[anon:") {
                anonymous.push(map);
            }
            continue;
        }
        if map.executable() {
            loaded.insert(backing.clone());
        }
        files.entry(backing).or_default().push(map);
    }
    let mut modules: Vec<_> = files
        .into_iter()
        .filter(|(key, _)| loaded.contains(key))
        .map(|(backing, maps)| Module { backing, maps })
        .collect();
    modules.sort_unstable_by_key(|module| module.maps[0].start);
    AddressSpace { modules, anonymous }
}

pub fn read(base: &Path) -> Result<Vec<Module>> {
    Ok(address_space(base)?.modules)
}

impl Module {
    pub fn info(
        &self,
        id: usize,
        exe: Option<&fs::Metadata>,
        elf_kind: Option<&'static str>,
    ) -> ModuleInfo {
        let b = &self.backing;
        let kind = if b.path == b"[vdso]" {
            "vdso"
        } else if exe.is_some_and(|m| self.matches(m)) {
            "main"
        } else {
            elf_kind.unwrap_or("executable_mapping")
        };
        ModuleInfo {
            id,
            kind,
            identity: self.identity(None),
            load_instances: Vec::new(),
            mappings: self
                .maps
                .iter()
                .map(|m| MappingInfo {
                    start: hex(m.start),
                    end: hex(m.end),
                    offset: hex(m.offset),
                    permissions: m.perms.clone(),
                })
                .collect(),
        }
    }

    pub fn identity(&self, build_id: Option<&[u8]>) -> ModuleIdentity {
        let b = &self.backing;
        ModuleIdentity {
            path: String::from_utf8_lossy(&b.path).into_owned(),
            device: format!("{:x}:{:x}", b.major, b.minor),
            inode: b.inode.to_string(),
            build_id: build_id.map(id_hex),
        }
    }

    pub fn path(&self) -> PathBuf {
        let path = self
            .backing
            .path
            .strip_suffix(b" (deleted)")
            .unwrap_or(&self.backing.path);
        PathBuf::from(OsString::from_vec(path.to_vec()))
    }

    pub fn mapping_at(&self, address: u64) -> Option<&Mapping> {
        self.maps.iter().find(|m| m.contains(address))
    }

    pub fn executable_at(&self, pc: u64) -> Option<&Mapping> {
        self.maps.iter().find(|m| m.contains(pc) && m.executable())
    }

    pub(crate) fn matches(&self, m: &fs::Metadata) -> bool {
        let b = &self.backing;
        b.inode == m.ino() && b.major == libc::major(m.dev()) && b.minor == libc::minor(m.dev())
    }

    pub(crate) fn open(&self, root: &Path, is_main: bool) -> Result<File> {
        let b = &self.backing;
        if b.inode == 0 {
            return Err(error("no on-disk image for this mapping"));
        }
        let mut candidates = vec![];
        if is_main {
            candidates.push(root.join("exe"));
        }
        if let Some(m) = self.maps.iter().find(|m| m.executable()) {
            candidates.push(
                root.join("map_files")
                    .join(format!("{:x}-{:x}", m.start, m.end)),
            );
        }
        let path = b.path.strip_suffix(b" (deleted)").unwrap_or(&b.path);
        if let Some(rel) = path.strip_prefix(b"/") {
            candidates.push(
                root.join("root")
                    .join(PathBuf::from(OsString::from_vec(rel.to_vec()))),
            );
        }
        let mut last = None;
        for path in candidates {
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)
            {
                Ok(file) => {
                    let metadata = file.metadata()?;
                    if metadata.is_file() && self.matches(&metadata) {
                        return Ok(file);
                    }
                    last = Some(error("backing file no longer matches the mapping"));
                }
                Err(e) => last = Some(e.into()),
            }
        }
        Err(last.unwrap_or_else(|| error("no accessible backing file")))
    }

    pub fn read_image(&self, root: &Path, exe: Option<&fs::Metadata>, max: u64) -> Result<Vec<u8>> {
        let file = self.open(root, exe.is_some_and(|m| self.matches(m)))?;
        if file.metadata()?.len() > max {
            return Err(error("module exceeds image byte budget"));
        }
        let mut bytes = Vec::new();
        file.take(max + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max {
            return Err(error("module exceeds image byte budget"));
        }
        Ok(bytes)
    }

    pub fn image_kind(&self, root: &Path) -> Option<&'static str> {
        let mut file = self.open(root, false).ok()?;
        let mut h = [0u8; 20];
        file.read_exact(&mut h).ok()?;
        (h[..6] == [0x7f, b'E', b'L', b'F', 2, 1] && u16::from_le_bytes([h[16], h[17]]) == 3)
            .then_some("shared_object")
    }
}

pub fn is_executable_module<'data>(obj: &object::File<'data, impl object::ReadRef<'data>>) -> bool {
    obj.format() == object::BinaryFormat::Elf
        && obj.is_64()
        && obj.is_little_endian()
        && matches!(obj.kind(), ObjectKind::Dynamic | ObjectKind::Executable)
}

#[derive(Clone, Copy)]
pub struct LoadSegment {
    pub address: u64,
    pub memory_size: u64,
    pub offset: u64,
    pub file_size: u64,
    pub executable: bool,
}

pub fn load_segments<'data, R: object::ReadRef<'data>>(
    obj: &object::File<'data, R>,
) -> impl Iterator<Item = LoadSegment> {
    // The ELF ObjectSegment iterator yields only PT_LOAD program headers.
    obj.segments().map(|segment| {
        let (offset, file_size) = segment.file_range();
        let executable = matches!(segment.flags(), SegmentFlags::Elf { p_flags, .. }
            if (p_flags & object::elf::PF_X).0 != 0);
        LoadSegment {
            address: segment.address(),
            memory_size: segment.size(),
            offset,
            file_size,
            executable,
        }
    })
}

impl LoadSegment {
    pub fn contains(self, address: u64) -> bool {
        address
            .checked_sub(self.address)
            .is_some_and(|delta| delta < self.memory_size)
    }
}

#[derive(Clone, Copy)]
pub struct Instance {
    pub base: u64,
    pub bias: i128,
}

impl Instance {
    pub fn relocate(self, address: u64) -> Option<u64> {
        u64::try_from(i128::from(address) + self.bias).ok()
    }

    fn unrelocate(self, address: u64) -> Option<u64> {
        u64::try_from(i128::from(address) - self.bias).ok()
    }
}

pub struct Layout {
    pub elf_base: u64,
    segments: Vec<LoadSegment>,
    pub instances: Vec<Instance>,
    page: u64,
}

impl Layout {
    pub fn new<'data>(
        obj: &object::File<'data, impl object::ReadRef<'data>>,
        module: &Module,
    ) -> Result<Self> {
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
        if page == 0 || !page.is_power_of_two() {
            return Err(error("invalid system page size"));
        }
        Self::from_segments(load_segments(obj).collect(), module, page)
    }

    pub(crate) fn from_segments(
        segments: Vec<LoadSegment>,
        module: &Module,
        page: u64,
    ) -> Result<Self> {
        let elf_base = segments
            .iter()
            .map(|s| s.address & !(page - 1))
            .min()
            .ok_or_else(|| error("ELF image has no loadable segments"))?;
        let mut layout = Self {
            elf_base,
            segments,
            instances: Vec::new(),
            page,
        };
        // Each file-backed executable mapping anchors a separate load bias.
        let mut biases = BTreeSet::new();
        for map in &module.maps {
            if !map.executable() {
                continue;
            }
            for &segment in layout.segments.iter().filter(|s| s.executable) {
                if let Some(bias) = layout.mapping_bias(map, segment) {
                    biases.insert(bias);
                }
            }
        }
        layout.instances = biases
            .into_iter()
            .filter_map(|bias| {
                let base = u64::try_from(i128::from(elf_base) + bias).ok()?;
                Some(Instance { base, bias })
            })
            .collect();
        Ok(layout)
    }

    fn mapping_bias(&self, map: &Mapping, segment: LoadSegment) -> Option<i128> {
        let mask = self.page - 1;
        if segment.file_size == 0 || segment.offset & mask != segment.address & mask {
            return None;
        }
        let first = segment.offset & !mask;
        let last = segment
            .offset
            .checked_add(segment.file_size)?
            .checked_add(mask)?
            & !mask;
        let map_last = map.offset.checked_add(map.end.checked_sub(map.start)?)?;
        if map.offset.max(first) >= map_last.min(last) {
            return None;
        }
        Some(
            i128::from(map.start) - i128::from(segment.address) - i128::from(map.offset)
                + i128::from(segment.offset),
        )
    }

    pub fn for_address(&self, map: &Mapping, address: u64) -> Option<(Instance, u64)> {
        let executable = map.executable();
        self.instances.iter().find_map(|&instance| {
            let elf_address = instance.unrelocate(address)?;
            self.segments
                .iter()
                .any(|&segment| {
                    (!executable || segment.executable)
                        && segment.contains(elf_address)
                        && self.mapping_bias(map, segment) == Some(instance.bias)
                })
                .then_some((instance, elf_address))
        })
    }

    pub fn runtime(
        &self,
        instance: Instance,
        address: u64,
        module: &Module,
        anonymous: &[Mapping],
    ) -> Option<u64> {
        if !self
            .segments
            .iter()
            .any(|segment| segment.contains(address))
        {
            return None;
        }
        let runtime = instance.relocate(address)?;
        if let Some(map) = module.mapping_at(runtime) {
            return (self.for_address(map, runtime)?.0.base == instance.base).then_some(runtime);
        }
        let map = anonymous.iter().find(|map| map.contains(runtime))?;
        self.zerofill_address(map, runtime, module)
            .is_some_and(|(found, _)| found.base == instance.base)
            .then_some(runtime)
    }

    pub fn zerofill_address(
        &self,
        map: &Mapping,
        address: u64,
        module: &Module,
    ) -> Option<(Instance, u64)> {
        self.instances.iter().find_map(|&instance| {
            let elf_address = instance.unrelocate(address)?;
            self.segments
                .iter()
                .any(|&segment| {
                    if !segment.contains(elf_address)
                        || elf_address - segment.address < segment.file_size
                    {
                        return false;
                    }
                    let memory_start = segment
                        .address
                        .checked_add(segment.file_size)
                        .and_then(|value| value.checked_add(self.page - 1))
                        .map(|value| value & !(self.page - 1))
                        .and_then(|value| instance.relocate(value));
                    memory_start == Some(map.start)
                        && module.maps.iter().any(|mapping| {
                            mapping.end == map.start
                                && self.mapping_bias(mapping, segment) == Some(instance.bias)
                        })
                })
                .then_some((instance, elf_address))
        })
    }
}

impl ModuleInfo {
    pub fn with_elf(
        mut self,
        build_id: Option<&[u8]>,
        layout: &Layout,
        kind: &'static str,
    ) -> Self {
        self.identity.build_id = build_id.map(id_hex);
        self.load_instances = layout
            .instances
            .iter()
            .map(|instance| LoadInstanceInfo {
                base: hex(instance.base),
                load_bias: signed_hex(instance.bias),
            })
            .collect();
        if self.kind == "executable_mapping" {
            self.kind = kind;
        }
        self
    }
}

pub fn signed_hex(value: i128) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{value:x}")
    }
}

pub fn symbol(obj: &object::File<'_>, pc: u64) -> Option<crate::cpp_names::Names> {
    let s = obj
        .symbols()
        .chain(obj.dynamic_symbols())
        .filter(|s| {
            s.kind() == SymbolKind::Text
                && s.is_definition()
                && pc >= s.address()
                && pc - s.address() < s.size()
        })
        .max_by_key(|s| s.address())?;
    let name = s.name().ok()?;
    Some(crate::cpp_names::names(name))
}
