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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Backing {
    major: u32,
    minor: u32,
    inode: u64,
    path: Vec<u8>,
}

pub struct Module {
    backing: Backing,
    pub maps: Vec<Mapping>,
}

#[derive(Serialize)]
pub struct ModuleInfo {
    id: usize,
    kind: &'static str,
    path: String,
    device: String,
    inode: String,
    mappings: Vec<MappingInfo>,
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

pub fn read(base: &Path) -> Result<Vec<Module>> {
    let data = fs::read(base.join("maps"))?;
    let mut files = BTreeMap::<Backing, Vec<Mapping>>::new();
    let mut executable = BTreeSet::new();
    for line in data.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
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
        let path = rest.trim_ascii_start();
        if inode == 0 && path != b"[vdso]" {
            continue;
        }
        let backing = Backing {
            major: u32::from_str_radix(major, 16)?,
            minor: u32::from_str_radix(minor, 16)?,
            inode,
            path: path.to_vec(),
        };
        if perms.as_bytes().get(2) == Some(&b'x') {
            executable.insert(backing.clone());
        }
        files.entry(backing).or_default().push(Mapping {
            start: u64::from_str_radix(start, 16)?,
            end: u64::from_str_radix(end, 16)?,
            offset,
            perms,
        });
    }
    let mut modules: Vec<_> = files
        .into_iter()
        .filter(|(k, _)| executable.contains(k))
        .map(|(backing, maps)| Module { backing, maps })
        .collect();
    modules.sort_unstable_by_key(|m| m.maps[0].start);
    Ok(modules)
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
            path: String::from_utf8_lossy(&b.path).into_owned(),
            device: format!("{:x}:{:x}", b.major, b.minor),
            inode: b.inode.to_string(),
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

    pub fn executable_at(&self, pc: u64) -> Option<&Mapping> {
        self.maps
            .iter()
            .find(|m| m.start <= pc && pc < m.end && m.perms.as_bytes().get(2) == Some(&b'x'))
    }

    fn matches(&self, m: &fs::Metadata) -> bool {
        let b = &self.backing;
        b.inode == m.ino() && b.major == libc::major(m.dev()) && b.minor == libc::minor(m.dev())
    }

    fn open(&self, root: &Path, is_main: bool) -> Result<File> {
        let b = &self.backing;
        if b.inode == 0 {
            return Err(error("no on-disk image for this mapping"));
        }
        let mut candidates = vec![];
        if is_main {
            candidates.push(root.join("exe"));
        }
        if let Some(m) = self
            .maps
            .iter()
            .find(|m| m.perms.as_bytes().get(2) == Some(&b'x'))
        {
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

pub fn is_executable_module(obj: &object::File<'_>) -> bool {
    obj.format() == object::BinaryFormat::Elf
        && obj.is_64()
        && obj.is_little_endian()
        && matches!(obj.kind(), ObjectKind::Dynamic | ObjectKind::Executable)
}

pub fn link_address(obj: &object::File<'_>, offset: u64) -> Option<u64> {
    obj.segments().find_map(|p| {
        let (off, size) = p.file_range();
        if !matches!(p.flags(), SegmentFlags::Elf {p_flags, ..} if (p_flags & object::elf::PF_X).0 != 0) {
            return None;
        }
        let delta = offset.checked_sub(off)?;
        (delta < size)
            .then(|| p.address().checked_add(delta))
            .flatten()
    })
}

pub fn symbol(obj: &object::File<'_>, pc: u64) -> Option<String> {
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
    Some(
        cpp_demangle::Symbol::new(name.as_bytes())
            .ok()
            .and_then(|s| s.demangle().ok())
            .unwrap_or_else(|| name.to_owned()),
    )
}
