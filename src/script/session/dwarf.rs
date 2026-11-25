use crate::{Result, error, modules, symbols::inspect::offline::DwarfImage};
use object::{Object, ObjectSection, SectionFlags};
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    ops::Range,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Instant,
};

const MAX_IMAGE: u64 = 64 * 1024 * 1024;

pub(in crate::script) struct AttachedDwarf {
    pub image: DwarfImage,
    regions: Vec<(Range<u64>, u64)>,
    bias: Option<u64>,
}

impl AttachedDwarf {
    pub fn load(
        path: PathBuf,
        position: &Value,
        infer: impl FnOnce(&object::File<'_>, &Path) -> Result<u64>,
    ) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&path)?;
        if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_IMAGE {
            return Err(error("expected a regular DWARF ELF file of at most 64 MiB"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_IMAGE + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_IMAGE {
            return Err(error("DWARF ELF file exceeds 64 MiB"));
        }
        let object = object::File::parse(bytes.as_slice())?;
        if object.format() != object::BinaryFormat::Elf
            || !object.is_64()
            || !object.is_little_endian()
            || object.architecture()
                != if crate::regs::ARCH == "x86_64" {
                    object::Architecture::X86_64
                } else {
                    object::Architecture::Aarch64
                }
        {
            return Err(error("DWARF file does not match the debugger's target ABI"));
        }
        if object.kind() == object::ObjectKind::Relocatable {
            return Err(error("attachDwarf expects a linked ELF debug image"));
        }
        let bias = match position {
            Value::Null => Some(infer(&object, &path)?),
            Value::String(_) => Some(super::target::parse_address(position)?),
            Value::Object(sections) if !sections.is_empty() => None,
            _ => {
                return Err(error(
                    "expected the ELF load bias or a nonempty section address map",
                ));
            }
        };
        let mut regions = Vec::new();
        if let Some(bias) = bias {
            for section in object.sections().filter(|section|
                matches!(section.flags(), SectionFlags::Elf { sh_flags, .. } if sh_flags.contains(object::elf::SHF_EXECINSTR))
            ) {
                let start = relocate(section.address(), bias)?;
                regions.push((start..relocate(start, section.size())?, section.address()));
            }
        } else if let Some(sections) = position.as_object() {
            for (name, start) in sections {
                let section = object
                    .section_by_name(name)
                    .filter(|section| section.size() != 0)
                    .ok_or_else(|| error(format!("missing or empty ELF section {name:?}")))?;
                let start = super::target::parse_address(start)?;
                regions.push((start..relocate(start, section.size())?, section.address()));
            }
        }
        regions.sort_unstable_by_key(|(range, _)| range.start);
        if regions
            .windows(2)
            .any(|pair| pair[0].0.end > pair[1].0.start)
        {
            return Err(error("overlapping runtime ELF section addresses"));
        }
        let image = DwarfImage::load(&object, bias.unwrap_or(0), path)?
            .ok_or_else(|| error("stripped dwarf: missing .debug_info"))?;
        Ok(Self {
            image,
            regions,
            bias,
        })
    }

    pub fn link_address(&self, address: u64) -> Option<u64> {
        self.regions
            .iter()
            .find(|(range, _)| range.contains(&address))
            .map(|(range, link)| link + (address - range.start))
    }

    pub fn runtime_address(&self, address: u64) -> Option<u64> {
        self.regions.iter().find_map(|(range, link)| {
            let offset = address.checked_sub(*link)?;
            (offset < range.end - range.start).then(|| range.start + offset)
        })
    }

    pub fn uniform_bias(&self) -> Option<u64> {
        self.bias
    }
}

fn relocate(address: u64, offset: u64) -> Result<u64> {
    address
        .checked_add(offset)
        .ok_or_else(|| error("ELF relocation overflows the address space"))
}

pub(super) fn infer_bias(
    root: &Path,
    debug: &object::File<'_>,
    path: &Path,
    deadline: Instant,
) -> Result<u64> {
    let build_id = debug.build_id()?;
    let exe = fs::metadata(root.join("exe")).ok();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let basename = name.strip_suffix(".debug").unwrap_or(name);
    let mut candidates = Vec::new();
    for module in modules::read(root)? {
        if Instant::now() >= deadline {
            return Err(error("ELF module matching timed out; supply a position"));
        }
        if build_id.is_none()
            && module
                .path()
                .file_name()
                .is_none_or(|name| name != basename)
        {
            continue;
        }
        let Ok(bytes) = module.read_image(root, exe.as_ref(), MAX_IMAGE) else {
            continue;
        };
        let Ok(object) = object::File::parse(bytes.as_slice()) else {
            continue;
        };
        if build_id.is_some() && object.build_id()? != build_id {
            continue;
        }
        let Ok(layout) = modules::Layout::new(&object, &module) else {
            continue;
        };
        for instance in layout.instances {
            candidates.push((module.path(), instance.bias));
        }
    }
    unique_bias(&candidates)
}

pub(in crate::script) fn unique_bias(candidates: &[(PathBuf, i128)]) -> Result<u64> {
    match candidates {
        [(_, bias)] => Ok(u64::try_from(*bias)?),
        [] => Err(error("no matching ELF module; supply a position")),
        _ => Err(error(format!(
            "ambiguous ELF modules {candidates:?}; supply a position"
        ))),
    }
}
