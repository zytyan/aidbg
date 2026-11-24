use crate::{Result, error, hex};
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, SectionFlags,
    SectionIndex, SymbolSection, elf,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path,
};

const LIMIT: usize = 16 * 1024 * 1024;

pub(super) fn relocate(
    file: &Path,
    base: u64,
    external: impl Fn(&str) -> Result<Option<u64>>,
) -> Result<(Vec<u8>, Vec<Value>)> {
    if !file.is_absolute() {
        return Err(error("object path must be absolute on the server"));
    }
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(file)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() > LIMIT as u64 {
        return Err(error("invalid or oversized object file"));
    }
    let mut bytes = Vec::new();
    input.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT {
        return Err(error("object file exceeds size limit"));
    }
    let object = object::File::parse(bytes.as_slice())?;
    let machine = if cfg!(target_arch = "x86_64") {
        object::Architecture::X86_64
    } else {
        object::Architecture::Aarch64
    };
    if object.format() != object::BinaryFormat::Elf
        || object.kind() != object::ObjectKind::Relocatable
        || object.architecture() != machine
        || !object.is_little_endian()
    {
        return Err(error(
            "expected a native little-endian ELF relocatable object",
        ));
    }
    let mut image = Vec::new();
    let mut sections = BTreeMap::<usize, (usize, usize)>::new();
    let mut unsupported = Vec::new();
    for section in object.sections() {
        let SectionFlags::Elf { sh_flags, .. } = section.flags() else {
            continue;
        };
        if !sh_flags.contains(elf::SHF_ALLOC) {
            continue;
        }
        if sh_flags.contains(elf::SHF_TLS) {
            unsupported.push("TLS");
            continue;
        }
        let alignment = section.align().max(1);
        if !alignment.is_power_of_two() || alignment > LIMIT as u64 {
            return Err(error("invalid ELF section alignment"));
        }
        let start = base
            .checked_add(image.len() as u64)
            .and_then(|address| address.checked_next_multiple_of(alignment))
            .ok_or_else(|| error("linked section address overflows"))?
            - base;
        let end = start
            .checked_add(section.size())
            .filter(|&size| size <= LIMIT as u64 && base.checked_add(size).is_some())
            .ok_or_else(|| error("linked object exceeds size limit"))?;
        let (start, end) = (start as usize, end as usize);
        sections.insert(section.index().0, (start, end));
        image.resize(end, 0);
        let data = section.data()?;
        image
            .get_mut(start..start + data.len())
            .filter(|_| data.len() <= end - start)
            .ok_or_else(|| error("invalid ELF section contents"))?
            .copy_from_slice(data);
    }
    if !unsupported.is_empty() {
        return Err(error("NotSupport: thread-local object sections"));
    }
    let resolve = |section: SectionIndex| -> Result<u64> {
        let (offset, _) = sections
            .get(&section.0)
            .ok_or_else(|| error("relocation references a non-allocated section"))?;
        Ok(base + *offset as u64)
    };
    for section in object.sections() {
        let Some(&(start, end)) = sections.get(&section.index().0) else {
            continue;
        };
        for (offset, relocation) in section.relocations() {
            let offset = usize::try_from(offset)?;
            let location = start
                .checked_add(offset)
                .filter(|&location| location < end)
                .ok_or_else(|| error("relocation lies outside its section"))?;
            let target = match relocation.target() {
                RelocationTarget::Section(section) => resolve(section)?,
                RelocationTarget::Symbol(index) => {
                    let symbol = object.symbol_by_index(index)?;
                    match symbol.section() {
                        SymbolSection::Section(section) => resolve(section)?
                            .checked_add(symbol.address())
                            .ok_or_else(|| error("symbol address overflow"))?,
                        SymbolSection::Absolute => symbol.address(),
                        SymbolSection::Undefined => {
                            let name = symbol.name()?;
                            match external(name)? {
                                Some(address) => address,
                                None if symbol.is_weak() => 0,
                                None => {
                                    return Err(error(format!("undefined object symbol {name}")));
                                }
                            }
                        }
                        _ => return Err(error("NotSupport: ELF common symbol storage")),
                    }
                }
                _ => return Err(error("unsupported ELF relocation target")),
            };
            let RelocationFlags::Elf { r_type } = relocation.flags() else {
                return Err(error("expected ELF relocation"));
            };
            if relocation.has_implicit_addend() {
                return Err(error(
                    "NotSupport: ELF relocations without explicit addends",
                ));
            }
            let target = i128::from(target) + i128::from(relocation.addend());
            let place = i128::from(base) + location as i128;
            apply(&mut image[location..end], r_type, target, place)?;
        }
    }
    let mut syms = Vec::new();
    for symbol in object.symbols().filter(|symbol| symbol.is_global()) {
        if let Some(section) = symbol.section_index()
            && sections.contains_key(&section.0)
            && let Ok(name) = symbol.name()
            && !name.is_empty()
        {
            syms.push(json!({"name":name,"address":hex(resolve(section)?.checked_add(symbol.address()).ok_or_else(||error("symbol address overflow"))?),
                "size":symbol.size(),"module":file}));
        }
    }
    Ok((image, syms))
}

fn replace(output: &mut [u8], bytes: &[u8]) -> Result<()> {
    output
        .get_mut(..bytes.len())
        .ok_or_else(|| error("relocation extends beyond section"))?
        .copy_from_slice(bytes);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn apply(output: &mut [u8], kind: elf::RelocationType, target: i128, place: i128) -> Result<()> {
    match kind {
        elf::R_X86_64_NONE => Ok(()),
        elf::R_X86_64_64 => replace(output, &u64::try_from(target)?.to_le_bytes()),
        elf::R_X86_64_32 => replace(output, &u32::try_from(target)?.to_le_bytes()),
        elf::R_X86_64_32S => replace(output, &i32::try_from(target)?.to_le_bytes()),
        elf::R_X86_64_PC32 | elf::R_X86_64_PLT32 => {
            replace(output, &i32::try_from(target - place)?.to_le_bytes())
        }
        _ => Err(error(format!(
            "NotSupport: x86-64 ELF relocation {}",
            kind.0
        ))),
    }
}

#[cfg(target_arch = "aarch64")]
fn apply(output: &mut [u8], kind: elf::RelocationType, target: i128, place: i128) -> Result<()> {
    match kind {
        elf::R_AARCH64_NONE => return Ok(()),
        elf::R_AARCH64_ABS64 => return replace(output, &u64::try_from(target)?.to_le_bytes()),
        elf::R_AARCH64_ABS32 => return replace(output, &u32::try_from(target)?.to_le_bytes()),
        elf::R_AARCH64_PREL32 => {
            return replace(output, &i32::try_from(target - place)?.to_le_bytes());
        }
        _ => {}
    }
    let delta = target - place;
    let (mask, bits) = match kind {
        elf::R_AARCH64_CALL26 | elf::R_AARCH64_JUMP26 => {
            if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
                return Err(error("AArch64 branch relocation is out of range"));
            }
            (0x03ff_ffff, (delta >> 2) as u32 & 0x03ff_ffff)
        }
        elf::R_AARCH64_ADR_PREL_PG_HI21 | elf::R_AARCH64_ADR_PREL_PG_HI21_NC => {
            let delta = ((target & !4095) - (place & !4095)) >> 12;
            if !(-(1 << 20)..(1 << 20)).contains(&delta) {
                return Err(error("AArch64 ADRP relocation is out of range"));
            }
            (
                0x60ff_ffe0,
                ((delta as u32 & 3) << 29) | ((delta as u32 & 0x1f_fffc) << 3),
            )
        }
        elf::R_AARCH64_ADD_ABS_LO12_NC
        | elf::R_AARCH64_LDST8_ABS_LO12_NC
        | elf::R_AARCH64_LDST16_ABS_LO12_NC
        | elf::R_AARCH64_LDST32_ABS_LO12_NC
        | elf::R_AARCH64_LDST64_ABS_LO12_NC
        | elf::R_AARCH64_LDST128_ABS_LO12_NC => {
            let shift = match kind {
                elf::R_AARCH64_LDST16_ABS_LO12_NC => 1,
                elf::R_AARCH64_LDST32_ABS_LO12_NC => 2,
                elf::R_AARCH64_LDST64_ABS_LO12_NC => 3,
                elf::R_AARCH64_LDST128_ABS_LO12_NC => 4,
                _ => 0,
            };
            (0x003f_fc00, ((target as u32 & 4095) >> shift) << 10)
        }
        _ => {
            return Err(error(format!(
                "NotSupport: AArch64 ELF relocation {}",
                kind.0
            )));
        }
    };
    let previous = u32::from_le_bytes(
        output
            .get(..4)
            .ok_or_else(|| error("truncated AArch64 relocation"))?
            .try_into()?,
    );
    replace(output, &((previous & !mask) | bits).to_le_bytes())
}
