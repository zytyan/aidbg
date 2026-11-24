use super::CaptureLimit;
use crate::{Result, error};
use nix::libc;
use object::elf::{DT_DEBUG, DT_NULL, PT_DYNAMIC, PT_PHDR};
use std::collections::BTreeSet;
use std::fs;
use std::ops::Range;
use std::path::Path;

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn debug_record(
    root: &Path,
    read: &impl Fn(u64, &mut [u8]) -> Result<()>,
) -> Result<Option<(Range<u64>, u64)>> {
    const PROGRAM_HEADER_SIZE: u64 = 56;
    const MAX_DYNAMIC_BYTES: u64 = 64 * 1024;
    let auxv = fs::read(root.join("auxv"))?;
    let aux = |kind: libc::c_ulong| {
        auxv.chunks_exact(16)
            .find(|entry| word(entry, 0) == kind as u64)
            .map_or(0, |entry| word(entry, 8))
    };
    if aux(libc::AT_BASE) == 0 {
        return Ok(None);
    }
    let phdr = aux(libc::AT_PHDR);
    let phnum = aux(libc::AT_PHNUM);
    if phdr == 0 || aux(libc::AT_PHENT) != PROGRAM_HEADER_SIZE || !(1..=1024).contains(&phnum) {
        return Err(error("program headers unavailable"));
    }
    let mut headers = vec![0; (phnum * PROGRAM_HEADER_SIZE) as usize];
    read(phdr, &mut headers)?;
    let header = |kind: u32| {
        headers
            .chunks_exact(PROGRAM_HEADER_SIZE as usize)
            .find(|bytes| u32::from_le_bytes(bytes[..4].try_into().unwrap()) == kind)
    };
    let phdr_entry = header(PT_PHDR.0).ok_or_else(|| error("PT_PHDR unavailable"))?;
    let bias = phdr
        .checked_sub(word(phdr_entry, 16))
        .ok_or_else(|| error("invalid load bias"))?;
    let dynamic_entry = header(PT_DYNAMIC.0).ok_or_else(|| error("PT_DYNAMIC unavailable"))?;
    let size = word(dynamic_entry, 32);
    if !(16..=MAX_DYNAMIC_BYTES).contains(&size) {
        return Err(error("invalid PT_DYNAMIC size"));
    }
    let address = bias
        .checked_add(word(dynamic_entry, 16))
        .ok_or_else(|| error("invalid PT_DYNAMIC address"))?;
    let mut dynamic = vec![0; size as usize];
    read(address, &mut dynamic)?;
    let debug = dynamic
        .chunks_exact(16)
        .take_while(|entry| word(entry, 0) != DT_NULL.0 as u64)
        .find(|entry| word(entry, 0) == DT_DEBUG.0 as u64)
        .map_or(0, |entry| word(entry, 8));
    let end = address
        .checked_add(size)
        .ok_or_else(|| error("invalid PT_DYNAMIC extent"))?;
    Ok(Some((address..end, debug)))
}

pub(crate) fn rendezvous(
    root: &Path,
    read: impl Fn(u64, &mut [u8]) -> Result<()>,
) -> Result<Option<(u64, u32)>> {
    let Some((_, debug)) = debug_record(root, &read)? else {
        return Ok(None);
    };
    if debug == 0 {
        return Ok(None);
    }
    let mut current = [0; 40];
    read(debug, &mut current)?;
    let hook = word(&current, 16);
    let state = u32::from_le_bytes(current[24..28].try_into().unwrap());
    Ok((hook != 0).then_some((hook, state)))
}

// GDB reads the live SVR4 linker rendezvous to locate shared objects in a core.
pub(super) fn ranges(
    root: &Path,
    page: u64,
    read: impl Fn(u64, &mut [u8]) -> Result<()>,
    limit: &CaptureLimit<'_>,
) -> Result<Vec<Range<u64>>> {
    const MAX_LINKS: usize = 16 * 1024;
    let Some((dynamic, mut debug)) = debug_record(root, &read)? else {
        return Ok(Vec::new());
    };
    let mut ranges = vec![dynamic];

    let mut visited = BTreeSet::new();
    while debug != 0 && visited.len() < MAX_LINKS && visited.insert(debug) {
        limit.check()?;
        let mut rendezvous = [0; 40];
        read(debug, &mut rendezvous)?;
        ranges.push(debug..debug + 40);
        let mut link = word(&rendezvous, 8);
        while link != 0 && visited.len() < MAX_LINKS && visited.insert(link) {
            limit.check()?;
            let mut record = [0; 40];
            read(link, &mut record)?;
            ranges.push(link..link + 40);
            let name = word(&record, 8);
            if name != 0 {
                let mut len = 0;
                while len < 4096 {
                    let at = name
                        .checked_add(len)
                        .ok_or_else(|| error("invalid link_map name address"))?;
                    let size = (page - at % page).min(256).min(4096 - len) as usize;
                    let mut buffer = [0; 256];
                    read(at, &mut buffer[..size])?;
                    if let Some(index) = buffer[..size].iter().position(|&c| c == 0) {
                        len += (index + 1) as u64;
                        break;
                    }
                    len += size as u64;
                }
                ranges.push(name..name + len);
            }
            link = word(&record, 24);
        }
        if u32::from_le_bytes(rendezvous[..4].try_into().unwrap()) < 2 {
            break;
        }
        let mut next = [0; 8];
        read(debug + 40, &mut next)?;
        ranges.push(debug + 40..debug + 48);
        debug = word(&next, 0);
    }
    if visited.len() == MAX_LINKS {
        return Err(error("dynamic linker list exceeds the capture limit"));
    }
    Ok(ranges)
}
