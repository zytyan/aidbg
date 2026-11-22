use super::*;

pub(crate) fn read_range(
    request: &crate::rpc::ReadMemoryRequest,
    read: impl FnOnce(u64, &mut [u8]) -> Result<usize>,
) -> Result<Value> {
    let address = request.address;
    let length = request.length as usize;
    if !(1..=64 * 1024).contains(&length) || address.checked_add(length as u64).is_none() {
        return Err(Diagnostic::new(
            "INVALID_ARGUMENT",
            "Read length must be 1–65536 bytes and the address range must fit in u64",
            None,
        )
        .into());
    }
    let mut bytes = vec![0; length];
    let count = read(address, &mut bytes)?;
    Ok(json!({
        "address": hex(address),
        "length": length,
        "bytes_read": count,
        "bytes": crate::modules::id_hex(&bytes[..count]),
        "complete": count == length,
        "first_unread_address": (count != length).then(|| hex(address + count as u64)),
    }))
}

pub fn read_live(pid: i32, request: &crate::rpc::ReadMemoryRequest) -> Result<Value> {
    read_range(request, |address, output| {
        crate::trace::read_process_prefix(pid, address, output, || true)
            .map_err(|error| Diagnostic::new("MEMORY_READ_FAILED", error.to_string(), None).into())
    })
}

impl Target {
    pub(crate) fn read_prefix(&self, address: u64, output: &mut [u8]) -> Result<usize> {
        match self.read_at(address, output) {
            Ok(()) => Ok(output.len()),
            Err(error) => match error.downcast_ref::<MissingMemory>() {
                Some(missing) => Ok((missing.0 - address) as usize),
                None => Err(error),
            },
        }
    }

    pub fn read_memory(&self, request: &crate::rpc::ReadMemoryRequest) -> Result<Value> {
        read_range(request, |address, output| self.read_prefix(address, output))
    }

    fn copy_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let mut data = vec![0; length];
        match self.read_at(address, &mut data) {
            Ok(()) => Ok(data),
            Err(error) => {
                if let Some(missing) = error.downcast_ref::<MissingMemory>() {
                    return Err(self.missing_memory(missing.0).into());
                }
                Err(error)
            }
        }
    }

    pub fn patch(&self, mut request: crate::rpc::PatchRequest) -> Result<Value> {
        let length = request.original_length.unwrap_or_default() as usize;
        if !(1..=crate::code::MAX_CODE).contains(&length) || !request.original.is_empty() {
            return Err(Diagnostic::new(
                "INVALID_ARGUMENT",
                "Core patch planning requires original_length and no original bytes",
                None,
            )
            .into());
        }
        request.original = self.copy_bytes(request.base, length)?;
        let mut report = serde_json::to_value(crate::code::patch(request)?)?;
        report["target_id"] = json!(self.id);
        report["warnings"] = json!(self.warnings);
        Ok(report)
    }

    pub fn emulate(&self, mut request: crate::rpc::EmulateRequest) -> Result<Value> {
        let handle = request.frame.clone().ok_or_else(|| {
            Diagnostic::new(
                "NO_FRAME_CONTEXT",
                "Select a core frame to initialize the emulator",
                None,
            )
        })?;
        let frame = self.frame(&handle).ok_or_else(|| {
            Diagnostic::new(
                "NO_FRAME_CONTEXT",
                "Frame is absent from this core target",
                None,
            )
        })?;
        let flags = handle
            .rsplit_once(':')
            .filter(|(_, index)| *index == "0")
            .and_then(|(prefix, _)| prefix.rsplit_once(':'))
            .and_then(|(_, tid)| tid.parse().ok())
            .and_then(|tid| self.threads.get(&tid).map(|thread| thread.flags));
        let mut missing = Vec::new();
        let (pc, flag_name, names) = simulation_registers();
        for (index, name) in names.iter().enumerate() {
            if *name == pc || request.registers.contains_key(*name) {
                continue;
            }
            match frame.regs.get(gimli::Register(index as u16)) {
                Ok(value) => {
                    request.registers.insert((*name).to_owned(), value);
                }
                Err(_) => missing.push(*name),
            }
        }
        if !request.registers.contains_key(flag_name) {
            if let Some(flags) = flags {
                request.registers.insert(flag_name.into(), flags);
            } else {
                missing.push(flag_name);
            }
        }
        if !missing.is_empty() {
            return Err(Diagnostic::new(
                "CORE_REGISTERS_UNAVAILABLE",
                format!(
                    "Core frame is missing simulated registers: {}",
                    missing.join(", ")
                ),
                Some("Use a captured top frame or provide explicit values for these registers."),
            )
            .into());
        }
        if let Some(length) = request.code_length {
            if !(1..=crate::code::MAX_CODE).contains(&(length as usize)) || !request.code.is_empty()
            {
                return Err(Diagnostic::new(
                    "INVALID_ARGUMENT",
                    "Supply code or a bounded core code_length",
                    None,
                )
                .into());
            }
            request.code = self.copy_bytes(request.address, length as usize)?;
        }

        const MAX_COPY: u64 = 256 * 1024;
        let copied_bytes = request
            .core_memory
            .iter()
            .map(|range| u64::from(range.length))
            .sum::<u64>()
            + request
                .memory
                .iter()
                .map(|copy| copy.contents.len() as u64)
                .sum::<u64>();
        if copied_bytes > MAX_COPY || request.core_memory.len() + request.memory.len() > 32 {
            return Err(Diagnostic::new(
                "INVALID_ARGUMENT",
                "Core emulation memory exceeds the simulation budget",
                None,
            )
            .into());
        }
        for range in request.core_memory.drain(..) {
            if range.length == 0 || range.overlays.len() > 32 {
                return Err(Diagnostic::new(
                    "INVALID_ARGUMENT",
                    "Invalid core copy length or overlay count",
                    None,
                )
                .into());
            }
            let mut contents = self.copy_bytes(range.address, range.length as usize)?;
            for overlay in range.overlays {
                let span = (|| {
                    let offset =
                        usize::try_from(overlay.address.checked_sub(range.address)?).ok()?;
                    Some(offset..offset.checked_add(overlay.contents.len())?)
                })();
                let Some(destination) = span.and_then(|span| contents.get_mut(span)) else {
                    return Err(Diagnostic::new(
                        "INVALID_ARGUMENT",
                        "Memory overlay lies outside its core copy",
                        None,
                    )
                    .into());
                };
                destination.copy_from_slice(&overlay.contents);
            }
            request.memory.push(crate::rpc::MemoryCopy {
                address: range.address,
                contents,
                writable: range.writable,
            });
        }
        let mut report = serde_json::to_value(crate::code::emulate(request)?)?;
        report["target_id"] = json!(self.id);
        report["frame"] = json!(handle);
        report["warnings"] = json!(self.warnings);
        Ok(report)
    }

    pub fn search_memory(&self, request: &crate::rpc::SearchMemoryRequest) -> Result<Value> {
        let regions = self
            .segments
            .iter()
            .map(|segment| SearchRegion {
                start: segment.start,
                end: segment.end,
                readable_end: segment.start + segment.size,
                executable: segment.executable,
            })
            .collect::<Vec<_>>();
        let mut report = search(
            request,
            self.architecture,
            &regions,
            self.warnings.clone(),
            |address, data| {
                self.read_at(address, data).map_err(|error| {
                    if let Some(missing) = error.downcast_ref::<MissingMemory>() {
                        self.missing_memory(missing.0).into()
                    } else {
                        error
                    }
                })
            },
        )?;
        if request.instruction_references {
            annotate_references(&mut report, |address| self.resolve(address).ok());
        }
        Ok(report)
    }

    pub fn pointer_chain(&self, base: u64, offsets: Vec<i64>) -> Result<Value> {
        pointer_chain_with(
            base,
            offsets,
            self.warnings.clone(),
            |address, bytes| self.read_prefix(address, bytes),
            |address| self.missing_memory(address),
        )
    }
}

pub fn pointer_chain_live(pid: i32, base: u64, offsets: Vec<i64>) -> Result<Value> {
    pointer_chain_with(
        base,
        offsets,
        Vec::new(),
        |address, bytes| crate::trace::read_process_prefix(pid, address, bytes, || true),
        live_missing_memory,
    )
}

pub(crate) fn live_missing_memory(address: u64) -> Diagnostic {
    Diagnostic::new(
        "MEMORY_UNAVAILABLE",
        format!("Cannot read pointer at {}", hex(address)),
        None,
    )
}

pub(crate) fn pointer_chain_with(
    base: u64,
    offsets: Vec<i64>,
    mut warnings: Vec<Diagnostic>,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<usize>,
    missing: impl Fn(u64) -> Diagnostic,
) -> Result<Value> {
    if !(1..=32).contains(&offsets.len()) {
        return Err(
            Diagnostic::new("INVALID_ARGUMENT", "Expected 1 to 32 pointer offsets", None).into(),
        );
    }
    let mut value = base;
    let mut steps = Vec::with_capacity(offsets.len());
    for offset in offsets {
        let Some(address) = value
            .checked_add_signed(offset)
            .filter(|address| address.checked_add(8).is_some())
        else {
            warnings.push(Diagnostic::new(
                "ADDRESS_OVERFLOW",
                "Pointer chain address overflowed",
                None,
            ));
            break;
        };
        let mut bytes = [0; 8];
        if read(address, &mut bytes)? != bytes.len() {
            warnings.push(missing(address));
            break;
        }
        value = u64::from_le_bytes(bytes);
        steps.push(json!({"address": hex(address), "value": hex(value)}));
    }
    Ok(json!({"steps": steps, "warnings": warnings}))
}

struct SearchRegion {
    start: u64,
    end: u64,
    readable_end: u64,
    executable: bool,
}

pub fn search_live(pid: i32, request: &crate::rpc::SearchMemoryRequest) -> Result<Value> {
    use std::os::fd::AsRawFd;

    let directory = File::open(format!("/proc/{pid}"))?;
    let root = std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    if crate::procfs::Status::read(&root)?.field("Tgid") != Some(&pid.to_string()) {
        return Err(error("pass the process ID (thread-group leader)"));
    }
    let memory = File::open(root.join("mem"))?;
    let architecture = crate::machine(&root)?;
    let regions = crate::modules::map_entries(&root)?
        .into_iter()
        .map(|(backing, map)| {
            let readable = map.perms.starts_with('r')
                && !matches!(
                    backing.path.as_slice(),
                    b"[vvar]" | b"[vvar_vclock]" | b"[vsyscall]"
                );
            SearchRegion {
                start: map.start,
                end: map.end,
                readable_end: if readable { map.end } else { map.start },
                executable: readable && map.executable(),
            }
        })
        .collect::<Vec<_>>();
    let mut report = search(
        request,
        architecture,
        &regions,
        Vec::new(),
        |address, data| {
            memory.read_exact_at(data, address)?;
            Ok(())
        },
    )?;
    if request.instruction_references {
        annotate_references(&mut report, |address| {
            let location = crate::symbols::resolve(pid, address, &[]).ok()?;
            Some(location.stop_site())
        });
    }
    report["pid"] = json!(pid);
    Ok(report)
}

fn search(
    request: &crate::rpc::SearchMemoryRequest,
    architecture: &str,
    regions: &[SearchRegion],
    mut warnings: Vec<Diagnostic>,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<Value> {
    if request.instruction_references {
        return instruction_references(request, architecture, regions, warnings, read);
    }
    if request.resume_from.is_some() {
        return Err(Diagnostic::new(
            "INVALID_ARGUMENT",
            "resume_from requires instruction_references",
            None,
        )
        .into());
    }
    let pointer_bytes = request.pointer_value.map(u64::to_le_bytes);
    let pattern = pointer_bytes
        .as_ref()
        .map_or(request.pattern.as_slice(), |bytes| bytes.as_slice());
    let start = request.start.unwrap_or(0);
    let end = request.end.unwrap_or(u64::MAX);
    let limit = request.limit.unwrap_or(64) as usize;
    let budget = u64::from(request.max_scan_bytes.unwrap_or(16 * 1024 * 1024));
    let alignment =
        u64::from(
            request
                .alignment
                .unwrap_or(if pointer_bytes.is_some() { 8 } else { 1 }),
        );
    if start >= end
        || pattern.is_empty()
        || pattern.len() > 256
        || !(1..=256).contains(&limit)
        || !(1..=256 * 1024 * 1024).contains(&budget)
        || !alignment.is_power_of_two()
        || alignment > 4096
        || (pointer_bytes.is_some() && !request.pattern.is_empty())
    {
        return Err(Diagnostic::new(
            "INVALID_ARGUMENT",
            "Invalid memory search range, pattern or budget",
            None,
        )
        .into());
    }
    let missing_bytes: u64 = regions
        .iter()
        .map(|segment| {
            end.min(segment.end)
                .saturating_sub(start.max(segment.readable_end))
        })
        .sum();
    let mut scanned = 0;
    let mut matches = Vec::new();
    let mut next_address = None;
    let mut previous_end = None;
    let mut window = Vec::with_capacity(64 * 1024 + pattern.len());
    'segments: for segment in regions {
        let mut address = start.max(segment.start);
        let stop = end.min(segment.readable_end);
        if address >= stop {
            continue;
        }
        if previous_end != Some(address) {
            window.clear();
        }
        while address < stop {
            if scanned == budget {
                next_address = Some(address - window.len() as u64);
                break 'segments;
            }
            let prefix = window.len();
            let base = address - prefix as u64;
            let count = (stop - address).min(budget - scanned).min(64 * 1024) as usize;
            window.resize(prefix + count, 0);
            read(address, &mut window[prefix..])?;
            for (offset, bytes) in window.windows(pattern.len()).enumerate() {
                let at = base + offset as u64;
                if at.is_multiple_of(alignment) && bytes == pattern {
                    if matches.len() == limit {
                        next_address = Some(at);
                        scanned += count as u64;
                        break 'segments;
                    }
                    matches.push(hex(at));
                }
            }
            scanned += count as u64;
            address += count as u64;
            let keep = window.len().min(pattern.len() - 1);
            let from = window.len() - keep;
            window.copy_within(from.., 0);
            window.truncate(keep);
        }
        previous_end = Some(stop);
    }
    if missing_bytes > 0 {
        warnings.push(Diagnostic::new(
            "SEARCH_COVERAGE_GAPS",
            format!("{missing_bytes} mapped bytes in the requested interval were not captured"),
            None,
        ));
    }
    if next_address.is_some() {
        warnings.push(Diagnostic::new(
            "SEARCH_TRUNCATED",
            "Search stopped at its result or byte limit",
            Some("Continue at next_address with the same pattern."),
        ));
    }
    Ok(json!({
        "matches": matches, "scanned_bytes": scanned, "uncaptured_bytes": missing_bytes,
        "next_address": next_address.map(hex),
        "kind": if pointer_bytes.is_some() { "pointer_value" } else { "byte_pattern" },
        "warnings": warnings,
    }))
}

fn annotate_references(report: &mut Value, mut resolve: impl FnMut(u64) -> Option<Value>) {
    if let Some(matches) = report["matches"].as_array_mut() {
        for row in matches {
            if let Some(address) = row["instruction"]
                .as_str()
                .and_then(|address| u64::from_str_radix(address.trim_start_matches("0x"), 16).ok())
                && let Some(site) = resolve(address)
            {
                row["function"] = site.get("function").unwrap_or(&site["display"]).clone();
                row["source_line"] = site["source_line"].clone();
            }
        }
    }
}

fn instruction_references(
    request: &crate::rpc::SearchMemoryRequest,
    architecture: &str,
    regions: &[SearchRegion],
    mut warnings: Vec<Diagnostic>,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<Value> {
    let limit = request.limit.unwrap_or(64) as usize;
    let range = request.start.zip(request.end).zip(request.pointer_value);
    let Some(((start, end), address)) = range.filter(|((start, end), _)| {
        end.checked_sub(*start).is_some_and(|length| {
            (1..=u64::from(request.max_scan_bytes.unwrap_or(65_536).min(65_536))).contains(&length)
        })
    }) else {
        return Err(Diagnostic::new("INVALID_ARGUMENT", "Instruction xref requires an address and a bounded start/end interval of at most 64 KiB", None).into());
    };
    if !(1..=256).contains(&limit)
        || request.alignment.is_some()
        || !request.pattern.is_empty()
        || (architecture == "aarch64" && (!start.is_multiple_of(4) || !end.is_multiple_of(4)))
        || !regions
            .iter()
            .any(|segment| segment.executable && segment.start <= start && end <= segment.end)
    {
        return Err(Diagnostic::new(
            "INVALID_ARGUMENT",
            "Instruction xref requires one executable mapping and aligned instruction boundaries",
            None,
        )
        .into());
    }
    let mut code = vec![0; (end - start) as usize];
    read(start, &mut code)?;
    let resume_from = request.resume_from.unwrap_or(start);
    if !(start..end).contains(&resume_from)
        || (architecture == "aarch64" && !resume_from.is_multiple_of(4))
    {
        return Err(Diagnostic::new(
            "INVALID_ARGUMENT",
            "resume_from must be an instruction address within start/end",
            None,
        )
        .into());
    }
    let report =
        crate::disassembly::references(architecture, start, &code, address, resume_from, limit)?;
    if report.decoded_end < end && report.next_address.is_none() {
        warnings.push(Diagnostic::new(
            "INSTRUCTION_DECODE_STOPPED",
            format!(
                "Instruction decoding stopped at {}",
                hex(report.decoded_end)
            ),
            None,
        ));
    }
    if report.skipped_words > 0 {
        warnings.push(Diagnostic::new(
            "INSTRUCTION_DECODE_GAPS",
            format!(
                "Skipped {} undecodable AArch64 instruction words",
                report.skipped_words
            ),
            None,
        ));
    }
    if report.next_address.is_some() {
        warnings.push(Diagnostic::new(
            "SEARCH_TRUNCATED",
            "Instruction xref reached its result limit",
            Some("Keep start/end and pass next_address as resume_from."),
        ));
    }
    Ok(json!({
        "kind": "instruction_reference", "matches": report.matches,
        "scanned_bytes": report.decoded_end - start, "next_address": report.next_address.map(hex),
        "warnings": warnings,
    }))
}

#[cfg(target_arch = "x86_64")]
fn simulation_registers() -> (&'static str, &'static str, &'static [&'static str]) {
    (
        "rip",
        "eflags",
        &[
            "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15", "rip",
        ],
    )
}

#[cfg(target_arch = "aarch64")]
fn simulation_registers() -> (&'static str, &'static str, &'static [&'static str]) {
    (
        "pc",
        "nzcv",
        &[
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x28", "x29", "x30", "sp", "pc",
        ],
    )
}
