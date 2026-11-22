use super::*;
use std::collections::BTreeMap;
use std::ffi::c_void;

const MAX_COPY: usize = 256 * 1024;
const MAX_EVENTS: usize = 512;
const MEM_READ: c_int = 16;
const MEM_WRITE: c_int = 17;

struct Engine(Handle);

impl Engine {
    fn open() -> Result<Self> {
        let (arch, mode) = if cfg!(target_arch = "x86_64") {
            (4, 8)
        } else {
            (2, 0)
        };
        let mut handle = ptr::null_mut();
        let code = unsafe { uc_open(arch, mode, &mut handle) };
        if code != 0 || handle.is_null() {
            return Err(engine_error("Unicorn open", uc_strerror, code));
        }
        Ok(Self(handle))
    }

    fn check(&self, action: &str, code: c_int) -> Result<()> {
        if code != 0 {
            Err(engine_error(action, uc_strerror, code))
        } else {
            Ok(())
        }
    }

    fn query(&self, kind: c_int) -> Result<usize> {
        let mut value = 0;
        self.check("Unicorn query", unsafe {
            uc_query(self.0, kind, &mut value)
        })?;
        Ok(value)
    }

    fn map_bytes(&self, page: &Range<u64>, address: u64, bytes: &[u8], perms: u32) -> Result<()> {
        self.check("Unicorn map", unsafe {
            uc_mem_map(self.0, page.start, page.end - page.start, perms)
        })?;
        self.check("Unicorn initialize memory", unsafe {
            uc_mem_write(self.0, address, bytes.as_ptr().cast(), bytes.len() as u64)
        })
    }

    fn reg(&self, id: c_int) -> Result<u64> {
        let mut value = 0;
        self.check("Unicorn read register", unsafe {
            uc_reg_read(self.0, id, (&mut value as *mut u64).cast())
        })?;
        Ok(value)
    }

    fn register_hook(
        &self,
        kind: c_int,
        callback: *mut c_void,
        state: &mut HookState,
    ) -> Result<()> {
        let mut hook = 0;
        // A start greater than end requests every address.
        self.check("Unicorn install hook", unsafe {
            uc_hook_add(
                self.0,
                &mut hook,
                kind,
                callback,
                (state as *mut HookState).cast(),
                1,
                0,
            )
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { uc_close(self.0) };
    }
}

fn registers() -> BTreeMap<String, c_int> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut names: BTreeMap<_, _> = [
            ("rax", 35),
            ("rbx", 37),
            ("rcx", 38),
            ("rdx", 40),
            ("rsi", 43),
            ("rdi", 39),
            ("rbp", 36),
            ("rsp", 44),
            ("rip", 41),
            ("eflags", 25),
        ]
        .into_iter()
        .map(|(name, number)| (name.to_owned(), number))
        .collect();
        names.extend((8..=15).map(|n| (format!("r{n}"), 106 + n - 8)));
        names
    }
    #[cfg(target_arch = "aarch64")]
    {
        let mut names: BTreeMap<_, _> =
            [("x29", 1), ("x30", 2), ("sp", 4), ("pc", 260), ("nzcv", 3)]
                .into_iter()
                .map(|(name, number)| (name.to_owned(), number))
                .collect();
        names.extend((0..=28).map(|n| (format!("x{n}"), 199 + n)));
        names
    }
}

fn pages(content: &Range<u64>, page: u64) -> Result<Range<u64>> {
    let mask = page - 1;
    let end = content
        .end
        .checked_add(mask)
        .ok_or_else(|| error("page-aligned range overflows"))?
        & !mask;
    Ok((content.start & !mask)..end)
}

struct ObjectProbe {
    name: String,
    bytes: Range<u64>,
    observed: Range<u64>,
}

struct Memory {
    window: Range<u64>,
    writable: bool,
}

#[derive(Serialize)]
struct Event {
    origin: &'static str,
    kind: &'static str,
    access: &'static str,
    address: String,
    size: u32,
    pc: String,
    object: Option<String>,
    write_value: Option<String>,
}

#[derive(Serialize)]
struct MemoryResult {
    address: String,
    bytes: String,
}

#[derive(Serialize)]
pub struct Report {
    architecture: &'static str,
    origin: &'static str,
    status: &'static str,
    instructions: usize,
    registers: BTreeMap<String, String>,
    unspecified_registers: Vec<String>,
    memory: Vec<MemoryResult>,
    events: Vec<Event>,
    dropped_events: usize,
    issue: Option<String>,
}

struct HookState {
    code: Range<u64>,
    copy: Vec<Memory>,
    watch: Vec<Range<u64>>,
    objects: Vec<ObjectProbe>,
    events: Vec<Event>,
    dropped_events: usize,
    instructions: usize,
    pc: u64,
    reason: Option<(&'static str, String)>,
}

impl HookState {
    fn emit(&mut self, event: Event) {
        if self.events.len() < MAX_EVENTS {
            self.events.push(event);
        } else {
            self.dropped_events += 1;
        }
    }

    fn observe(&mut self, address: u64, size: u32, write_value: Option<u64>, access: &'static str) {
        let Some(end) = address.checked_add(u64::from(size)) else {
            return;
        };
        let span = address..end;
        if self.watch.iter().any(|watch| intersects(watch, &span)) {
            self.emit(self.event("watchpoint", address, size, write_value, access, None));
        }
        for index in 0..self.objects.len() {
            let object = &self.objects[index];
            if intersects(&object.observed, &span) && !contains(&object.bytes, &span) {
                self.emit(self.event(
                    "object_out_of_bounds",
                    address,
                    size,
                    write_value,
                    access,
                    Some(object.name.clone()),
                ));
            }
        }
    }

    fn event(
        &self,
        kind: &'static str,
        address: u64,
        size: u32,
        write_value: Option<u64>,
        access: &'static str,
        object: Option<String>,
    ) -> Event {
        Event {
            origin: "simulation",
            kind,
            access,
            address: hex(address),
            size,
            pc: hex(self.pc),
            object,
            write_value: write_value.map(hex),
        }
    }

    fn fault(&mut self, handle: Handle, status: &'static str, message: String) {
        if self.reason.is_none() {
            self.reason = Some((status, message));
            unsafe { uc_emu_stop(handle) };
        }
    }
}

unsafe extern "C" fn code_hook(handle: Handle, address: u64, size: u32, data: *mut c_void) {
    let state = unsafe { &mut *data.cast::<HookState>() };
    state.pc = address;
    if address < state.code.start
        || address
            .checked_add(u64::from(size))
            .is_none_or(|end| end > state.code.end)
    {
        state.fault(
            handle,
            "missing_state",
            format!("instruction at {} is outside copied code", hex(address)),
        );
    } else {
        state.instructions += 1;
    }
}

unsafe extern "C" fn memory_hook(
    handle: Handle,
    kind: c_int,
    address: u64,
    size: c_int,
    value: i64,
    data: *mut c_void,
) {
    let state = unsafe { &mut *data.cast::<HookState>() };
    if state.reason.is_some() || size <= 0 {
        return;
    }
    let write = kind == MEM_WRITE;
    let access = if write { "write" } else { "read" };
    let write_value =
        (write && size <= 8).then_some(value as u64 & (u64::MAX >> ((8 - size.clamp(1, 8)) * 8)));
    state.observe(address, size as u32, write_value, access);
    let Some(end) = address.checked_add(size as u64) else {
        state.fault(
            handle,
            "missing_state",
            "emulated memory access overflowed".into(),
        );
        return;
    };
    let span = address..end;
    if kind == MEM_READ && contains(&state.code, &span) {
        return;
    }
    match state
        .copy
        .iter()
        .find(|memory| contains(&memory.window, &span))
    {
        None => state.fault(
            handle,
            "missing_state",
            format!("{access} at {} extends outside copied memory", hex(address)),
        ),
        Some(memory) if write && !memory.writable => state.fault(
            handle,
            "fault",
            format!("write to read-only copy at {}", hex(address)),
        ),
        _ => {}
    }
}

unsafe extern "C" fn invalid_hook(
    handle: Handle,
    kind: c_int,
    address: u64,
    size: c_int,
    value: i64,
    data: *mut c_void,
) -> bool {
    let state = unsafe { &mut *data.cast::<HookState>() };
    if state.reason.is_none() {
        let (status, access) = match kind {
            19 => ("missing_state", "read"),
            20 => ("missing_state", "write"),
            21 => ("missing_state", "execute"),
            22 => ("fault", "write"),
            23 => ("fault", "read"),
            _ => ("fault", "execute"),
        };
        if size > 0 && access != "execute" {
            let write_value = (access == "write" && size <= 8).then_some(value as u64);
            state.observe(address, size as u32, write_value, access);
        }
        state.fault(
            handle,
            status,
            format!("{access} at {} failed in simulated memory", hex(address)),
        );
    }
    false
}

pub fn emulate(request: rpc::EmulateRequest) -> Result<Report> {
    let rpc::EmulateRequest {
        address,
        code,
        registers: requested,
        memory,
        watch,
        objects,
        instruction_limit,
        timeout_ms,
        ..
    } = request;
    let limit = instruction_limit.unwrap_or(1000) as usize;
    let timeout = timeout_ms.unwrap_or(100);
    if code.is_empty()
        || code.len() > MAX_CODE
        || !(1..=100_000).contains(&limit)
        || !(1..=1000).contains(&timeout)
        || memory.len() > 32
        || watch.len() > 32
        || objects.len() > 32
        || memory.iter().map(|m| m.contents.len()).sum::<usize>() > MAX_COPY
    {
        return Err(error(
            "simulation exceeds code, memory, probe or execution limits",
        ));
    }
    if cfg!(target_arch = "aarch64")
        && (!address.is_multiple_of(4) || !code.len().is_multiple_of(4))
    {
        return Err(error(
            "AArch64 code address and size must be four-byte aligned",
        ));
    }
    let register_ids = registers();
    let pc = if cfg!(target_arch = "x86_64") {
        "rip"
    } else {
        "pc"
    };
    for (name, value) in &requested {
        if !register_ids.contains_key(name.as_str()) || (name == pc && *value != address) {
            return Err(error(format!(
                "invalid simulation register assignment: {name}"
            )));
        }
    }
    let code_range = range(address, code.len() as u64)?;
    let mut hooks = HookState {
        code: code_range.clone(),
        copy: Vec::new(),
        watch: watch
            .into_iter()
            .map(|r| range(r.address, r.length))
            .collect::<Result<_>>()?,
        objects: objects
            .into_iter()
            .map(|probe| {
                if probe.name.is_empty() || probe.name.len() > 128 || probe.guard_bytes > 4096 {
                    return Err(error("invalid object probe name or guard size"));
                }
                let bytes = range(probe.address, probe.length)?;
                let observed = bytes.start.saturating_sub(u64::from(probe.guard_bytes))
                    ..bytes.end.saturating_add(u64::from(probe.guard_bytes));
                Ok(ObjectProbe {
                    name: probe.name,
                    bytes,
                    observed,
                })
            })
            .collect::<Result<_>>()?,
        events: Vec::new(),
        dropped_events: 0,
        instructions: 0,
        pc: address,
        reason: None,
    };
    let engine = Engine::open()?;
    let page = engine.query(2)? as u64;
    if !page.is_power_of_two() {
        return Err(error("Unicorn reported invalid page size"));
    }
    let code_pages = pages(&code_range, page)?;
    engine.map_bytes(&code_pages, address, &code, 5)?;
    let mut mapped = vec![code_pages];
    for copy in &memory {
        let window = range(copy.address, copy.contents.len() as u64)?;
        let page_range = pages(&window, page)?;
        if mapped.iter().any(|other| intersects(other, &page_range)) {
            return Err(error(
                "copied code and memory regions must occupy disjoint emulator pages",
            ));
        }
        engine.map_bytes(
            &page_range,
            copy.address,
            &copy.contents,
            if copy.writable { 3 } else { 1 },
        )?;
        mapped.push(page_range);
        hooks.copy.push(Memory {
            window,
            writable: copy.writable,
        });
    }
    for (name, value) in &requested {
        if name != pc {
            engine.check("Unicorn write register", unsafe {
                uc_reg_write(engine.0, register_ids[name], (value as *const u64).cast())
            })?;
        }
    }
    engine.register_hook(4, code_hook as *mut c_void, &mut hooks)?;
    engine.register_hook(1024 | 2048, memory_hook as *mut c_void, &mut hooks)?;
    engine.register_hook(1008, invalid_hook as *mut c_void, &mut hooks)?;
    let result = unsafe {
        uc_emu_start(
            engine.0,
            address,
            code_range.end,
            u64::from(timeout) * 1000,
            limit,
        )
    };
    let pc_id = register_ids[pc];
    let (status, issue) = if let Some((status, issue)) = hooks.reason.take() {
        (status, Some(issue))
    } else if result != 0 {
        (
            "fault",
            Some(engine_error("Unicorn execution", uc_strerror, result).to_string()),
        )
    } else if engine.query(4)? != 0 {
        ("timeout", Some("execution exceeded the time limit".into()))
    } else if engine.reg(pc_id)? == code_range.end {
        ("complete", None)
    } else if hooks.instructions >= limit {
        (
            "instruction_limit",
            Some("execution reached the instruction limit".into()),
        )
    } else {
        (
            "stopped",
            Some("emulation stopped before reaching the end of copied code".into()),
        )
    };
    let mut registers = BTreeMap::new();
    let mut unspecified_registers = Vec::new();
    for (name, id) in register_ids {
        registers.insert(name.clone(), hex(engine.reg(id)?));
        if name != pc && !requested.contains_key(&name) {
            unspecified_registers.push(name);
        }
    }
    let mut memory_output = Vec::new();
    for copy in memory {
        let mut bytes = copy.contents;
        engine.check("Unicorn read memory copy", unsafe {
            uc_mem_read(
                engine.0,
                copy.address,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u64,
            )
        })?;
        memory_output.push(MemoryResult {
            address: hex(copy.address),
            bytes: modules::id_hex(&bytes),
        });
    }
    drop(engine);
    Ok(Report {
        architecture: regs::ARCH,
        origin: "simulation",
        status,
        instructions: hooks.instructions,
        registers,
        unspecified_registers,
        memory: memory_output,
        events: hooks.events,
        dropped_events: hooks.dropped_events,
        issue,
    })
}
