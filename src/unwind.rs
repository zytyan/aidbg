use crate::modules::{self, Layout, Module, ModuleInfo};
use crate::regs::{FP, PC, Registers, SP};
use crate::trace::Trace;
use crate::{Result, error, hex};
use gimli::{
    BaseAddresses, CfaRule, DebugFrame, EhFrame, EhFrameHdr, Encoding, EndianArcSlice,
    EvaluationResult, Expression, FrameDescriptionEntry, LittleEndian, Location, ParsedEhFrameHdr,
    RegisterRule, UnwindContext, UnwindSection, Value, Vendor,
};
use object::{Object, ObjectSection};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const MAX_DEPTH: usize = 32;
const MAX_IMAGE: u64 = 32 * 1024 * 1024;
const MAX_IMAGES_TOTAL: u64 = 64 * 1024 * 1024;
type Data = EndianArcSlice<LittleEndian>;

struct Image {
    bytes: Arc<Vec<u8>>,
    symbols: Option<Vec<u8>>,
    eh: EhFrame<Data>,
    eh_index: Option<ParsedEhFrameHdr<Data>>,
    debug: DebugFrame<Data>,
    bases: BaseAddresses,
    layout: Layout,
}

impl Image {
    fn new(bytes: Arc<Vec<u8>>, module: &Module) -> Result<Self> {
        let obj = object::File::parse(bytes.as_slice())?;
        if !modules::is_executable_module(&obj) {
            return Err(error("unsupported module ELF"));
        }
        let layout = Layout::new(&obj, module)?;
        let section = |name| -> Result<Data> {
            // Frame sections are typically small. Bound decompression before
            // asking object to allocate uncompressed bytes.
            let data: Arc<[u8]> = if let Some(s) = obj.section_by_name(name) {
                let compressed = s.compressed_data()?;
                if compressed.uncompressed_size > MAX_IMAGE {
                    return Err(error("CFI section exceeds byte budget"));
                }
                Arc::from(s.uncompressed_data()?.as_ref())
            } else {
                Arc::from(&[][..])
            };
            Ok(Data::new(data, LittleEndian))
        };
        let mut eh = EhFrame::from(section(".eh_frame")?);
        let mut debug = DebugFrame::from(section(".debug_frame")?);
        eh.set_address_size(8);
        debug.set_address_size(8);
        if cfg!(target_arch = "aarch64") {
            eh.set_vendor(Vendor::AArch64);
            debug.set_vendor(Vendor::AArch64);
        }
        let addr = |name| obj.section_by_name(name).map(|s| s.address()).unwrap_or(0);
        let bases = BaseAddresses::default()
            .set_eh_frame(addr(".eh_frame"))
            .set_eh_frame_hdr(addr(".eh_frame_hdr"))
            .set_text(addr(".text"))
            .set_got(addr(".got"));
        let eh_index = section(".eh_frame_hdr")
            .ok()
            .and_then(|header| EhFrameHdr::from(header).parse(&bases, 8).ok());
        Ok(Self {
            bytes,
            symbols: None,
            eh,
            eh_index,
            debug,
            bases,
            layout,
        })
    }

    fn step(&self, pc: u64, ctx: Context<'_>, saved_cfa: &mut Option<u64>) -> Result<Step> {
        self.with_fde(pc, |section, fde| match section {
            CallFrameSection::Eh(section) => self.step_section(section, fde, pc, ctx, saved_cfa),
            CallFrameSection::Debug(section) => self.step_section(section, fde, pc, ctx, saved_cfa),
        })
    }

    fn with_fde<T>(
        &self,
        pc: u64,
        use_fde: impl FnOnce(CallFrameSection<'_>, FrameDescriptionEntry<Data>) -> Result<T>,
    ) -> Result<T> {
        let entry = self
            .eh_index
            .as_ref()
            .and_then(ParsedEhFrameHdr::table)
            .and_then(|index| {
                index
                    .fde_for_address(&self.eh, &self.bases, pc, EhFrame::cie_from_offset)
                    .ok()
            })
            .map(Ok)
            .unwrap_or_else(|| {
                self.eh
                    .fde_for_address(&self.bases, pc, EhFrame::cie_from_offset)
            });
        match entry {
            Err(e) if e == gimli::Error::NoUnwindInfoForAddress => {
                let fde =
                    self.debug
                        .fde_for_address(&self.bases, pc, DebugFrame::cie_from_offset)?;
                use_fde(CallFrameSection::Debug(&self.debug), fde)
            }
            result => use_fde(CallFrameSection::Eh(&self.eh), result?),
        }
    }

    fn step_section<S: UnwindSection<Data>>(
        &self,
        section: &S,
        fde: FrameDescriptionEntry<Data>,
        pc: u64,
        mut c: Context<'_>,
        saved_cfa: &mut Option<u64>,
    ) -> Result<Step> {
        if fde.is_signal_trampoline() {
            return Ok(Step::Unsupported("signal_trampoline"));
        }
        let enc = fde.cie().encoding();
        let ret = fde.cie().return_address_register();
        let mut cache = UnwindContext::new();
        let row = fde.unwind_info_for_address(section, &self.bases, &mut cache, pc)?;
        let signed_return = cfg!(target_arch = "aarch64")
            && matches!(row.register(gimli::AArch64::RA_SIGN_STATE), Some(RegisterRule::Constant(v)) if v != 0);
        let cfa = cfa_value(row.cfa(), section, enc, c)?;
        // Live variable inspection uses the adjusted lookup PC in caller frames.
        // A direct rule on another register gives the same CFA in either context.
        if c.regs.get(PC).ok() == Some(pc.wrapping_add(c.bias))
            || matches!(row.cfa(), CfaRule::RegisterAndOffset { register, .. } if *register != PC)
        {
            *saved_cfa = Some(cfa);
        }
        c.cfa = Some(cfa);
        // Only retain ABI callee-saved registers across a frame when CFI
        // doesn't supply a rule. An x86 return address requires a rule.
        let mut next = c.regs;
        for n in 0..33 {
            let reg = gimli::Register(n);
            let retained = if cfg!(target_arch = "x86_64") {
                matches!(n, 3 | 6 | 12..=15)
            } else {
                matches!(n, 19..=30)
            };
            if let Some(rule) = row.register(reg) {
                next.set(reg, rule_value(rule, reg, section, enc, c, cfa).ok());
            } else if !retained {
                next.set(reg, None);
            }
        }
        if matches!(row.register(ret), Some(RegisterRule::Undefined))
            || (row.register(ret).is_none() && cfg!(target_arch = "x86_64"))
        {
            return Ok(Step::End);
        }
        let mut pc = next.get(ret)?;
        if signed_return {
            pc &= !c.regs.instruction_pac_mask();
        }
        if pc == 0 {
            return Ok(Step::End);
        }
        next.set(PC, Some(pc));
        next.set(SP, Some(cfa));
        if cfg!(target_arch = "aarch64") {
            // The callee's saved LR is the caller's PC. It cannot also be used
            // as the caller's incoming LR if the next row needs that register.
            next.set(gimli::AArch64::X30, None);
        }
        Ok(Step::Next(next, "cfi"))
    }

    fn cfa(&self, pc: u64, context: Context<'_>) -> Result<u64> {
        self.with_fde(pc, |section, fde| match section {
            CallFrameSection::Eh(section) => self.cfa_section(section, fde, pc, context),
            CallFrameSection::Debug(section) => self.cfa_section(section, fde, pc, context),
        })
    }

    fn cfa_section<S: UnwindSection<Data>>(
        &self,
        section: &S,
        fde: FrameDescriptionEntry<Data>,
        pc: u64,
        context: Context<'_>,
    ) -> Result<u64> {
        let mut cache = UnwindContext::new();
        let row = fde.unwind_info_for_address(section, &self.bases, &mut cache, pc)?;
        cfa_value(row.cfa(), section, fde.cie().encoding(), context)
    }
}

enum CallFrameSection<'a> {
    Eh(&'a EhFrame<Data>),
    Debug(&'a DebugFrame<Data>),
}

fn cfa_value<S: UnwindSection<Data>>(
    rule: &CfaRule<usize>,
    section: &S,
    encoding: Encoding,
    context: Context<'_>,
) -> Result<u64> {
    match rule {
        CfaRule::RegisterAndOffset { register, offset } => {
            Ok(context.regs.get(*register)?.wrapping_add_signed(*offset))
        }
        CfaRule::Expression(expr) => evaluate(expr.get(section)?, encoding, context),
    }
}

pub(crate) fn canonical_frame_address(
    bytes: Arc<Vec<u8>>,
    module: &Module,
    link: u64,
    bias: u64,
    memory: &dyn UnwindMemory,
    registers: Registers,
) -> Result<u64> {
    let image = Image::new(bytes, module)?;
    let context = Context {
        memory,
        regs: registers,
        cfa: None,
        bias,
    };
    image.cfa(link, context)
}

#[derive(Clone, Copy)]
struct Context<'a> {
    memory: &'a dyn UnwindMemory,
    regs: Registers,
    cfa: Option<u64>,
    bias: u64,
}

#[derive(Debug)]
pub(crate) struct MissingMemory(pub u64);

impl std::fmt::Display for MissingMemory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "memory page unavailable in core at {}",
            hex(self.0)
        )
    }
}

impl std::error::Error for MissingMemory {}

pub(crate) trait UnwindMemory {
    fn read_word(&self, address: u64, size: usize) -> Result<u64>;
}

impl UnwindMemory for Trace {
    fn read_word(&self, address: u64, size: usize) -> Result<u64> {
        Trace::read_word(self, address, size)
    }
}

fn evaluate(expr: Expression<Data>, encoding: Encoding, c: Context<'_>) -> Result<u64> {
    let mut eval = expr.evaluation(encoding);
    eval.set_max_iterations(256);
    let mut state = eval.evaluate()?;
    loop {
        state = match state {
            EvaluationResult::Complete => break,
            EvaluationResult::RequiresMemory {
                address,
                size,
                space: None,
                base_type,
            } if base_type.0 == 0 => eval.resume_with_memory(Value::Generic(
                c.memory.read_word(address, usize::from(size))?,
            ))?,
            EvaluationResult::RequiresRegister {
                register,
                base_type,
            } if base_type.0 == 0 => {
                eval.resume_with_register(Value::Generic(c.regs.get(register)?))?
            }
            EvaluationResult::RequiresCallFrameCfa => {
                eval.resume_with_call_frame_cfa(c.cfa.ok_or_else(|| error("CFA unavailable"))?)?
            }
            EvaluationResult::RequiresRelocatedAddress(addr) => {
                eval.resume_with_relocated_address(addr.wrapping_add(c.bias))?
            }
            other => {
                return Err(error(format!(
                    "unsupported CFI expression continuation: {other:?}"
                )));
            }
        }
    }
    let pieces = eval.result();
    if pieces.len() != 1 || pieces[0].size_in_bits.is_some() || pieces[0].bit_offset.is_some() {
        return Err(error("unsupported composite CFI expression"));
    }
    match pieces[0].location {
        Location::Address { address } => Ok(address),
        Location::Register { register } => c.regs.get(register),
        Location::Value { value } => Ok(value.to_u64(u64::MAX)?),
        _ => Err(error("CFI expression did not return a scalar")),
    }
}

fn rule_value<S: UnwindSection<Data>>(
    rule: RegisterRule<usize>,
    reg: gimli::Register,
    section: &S,
    enc: Encoding,
    c: Context<'_>,
    cfa: u64,
) -> Result<u64> {
    match rule {
        RegisterRule::SameValue => c.regs.get(reg),
        RegisterRule::Offset(off) => c.memory.read_word(cfa.wrapping_add_signed(off), 8),
        RegisterRule::ValOffset(off) => Ok(cfa.wrapping_add_signed(off)),
        RegisterRule::Register(r) => c.regs.get(r),
        RegisterRule::Expression(expr) => {
            c.memory.read_word(evaluate(expr.get(section)?, enc, c)?, 8)
        }
        RegisterRule::ValExpression(expr) => evaluate(expr.get(section)?, enc, c),
        RegisterRule::Constant(value) => Ok(value),
        _ => Err(error(format!("caller register {} unavailable", reg.0))),
    }
}

enum Step {
    Next(Registers, &'static str),
    End,
    Unsupported(&'static str),
}

fn frame_pointer(c: Context<'_>, modules: &[Module]) -> Result<Step> {
    let fp = c.regs.get(FP)?;
    let sp = c.regs.get(SP)?;
    if fp % 8 != 0 || fp < sp || fp - sp > 1024 * 1024 {
        return Err(error("no plausible frame-pointer record"));
    }
    let previous = c.memory.read_word(fp, 8)?;
    let ret = c.memory.read_word(
        fp.checked_add(8)
            .ok_or_else(|| error("frame pointer overflow"))?,
        8,
    )? & !c.regs.instruction_pac_mask();
    if ret == 0 && previous == 0 {
        return Ok(Step::End);
    }
    if previous != 0 && previous <= fp {
        return Err(error("frame-pointer chain did not advance"));
    }
    let lookup = ret
        .checked_sub(1)
        .ok_or_else(|| error("empty return address"))?;
    if !modules.iter().any(|m| m.executable_at(lookup).is_some()) {
        return Err(error(
            "frame-pointer return address is outside known executable mappings",
        ));
    }
    let mut regs = c.regs;
    regs.set(PC, Some(ret));
    regs.set(SP, fp.checked_add(16));
    regs.set(FP, Some(previous));
    if cfg!(target_arch = "aarch64") {
        regs.set(gimli::AArch64::X30, None);
    }
    Ok(Step::Next(regs, "frame_pointer"))
}

fn syscall_return(c: Context<'_>, modules: &[Module]) -> Option<Step> {
    if !cfg!(target_arch = "x86_64") {
        return None;
    }
    let pc = c.regs.get(PC).ok()?;
    let syscall = pc.checked_sub(2)?;
    // Linux reports the PC after SYSCALL. If the next instruction is a
    // near RET, RSP already points at this frame's return address.
    if !modules.iter().any(|module| {
        module
            .executable_at(syscall)
            .is_some_and(|mapping| mapping.file_offset(pc).is_some())
    }) || c.memory.read_word(syscall, 2).ok()? != 0x050f
        || c.memory.read_word(pc, 1).ok()? != 0xc3
    {
        return None;
    }
    let sp = c.regs.get(SP).ok()?;
    let ret = c.memory.read_word(sp, 8).ok()?;
    let lookup = ret.checked_sub(1)?;
    if !modules
        .iter()
        .any(|module| module.executable_at(lookup).is_some())
    {
        return None;
    }
    let mut next = Registers::empty();
    for register in [3, 6, 12, 13, 14, 15].map(gimli::Register) {
        next.set(register, c.regs.get(register).ok());
    }
    next.set(PC, Some(ret));
    next.set(SP, sp.checked_add(8));
    Some(Step::Next(next, "syscall_return"))
}

#[derive(Serialize)]
pub struct Frame {
    pc: String,
    lookup_pc: String,
    sp: String,
    pub(crate) module_id: Option<usize>,
    file_offset: Option<String>,
    elf_address: Option<String>,
    module_instance: Option<String>,
    module_offset: Option<String>,
    function: Option<String>,
    file: Option<PathBuf>,
    line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) args: Option<serde_json::Value>,
    #[serde(flatten)]
    names: Option<crate::cpp_names::Names>,
    missing_debug_sections: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) inline_frames: Vec<crate::symbols::inspect::InlineFrame>,
    pub(crate) method: &'static str,
    #[serde(skip)]
    pub(crate) link_pc: Option<u64>,
    #[serde(skip)]
    pub(crate) cfa: Option<u64>,
    #[serde(skip)]
    pub(crate) lookup_address: u64,
}

impl Frame {
    pub(crate) fn return_site(&self) -> Result<(u64, u64)> {
        Ok((
            u64::from_str_radix(self.pc.trim_start_matches("0x"), 16)?,
            u64::from_str_radix(self.sp.trim_start_matches("0x"), 16)?,
        ))
    }
}

#[derive(Serialize)]
pub struct Stack {
    pub frames: Vec<Frame>,
    pub complete: bool,
    pub stop_reason: String,
}

pub struct Images {
    data: BTreeMap<usize, std::result::Result<Image, String>>,
    bytes: u64,
}

impl Images {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
            bytes: 0,
        }
    }

    fn image(
        &mut self,
        id: usize,
        m: &Module,
        root: &Path,
        exe: Option<&Metadata>,
    ) -> std::result::Result<&Image, &str> {
        self.data
            .entry(id)
            .or_insert_with(|| {
                let _phase = crate::snapshot_timing::phase("elf_image");
                let cap = (MAX_IMAGES_TOTAL - self.bytes).min(MAX_IMAGE);
                let bytes = m.read_image(root, exe, cap).map_err(|e| e.to_string())?;
                self.bytes += bytes.len() as u64;
                let mut image = Image::new(Arc::new(bytes), m).map_err(|e| e.to_string())?;
                if let Ok(obj) = object::File::parse(image.bytes.as_slice())
                    && !obj.has_debug_symbols()
                    && let Some((_, symbols)) =
                        crate::snapshot_timing::measure("external_debug", || {
                            crate::symbols::find_external_debug(
                                Some(&root.join("root")),
                                &m.path(),
                                &obj,
                                MAX_IMAGES_TOTAL - self.bytes,
                            )
                        })
                {
                    self.bytes += symbols.len() as u64;
                    image.symbols = Some(symbols);
                }
                Ok(image)
            })
            .as_ref()
            .map_err(String::as_str)
    }

    pub fn module_info(
        &self,
        id: usize,
        m: &Module,
        root: Option<&Path>,
        exe: Option<&Metadata>,
    ) -> ModuleInfo {
        let info = m.info(id, exe, None);
        if let Some(Ok(image)) = self.data.get(&id)
            && let Ok(obj) = object::File::parse(image.bytes.as_slice())
        {
            let kind = match obj.kind() {
                object::ObjectKind::Dynamic => "shared_object",
                _ => "executable_mapping",
            };
            return info.with_elf(obj.build_id().ok().flatten(), &image.layout, kind);
        }
        if let Some(kind) = root.and_then(|root| m.image_kind(root)) {
            return m.info(id, exe, Some(kind));
        }
        info
    }

    pub fn symbolize(&self, stack: &mut Stack) {
        self.symbolize_frames(stack, None, None);
    }

    pub(crate) fn symbolize_until(
        &self,
        stack: &mut Stack,
        deadline: Instant,
        root: &Path,
        modules: &[Module],
        executable: Option<&Metadata>,
    ) {
        self.symbolize_frames(stack, Some(deadline), Some((root, modules, executable)));
    }

    fn symbol_objects(
        &self,
        frame: &Frame,
    ) -> Option<(u64, object::File<'_>, Option<object::File<'_>>)> {
        let (module, pc) = frame.module_id.zip(frame.link_pc)?;
        let image = self.data.get(&module)?.as_ref().ok()?;
        let object = object::File::parse(image.bytes.as_slice()).ok()?;
        let debug = image
            .symbols
            .as_deref()
            .and_then(|bytes| object::File::parse(bytes).ok());
        Some((pc, object, debug))
    }

    fn symbolize_frames(
        &self,
        stack: &mut Stack,
        deadline: Option<Instant>,
        live: Option<(&Path, &[Module], Option<&Metadata>)>,
    ) {
        // A large DWARF line table must not consume the time available for
        // naming callers whose ELF symbols are already loaded.
        let names = crate::snapshot_timing::phase("elf_names");
        for frame in &mut stack.frames {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return;
            }
            let Some((pc, object, debug)) = self.symbol_objects(frame) else {
                continue;
            };
            frame.missing_debug_sections =
                crate::symbols::missing_debug_sections(&object, debug.as_ref());
            frame.names = debug
                .as_ref()
                .and_then(|debug| modules::symbol(debug, pc))
                .or_else(|| modules::symbol(&object, pc));
            frame.function = frame.names.as_ref().map(|names| {
                names
                    .demangled_name
                    .as_ref()
                    .unwrap_or(&names.display_name)
                    .clone()
            });
        }
        drop(names);
        let mut loaded = BTreeMap::new();
        for frame in &mut stack.frames {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                break;
            }
            if let Some((root, modules, executable)) = live
                && let Some((id, pc)) = frame.module_id.zip(frame.link_pc)
                && let Some(module) = modules.get(id)
                && let Ok(images) = loaded.entry(id).or_insert_with(|| {
                    crate::symbols::inspect::live_source_images(root, module, executable)
                })
            {
                if let Some(source) = images.iter().find_map(|dwarf| {
                    crate::snapshot_timing::measure("dwarf_lines", || dwarf.line(pc))
                        .ok()
                        .flatten()
                }) {
                    frame.file = Some(source.file);
                    frame.line = source.line;
                }
                if let Some(deadline) = deadline
                    && Instant::now() < deadline
                {
                    frame.inline_frames = images
                        .iter()
                        .find_map(|dwarf| {
                            let frames = crate::snapshot_timing::measure("dwarf_inline", || {
                                dwarf.inline_frames(pc, deadline)
                            })
                            .ok()?;
                            (!frames.is_empty()).then_some(frames)
                        })
                        .unwrap_or_default();
                }
                continue;
            }
            let Some((pc, object, debug)) = self.symbol_objects(frame) else {
                continue;
            };
            if let Some(source) = debug
                .as_ref()
                .and_then(|debug| {
                    crate::snapshot_timing::measure("dwarf_lines", || {
                        crate::symbols::dwarf_line(debug, pc)
                    })
                    .ok()
                    .flatten()
                })
                .or_else(|| {
                    crate::snapshot_timing::measure("dwarf_lines", || {
                        crate::symbols::dwarf_line(&object, pc)
                    })
                    .ok()
                    .flatten()
                })
            {
                frame.file = Some(source.file);
                frame.line = source.line;
            }
            if let Some(deadline) = deadline
                && Instant::now() < deadline
            {
                let _phase = crate::snapshot_timing::phase("dwarf_inline");
                frame.inline_frames = crate::symbols::dwarf_inline_frames(
                    debug.as_ref().unwrap_or(&object),
                    pc,
                    deadline,
                )
                .unwrap_or_default();
            }
        }
    }

    pub(crate) fn profile_location(
        &mut self,
        pc: u64,
        maps: &[Module],
        root: &Path,
        exe: Option<&Metadata>,
    ) -> Option<(usize, u64, Option<(String, u64)>)> {
        let (id, module, map) = maps
            .iter()
            .enumerate()
            .find_map(|(id, module)| module.executable_at(pc).map(|map| (id, module, map)))?;
        let image = self.image(id, module, root, exe).ok()?;
        let (_, link) = image.layout.for_address(map, pc)?;
        let object = object::File::parse(image.bytes.as_slice()).ok()?;
        let offset = link.checked_sub(image.layout.elf_base)?;
        let symbol = modules::text_symbol(&object, link)
            .filter(|(_, base)| *base >= image.layout.elf_base)
            .map(|(name, base)| (name.to_owned(), link - base));
        Some((id, offset, symbol))
    }

    pub fn walk(
        &mut self,
        memory: &dyn UnwindMemory,
        regs: Registers,
        maps: &[Module],
        root: &Path,
        exe: Option<&Metadata>,
        deadline: Instant,
    ) -> Stack {
        self.walk_registers(memory, regs, maps, root, exe, deadline, |_, _| {})
    }

    pub(crate) fn walk_registers(
        &mut self,
        memory: &dyn UnwindMemory,
        mut regs: Registers,
        maps: &[Module],
        root: &Path,
        exe: Option<&Metadata>,
        deadline: Instant,
        mut observe: impl FnMut(usize, Registers),
    ) -> Stack {
        let mut frames = Vec::new();
        let mut seen = BTreeSet::new();
        let mut method = "registers";
        let result: Result<&'static str> = (|| {
            for index in 0..MAX_DEPTH {
                // Keep the first frame even when a per-stack unwind is unavailable.
                let pc = regs.get(PC)?;
                let sp = regs.get(SP)?;
                if pc == 0 || !seen.insert((pc, sp)) {
                    return Err(error("zero PC or repeated frame"));
                }
                let lookup = pc - u64::from(index > 0);
                let mut frame_regs = regs;
                frame_regs.set(PC, Some(lookup));
                observe(index, frame_regs);
                let d = maps
                    .iter()
                    .enumerate()
                    .find_map(|(i, m)| m.executable_at(lookup).map(|map| (i, m, map)));
                let file_offset = d.and_then(|(_, _, m)| m.file_offset(lookup));
                let mut frame = Frame {
                    pc: hex(pc),
                    lookup_pc: hex(lookup),
                    sp: hex(sp),
                    module_id: d.map(|(i, _, _)| i),
                    file_offset: file_offset.map(hex),
                    elf_address: None,
                    module_instance: None,
                    module_offset: None,
                    function: None,
                    file: None,
                    line: None,
                    args: None,
                    names: None,
                    missing_debug_sections: Vec::new(),
                    inline_frames: Vec::new(),
                    method,
                    link_pc: None,
                    cfa: None,
                    lookup_address: lookup,
                };
                if Instant::now() >= deadline {
                    frames.push(frame);
                    return Err(error("snapshot deadline reached"));
                }
                let mut c = Context {
                    memory,
                    regs,
                    cfa: None,
                    bias: 0,
                };
                let step = (|| -> Result<Step> {
                    let (id, module, map) =
                        d.ok_or_else(|| error("PC outside known file-backed modules"))?;
                    let image = self.image(id, module, root, exe).map_err(error)?;
                    let (instance, link) = image
                        .layout
                        .for_address(map, lookup)
                        .ok_or_else(|| error("no executable ELF segment for PC"))?;
                    frame.link_pc = Some(link);
                    frame.elf_address = Some(hex(link));
                    frame.module_instance = Some(hex(instance.base));
                    frame.module_offset = Some(hex(link - image.layout.elf_base));
                    c.bias = lookup.wrapping_sub(link);
                    image.step(link, c, &mut frame.cfa)
                })();
                frames.push(frame);
                let step = step.or_else(|cfi| {
                    if index == 0
                        && let Some(step) = syscall_return(c, maps)
                    {
                        return Ok(step);
                    }
                    frame_pointer(c, maps)
                        .map_err(|fp| error(format!("CFI: {cfi}; frame pointer: {fp}")))
                })?;
                match step {
                    Step::End => return Ok("end_of_stack"),
                    Step::Unsupported(reason) => return Err(error(reason)),
                    Step::Next(next, via) => {
                        if next.get(SP)? < sp {
                            return Err(error("caller SP moved backwards"));
                        }
                        regs = if via == "frame_pointer" {
                            frame_pointer_registers(next)
                        } else {
                            next
                        };
                        method = via;
                    }
                }
            }
            Err(error("frame_limit"))
        })();
        Stack {
            frames,
            complete: result.is_ok(),
            stop_reason: result.map(str::to_owned).unwrap_or_else(|e| e.to_string()),
        }
    }
}

pub(crate) struct OfflineImage {
    image: Image,
    bias: u64,
}

impl OfflineImage {
    pub fn new(bytes: Vec<u8>, bias: u64) -> Result<Self> {
        let module = Module {
            backing: modules::Backing {
                major: 0,
                minor: 0,
                inode: 0,
                path: Vec::new(),
            },
            maps: Vec::new(),
        };
        Ok(Self {
            image: Image::new(Arc::new(bytes), &module)?,
            bias,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.image.bytes
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        Arc::unwrap_or_clone(self.image.bytes)
    }

    pub(crate) fn bias(&self) -> u64 {
        self.bias
    }

    fn contains_code(&self, link: u64) -> bool {
        use object::ObjectSegment;
        let Ok(file) = object::File::parse(self.image.bytes.as_slice()) else {
            return false;
        };
        file.segments().any(|segment| {
            matches!(segment.flags(), object::SegmentFlags::Elf { p_flags, .. } if p_flags.contains(object::elf::PF_X))
                && link.checked_sub(segment.address()).is_some_and(|offset| offset < segment.size())
        })
    }
}

pub(crate) struct OfflineFrame {
    pub regs: Registers,
    pub pc: u64,
    pub link: Option<u64>,
    pub lookup_pc: u64,
    pub cfa: Option<u64>,
}

fn frame_pointer_registers(next: Registers) -> Registers {
    // A frame record alone does not recover the caller's general registers.
    let mut recovered = Registers::empty();
    recovered.set_instruction_pac_mask(next.instruction_pac_mask());
    for register in [PC, SP, FP] {
        recovered.set(register, next.get(register).ok());
    }
    recovered
}

pub(crate) fn offline_frames<I: AsRef<OfflineImage>>(
    memory: &dyn UnwindMemory,
    image_at: impl Fn(u64) -> Option<(I, u64)>,
    mut regs: Registers,
    mappings: &[Module],
) -> Vec<OfflineFrame> {
    let mut frames = Vec::new();
    let mut seen = BTreeSet::new();
    for index in 0..MAX_DEPTH {
        let (Ok(pc), Ok(sp)) = (regs.get(PC), regs.get(SP)) else {
            break;
        };
        if pc == 0 || !seen.insert((pc, sp)) {
            break;
        }
        let lookup = pc - u64::from(index > 0);
        let mut context = Context {
            memory,
            regs,
            cfa: None,
            bias: 0,
        };
        let mut frame = OfflineFrame {
            regs,
            pc,
            link: None,
            lookup_pc: lookup,
            cfa: None,
        };
        let step = image_at(lookup).and_then(|(image, link)| {
            let image = image.as_ref();
            if !image.contains_code(link) {
                return None;
            }
            context.bias = lookup.wrapping_sub(link);
            frame.link = Some(link);
            let step = image.image.step(link, context, &mut frame.cfa).ok();
            if frame.cfa.is_none() {
                frame.cfa = image.image.cfa(link, context).ok();
            }
            step
        });
        let step = step.or_else(|| {
            if index != 0 {
                return None;
            }
            let step = syscall_return(context, mappings)?;
            frame.cfa = sp.checked_add(8);
            Some(step)
        });
        if frame.cfa.is_none()
            && let Ok(fp) = regs.get(FP)
            && fp % 8 == 0
            && fp >= sp
            && fp - sp <= 1024 * 1024
        {
            frame.cfa = fp.checked_add(16);
        }
        frames.push(frame);
        let Some(Step::Next(next, method)) = step.or_else(|| frame_pointer(context, mappings).ok())
        else {
            break;
        };
        if next.get(SP).is_ok_and(|next_sp| next_sp < sp) {
            break;
        }
        regs = if method == "frame_pointer" {
            frame_pointer_registers(next)
        } else {
            next
        };
    }
    frames
}
