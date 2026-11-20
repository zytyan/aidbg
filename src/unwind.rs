use crate::modules::{self, Layout, Module, ModuleInfo};
use crate::regs::{FP, PC, Registers, SP};
use crate::trace::Trace;
use crate::{Result, error, hex};
use gimli::{
    BaseAddresses, CfaRule, DebugFrame, EhFrame, Encoding, EndianArcSlice, EvaluationResult,
    Expression, LittleEndian, Location, RegisterRule, UnwindContext, UnwindSection, Value, Vendor,
};
use object::{Object, ObjectSection};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::Metadata;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

const MAX_DEPTH: usize = 32;
const MAX_IMAGE: u64 = 32 * 1024 * 1024;
const MAX_IMAGES_TOTAL: u64 = 64 * 1024 * 1024;
type Data = EndianArcSlice<LittleEndian>;

struct Image {
    bytes: Vec<u8>,
    eh: EhFrame<Data>,
    debug: DebugFrame<Data>,
    bases: BaseAddresses,
    layout: Layout,
}

impl Image {
    fn new(bytes: Vec<u8>, module: &Module) -> Result<Self> {
        let obj = object::File::parse(&*bytes)?;
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
            .set_text(addr(".text"))
            .set_got(addr(".got"));
        Ok(Self {
            bytes,
            eh,
            debug,
            bases,
            layout,
        })
    }

    fn step(&self, pc: u64, ctx: Context<'_>) -> Result<Step> {
        match self.step_section(&self.eh, pc, ctx) {
            Err(e)
                if e.downcast_ref::<gimli::Error>()
                    == Some(&gimli::Error::NoUnwindInfoForAddress) =>
            {
                self.step_section(&self.debug, pc, ctx)
            }
            result => result,
        }
    }

    fn step_section<S: UnwindSection<Data>>(
        &self,
        section: &S,
        pc: u64,
        mut c: Context<'_>,
    ) -> Result<Step> {
        let fde = section.fde_for_address(&self.bases, pc, S::cie_from_offset)?;
        if fde.is_signal_trampoline() {
            return Ok(Step::Unsupported("signal_trampoline"));
        }
        let enc = fde.cie().encoding();
        let ret = fde.cie().return_address_register();
        let mut cache = UnwindContext::new();
        let row = fde.unwind_info_for_address(section, &self.bases, &mut cache, pc)?;
        if cfg!(target_arch = "aarch64")
            && matches!(row.register(gimli::AArch64::RA_SIGN_STATE),Some(RegisterRule::Constant(v)) if v!=0)
        {
            return Ok(Step::Unsupported("aarch64_pac"));
        }
        let cfa = match row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => {
                c.regs.get(*register)?.wrapping_add_signed(*offset)
            }
            CfaRule::Expression(expr) => evaluate(expr.get(section)?, enc, c)?,
        };
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
        let pc = next.get(ret)?;
        if pc == 0 {
            return Ok(Step::End);
        }
        next.set(PC, Some(pc));
        next.set(SP, Some(cfa));
        Ok(Step::Next(next, "cfi"))
    }
}

#[derive(Clone, Copy)]
struct Context<'a> {
    trace: &'a Trace<'a>,
    regs: Registers,
    cfa: Option<u64>,
    bias: u64,
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
                c.trace.read_word(address, usize::from(size))?,
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
        RegisterRule::Offset(off) => c.trace.read_word(cfa.wrapping_add_signed(off), 8),
        RegisterRule::ValOffset(off) => Ok(cfa.wrapping_add_signed(off)),
        RegisterRule::Register(r) => c.regs.get(r),
        RegisterRule::Expression(expr) => {
            c.trace.read_word(evaluate(expr.get(section)?, enc, c)?, 8)
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
    let previous = c.trace.read_word(fp, 8)?;
    let ret = c.trace.read_word(
        fp.checked_add(8)
            .ok_or_else(|| error("frame pointer overflow"))?,
        8,
    )?;
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
    Ok(Step::Next(regs, "frame_pointer"))
}

#[derive(Serialize)]
pub struct Frame {
    pc: String,
    lookup_pc: String,
    sp: String,
    module_id: Option<usize>,
    file_offset: Option<String>,
    elf_address: Option<String>,
    module_instance: Option<String>,
    module_offset: Option<String>,
    function: Option<String>,
    #[serde(flatten)]
    names: Option<crate::cpp_names::Names>,
    method: &'static str,
    #[serde(skip)]
    link_pc: Option<u64>,
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
                let cap = (MAX_IMAGES_TOTAL - self.bytes).min(MAX_IMAGE);
                let bytes = m.read_image(root, exe, cap).map_err(|e| e.to_string())?;
                self.bytes += bytes.len() as u64;
                Image::new(bytes, m).map_err(|e| e.to_string())
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
            && let Ok(obj) = object::File::parse(&*image.bytes)
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
        for frame in &mut stack.frames {
            let Some((module, pc)) = frame.module_id.zip(frame.link_pc) else {
                continue;
            };
            let Some(Ok(image)) = self.data.get(&module) else {
                continue;
            };
            if let Ok(obj) = object::File::parse(&*image.bytes) {
                frame.names = modules::symbol(&obj, pc);
                frame.function = frame.names.as_ref().map(|names| {
                    names
                        .demangled_name
                        .as_ref()
                        .unwrap_or(&names.display_name)
                        .clone()
                });
            }
        }
    }

    pub fn walk(
        &mut self,
        trace: &Trace<'_>,
        mut regs: Registers,
        maps: &[Module],
        root: &Path,
        exe: Option<&Metadata>,
        deadline: Instant,
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
                    names: None,
                    method,
                    link_pc: None,
                };
                if Instant::now() >= deadline {
                    frames.push(frame);
                    return Err(error("snapshot deadline reached"));
                }
                let mut c = Context {
                    trace,
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
                    image.step(link, c)
                })();
                frames.push(frame);
                let step = step.or_else(|cfi| {
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
                        regs = next;
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
