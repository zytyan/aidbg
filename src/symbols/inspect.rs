use super::*;
use crate::procfs::start_ticks;
use crate::regs::{self, PC, Registers};
use crate::trace::{Cleanup, Trace};
use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EvaluationResult, Expression, Location, Unit,
    UnitOffset, Value,
};
use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

mod cache;
mod expression;
mod source_cache;
pub(crate) mod type_graph;
pub(crate) use cache::warm as warm_dwarf;
pub(crate) mod offline;
use expression::Number;

type Reader<'a> = EndianSlice<'a, LittleEndian>;
type Die<'a> = DebuggingInformationEntry<Reader<'a>>;
type Offset = UnitOffset<usize>;
type Attr<'a> = AttributeValue<Reader<'a>>;

const MAX_VALUE: usize = 256;
const MAX_DIES: usize = 200_000;

#[derive(Debug)]
struct Failure(&'static str, String);

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.1)
    }
}

impl std::error::Error for Failure {}

fn failure(code: &'static str, message: impl ToString) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(Failure(code, message.to_string()))
}

fn memory_failure(
    err: Box<dyn std::error::Error + Send + Sync>,
) -> Box<dyn std::error::Error + Send + Sync> {
    if err.is::<crate::unwind::MissingMemory>() {
        failure("missing_page", err)
    } else {
        failure("read_failed", err)
    }
}

#[derive(Debug)]
enum Access {
    Address,
    Deref,
    Member(String),
    Index(u64),
}

#[derive(Clone, Copy)]
pub(crate) enum Discovery {
    Locals,
    Parameters,
    Globals,
    Types,
}

pub(crate) fn discover_stopped(
    root: &Path,
    memory: &dyn crate::unwind::UnwindMemory,
    registers: Registers,
    kind: Discovery,
    pattern: &str,
    page: (usize, usize),
    deadline: Instant,
) -> Result<serde_json::Value> {
    let (dwarf, frame) = stopped_dwarf(root, memory, registers)?;
    let (offset, limit) = page;
    let result = match kind {
        Discovery::Locals => {
            dwarf.variables(memory, Some(&frame), pattern, offset, limit, deadline)
        }
        Discovery::Parameters => dwarf.parameters(memory, &frame, limit, deadline),
        Discovery::Globals => dwarf.variables(memory, None, pattern, offset, limit, deadline),
        Discovery::Types => dwarf.types(pattern, offset, limit, deadline),
    };
    result.map_err(|error| {
        if error
            .downcast_ref::<Failure>()
            .is_some_and(|failure| failure.0 == "limit_reached")
        {
            crate::Diagnostic::new(
                "LIMIT_REACHED",
                error.to_string(),
                Some("Use a smaller page or increase the callback timeout."),
            )
            .into()
        } else {
            error
        }
    })
}

pub(crate) fn live_source_images(
    root: &Path,
    module: &modules::Module,
    executable: Option<&fs::Metadata>,
) -> Result<Vec<offline::DwarfImage>> {
    let image = cache::live_image(root, module, executable)?;
    Ok(image
        .separate
        .iter()
        .chain(&image.primary)
        .map(|data| offline::DwarfImage {
            data: data.clone(),
            bias: 0,
            path: module.path(),
        })
        .collect())
}

pub(crate) fn live_data_at(
    root: &Path,
    memory: &dyn crate::unwind::UnwindMemory,
    address: u64,
    hit: &serde_json::Value,
    deadline: Instant,
) -> Option<serde_json::Value> {
    use serde_json::json;
    if hit["kind"] != "data" || hit["match"] == "nearest" {
        return None;
    }
    let name = hit["name"].as_str()?;
    let path = std::path::Path::new(hit["module"]["path"].as_str()?);
    let space = modules::address_space(root).ok()?;
    let exe = fs::metadata(root.join("exe")).ok();
    let module = space.modules.iter().find(|module| module.path() == path)?;
    let cached = cache::live_image(root, module, exe.as_ref()).ok()?;
    let image = object::File::parse(cached.bytes.as_slice()).ok()?;
    let layout = Layout::new(&image, module).ok()?;
    let relocated = module
        .mapping_at(address)
        .and_then(|map| layout.for_address(map, address))
        .or_else(|| {
            space
                .anonymous
                .iter()
                .find(|map| map.contains(address))
                .and_then(|map| layout.zerofill_address(map, address, module))
        })?;
    let dwarf = offline::DwarfImage {
        bias: u64::try_from(relocated.0.bias).ok()?,
        path: path.to_path_buf(),
        data: cached
            .separate
            .as_ref()
            .or(cached.primary.as_ref())?
            .clone(),
    };
    let value = dwarf.inspect(name, memory, Registers::empty(), None, None, deadline, None);
    let value = value.get("result")?;
    if value["address"] != hit["address"] {
        return None;
    }
    let graph = dwarf.variable_type_graph(name, None, deadline).ok()??;
    Some(json!({"type":value["type"]["name"],"graph":graph}))
}

pub(crate) fn live_variable_image(
    root: &Path,
    module: &modules::Module,
    executable: Option<&fs::Metadata>,
) -> Result<Option<offline::DwarfImage>> {
    let image = cache::live_image(root, module, executable)?;
    Ok(image
        .separate
        .as_ref()
        .or(image.primary.as_ref())
        .map(|data| offline::DwarfImage {
            data: data.clone(),
            bias: 0,
            path: module.path(),
        }))
}

struct MappedDwarf {
    dwarf: offline::DwarfImage,
    cached: std::sync::Arc<cache::LiveImage>,
    module: modules::Module,
    link: u64,
}

fn mapped_dwarf(root: &Path, pc: u64) -> Result<Option<MappedDwarf>> {
    let _context = crate::snapshot_timing::phase("variable_context");
    let exe = fs::metadata(root.join("exe")).ok();
    let Some(module) = modules::read(root)?
        .into_iter()
        .find(|module| module.executable_at(pc).is_some())
    else {
        return Ok(None);
    };
    let cached = cache::live_image(root, &module, exe.as_ref())?;
    let Some(data) = cached.separate.as_ref().or(cached.primary.as_ref()) else {
        return Ok(None);
    };
    let image = object::File::parse(cached.bytes.as_slice())?;
    let layout = Layout::new(&image, &module)?;
    let Some((instance, link)) = module
        .executable_at(pc)
        .and_then(|mapping| layout.for_address(mapping, pc))
    else {
        return Ok(None);
    };
    let dwarf = offline::DwarfImage {
        bias: u64::try_from(instance.bias)?,
        path: module.path(),
        data: data.clone(),
    };
    Ok(Some(MappedDwarf {
        dwarf,
        cached,
        module,
        link,
    }))
}

pub(crate) fn variable_type_at_pc(
    root: &Path,
    pc: u64,
    name: &str,
    deadline: Instant,
) -> Result<Option<type_graph::Graph>> {
    match mapped_dwarf(root, pc)? {
        Some(frame) => frame
            .dwarf
            .variable_type_graph(name, Some(frame.link), deadline),
        None => Ok(None),
    }
}

pub(crate) fn variable_query_limited(err: &(dyn std::error::Error + 'static)) -> bool {
    err.downcast_ref::<Failure>()
        .is_some_and(|err| err.0 == "limit_reached")
}

pub(crate) fn stopped_dwarf(
    root: &Path,
    memory: &dyn crate::unwind::UnwindMemory,
    registers: Registers,
) -> Result<(offline::DwarfImage, crate::unwind::OfflineFrame)> {
    let pc = registers.get(PC)?;
    let MappedDwarf {
        dwarf,
        cached,
        module,
        link,
    } = mapped_dwarf(root, pc)?.ok_or_else(|| {
        crate::Diagnostic::new(
            "NO_DWARF",
            "No verified DWARF image for the current frame",
            Some("Stop in a module with matching debug information."),
        )
    })?;
    let cfa = crate::snapshot_timing::measure("variable_cfa", || {
        crate::unwind::canonical_frame_address(
            cached.bytes.clone(),
            &module,
            link,
            dwarf.bias,
            memory,
            registers,
        )
    })
    .ok();
    Ok((
        dwarf,
        crate::unwind::OfflineFrame {
            pc,
            regs: registers,
            link: Some(link),
            lookup_pc: pc,
            cfa,
        },
    ))
}

pub(crate) fn enrich_arguments(
    result: Result<serde_json::Value>,
    deadline: Instant,
    mut symbolize: impl FnMut(u64) -> Option<serde_json::Value>,
) -> serde_json::Value {
    use serde_json::json;

    let mut page = match result {
        Ok(page) => page,
        Err(error) => {
            return json!({"status": "unavailable", "items": [], "issue": error.to_string()});
        }
    };
    page["status"] = json!(if page["next_offset"].is_null() {
        "complete"
    } else {
        "partial"
    });
    if let Some(items) = page["items"].as_array_mut() {
        for item in items {
            if Instant::now() >= deadline {
                break;
            }
            let value = &mut item["value"]["result"];
            if value["type"]["kind"] == "pointer"
                && let Some(address) = value["value"].as_str()
                && let Ok(address) = u64::from_str_radix(address.trim_start_matches("0x"), 16)
                && address != 0
                && let Some(symbol) = symbolize(address)
            {
                value["symbol"] = symbol;
            }
        }
    }
    page
}

pub(crate) fn stopped_arguments(
    pid: i32,
    root: &Path,
    memory: &dyn crate::unwind::UnwindMemory,
    registers: Registers,
    deadline: Instant,
) -> serde_json::Value {
    let result = if Instant::now() < deadline {
        discover_stopped(
            root,
            memory,
            registers,
            Discovery::Parameters,
            "*",
            (0, 8),
            deadline,
        )
    } else {
        Err(failure(
            "limit_reached",
            "argument capture deadline reached",
        ))
    };
    enrich_arguments(result, deadline, |address| {
        super::resolve(pid, address, &[]).ok()?.symbol_location()
    })
}

struct Parser<'a> {
    text: &'a str,
    rest: &'a str,
    operations: Vec<Access>,
    spans: Vec<std::ops::Range<usize>>,
    root_span: std::ops::Range<usize>,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            rest: text,
            operations: vec![],
            spans: vec![],
            root_span: 0..0,
        }
    }

    fn position(&self) -> usize {
        self.text.len() - self.rest.trim_start().len()
    }

    fn push(&mut self, op: Access, start: usize, end: usize) {
        self.operations.push(op);
        self.spans.push(start..end);
    }

    fn eat(&mut self, prefix: &str) -> bool {
        self.rest = self.rest.trim_start();
        if let Some(rest) = self.rest.strip_prefix(prefix) {
            self.rest = rest;
            true
        } else {
            false
        }
    }

    fn identifier(&mut self) -> Result<String> {
        self.rest = self.rest.trim_start();
        let end = self
            .rest
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
            .count();
        if end == 0 || self.rest.as_bytes()[0].is_ascii_digit() {
            return Err(error("expected C/C++ identifier"));
        }
        let (name, rest) = self.rest.split_at(end);
        self.rest = rest;
        Ok(name.to_owned())
    }

    fn expression(&mut self, depth: usize) -> Result<String> {
        if depth > 24 {
            return Err(error("expression nesting exceeds limit"));
        }
        let start = self.position();
        if self.eat("*") {
            let name = self.expression(depth + 1)?;
            self.push(Access::Deref, start, start + 1);
            return Ok(name);
        }
        let name = if self.eat("(") {
            let name = self.expression(depth + 1)?;
            if !self.eat(")") {
                return Err(error("missing closing parenthesis"));
            }
            name
        } else {
            let mut name = if self.eat("::") {
                "::".to_owned()
            } else {
                String::new()
            };
            name.push_str(&self.identifier()?);
            while self.eat("::") {
                name.push_str("::");
                name.push_str(&self.identifier()?);
            }
            self.root_span = start
                ..(start
                    + self.text[start..self.text.len() - self.rest.len()]
                        .trim_end()
                        .len());
            name
        };
        loop {
            let start = self.position();
            if self.eat("->") {
                self.push(Access::Deref, start, start + 2);
                let member_start = self.position();
                let member = self.identifier()?;
                let end = member_start + member.len();
                self.push(Access::Member(member), member_start, end);
            } else if self.eat(".") {
                let member_start = self.position();
                let member = self.identifier()?;
                let end = member_start + member.len();
                self.push(Access::Member(member), member_start, end);
            } else if self.eat("[") {
                self.rest = self.rest.trim_start();
                let end = self.rest.bytes().take_while(u8::is_ascii_digit).count();
                let index = self.rest[..end]
                    .parse::<u64>()
                    .map_err(|_| error("expected a nonnegative array index"))?;
                self.rest = &self.rest[end..];
                if !self.eat("]") {
                    return Err(error("missing closing array bracket"));
                }
                self.push(
                    Access::Index(index),
                    start,
                    self.text.len() - self.rest.len(),
                );
            } else {
                return Ok(name);
            }
            if self.operations.len() > 48 {
                return Err(error("too many expression operations"));
            }
        }
    }
}

#[derive(Serialize)]
struct Type {
    name: Option<String>,
    kind: &'static str,
    byte_size: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<Field>,
    #[serde(skip_serializing_if = "Option::is_none")]
    element_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<Vec<u64>>,
}

#[derive(Serialize)]
struct Field {
    name: Option<String>,
    type_name: Option<String>,
    offset: Option<u64>,
    byte_size: Option<usize>,
    base_class: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    element_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    element_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<Vec<u64>>,
}

#[derive(Serialize)]
struct Datum {
    #[serde(rename = "type")]
    ty: Type,
    address: Option<String>,
    bytes: String,
    value: serde_json::Value,
    module: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<serde_json::Value>,
    #[serde(skip)]
    number: Option<Number>,
}

#[derive(Serialize)]
pub struct Report {
    pid: i32,
    tid: i32,
    expression: String,
    #[serde(flatten)]
    outcome: Outcome,
    cleanup: Cleanup,
}

#[derive(Serialize)]
struct Outcome {
    status: &'static str,
    result: Option<Datum>,
    issue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    hint: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<serde_json::Value>,
}

impl Outcome {
    fn from_result(result: Result<Datum>) -> Self {
        match result {
            Ok(mut value) => {
                if value.ty.byte_size == 8 && (value.value.is_i64() || value.value.is_u64()) {
                    value.value = serde_json::Value::String(value.value.to_string());
                }
                Self {
                    status: "complete",
                    result: Some(value),
                    issue: None,
                    code: None,
                    message: None,
                    hint: None,
                    children: None,
                }
            }
            Err(e) => {
                let status = e.downcast_ref::<Failure>().map_or("unsupported", |f| f.0);
                Self::failed(status, status.to_ascii_uppercase(), e.to_string())
            }
        }
    }

    fn symbolize_pointer(&mut self, pid: i32, deadline: Instant) {
        if Instant::now() >= deadline {
            return;
        }
        let Some(value) = self
            .result
            .as_mut()
            .filter(|value| value.ty.kind == "pointer")
        else {
            return;
        };
        if let Some(address) = value
            .value
            .as_str()
            .and_then(|text| u64::from_str_radix(text.trim_start_matches("0x"), 16).ok())
            .filter(|address| *address != 0)
        {
            value.symbol = super::resolve(pid, address, &[])
                .ok()
                .and_then(|resolved| resolved.symbol_location());
        }
    }

    fn failed(status: &'static str, code: String, message: String) -> Self {
        Self {
            status,
            result: None,
            issue: Some(message.clone()),
            code: Some(code),
            children: None,
            message: Some(message),
            hint: match status {
                "null_pointer" => Some("Inspect the pointer before dereferencing it."),
                "out_of_bounds" => Some("Use an index within the array's DWARF bounds."),
                _ => None,
            },
        }
    }
}

struct Eval<'a, 'read> {
    dwarf: &'read Dwarf<Reader<'a>>,
    unit: &'read Unit<Reader<'a>>,
    memory: &'read dyn crate::unwind::UnwindMemory,
    regs: Registers,
    link_pc: Option<u64>,
    cfa: Option<u64>,
    bias: i128,
    preview_deadline: Option<Instant>,
}

impl<'a> Eval<'a, '_> {
    fn location(&self, attr: Attr<'a>) -> Result<Expression<Reader<'a>>> {
        if let AttributeValue::Exprloc(expr) = attr {
            return Ok(expr);
        }
        if let Some(mut list) = self.dwarf.attr_locations(self.unit, attr)? {
            while let Some(entry) = list.next()? {
                if self
                    .link_pc
                    .is_some_and(|pc| (entry.range.begin..entry.range.end).contains(&pc))
                {
                    return Ok(entry.data);
                }
            }
            return Err(failure(
                "unavailable_at_pc",
                "no location entry covers the current PC",
            ));
        }
        Err(failure(
            "unsupported",
            "unsupported DWARF location attribute",
        ))
    }

    fn evaluate_pieces(
        &self,
        expr: Expression<Reader<'a>>,
        frame_base: Option<u64>,
    ) -> Result<Vec<gimli::Piece<Reader<'a>>>> {
        let mut evaluation = expr.evaluation(self.unit.encoding());
        evaluation.set_max_iterations(256);
        let mut state = evaluation.evaluate()?;
        loop {
            state = match state {
                EvaluationResult::Complete => break,
                EvaluationResult::RequiresMemory {
                    address,
                    size,
                    space: None,
                    base_type,
                } if base_type.0 == 0 => {
                    let word = self
                        .memory
                        .read_word(address, size.into())
                        .map_err(memory_failure)?;
                    evaluation.resume_with_memory(Value::Generic(word))?
                }
                EvaluationResult::RequiresRegister {
                    register,
                    base_type,
                } if base_type.0 == 0 => {
                    let word = self
                        .regs
                        .get(register)
                        .map_err(|e| failure("unavailable_at_pc", e))?;
                    evaluation.resume_with_register(Value::Generic(word))?
                }
                EvaluationResult::RequiresFrameBase => {
                    evaluation.resume_with_frame_base(frame_base.ok_or_else(|| {
                        failure("unavailable_at_pc", "DWARF frame base unavailable")
                    })?)?
                }
                EvaluationResult::RequiresCallFrameCfa => {
                    evaluation.resume_with_call_frame_cfa(self.cfa.ok_or_else(|| {
                        failure("unavailable_at_pc", "canonical frame address unavailable")
                    })?)?
                }
                EvaluationResult::RequiresRelocatedAddress(address) => evaluation
                    .resume_with_relocated_address(u64::try_from(
                        i128::from(address) + self.bias,
                    )?)?,
                EvaluationResult::RequiresIndexedAddress { index, relocate } => {
                    let address = self.dwarf.address(self.unit, index)?;
                    let address = if relocate {
                        u64::try_from(i128::from(address) + self.bias)?
                    } else {
                        address
                    };
                    evaluation.resume_with_indexed_address(address)?
                }
                EvaluationResult::RequiresEntryValue(_) => {
                    return Err(failure(
                        "unavailable_at_pc",
                        "DWARF location requires registers from function entry",
                    ));
                }
                other => {
                    return Err(failure(
                        "unsupported",
                        format!("unsupported DWARF expression: {other:?}"),
                    ));
                }
            };
        }
        Ok(evaluation.result())
    }

    fn locate(&self, expr: Expression<Reader<'a>>, frame_base: Option<u64>) -> Result<Place> {
        let pieces = self.evaluate_pieces(expr, frame_base)?;
        if let [piece] = pieces.as_slice()
            && piece.size_in_bits.is_none()
            && piece.bit_offset.is_none()
        {
            return self.place(piece.location);
        }
        let mut bytes = Vec::new();
        for piece in pieces {
            let size = piece
                .size_in_bits
                .filter(|size| size.is_multiple_of(8))
                .and_then(|size| usize::try_from(size / 8).ok())
                .filter(|size| *size <= MAX_VALUE - bytes.len())
                .ok_or_else(|| {
                    failure(
                        "unsupported",
                        "DWARF piece is not byte-aligned or exceeds the value budget",
                    )
                })?;
            let offset = piece.bit_offset.unwrap_or_default();
            if !offset.is_multiple_of(8) {
                return Err(failure(
                    "unsupported",
                    "DWARF piece offset is not byte-aligned",
                ));
            }
            if size != 0 {
                let place = self.place(piece.location)?.advance(offset / 8)?;
                bytes.extend_from_slice(&self.bytes(&place, size)?);
            }
        }
        Ok(Place::Bytes(bytes))
    }

    fn place(&self, location: Location<Reader<'a>>) -> Result<Place> {
        match location {
            Location::Address { address } => Ok(Place::Address(address)),
            Location::Register { register } => Ok(Place::Bytes(
                self.regs
                    .get(register)
                    .map_err(|e| failure("unavailable_at_pc", e))?
                    .to_le_bytes()
                    .to_vec(),
            )),
            Location::Value { value } => {
                Ok(Place::Bytes(value.to_u64(u64::MAX)?.to_le_bytes().to_vec()))
            }
            Location::Bytes { value } => Ok(Place::Bytes(value.to_vec())),
            Location::Empty => Err(failure("optimized_out", "empty DWARF location")),
            _ => Err(failure(
                "unsupported",
                "unsupported DWARF variable location",
            )),
        }
    }

    fn bytes(&self, location: &Place, len: usize) -> Result<Vec<u8>> {
        if len > MAX_VALUE {
            return Err(failure(
                "unsupported",
                format!("value exceeds {MAX_VALUE} byte limit"),
            ));
        }
        match location {
            Place::Bytes(bytes) => bytes.get(..len).map(<[u8]>::to_vec).ok_or_else(|| {
                failure(
                    "unsupported",
                    "DWARF value is shorter than its declared type",
                )
            }),
            Place::Address(address) => {
                let mut bytes = Vec::with_capacity(len);
                while bytes.len() < len {
                    let size = (len - bytes.len()).min(8);
                    let address = address
                        .checked_add(bytes.len() as u64)
                        .ok_or_else(|| error("value range overflows"))?;
                    let word = self
                        .memory
                        .read_word(address, size)
                        .map_err(memory_failure)?;
                    bytes.extend_from_slice(&word.to_le_bytes()[..size]);
                }
                Ok(bytes)
            }
        }
    }
}

#[derive(Clone)]
enum Place {
    Address(u64),
    Bytes(Vec<u8>),
}

impl Place {
    fn advance(mut self, bytes: u64) -> Result<Self> {
        match &mut self {
            Self::Address(address) => {
                *address = address
                    .checked_add(bytes)
                    .ok_or_else(|| error("address overflow"))?
            }
            Self::Bytes(value) => {
                let offset = usize::try_from(bytes)?;
                if offset > value.len() {
                    return Err(error("member offset outside value"));
                }
                value.drain(..offset);
            }
        }
        Ok(self)
    }
}

fn reference(unit: &Unit<Reader<'_>>, attr: Option<Attr<'_>>) -> Option<Offset> {
    match attr? {
        AttributeValue::UnitRef(offset) => Some(offset),
        AttributeValue::DebugInfoRef(offset) => offset.to_unit_offset(&unit.header),
        _ => None,
    }
}

fn resolved_attr<'a>(
    unit: &Unit<Reader<'a>>,
    entry: &Die<'a>,
    name: gimli::DwAt,
    depth: usize,
) -> Result<Option<Attr<'a>>> {
    if depth > 8 {
        return Err(error("DWARF attribute reference chain too deep"));
    }
    if let Some(attr) = entry.attr_value(name) {
        return Ok(Some(attr));
    }
    for key in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
        if let Some(offset) = reference(unit, entry.attr_value(key))
            && let Some(value) = resolved_attr(unit, &unit.entry(offset)?, name, depth + 1)?
        {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn name<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<Reader<'a>>,
    entry: &Die<'a>,
) -> Result<Option<String>> {
    resolved_attr(unit, entry, gimli::DW_AT_name, 0)?
        .map(|attr| {
            Ok(dwarf
                .attr_string(unit, attr)?
                .to_string_lossy()
                .into_owned())
        })
        .transpose()
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InlineFrame {
    symbol: String,
    call_file: Option<PathBuf>,
    call_line: Option<u64>,
}

fn inline_frame<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<Reader<'a>>,
    entry: &Die<'a>,
) -> Result<InlineFrame> {
    let symbol = name(dwarf, unit, entry)?.unwrap_or_else(|| "<inline>".to_owned());
    let call_file = match (
        unit.line_program.as_ref(),
        entry.attr_value(gimli::DW_AT_call_file),
    ) {
        (Some(program), Some(AttributeValue::FileIndex(index))) => program
            .header()
            .file(index)
            .map(|file| super::source_path(dwarf, &unit, program.header(), file))
            .transpose()?,
        _ => None,
    };
    let call_line = entry
        .attr_value(gimli::DW_AT_call_line)
        .and_then(|value| value.udata_value());
    Ok(InlineFrame {
        symbol,
        call_file,
        call_line,
    })
}

pub(crate) fn inline_frames(
    dwarf: &Dwarf<Reader<'_>>,
    pc: u64,
    deadline: Instant,
) -> Result<Vec<InlineFrame>> {
    let mut units = dwarf.units();
    let mut budget = ScanBudget::foreground(deadline);
    while let Some(header) = units.next()? {
        budget.entry()?;
        let unit = dwarf.unit(header)?;
        let mut ranges = dwarf.unit_ranges(&unit)?;
        let mut covered = None;
        while let Some(range) = ranges.next()? {
            covered = Some((range.begin..range.end).contains(&pc));
            if covered == Some(true) {
                break;
            }
        }
        if covered == Some(false) {
            continue;
        }
        let mut best = Vec::new();
        let mut active = Vec::new();
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs()? {
            budget.entry()?;
            active.retain(|(depth, _)| *depth < entry.depth());
            if entry.tag() != gimli::DW_TAG_inlined_subroutine {
                continue;
            }
            let mut ranges = dwarf.die_ranges(&unit, entry)?;
            while let Some(range) = ranges.next()? {
                if !(range.begin..range.end).contains(&pc) {
                    continue;
                }
                active.push((entry.depth(), inline_frame(dwarf, &unit, entry)?));
                if active.len() > best.len() {
                    best = active
                        .iter()
                        .rev()
                        .map(|(_, frame)| frame.clone())
                        .collect();
                }
                break;
            }
        }
        if !best.is_empty() {
            return Ok(best);
        }
    }
    Ok(Vec::new())
}

fn typedef_target<'a>(unit: &Unit<Reader<'a>>, entry: &Die<'a>) -> Result<Offset> {
    reference(unit, resolved_attr(unit, entry, gimli::DW_AT_type, 0)?).ok_or_else(|| {
        failure(
            "unsupported",
            "type reference missing or outside compilation unit",
        )
    })
}

fn underlying<'a>(unit: &Unit<Reader<'a>>, mut offset: Offset) -> Result<Die<'a>> {
    for _ in 0..16 {
        let entry = unit.entry(offset)?;
        match entry.tag() {
            gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type
            | gimli::DW_TAG_typedef => offset = typedef_target(unit, &entry)?,
            _ => return Ok(entry),
        }
    }
    Err(error("DWARF type alias chain too deep"))
}

fn array_dimensions(unit: &Unit<Reader<'_>>, array: &Die<'_>) -> Result<Vec<u64>> {
    let mut cursor = unit.entries_at_offset(array.offset())?;
    let root_depth = cursor.next_dfs()?.map_or(0, |root| root.depth());
    let mut dimensions = Vec::new();
    while let Some(child) = cursor.next_dfs()? {
        if child.depth() <= root_depth {
            break;
        }
        if child.depth() == root_depth + 1 && child.tag() == gimli::DW_TAG_subrange_type {
            let lower = child
                .attr_value(gimli::DW_AT_lower_bound)
                .and_then(|v| v.udata_value())
                .unwrap_or(0);
            if lower != 0 {
                return Err(failure("unsupported", "nonzero array lower bound"));
            }
            let count = child
                .attr_value(gimli::DW_AT_count)
                .and_then(|v| v.udata_value())
                .or_else(|| {
                    child
                        .attr_value(gimli::DW_AT_upper_bound)?
                        .udata_value()?
                        .checked_add(1)
                })
                .ok_or_else(|| failure("unsupported", "array bound is not constant"))?;
            if dimensions.len() >= 16 {
                return Err(failure(
                    "limit_reached",
                    "array has more than 16 dimensions",
                ));
            }
            dimensions.push(count);
        }
    }
    if dimensions.is_empty() {
        return Err(failure("unsupported", "array bound missing"));
    }
    Ok(dimensions)
}

fn array_length(unit: &Unit<Reader<'_>>, array: &Die<'_>) -> Result<u64> {
    let dimensions = array_dimensions(unit, array)?;
    match dimensions.as_slice() {
        [count] => Ok(*count),
        _ => Err(failure(
            "unsupported",
            "multidimensional array indexing is unsupported",
        )),
    }
}

fn type_size<'a>(unit: &Unit<Reader<'a>>, entry: &Die<'a>, depth: usize) -> Result<usize> {
    if depth > 16 {
        return Err(error("DWARF type nesting exceeds limit"));
    }
    if let Some(size) = entry
        .attr_value(gimli::DW_AT_byte_size)
        .and_then(|v| v.udata_value())
    {
        return Ok(usize::try_from(size)?);
    }
    match entry.tag() {
        gimli::DW_TAG_pointer_type
        | gimli::DW_TAG_reference_type
        | gimli::DW_TAG_rvalue_reference_type => Ok(unit.encoding().address_size as usize),
        gimli::DW_TAG_array_type => {
            let element = underlying(unit, typedef_target(unit, entry)?)?;
            let size = type_size(unit, &element, depth + 1)?;
            array_dimensions(unit, entry)?
                .into_iter()
                .try_fold(size, |size, count| {
                    size.checked_mul(usize::try_from(count)?)
                        .ok_or_else(|| error("array size overflow"))
                })
        }
        _ => Err(failure("unsupported", "type size missing")),
    }
}

fn member_offset(entry: &Die<'_>, aggregate: &Die<'_>) -> Result<u64> {
    if entry.attr_value(gimli::DW_AT_bit_size).is_some() {
        return Err(failure("unsupported", "bit-field layout is unsupported"));
    }
    match entry.attr_value(gimli::DW_AT_data_member_location) {
        Some(value) => value
            .udata_value()
            .ok_or_else(|| failure("unsupported", "nonconstant member layout")),
        None if aggregate.tag() == gimli::DW_TAG_union_type => Ok(0),
        None => Err(failure("unsupported", "member offset missing")),
    }
}

fn fields<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<Reader<'a>>,
    entry: &Die<'a>,
) -> Result<Vec<Field>> {
    let mut cursor = unit.entries_at_offset(entry.offset())?;
    let root_depth = cursor.next_dfs()?.map_or(0, |root| root.depth());
    let mut fields = Vec::new();
    while let Some(child) = cursor.next_dfs()? {
        if child.depth() <= root_depth {
            break;
        }
        if child.depth() != root_depth + 1
            || !matches!(
                child.tag(),
                gimli::DW_TAG_member | gimli::DW_TAG_inheritance
            )
        {
            continue;
        }
        if fields.len() >= 128 {
            return Err(failure(
                "limit_reached",
                "type layout has more than 128 fields",
            ));
        }
        let ty = typedef_target(unit, child)
            .ok()
            .and_then(|ty| underlying(unit, ty).ok());
        let array = ty
            .as_ref()
            .filter(|ty| ty.tag() == gimli::DW_TAG_array_type);
        let element_type = array
            .and_then(|ty| typedef_target(unit, ty).ok())
            .and_then(|element| unit.entry(element).ok())
            .and_then(|element| name(dwarf, unit, &element).ok().flatten());
        fields.push(Field {
            name: name(dwarf, unit, child)?,
            type_name: ty
                .as_ref()
                .and_then(|ty| name(dwarf, unit, ty).ok().flatten()),
            offset: member_offset(child, entry).ok(),
            byte_size: ty.as_ref().and_then(|ty| type_size(unit, ty, 0).ok()),
            base_class: child.tag() == gimli::DW_TAG_inheritance,
            element_type,
            element_count: array.and_then(|ty| array_length(unit, ty).ok()),
            dimensions: array.and_then(|ty| array_dimensions(unit, ty).ok()),
        });
    }
    Ok(fields)
}

fn unknown_member<'a>(eval: &Eval<'a, '_>, aggregate: &Die<'a>, field: &str) -> String {
    let mut candidates: Vec<_> = fields(eval.dwarf, eval.unit, aggregate)
        .unwrap_or_default()
        .into_iter()
        .filter(|member| !member.base_class)
        .filter_map(|member| member.name)
        .collect();
    candidates.sort_by_key(|name| {
        let common = name
            .bytes()
            .zip(field.bytes())
            .take_while(|(a, b)| a == b)
            .count();
        (std::cmp::Reverse(common), name.len().abs_diff(field.len()))
    });
    candidates.dedup();
    candidates.truncate(5);
    let mut message = format!("member {field} not found");
    if !candidates.is_empty() {
        message.push_str(&format!(". Did you mean {}?", candidates.join(", ")));
    }
    message
}

fn find_member<'a>(
    eval: &Eval<'a, '_>,
    aggregate: &Die<'a>,
    field: &str,
    depth: usize,
    with_offset: bool,
) -> Result<Option<(Offset, u64)>> {
    if depth > 12 {
        return Err(failure(
            "unsupported",
            "inheritance hierarchy exceeds limit",
        ));
    }
    if matches!(
        aggregate.attr_value(gimli::DW_AT_declaration),
        Some(AttributeValue::Flag(true))
    ) {
        return Err(failure(
            "unsupported",
            "member lookup has an incomplete DWARF type",
        ));
    }
    let mut cursor = eval.unit.entries_at_offset(aggregate.offset())?;
    cursor.next_dfs()?;
    let mut bases = Vec::new();
    while let Some(entry) = cursor.next_dfs()? {
        if entry.depth() <= aggregate.depth() {
            break;
        }
        if entry.depth() != aggregate.depth() + 1 {
            continue;
        }
        if entry.tag() == gimli::DW_TAG_member
            && name(eval.dwarf, eval.unit, entry)?.as_deref() == Some(field)
        {
            return Ok(Some((
                typedef_target(eval.unit, entry)?,
                if with_offset {
                    member_offset(entry, aggregate)?
                } else {
                    0
                },
            )));
        }
        if entry.tag() == gimli::DW_TAG_inheritance {
            bases.push(entry.offset());
        }
    }
    let mut found = None;
    for offset in bases {
        let inheritance = eval.unit.entry(offset)?;
        let base = underlying(eval.unit, typedef_target(eval.unit, &inheritance)?)?;
        if let Some((ty, delta)) = find_member(eval, &base, field, depth + 1, with_offset)? {
            if found.is_some() {
                return Err(failure("ambiguous", "inherited member is ambiguous"));
            }
            let offset = if with_offset {
                member_offset(&inheritance, aggregate)?
                    .checked_add(delta)
                    .ok_or_else(|| error("member offset overflow"))?
            } else {
                0
            };
            found = Some((ty, offset));
        }
    }
    Ok(found)
}

fn word(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(failure("unsupported", "scalar size is unsupported"));
    }
    let mut data = [0; 8];
    data[..bytes.len()].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(data))
}

fn pointer<'a>(eval: &Eval<'a, '_>, place: &Place, entry: &Die<'a>) -> Result<u64> {
    let address = word(&eval.bytes(place, type_size(eval.unit, entry, 0)?)?)?;
    if address == 0 {
        return Err(failure("null_pointer", "null pointer dereference"));
    }
    Ok(address)
}

enum ArrayStorage<'a> {
    Elements(Die<'a>, u64),
    Empty,
}

fn array_storage<'a>(
    eval: &Eval<'a, '_>,
    entry: &Die<'a>,
    with_offset: bool,
) -> Result<Option<ArrayStorage<'a>>> {
    if entry.tag() == gimli::DW_TAG_array_type {
        return Ok(Some(ArrayStorage::Elements(
            eval.unit.entry(entry.offset())?,
            0,
        )));
    }
    if !matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type
    ) {
        return Ok(None);
    }
    let Some(name) = name(eval.dwarf, eval.unit, entry)? else {
        return Ok(None);
    };
    let name = name.strip_prefix("std::").unwrap_or(&name);
    if !name.starts_with("array<") {
        return Ok(None);
    }
    let storage = match find_member(eval, entry, "_M_elems", 0, with_offset)? {
        Some(storage) => Some(storage),
        None => find_member(eval, entry, "__elems_", 0, with_offset)?,
    };
    if let Some((storage, offset)) = storage {
        let storage = underlying(eval.unit, storage)?;
        if storage.tag() == gimli::DW_TAG_array_type {
            return Ok(Some(ArrayStorage::Elements(storage, offset)));
        }
    }
    Ok(name
        .trim_end_matches('>')
        .rsplit_once(',')
        .is_some_and(|(_, count)| count.trim() == "0")
        .then_some(ArrayStorage::Empty))
}

fn index_type<'a>(
    eval: &Eval<'a, '_>,
    entry: &Die<'a>,
    index: u64,
    with_offset: bool,
) -> Result<Option<(Offset, u64)>> {
    if entry.tag() == gimli::DW_TAG_pointer_type {
        return Ok(Some((typedef_target(eval.unit, entry)?, 0)));
    }
    match array_storage(eval, entry, with_offset)? {
        Some(ArrayStorage::Elements(array, offset)) if index < array_length(eval.unit, &array)? => {
            Ok(Some((typedef_target(eval.unit, &array)?, offset)))
        }
        Some(_) => Err(failure("out_of_bounds", "array index out of bounds")),
        None => Ok(None),
    }
}

fn access(
    eval: &Eval<'_, '_>,
    mut ty: Offset,
    mut place: Place,
    operations: &[Access],
) -> Result<(Offset, Place)> {
    for op in operations {
        let entry = underlying(eval.unit, ty)?;
        match op {
            Access::Deref if entry.tag() == gimli::DW_TAG_pointer_type => {
                place = Place::Address(pointer(eval, &place, &entry)?);
                ty = typedef_target(eval.unit, &entry)?;
            }
            Access::Index(index) => {
                let (element, offset) =
                    index_type(eval, &entry, *index, true)?.ok_or_else(|| {
                        failure(
                            "unsupported",
                            "expression operation does not match the DWARF type",
                        )
                    })?;
                if entry.tag() == gimli::DW_TAG_pointer_type {
                    place = Place::Address(pointer(eval, &place, &entry)?);
                }
                ty = element;
                let element = underlying(eval.unit, ty)?;
                let size = type_size(eval.unit, &element, 0)? as u64;
                place = place.advance(offset)?.advance(
                    index
                        .checked_mul(size)
                        .ok_or_else(|| error("array offset overflow"))?,
                )?;
            }
            Access::Member(field)
                if matches!(
                    entry.tag(),
                    gimli::DW_TAG_structure_type
                        | gimli::DW_TAG_class_type
                        | gimli::DW_TAG_union_type
                ) =>
            {
                let (member, offset) = find_member(eval, &entry, field, 0, true)?
                    .ok_or_else(|| failure("not_found", unknown_member(eval, &entry, field)))?;
                place = place.advance(offset)?;
                ty = member;
            }
            _ => {
                return Err(failure(
                    "unsupported",
                    "expression operation does not match the DWARF type",
                ));
            }
        }
        let entry = underlying(eval.unit, ty)?;
        if matches!(
            entry.tag(),
            gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type
        ) {
            place = Place::Address(pointer(eval, &place, &entry)?);
            ty = typedef_target(eval.unit, &entry)?;
        }
    }
    Ok((ty, place))
}

fn char_pointer<'a>(eval: &Eval<'a, '_>, ty: &Die<'a>) -> Option<()> {
    if ty.tag() != gimli::DW_TAG_pointer_type {
        return None;
    }
    let target = underlying(eval.unit, typedef_target(eval.unit, ty).ok()?).ok()?;
    (target.tag() == gimli::DW_TAG_base_type
        && name(eval.dwarf, eval.unit, &target)
            .ok()
            .flatten()
            .as_deref()
            == Some("char"))
    .then_some(())
}

fn string_preview<'a>(
    eval: &Eval<'a, '_>,
    entry: &Die<'a>,
    place: &Place,
    bytes: &[u8],
) -> Option<serde_json::Value> {
    let deadline = eval.preview_deadline?;
    let (address, length) = if char_pointer(eval, entry).is_some() {
        (word(bytes).ok()?, None)
    } else if matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type
    ) {
        let name = name(eval.dwarf, eval.unit, entry).ok()??;
        let name = name.strip_prefix("std::").unwrap_or(&name);
        let name = name.strip_prefix("__cxx11::").unwrap_or(name);
        let read_member = |ty, place, field| {
            let (ty, place) = access(eval, ty, place, &[Access::Member(field)]).ok()?;
            Some((underlying(eval.unit, ty).ok()?, place))
        };
        let (pointer, pointer_place, length_member) = if name.starts_with("basic_string_view<char,")
        {
            let (pointer, place) = read_member(entry.offset(), place.clone(), "_M_str".into())?;
            (pointer, place, "_M_len")
        } else if name.starts_with("basic_string<char,") {
            let (storage, place) =
                read_member(entry.offset(), place.clone(), "_M_dataplus".into())?;
            let (pointer, place) = read_member(storage.offset(), place, "_M_p".into())?;
            (pointer, place, "_M_string_length")
        } else {
            return None;
        };
        char_pointer(eval, &pointer)?;
        let (length_ty, length_place) =
            read_member(entry.offset(), place.clone(), length_member.into())?;
        if length_ty.tag() != gimli::DW_TAG_base_type
            || !matches!(
                length_ty.attr_value(gimli::DW_AT_encoding),
                Some(AttributeValue::Encoding(gimli::DW_ATE_unsigned))
            )
        {
            return None;
        }
        let length = word(
            &eval
                .bytes(&length_place, type_size(eval.unit, &length_ty, 0).ok()?)
                .ok()?,
        )
        .ok()?;
        let address = word(
            &eval
                .bytes(&pointer_place, type_size(eval.unit, &pointer, 0).ok()?)
                .ok()?,
        )
        .ok()?;
        (address, Some(length))
    } else {
        return None;
    };
    let mut preview = Vec::new();
    let mut status = "complete";
    let limit = length.unwrap_or(MAX_VALUE as u64).min(MAX_VALUE as u64);
    if address == 0 && length != Some(0) {
        status = "null_pointer";
    } else {
        while (preview.len() as u64) < limit {
            if Instant::now() >= deadline {
                status = "limit_reached";
                break;
            }
            let Some(next) = address.checked_add(preview.len() as u64) else {
                status = "read_failed";
                break;
            };
            match eval.memory.read_word(next, 1) {
                Ok(0) if length.is_none() => break,
                Ok(byte) => preview.push(byte as u8),
                Err(error) => {
                    status = if error.is::<crate::unwind::MissingMemory>() {
                        "missing_page"
                    } else {
                        "read_failed"
                    };
                    break;
                }
            }
        }
        if status == "complete"
            && length.unwrap_or(limit + 1) > preview.len() as u64
            && preview.len() as u64 == limit
        {
            status = "truncated";
        }
    }
    Some(serde_json::json!({
        "address": hex(address), "length": length,
        "text": String::from_utf8_lossy(&preview), "bytes": id_hex(&preview), "status": status,
    }))
}

fn frame_relative_location<'a>(eval: &Eval<'a, '_>, entry: &Die<'a>) -> bool {
    let Ok(Some(attribute)) = resolved_attr(eval.unit, entry, gimli::DW_AT_location, 0) else {
        return false;
    };
    let Ok(expression) = eval.location(attribute) else {
        return false;
    };
    let mut operations = expression.operations(eval.unit.encoding());
    while let Ok(Some(op)) = operations.next() {
        match op {
            gimli::Operation::FrameOffset { .. } | gimli::Operation::CallFrameCFA => return true,
            gimli::Operation::RegisterOffset { register, .. }
                if register == regs::SP || register == regs::FP =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn evaluate_candidate<'a>(
    eval: &Eval<'a, '_>,
    candidate: &Candidate<'a>,
    operations: &[Access],
    module: PathBuf,
) -> Result<Datum> {
    let entry = eval.unit.entry(candidate.offset)?;
    if candidate.prologue && frame_relative_location(eval, &entry) {
        return Err(failure(
            "unavailable_at_pc",
            "Frame-relative storage may be uninitialized at function entry",
        ));
    }
    evaluate_variable(eval, &entry, candidate.frame_base, operations, module)
}

fn evaluate_variable<'a>(
    eval: &Eval<'a, '_>,
    entry: &Die<'a>,
    frame_base: Option<Attr<'a>>,
    operations: &[Access],
    module: PathBuf,
) -> Result<Datum> {
    let location = crate::snapshot_timing::phase("variable_location");
    let ty = typedef_target(eval.unit, entry)?;
    let place = if let Some(attr) = resolved_attr(eval.unit, entry, gimli::DW_AT_location, 0)? {
        let frame_base = frame_base.and_then(|attr| {
            match eval.locate(eval.location(attr).ok()?, None).ok()? {
                Place::Address(address) => Some(address),
                Place::Bytes(bytes) => word(&bytes).ok(),
            }
        });
        eval.locate(eval.location(attr)?, frame_base)?
    } else if let Some(attr) = resolved_attr(eval.unit, entry, gimli::DW_AT_const_value, 0)? {
        match attr {
            AttributeValue::Block(value) => Place::Bytes(value.to_vec()),
            value => {
                let word = value
                    .udata_value()
                    .or_else(|| value.sdata_value().map(|v| v as u64))
                    .ok_or_else(|| failure("unsupported", "unsupported DWARF constant value"))?;
                Place::Bytes(word.to_le_bytes().to_vec())
            }
        }
    } else {
        return Err(failure(
            "optimized_out",
            "DWARF variable has no materialized location or constant",
        ));
    };
    drop(location);
    let address_of = matches!(operations.last(), Some(Access::Address));
    let operations = if address_of {
        &operations[..operations.len() - 1]
    } else {
        operations
    };
    let ty_entry = underlying(eval.unit, ty)?;
    let (ty, place) = if matches!(
        ty_entry.tag(),
        gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type
    ) {
        (
            typedef_target(eval.unit, &ty_entry)?,
            Place::Address(pointer(eval, &place, &ty_entry)?),
        )
    } else {
        (ty, place)
    };
    let (ty, place) = access(eval, ty, place, operations)?;
    let entry = underlying(eval.unit, ty)?;
    if address_of {
        let Place::Address(address) = place else {
            return Err(failure(
                "address_unavailable",
                "the lvalue has no memory address at this PC",
            ));
        };
        let mut result = Number::Pointer(address).datum();
        if let Some(name) = name(eval.dwarf, eval.unit, &entry)? {
            result.ty.name = Some(format!("{name} *"));
        }
        result.module = Some(module);
        return Ok(result);
    }
    let size = type_size(eval.unit, &entry, 0)?;
    let composite = matches!(
        entry.tag(),
        gimli::DW_TAG_array_type
            | gimli::DW_TAG_structure_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_union_type
    );
    let bytes = eval.bytes(&place, if composite { size.min(MAX_VALUE) } else { size })?;
    let kind = match entry.tag() {
        gimli::DW_TAG_pointer_type => "pointer",
        gimli::DW_TAG_base_type => "scalar",
        gimli::DW_TAG_enumeration_type => "enum",
        gimli::DW_TAG_array_type => "array",
        gimli::DW_TAG_class_type => "class",
        gimli::DW_TAG_structure_type => "struct",
        gimli::DW_TAG_union_type => "union",
        _ => "other",
    };
    let encoding = entry.attr_value(gimli::DW_AT_encoding);
    let number = if kind == "pointer" {
        Some(Number::Pointer(word(&bytes)?))
    } else {
        Number::dwarf(
            &bytes,
            match encoding.as_ref() {
                Some(AttributeValue::Encoding(encoding)) => Some(*encoding),
                _ => None,
            },
        )
    };
    let value = match (kind, encoding, bytes.len()) {
        ("pointer", _, _) => serde_json::json!(hex(word(&bytes)?)),
        (
            "scalar" | "enum",
            Some(AttributeValue::Encoding(gimli::DW_ATE_signed | gimli::DW_ATE_signed_char)),
            1..=8,
        ) => {
            let shift = (8 - bytes.len()) * 8;
            serde_json::json!(((word(&bytes)? << shift) as i64) >> shift)
        }
        ("scalar", Some(AttributeValue::Encoding(gimli::DW_ATE_boolean)), 1..=8) => {
            serde_json::json!(word(&bytes)? != 0)
        }
        ("scalar", Some(AttributeValue::Encoding(gimli::DW_ATE_float)), 4) => {
            serde_json::json!(f32::from_bits(word(&bytes)? as u32))
        }
        ("scalar", Some(AttributeValue::Encoding(gimli::DW_ATE_float)), 8) => {
            serde_json::json!(f64::from_bits(word(&bytes)?))
        }
        ("scalar" | "enum", _, 1..=8) => serde_json::json!(word(&bytes)?),
        _ => serde_json::Value::Null,
    };
    let dimensions = match array_storage(eval, &entry, false)? {
        Some(ArrayStorage::Elements(array, _)) => Some(array_dimensions(eval.unit, &array)?),
        Some(ArrayStorage::Empty) => Some(vec![0]),
        None => None,
    };
    Ok(Datum {
        ty: Type {
            name: name(eval.dwarf, eval.unit, &eval.unit.entry(ty)?)?
                .or(name(eval.dwarf, eval.unit, &entry)?),
            kind,
            byte_size: size,
            fields: if matches!(kind, "struct" | "class" | "union") {
                fields(eval.dwarf, eval.unit, &entry)?
            } else {
                Vec::new()
            },
            element_count: dimensions.as_deref().and_then(|dims| match dims {
                [count] => Some(*count),
                _ => None,
            }),
            dimensions,
        },
        address: match place {
            Place::Address(address) => Some(hex(address)),
            _ => None,
        },
        preview: string_preview(eval, &entry, &place, &bytes),
        symbol: None,
        bytes: id_hex(&bytes),
        value,
        module: Some(module),
        number,
    })
}

#[derive(Clone, Default)]
struct Scope<'a> {
    local: bool,
    active: bool,
    namespace: String,
    frame_base: Option<Attr<'a>>,
    frame_base_owner: Option<Offset>,
    frame_contains_pc: bool,
    ranges: std::sync::Arc<[gimli::Range]>,
    prologue: bool,
}

#[derive(Clone)]
struct Candidate<'a> {
    offset: Offset,
    priority: usize,
    concrete: bool,
    active: bool,
    ranges: std::sync::Arc<[gimli::Range]>,
    prologue: bool,
    frame_base: Option<Attr<'a>>,
    frame_base_owner: Option<Offset>,
}

fn prefer<'a>(best: &mut Option<Candidate<'a>>, ambiguous: &mut bool, candidate: Candidate<'a>) {
    let rank = |entry: &Candidate<'_>| (entry.priority, entry.concrete);
    match best.as_ref() {
        Some(old) if rank(old) > rank(&candidate) => {}
        Some(old) if rank(old) == rank(&candidate) => *ambiguous = true,
        _ => {
            *best = Some(candidate);
            *ambiguous = false;
        }
    }
}

fn inline_origin_variable<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<Reader<'a>>,
    scope: &Die<'a>,
    target: &str,
) -> Result<Option<Offset>> {
    let Some(origin) = reference(unit, scope.attr_value(gimli::DW_AT_abstract_origin)) else {
        return Ok(None);
    };
    let mut entries = unit.entries_at_offset(origin)?;
    entries.next_dfs()?;
    for _ in 0..1024 {
        let Some(entry) = entries.next_dfs()? else {
            break;
        };
        if entry.depth() <= 0 {
            break;
        }
        if entry.depth() == 1
            && matches!(
                entry.tag(),
                gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter
            )
            && name(dwarf, unit, entry)?.as_deref() == Some(target)
        {
            return Ok(Some(entry.offset()));
        }
    }
    Ok(None)
}

type VariableVisitor<'a, 'v> = dyn FnMut(&str, bool, gimli::DwTag, &Candidate<'a>) -> bool + 'v;

struct ScanBudget {
    scanned: usize,
    limit: usize,
    deadline: Option<Instant>,
}

impl ScanBudget {
    fn foreground(deadline: Instant) -> Self {
        Self {
            scanned: 0,
            limit: MAX_DIES,
            deadline: Some(deadline),
        }
    }

    fn entry(&mut self) -> Result<()> {
        self.scanned += 1;
        if self.scanned > self.limit
            || (self.scanned.is_multiple_of(128)
                && self
                    .deadline
                    .is_some_and(|deadline| Instant::now() >= deadline))
        {
            return Err(failure(
                "limit_reached",
                "DWARF variable lookup exceeded its capture budget",
            ));
        }
        Ok(())
    }
}

fn find_variable<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<Reader<'a>>,
    target: &str,
    link_pc: Option<u64>,
    budget: &mut ScanBudget,
    mut shadow: Option<&mut bool>,
    mut visit: Option<&mut VariableVisitor<'a, '_>>,
    all_locals: bool,
    function: Option<Offset>,
) -> Result<Option<Candidate<'a>>> {
    let mut entries = match function {
        Some(offset) => unit.entries_at_offset(offset)?,
        None => unit.entries(),
    };
    let mut scopes: Vec<Scope<'a>> = Vec::new();
    let mut declarations = BTreeMap::new();
    let mut best: Option<Candidate<'a>> = None;
    let mut ambiguous = false;
    let prune =
        shadow.is_none() && !all_locals && link_pc.is_some() && !crate::snapshot_timing::baseline();
    let mut at_sibling = false;
    loop {
        let entry = if std::mem::take(&mut at_sibling) {
            entries.current()
        } else {
            entries.next_dfs()?
        };
        let Some(entry) = entry else {
            break;
        };
        budget.entry()?;
        if function.is_some_and(|offset| entry.depth() <= 0 && entry.offset() != offset) {
            break;
        }
        let depth = usize::try_from(entry.depth())?;
        if depth > 96 {
            return Err(failure(
                "unsupported",
                "DWARF lexical nesting exceeds limit",
            ));
        }
        scopes.truncate(depth);
        let mut scope = scopes.last().cloned().unwrap_or_else(|| Scope {
            active: true,
            ..Scope::default()
        });
        let tag = entry.tag();
        if matches!(
            tag,
            gimli::DW_TAG_subprogram
                | gimli::DW_TAG_inlined_subroutine
                | gimli::DW_TAG_lexical_block
        ) {
            let mut ranges = dwarf.die_ranges(unit, entry)?;
            let mut bounds = Vec::new();
            let mut contains = false;
            let mut has_ranges = false;
            let mut at_entry = false;
            while let Some(range) = ranges.next()? {
                has_ranges = true;
                contains |= link_pc.is_some_and(|pc| (range.begin..range.end).contains(&pc));
                at_entry |= link_pc == Some(range.begin);
                if all_locals {
                    bounds.push(range);
                }
            }
            if tag == gimli::DW_TAG_subprogram {
                scope.frame_contains_pc = scope.active && contains;
                scope.prologue = at_entry;
            }
            if has_ranges || tag != gimli::DW_TAG_lexical_block {
                scope.active &= contains;
            }
            if !bounds.is_empty() {
                scope.ranges = bounds.into();
            }
            scope.local = true;
            if let Some(frame_base) = entry.attr_value(gimli::DW_AT_frame_base) {
                scope.frame_base = Some(frame_base);
                scope.frame_base_owner = Some(entry.offset());
            }
            if scope.active
                && tag == gimli::DW_TAG_inlined_subroutine
                && let Some(offset) = inline_origin_variable(dwarf, unit, entry, target)?
            {
                // Some optimizers omit a concrete DIE for an eliminated inlined variable.
                prefer(
                    &mut best,
                    &mut ambiguous,
                    Candidate {
                        offset,
                        priority: depth + 2,
                        concrete: false,
                        active: true,
                        ranges: scope.ranges.clone(),
                        prologue: scope.prologue,
                        frame_base: scope.frame_base,
                        frame_base_owner: scope.frame_base_owner,
                    },
                );
            }
        }
        if prune
            && scope.local
            && !scope.active
            && entry.has_children()
            && matches!(entry.attr_value(gimli::DW_AT_sibling),
                Some(AttributeValue::UnitRef(offset)) if offset.0 > entry.offset().0)
        {
            crate::snapshot_timing::count("variable_sibling_jumps");
            at_sibling = entries.next_sibling()?.is_some();
            continue;
        }
        if !scope.local
            && matches!(
                tag,
                gimli::DW_TAG_namespace | gimli::DW_TAG_class_type | gimli::DW_TAG_structure_type
            )
            && let Some(namespace) = name(dwarf, unit, entry)?
        {
            scope.namespace.push_str(&namespace);
            scope.namespace.push_str("::");
        }
        if let Some(shadow) = shadow.as_deref_mut()
            && scope.local
            && matches!(tag, gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter)
            && name(dwarf, unit, entry)?.as_deref() == Some(target)
        {
            *shadow = true;
        }
        if (scope.active || (all_locals && scope.frame_contains_pc))
            && matches!(tag, gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter)
            && let Some(name) = name(dwarf, unit, entry)?
        {
            let specification = reference(unit, entry.attr_value(gimli::DW_AT_specification));
            let qualified = specification
                .and_then(|offset| declarations.get(&offset.0).cloned())
                .unwrap_or_else(|| format!("{}{name}", scope.namespace));
            if matches!(
                entry.attr_value(gimli::DW_AT_declaration),
                Some(AttributeValue::Flag(true))
            ) {
                declarations.insert(entry.offset().0, qualified);
            } else {
                let priority = if scope.local { depth + 1 } else { 0 };
                let candidate = Candidate {
                    offset: entry.offset(),
                    priority,
                    concrete: true,
                    active: scope.active,
                    ranges: scope.ranges.clone(),
                    prologue: scope.prologue,
                    frame_base: scope.frame_base,
                    frame_base_owner: scope.frame_base_owner,
                };
                if let Some(visit) = visit.as_mut() {
                    if !visit(
                        if scope.local { &name } else { &qualified },
                        scope.local,
                        tag,
                        &candidate,
                    ) {
                        break;
                    }
                } else if (scope.local && name == target)
                    || (!scope.local && qualified == target.strip_prefix("::").unwrap_or(target))
                {
                    prefer(&mut best, &mut ambiguous, candidate);
                }
            }
        }
        scopes.push(scope);
    }
    if ambiguous {
        return Err(failure(
            "ambiguous",
            "multiple matching DWARF variables in the same scope",
        ));
    }
    Ok(best)
}

#[derive(Clone, Copy)]
enum LiveModules<'a> {
    Filter {
        module: Option<&'a str>,
        instance: Option<u64>,
    },
    FrameFirst,
    FrameOnly,
}

struct Query<'a> {
    target: &'a str,
    operations: &'a [Access],
    memory: &'a dyn crate::unwind::UnwindMemory,
    registers: Registers,
    deadline: Instant,
}

struct MatchValue {
    priority: usize,
    value: Result<Datum>,
}

fn load_sections<'a, T>(
    obj: &object::File<'a>,
    convert: impl Fn(std::borrow::Cow<'a, [u8]>) -> T,
) -> Result<DwarfSections<T>> {
    let mut total = 0;
    DwarfSections::load(|id| -> Result<_> {
        let Some(section) = obj.section_by_name(id.name()) else {
            return Ok(convert(std::borrow::Cow::Borrowed(&[][..])));
        };
        let size = section.compressed_data()?.uncompressed_size;
        if size > 32 * 1024 * 1024 - total {
            return Err(failure(
                "limit_reached",
                "variable DWARF section budget exceeded",
            ));
        }
        total += size;
        Ok(convert(section.uncompressed_data()?))
    })
}

impl Query<'_> {
    fn read_image(
        &mut self,
        data: &cache::Data,
        module: &Module,
        instance: modules::Instance,
        link_pc: Option<u64>,
        cfa: Option<u64>,
    ) -> Result<Option<MatchValue>> {
        let dwarf = data.borrow();
        Ok(data
            .lookup(
                &dwarf,
                self.target,
                link_pc,
                None,
                self.deadline,
                |dwarf, unit, candidate| {
                    let eval = Eval {
                        dwarf,
                        unit,
                        memory: self.memory,
                        regs: self.registers,
                        link_pc,
                        cfa,
                        bias: instance.bias,
                        preview_deadline: Some(self.deadline),
                    };
                    evaluate_candidate(&eval, &candidate, self.operations, module.path())
                },
            )?
            .map(|(priority, value)| MatchValue { priority, value }))
    }

    fn read_process(&mut self, root: &Path, selection: LiveModules<'_>) -> Result<Datum> {
        let (filter, selected_instance) = match selection {
            LiveModules::Filter { module, instance } => (module, instance),
            LiveModules::FrameFirst | LiveModules::FrameOnly => (None, None),
        };
        let pc = self.registers.get(PC)?;
        let exe = fs::metadata(root.join("exe")).ok();
        let mut modules = modules::read(root)?;
        if matches!(selection, LiveModules::FrameOnly) {
            modules.retain(|module| module.executable_at(pc).is_some());
        }
        modules.sort_by_key(|module| module.executable_at(pc).is_none());
        let mut global = None;
        let mut eligible_debug = false;
        for module in modules {
            if Instant::now() >= self.deadline {
                return Err(failure(
                    "limit_reached",
                    "DWARF module search exceeded its capture budget",
                ));
            }
            if filter.is_some_and(|f| !path_matches(&module, f) && !may_be_build_id(f)) {
                continue;
            }
            let Ok(cached) = cache::live_image(root, &module, exe.as_ref()) else {
                continue;
            };
            let Ok(image) = object::File::parse(cached.bytes.as_slice()) else {
                continue;
            };
            if !modules::is_executable_module(&image)
                || filter
                    .is_some_and(|f| !module_matches(&module, f, image.build_id().ok().flatten()))
            {
                continue;
            }
            let layout = Layout::new(&image, &module)?;
            let current = module
                .executable_at(pc)
                .and_then(|map| layout.for_address(map, pc));
            if cached.primary.is_none() && cached.separate.is_none() {
                continue;
            }
            eligible_debug = true;
            for instance in layout.instances {
                if selected_instance.is_some_and(|base| base != instance.base)
                    || (matches!(selection, LiveModules::FrameOnly)
                        && current.is_none_or(|(active, _)| active.base != instance.base))
                {
                    continue;
                }
                let link_pc = current
                    .and_then(|(active, link)| (active.base == instance.base).then_some(link));
                let cfa = link_pc.and_then(|link| {
                    crate::unwind::canonical_frame_address(
                        cached.bytes.clone(),
                        &module,
                        link,
                        pc.wrapping_sub(link),
                        self.memory,
                        self.registers,
                    )
                    .ok()
                });
                let mut found = None;
                for data in cached.separate.iter().chain(&cached.primary) {
                    found = self.read_image(data, &module, instance, link_pc, cfa)?;
                    if found.is_some() {
                        break;
                    }
                }
                if let Some(found) = found {
                    if found.priority > 0
                        || (matches!(selection, LiveModules::FrameFirst) && link_pc.is_some())
                    {
                        return found.value;
                    }
                    if global.is_some() {
                        return Err(failure(
                            "ambiguous",
                            "multiple globals match; specify the module or load instance",
                        ));
                    }
                    global = Some(found.value);
                }
            }
        }
        global.unwrap_or_else(|| {
            if eligible_debug {
                Err(failure(
                    "not_found",
                    "variable not found in the selected scope",
                ))
            } else {
                Err(failure(
                    "unsupported",
                    "usable DWARF variable information was not found",
                ))
            }
        })
    }
}

pub fn inspect(
    pid: i32,
    tid: Option<i32>,
    expression: String,
    module: Option<&str>,
    instance: Option<u64>,
    timeout_ms: Option<u32>,
    expand: Option<crate::rpc::InspectExpansion>,
) -> Result<Report> {
    let process = Process::open(pid)?;
    let mut trace = Trace::new(pid, &process.root, start_ticks(&process.root)?);
    let mut report = inspect_with_trace(
        pid,
        tid,
        expression,
        module,
        instance,
        timeout_ms,
        expand,
        &process.root,
        &mut trace,
    )?;
    report.cleanup = trace.close();
    if !report.cleanup.ok() {
        report.outcome.status = "cleanup_failed";
    }
    Ok(report)
}

pub(crate) fn inspect_with_trace(
    pid: i32,
    tid: Option<i32>,
    expression: String,
    module: Option<&str>,
    instance: Option<u64>,
    timeout_ms: Option<u32>,
    expand: Option<crate::rpc::InspectExpansion>,
    root: &Path,
    trace: &mut Trace,
) -> Result<Report> {
    let tid = tid.unwrap_or(pid);
    let timeout = timeout_ms.unwrap_or(750);
    if !(1..=5000).contains(&timeout) {
        return Err(crate::Diagnostic::new(
            "INVALID_ARGUMENT",
            "inspect timeout_ms must be in 1..=5000",
            None,
        )
        .into());
    }
    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout));
    let result = (|| -> Result<Outcome> {
        trace
            .freeze(deadline)
            .map_err(|e| failure("read_failed", e))?;
        if crate::machine(root)? != regs::ARCH {
            return Err(failure(
                "unsupported",
                "target ABI does not match inspection server",
            ));
        }
        if !trace
            .threads
            .get(&tid)
            .is_some_and(|thread| thread.stop.is_some())
        {
            return Err(failure(
                "read_failed",
                "selected TID is not stopped in the target",
            ));
        }
        let registers = regs::read(tid)
            .map_err(|e| failure("read_failed", e))?
            .stack;
        let mut outcome = inspect_projection(&expression, expand, deadline, |text| {
            evaluate_live(
                parse_live(text, module)?,
                root,
                LiveModules::Filter { module, instance },
                trace,
                registers,
                deadline,
            )
        });
        outcome.symbolize_pointer(pid, deadline);
        Ok(outcome)
    })();
    let outcome = result.unwrap_or_else(|error| Outcome::from_result(Err(error)));
    Ok(live_report(pid, tid, expression, outcome))
}

pub(crate) fn inspect_request_with_trace(
    pid: i32,
    tid: Option<i32>,
    request: crate::rpc::InspectRequest,
    root: &Path,
    trace: &mut Trace,
) -> Result<serde_json::Value> {
    use serde_json::json;
    let tid = tid.unwrap_or(pid);
    let timeout = request.timeout_ms.unwrap_or(750);
    let batch = !request.expressions.is_empty();
    if !(1..=5000).contains(&timeout) {
        return Err(crate::Diagnostic::new(
            "INVALID_ARGUMENT",
            "inspect timeout_ms must be in 1..=5000",
            None,
        )
        .into());
    }
    if batch && (!request.expression.is_empty() || request.expressions.len() > 16) {
        return Err(crate::Diagnostic::new(
            "INVALID_ARGUMENT",
            "Supply a single expression or at most 16 expressions",
            None,
        )
        .into());
    }
    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout));
    let index = request.frame_index.unwrap_or_default() as usize;
    let context = (|| -> Result<_> {
        trace
            .freeze(deadline)
            .map_err(|e| failure("read_failed", e))?;
        if crate::machine(root)? != regs::ARCH {
            return Err(failure(
                "unsupported",
                "target ABI does not match inspection server",
            ));
        }
        if !trace
            .threads
            .get(&tid)
            .is_some_and(|thread| thread.stop.is_some())
        {
            return Err(failure(
                "read_failed",
                "selected TID is not stopped in the target",
            ));
        }
        let mut registers = regs::read(tid)
            .map_err(|e| failure("read_failed", e))?
            .stack;
        if let Some(crate::trace::Stop::Software { address, .. }) = trace.threads[&tid].stop {
            registers.set(PC, Some(address));
        }
        let mut metadata =
            json!({"tid": tid, "index": index, "pc": crate::hex(registers.get(PC)?)});
        if index > 0 {
            let maps = modules::read(root)?;
            let exe = fs::metadata(root.join("exe")).ok();
            let mut found = None;
            let mut images = crate::unwind::Images::new();
            let stack = images.walk_registers(
                trace,
                registers,
                &maps,
                root,
                exe.as_ref(),
                deadline,
                |i, regs| {
                    if i == index {
                        found = Some(regs);
                    }
                },
            );
            registers =
                found.ok_or_else(|| failure("read_failed", "selected frame was not recovered"))?;
            if let Some(frame) = stack.frames.get(index) {
                metadata = json!(frame);
                metadata["tid"] = tid.into();
                metadata["index"] = index.into();
            }
            registers.set(PC, registers.get(PC).ok().and_then(|pc| pc.checked_sub(1)));
        }
        Ok((registers, metadata))
    })();
    let module = request.module.as_deref();
    let selection = if request.run_id.is_some() && module.is_none() && request.instance.is_none() {
        LiveModules::FrameFirst
    } else {
        LiveModules::Filter {
            module,
            instance: request.instance,
        }
    };
    let mut evaluate = |text: &str| {
        let outcome = match &context {
            Ok((registers, _)) => {
                let mut outcome =
                    inspect_projection(text, request.expand.clone(), deadline, |text| {
                        evaluate_live(
                            parse_live(text, module)?,
                            root,
                            selection,
                            trace,
                            *registers,
                            deadline,
                        )
                    });
                outcome.symbolize_pointer(pid, deadline);
                outcome
            }
            Err(error) => {
                let code = error
                    .downcast_ref::<Failure>()
                    .map_or("read_failed", |issue| issue.0);
                Outcome::from_result(Err(failure(code, error)))
            }
        };
        json!(live_report(pid, tid, text.to_owned(), outcome))
    };
    let mut value = inspect_batch(&request, &mut evaluate);
    if (batch || request.frame_index.is_some())
        && let Ok((_, frame)) = context
    {
        value["frame"] = frame;
    }
    Ok(value)
}

pub(crate) fn inspect_batch(
    request: &crate::rpc::InspectRequest,
    mut evaluate: impl FnMut(&str) -> serde_json::Value,
) -> serde_json::Value {
    use serde_json::json;
    if request.expressions.is_empty() {
        return evaluate(&request.expression);
    }
    let results: Vec<_> = request
        .expressions
        .iter()
        .map(|text| json!({"expression": text, "value": evaluate(text)}))
        .collect();
    let status = if results
        .iter()
        .all(|result| result["value"]["status"] == "complete")
    {
        "complete"
    } else {
        "partial"
    };
    json!({"status": status, "results": results})
}

pub(crate) fn inspect_stopped(
    pid: i32,
    tid: i32,
    expression: String,
    root: &Path,
    memory: &dyn crate::unwind::UnwindMemory,
    registers: Registers,
    deadline: Instant,
    expand: Option<crate::rpc::InspectExpansion>,
) -> Report {
    let mut outcome = inspect_projection(&expression, expand, deadline, |text| {
        evaluate_live(
            parse_live(text, None)?,
            root,
            LiveModules::FrameOnly,
            memory,
            registers,
            deadline,
        )
    });
    outcome.symbolize_pointer(pid, deadline);
    live_report(pid, tid, expression, outcome)
}

fn inspect_projection(
    expression: &str,
    expand: Option<crate::rpc::InspectExpansion>,
    deadline: Instant,
    mut evaluate: impl FnMut(&str) -> Result<Datum>,
) -> Outcome {
    let mut outcome = Outcome::from_result(evaluate(expression));
    let (Some(options), Some(value)) = (expand, outcome.result.as_ref()) else {
        return outcome;
    };
    let limit = options.limit.unwrap_or(16);
    if !(1..=64).contains(&limit) {
        return Outcome::failed(
            "invalid_argument",
            "INVALID_ARGUMENT".into(),
            "expansion limit must be in 1..=64".into(),
        );
    }
    let mut nested_budget = 64;
    outcome.children = Some(expand_value(
        value,
        expression,
        options.offset.into(),
        limit,
        deadline,
        &mut evaluate,
        Some(&mut nested_budget),
    ));
    outcome
}

fn expand_value(
    value: &Datum,
    expression: &str,
    offset: u64,
    limit: u32,
    deadline: Instant,
    evaluate: &mut impl FnMut(&str) -> Result<Datum>,
    mut nested_budget: Option<&mut usize>,
) -> serde_json::Value {
    let fields: Vec<_> = value
        .ty
        .fields
        .iter()
        .filter(|field| !field.base_class)
        .filter_map(|field| field.name.as_deref())
        .collect();
    let count = value.ty.element_count.unwrap_or(fields.len() as u64);
    let end = count.min(offset + u64::from(limit));
    let mut items = Vec::new();
    let mut next = offset;
    for index in offset..end {
        if Instant::now() >= deadline {
            break;
        }
        let base = if expression.trim_start().starts_with('*') {
            format!("({expression})")
        } else {
            expression.to_owned()
        };
        let child = if value.ty.element_count.is_some() {
            format!("{base}[{index}]")
        } else {
            format!("{base}.{}", fields[index as usize])
        };
        let mut outcome = Outcome::from_result(evaluate(&child));
        if value.ty.element_count.is_some()
            && let Some(remaining) = nested_budget.as_deref_mut()
            && let Some(element) = outcome
                .result
                .as_ref()
                .filter(|element| !element.ty.fields.is_empty())
        {
            let limit = (*remaining).min(8);
            *remaining -= limit;
            outcome.children = Some(expand_value(
                element,
                &child,
                0,
                limit as u32,
                deadline,
                evaluate,
                None,
            ));
        }
        items.push(serde_json::json!({"expression": child, "value": outcome}));
        next += 1;
    }
    serde_json::json!({"items": items, "next_offset": (next < count).then_some(next),
        "warnings": if next < end { vec![crate::Diagnostic::new("LIMIT_REACHED", "Expansion reached the inspection deadline", None)] } else { Vec::new() }})
}

fn parse_live(expression: &str, module: Option<&str>) -> Result<expression::Expression> {
    if expression.is_empty()
        || expression.len() > 512
        || module.is_some_and(|name| name.len() > 4096)
    {
        return Err(failure(
            "invalid_expression",
            "expected an expression of 1–512 bytes and a module filter of at most 4096 bytes",
        ));
    }
    expression::Expression::parse(expression).map_err(|e| failure("invalid_expression", e))
}

fn evaluate_live(
    parsed: expression::Expression,
    root: &Path,
    selection: LiveModules<'_>,
    memory: &dyn crate::unwind::UnwindMemory,
    registers: Registers,
    deadline: Instant,
) -> Result<Datum> {
    let mut lookups = 0;
    parsed.evaluate(&mut |target, operations| {
        lookups += 1;
        if lookups > 16 {
            return Err(failure(
                "limit_reached",
                "expression exceeds 16 variable lookups",
            ));
        }
        if Instant::now() >= deadline {
            return Err(failure(
                "limit_reached",
                "inspection exceeded its capture budget",
            ));
        }
        Query {
            target,
            operations,
            memory,
            registers,
            deadline,
        }
        .read_process(root, selection)
    })
}

fn live_report(pid: i32, tid: i32, expression: String, outcome: Outcome) -> Report {
    Report {
        pid,
        tid,
        expression,
        outcome,
        cleanup: Cleanup::default(),
    }
}
