use super::*;
use crate::procfs::start_ticks;
use crate::regs::{self, PC, Registers};
use crate::trace::{Cleanup, Trace};
use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EvaluationResult, Expression, Location, Unit,
    UnitOffset, Value,
};
use std::fmt;
use std::time::{Duration, Instant};

mod expression;
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

#[derive(Debug)]
enum Access {
    Deref,
    Member(String),
    Index(u64),
}

struct Parser<'a> {
    rest: &'a str,
    operations: Vec<Access>,
}

impl Parser<'_> {
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
        if self.eat("*") {
            let name = self.expression(depth + 1)?;
            self.operations.push(Access::Deref);
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
            name
        };
        loop {
            if self.eat("->") {
                self.operations.push(Access::Deref);
                let member = self.identifier()?;
                self.operations.push(Access::Member(member));
            } else if self.eat(".") {
                let member = self.identifier()?;
                self.operations.push(Access::Member(member));
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
                self.operations.push(Access::Index(index));
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
}

#[derive(Serialize)]
struct Field {
    name: Option<String>,
    type_name: Option<String>,
    offset: Option<u64>,
    byte_size: Option<usize>,
    base_class: bool,
}

#[derive(Serialize)]
struct Datum {
    #[serde(rename = "type")]
    ty: Type,
    address: Option<String>,
    bytes: String,
    value: serde_json::Value,
    module: Option<PathBuf>,
    #[serde(skip)]
    number: Option<Number>,
}

#[derive(Serialize)]
pub struct Report {
    pid: i32,
    tid: i32,
    expression: String,
    status: &'static str,
    result: Option<Datum>,
    issue: Option<String>,
    cleanup: Cleanup,
}

struct Eval<'a, 'read> {
    dwarf: &'read Dwarf<Reader<'a>>,
    unit: &'read Unit<Reader<'a>>,
    trace: &'read Trace<'read>,
    regs: Registers,
    link_pc: Option<u64>,
    cfa: Option<u64>,
    bias: i128,
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

    fn evaluate(
        &self,
        expr: Expression<Reader<'a>>,
        frame_base: Option<u64>,
    ) -> Result<Location<Reader<'a>>> {
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
                        .trace
                        .read_word(address, size.into())
                        .map_err(|e| failure("read_failed", e))?;
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
        match evaluation.result().as_slice() {
            [piece] if piece.size_in_bits.is_none() && piece.bit_offset.is_none() => {
                Ok(piece.location)
            }
            _ => Err(failure(
                "unsupported",
                "DWARF location uses multiple pieces or bit offsets",
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
                        .trace
                        .read_word(address, size)
                        .map_err(|e| failure("read_failed", e))?;
                    bytes.extend_from_slice(&word.to_le_bytes()[..size]);
                }
                Ok(bytes)
            }
        }
    }
}

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

fn array_length(unit: &Unit<Reader<'_>>, array: &Die<'_>) -> Result<u64> {
    let mut cursor = unit.entries_at_offset(array.offset())?;
    cursor.next_dfs()?;
    let mut count = None;
    while let Some(child) = cursor.next_dfs()? {
        if child.depth() <= array.depth() {
            break;
        }
        if child.depth() == array.depth() + 1 && child.tag() == gimli::DW_TAG_subrange_type {
            if count.is_some() {
                return Err(failure(
                    "unsupported",
                    "multidimensional array layout is unsupported",
                ));
            }
            let lower = child
                .attr_value(gimli::DW_AT_lower_bound)
                .and_then(|v| v.udata_value())
                .unwrap_or(0);
            if lower != 0 {
                return Err(failure("unsupported", "nonzero array lower bound"));
            }
            count = child
                .attr_value(gimli::DW_AT_count)
                .and_then(|v| v.udata_value())
                .or_else(|| {
                    child
                        .attr_value(gimli::DW_AT_upper_bound)?
                        .udata_value()?
                        .checked_add(1)
                });
            if count.is_none() {
                return Err(failure("unsupported", "array bound is not constant"));
            }
        }
    }
    count.ok_or_else(|| failure("unsupported", "array bound missing"))
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
            type_size(unit, &element, depth + 1)?
                .checked_mul(usize::try_from(array_length(unit, entry)?)?)
                .ok_or_else(|| error("array size overflow"))
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

fn fields<'a>(eval: &Eval<'a, '_>, entry: &Die<'a>) -> Result<Vec<Field>> {
    let mut cursor = eval.unit.entries_at_offset(entry.offset())?;
    cursor.next_dfs()?;
    let mut fields = Vec::new();
    while let Some(child) = cursor.next_dfs()? {
        if child.depth() <= entry.depth() {
            break;
        }
        if child.depth() != entry.depth() + 1
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
        let ty = typedef_target(eval.unit, child)
            .ok()
            .and_then(|ty| underlying(eval.unit, ty).ok());
        fields.push(Field {
            name: name(eval.dwarf, eval.unit, child)?,
            type_name: ty
                .as_ref()
                .and_then(|ty| name(eval.dwarf, eval.unit, ty).ok().flatten()),
            offset: member_offset(child, entry).ok(),
            byte_size: ty.as_ref().and_then(|ty| type_size(eval.unit, ty, 0).ok()),
            base_class: child.tag() == gimli::DW_TAG_inheritance,
        });
    }
    Ok(fields)
}

fn find_member<'a>(
    eval: &Eval<'a, '_>,
    aggregate: &Die<'a>,
    field: &str,
    depth: usize,
) -> Result<Option<(Offset, u64)>> {
    if depth > 12 {
        return Err(failure(
            "unsupported",
            "inheritance hierarchy exceeds limit",
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
                member_offset(entry, aggregate)?,
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
        if let Some((ty, delta)) = find_member(eval, &base, field, depth + 1)? {
            if found.is_some() {
                return Err(failure("ambiguous", "inherited member is ambiguous"));
            }
            let offset = member_offset(&inheritance, aggregate)?
                .checked_add(delta)
                .ok_or_else(|| error("member offset overflow"))?;
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
        return Err(failure("read_failed", "null pointer dereference"));
    }
    Ok(address)
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
            Access::Index(index)
                if matches!(
                    entry.tag(),
                    gimli::DW_TAG_array_type | gimli::DW_TAG_pointer_type
                ) =>
            {
                if entry.tag() == gimli::DW_TAG_pointer_type {
                    place = Place::Address(pointer(eval, &place, &entry)?);
                } else if *index >= array_length(eval.unit, &entry)? {
                    return Err(failure("read_failed", "array index out of bounds"));
                }
                ty = typedef_target(eval.unit, &entry)?;
                let element = underlying(eval.unit, ty)?;
                let size = type_size(eval.unit, &element, 0)? as u64;
                place = place.advance(
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
                let (member, offset) = find_member(eval, &entry, field, 0)?
                    .ok_or_else(|| failure("not_found", format!("member {field} not found")))?;
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

fn evaluate_variable<'a>(
    eval: &Eval<'a, '_>,
    entry: &Die<'a>,
    frame_base: Option<Attr<'a>>,
    operations: &[Access],
    module: &Module,
) -> Result<Datum> {
    let ty = typedef_target(eval.unit, entry)?;
    let place = if let Some(attr) = resolved_attr(eval.unit, entry, gimli::DW_AT_location, 0)? {
        let frame_base = frame_base.and_then(|attr| {
            match eval.evaluate(eval.location(attr).ok()?, None).ok()? {
                Location::Address { address } => Some(address),
                Location::Register { register } => eval.regs.get(register).ok(),
                Location::Value { value } => value.to_u64(u64::MAX).ok(),
                _ => None,
            }
        });
        match eval.evaluate(eval.location(attr)?, frame_base)? {
            Location::Address { address } => Place::Address(address),
            Location::Register { register } => Place::Bytes(
                eval.regs
                    .get(register)
                    .map_err(|e| failure("unavailable_at_pc", e))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            Location::Value { value } => {
                Place::Bytes(value.to_u64(u64::MAX)?.to_le_bytes().to_vec())
            }
            Location::Bytes { value } => Place::Bytes(value.to_vec()),
            Location::Empty => return Err(failure("optimized_out", "empty DWARF location")),
            _ => {
                return Err(failure(
                    "unsupported",
                    "unsupported DWARF variable location",
                ));
            }
        }
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
    let (ty, place) = access(eval, ty, place, operations)?;
    let entry = underlying(eval.unit, ty)?;
    let size = type_size(eval.unit, &entry, 0)?;
    let bytes = eval.bytes(&place, size)?;
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
    let number = Number::dwarf(
        &bytes,
        match encoding.as_ref() {
            Some(AttributeValue::Encoding(encoding)) => Some(*encoding),
            _ => None,
        },
    );
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
    Ok(Datum {
        ty: Type {
            name: name(eval.dwarf, eval.unit, &eval.unit.entry(ty)?)?
                .or(name(eval.dwarf, eval.unit, &entry)?),
            kind,
            byte_size: size,
            fields: if matches!(kind, "struct" | "class" | "union") {
                fields(eval, &entry)?
            } else {
                Vec::new()
            },
            element_count: if kind == "array" {
                Some(array_length(eval.unit, &entry)?)
            } else {
                None
            },
        },
        address: match place {
            Place::Address(address) => Some(hex(address)),
            _ => None,
        },
        bytes: id_hex(&bytes),
        value,
        module: Some(module.path()),
        number,
    })
}

#[derive(Clone, Default)]
struct Scope<'a> {
    local: bool,
    active: bool,
    namespace: String,
    frame_base: Option<Attr<'a>>,
}

struct Candidate<'a> {
    offset: Offset,
    priority: usize,
    concrete: bool,
    frame_base: Option<Attr<'a>>,
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

fn find_variable<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<Reader<'a>>,
    target: &str,
    link_pc: Option<u64>,
    scanned: &mut usize,
    deadline: Instant,
) -> Result<Option<Candidate<'a>>> {
    let mut entries = unit.entries();
    let mut scopes: Vec<Scope<'a>> = Vec::new();
    let mut declarations = BTreeMap::new();
    let mut best: Option<Candidate<'a>> = None;
    let mut ambiguous = false;
    while let Some(entry) = entries.next_dfs()? {
        *scanned += 1;
        if *scanned > MAX_DIES || ((*scanned).is_multiple_of(128) && Instant::now() >= deadline) {
            return Err(failure(
                "limit_reached",
                "DWARF variable lookup exceeded its capture budget",
            ));
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
            if scope.active {
                let mut all = dwarf.die_ranges(unit, entry)?;
                let mut has_ranges = false;
                let mut contains = false;
                while let Some(range) = all.next()? {
                    has_ranges = true;
                    contains |= link_pc.is_some_and(|pc| (range.begin..range.end).contains(&pc));
                }
                if has_ranges || tag != gimli::DW_TAG_lexical_block {
                    scope.active = contains;
                }
            }
            scope.local = true;
            scope.frame_base = entry
                .attr_value(gimli::DW_AT_frame_base)
                .or(scope.frame_base);
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
                        frame_base: scope.frame_base,
                    },
                );
            }
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
        if scope.active
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
            } else if (scope.local && name == target)
                || (!scope.local && qualified == target.strip_prefix("::").unwrap_or(target))
            {
                let priority = if scope.local { depth + 1 } else { 0 };
                let candidate = Candidate {
                    offset: entry.offset(),
                    priority,
                    concrete: true,
                    frame_base: scope.frame_base,
                };
                prefer(&mut best, &mut ambiguous, candidate);
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

struct Query<'a> {
    target: &'a str,
    operations: &'a [Access],
    trace: &'a Trace<'a>,
    registers: Registers,
    deadline: Instant,
    scanned: usize,
}

struct MatchValue {
    priority: usize,
    value: Result<Datum>,
}

impl Query<'_> {
    fn read_image(
        &mut self,
        obj: &object::File<'_>,
        module: &Module,
        instance: modules::Instance,
        link_pc: Option<u64>,
        cfa: Option<u64>,
    ) -> Result<Option<MatchValue>> {
        if obj.section_by_name(".debug_info").is_none() {
            return Ok(None);
        }
        let mut total = 0;
        let sections = DwarfSections::load(|id| -> Result<_> {
            let Some(section) = obj.section_by_name(id.name()) else {
                return Ok(std::borrow::Cow::Borrowed(&[][..]));
            };
            let size = section.compressed_data()?.uncompressed_size;
            if size > 32 * 1024 * 1024 - total {
                return Err(failure(
                    "limit_reached",
                    "variable DWARF section budget exceeded",
                ));
            }
            total += size;
            Ok(section.uncompressed_data()?)
        })?;
        let dwarf = sections.borrow(|bytes| EndianSlice::new(bytes, LittleEndian));
        let mut units = dwarf.units();
        let mut best: Option<MatchValue> = None;
        while let Some(header) = units.next()? {
            if Instant::now() >= self.deadline {
                return Err(failure(
                    "limit_reached",
                    "DWARF variable lookup exceeded its capture budget",
                ));
            }
            let unit = dwarf.unit(header)?;
            let Some(candidate) = find_variable(
                &dwarf,
                &unit,
                self.target,
                link_pc,
                &mut self.scanned,
                self.deadline,
            )?
            else {
                continue;
            };
            if best
                .as_ref()
                .is_some_and(|old| old.priority >= candidate.priority)
            {
                if best
                    .as_ref()
                    .is_some_and(|old| old.priority == candidate.priority)
                {
                    best = Some(MatchValue {
                        priority: candidate.priority,
                        value: Err(failure(
                            "ambiguous",
                            "multiple compilation units define the variable",
                        )),
                    });
                }
                continue;
            }
            let eval = Eval {
                dwarf: &dwarf,
                unit: &unit,
                trace: self.trace,
                regs: self.registers,
                link_pc,
                cfa,
                bias: instance.bias,
            };
            let entry = unit.entry(candidate.offset)?;
            let value =
                evaluate_variable(&eval, &entry, candidate.frame_base, self.operations, module);
            best = Some(MatchValue {
                priority: candidate.priority,
                value,
            });
        }
        Ok(best)
    }

    fn read_process(
        &mut self,
        root: &Path,
        filter: Option<&str>,
        selected_instance: Option<u64>,
    ) -> Result<Datum> {
        let pc = self.registers.get(PC)?;
        let exe = fs::metadata(root.join("exe")).ok();
        let mut modules = modules::read(root)?;
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
            let Ok(bytes) = module.read_image(root, exe.as_ref(), IMAGE_LIMIT) else {
                continue;
            };
            let Ok(image) = object::File::parse(&*bytes) else {
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
            let debug = DebugFile::discover(root, &module, &image);
            let debug = debug.as_ref().and_then(DebugFile::parse);
            if image.section_by_name(".debug_info").is_none()
                && debug
                    .as_ref()
                    .is_none_or(|obj| obj.section_by_name(".debug_info").is_none())
            {
                continue;
            }
            eligible_debug = true;
            for instance in layout.instances {
                if selected_instance.is_some_and(|base| base != instance.base) {
                    continue;
                }
                let link_pc = current
                    .and_then(|(active, link)| (active.base == instance.base).then_some(link));
                let cfa = link_pc.and_then(|link| {
                    crate::unwind::canonical_frame_address(
                        bytes.clone(),
                        &module,
                        link,
                        pc.wrapping_sub(link),
                        self.trace,
                        self.registers,
                    )
                    .ok()
                });
                let found = if let Some(dwarf) = &debug {
                    self.read_image(dwarf, &module, instance, link_pc, cfa)?
                } else {
                    None
                };
                let found = if found.is_some() {
                    found
                } else {
                    self.read_image(&image, &module, instance, link_pc, cfa)?
                };
                if let Some(found) = found {
                    if found.priority > 0 {
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
) -> Result<Report> {
    if expression.is_empty()
        || expression.len() > 512
        || module.is_some_and(|name| name.len() > 4096)
    {
        return Err(error(
            "expected an expression of 1–512 bytes and a module filter of at most 4096 bytes",
        ));
    }
    let parsed = expression::Expression::parse(&expression)?;
    let process = Process::open(pid)?;
    let tid = tid.unwrap_or(pid);
    let mut trace = Trace::new(pid, &process.root, start_ticks(&process.root)?);
    let deadline = Instant::now() + Duration::from_millis(750);
    let result = (|| -> Result<Datum> {
        trace
            .freeze(deadline)
            .map_err(|e| failure("read_failed", e))?;
        if crate::machine(&process.root)? != regs::ARCH {
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
        let mut scanned = 0;
        let mut lookups = 0;
        parsed.evaluate(&mut |target, operations| {
            lookups += 1;
            if lookups > 16 {
                return Err(failure(
                    "limit_reached",
                    "expression exceeds 16 variable lookups",
                ));
            }
            let mut query = Query {
                target,
                operations,
                trace: &trace,
                registers,
                deadline,
                scanned,
            };
            let value = query.read_process(&process.root, module, instance);
            scanned = query.scanned;
            value
        })
    })();
    let cleanup = trace.close();
    let (mut status, result, issue) = match result {
        Ok(value) => ("complete", Some(value), None),
        Err(e) => (
            e.downcast_ref::<Failure>().map_or("unsupported", |e| e.0),
            None,
            Some(e.to_string()),
        ),
    };
    if !cleanup.ok() {
        status = "cleanup_failed";
    }
    Ok(Report {
        pid,
        tid,
        expression,
        status,
        result,
        issue,
        cleanup,
    })
}
