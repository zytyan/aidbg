use super::*;
use crate::unwind::UnwindMemory;
use serde_json::{Value as Json, json};
use std::ops::Range;

pub(crate) struct Validation {
    pub status: &'static str,
    pub code: &'static str,
    pub message: String,
    pub span: Option<Range<usize>>,
}

impl Validation {
    pub fn unchecked(code: &'static str) -> Self {
        Self {
            status: "unchecked",
            code,
            message: String::new(),
            span: None,
        }
    }

    fn invalid(code: &'static str, message: impl Into<String>, span: Range<usize>) -> Self {
        Self {
            status: "error",
            code,
            message: message.into(),
            span: Some(span),
        }
    }
}

pub(crate) struct DwarfImage {
    sections: DwarfSections<Vec<u8>>,
    pub bias: u64,
    pub path: PathBuf,
}

impl DwarfImage {
    pub fn load(obj: &object::File<'_>, bias: u64, path: PathBuf) -> Result<Option<Self>> {
        if obj.section_by_name(".debug_info").is_none() {
            return Ok(None);
        }
        let sections = load_sections(obj, std::borrow::Cow::into_owned)?;
        Ok(Some(Self {
            sections,
            bias,
            path,
        }))
    }

    pub fn line(&self, pc: u64) -> Result<Option<super::super::Line>> {
        let dwarf = self
            .sections
            .borrow(|bytes| EndianSlice::new(bytes, LittleEndian));
        super::super::line_for_pc(&dwarf, pc)
    }

    fn lookup<T>(
        &self,
        target: &str,
        pc: Option<u64>,
        mut shadow: Option<&mut bool>,
        deadline: Instant,
        mut evaluate: impl FnMut(&Dwarf<Reader<'_>>, &Unit<Reader<'_>>, Candidate<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        let dwarf = self
            .sections
            .borrow(|bytes| EndianSlice::new(bytes, LittleEndian));
        let mut units = dwarf.units();
        let mut scanned = 0;
        let mut best = None;
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let Some(candidate) = find_variable(
                &dwarf,
                &unit,
                target,
                pc,
                &mut scanned,
                deadline,
                shadow.as_deref_mut(),
                None,
            )?
            else {
                continue;
            };
            match best {
                Some((priority, _)) if priority > candidate.priority => continue,
                Some((priority, _)) if priority == candidate.priority => {
                    best = Some((
                        priority,
                        Err(failure(
                            "ambiguous",
                            "multiple compilation units define the variable",
                        )),
                    ));
                }
                _ => {
                    let result = evaluate(&dwarf, &unit, candidate.clone());
                    best = Some((candidate.priority, result));
                }
            }
        }
        best.map(|(_, value)| value).transpose()
    }

    pub fn parameters(
        &self,
        memory: &dyn UnwindMemory,
        frame: &crate::unwind::OfflineFrame,
        limit: usize,
        deadline: Instant,
    ) -> Result<Json> {
        self.variable_page(memory, Some(frame), "*", 0, limit, deadline, true)
    }

    pub fn variables(
        &self,
        memory: &dyn UnwindMemory,
        frame: Option<&crate::unwind::OfflineFrame>,
        pattern: &str,
        offset: usize,
        limit: usize,
        deadline: Instant,
    ) -> Result<Json> {
        self.variable_page(memory, frame, pattern, offset, limit, deadline, false)
    }

    fn variable_page(
        &self,
        memory: &dyn UnwindMemory,
        frame: Option<&crate::unwind::OfflineFrame>,
        pattern: &str,
        offset: usize,
        limit: usize,
        deadline: Instant,
        parameters: bool,
    ) -> Result<Json> {
        if pattern.len() > 1024 {
            return Err(crate::Diagnostic::new(
                "INVALID_ARGUMENT",
                "Glob exceeds 1024 bytes",
                None,
            )
            .into());
        }
        let pattern = glob::Pattern::new(pattern)?;
        let dwarf = self
            .sections
            .borrow(|bytes| EndianSlice::new(bytes, LittleEndian));
        let mut units = dwarf.units();
        let mut items = Vec::new();
        let mut scanned = 0;
        let mut matched = 0;
        let mut truncated = false;
        let pc = frame.and_then(|frame| frame.link);
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let eval = Eval {
                dwarf: &dwarf,
                unit: &unit,
                memory,
                regs: frame.map_or_else(Registers::empty, |frame| frame.regs),
                link_pc: pc,
                cfa: frame.and_then(|frame| frame.cfa),
                bias: i128::from(self.bias),
                preview_deadline: None,
            };
            find_variable(
                &dwarf,
                &unit,
                "",
                pc,
                &mut scanned,
                deadline,
                None,
                Some(&mut |qualified, local, tag, candidate| {
                    if local != frame.is_some()
                        || !pattern.matches(qualified)
                        || (parameters && tag != gimli::DW_TAG_formal_parameter)
                    {
                        return true;
                    }
                    matched += 1;
                    if matched <= offset {
                        return true;
                    }
                    if items.len() == limit {
                        truncated = true;
                        return false;
                    }
                    if parameters {
                        let outcome = Outcome::from_result(
                            unit.entry(candidate.offset)
                                .map_err(Into::into)
                                .and_then(|entry| {
                                    evaluate_variable(
                                        &eval,
                                        &entry,
                                        candidate.frame_base,
                                        &[],
                                        self.path.clone(),
                                    )
                                }),
                        );
                        items.push(json!({"name": qualified, "value": outcome}));
                        return true;
                    }
                    let entry = unit.entry(candidate.offset);
                    let availability = entry
                        .as_ref()
                        .ok()
                        .map(|entry| {
                            if matches!(
                                resolved_attr(&unit, entry, gimli::DW_AT_location, 0),
                                Ok(None)
                            ) && matches!(
                                resolved_attr(&unit, entry, gimli::DW_AT_const_value, 0),
                                Ok(None)
                            ) {
                                return "optimized_out";
                            }
                            match evaluate_variable(
                                &eval,
                                entry,
                                candidate.frame_base,
                                &[],
                                self.path.clone(),
                            ) {
                                Ok(_) => "readable",
                                Err(error) => error
                                    .downcast_ref::<Failure>()
                                    .map_or("unavailable", |issue| issue.0),
                            }
                        })
                        .unwrap_or("unavailable");
                    items.push(json!({
                    "name": qualified, "kind": if tag == gimli::DW_TAG_formal_parameter { "parameter" } else { "variable" },
                    "scope": if local { "local" } else { "global" }, "scope_depth": candidate.priority,
                    "module": self.path, "unit_offset": gimli::UnitOffset(0).to_debug_info_offset(&unit.header).map(|offset| offset.0),
                    "availability": availability,
                }));
                    true
                }),
            )?;
            if truncated || (parameters && !items.is_empty()) {
                break;
            }
        }
        Ok(
            json!({"items": items, "next_offset": truncated.then_some(offset + limit), "warnings": []}),
        )
    }

    pub fn types(
        &self,
        pattern: &str,
        offset: usize,
        limit: usize,
        deadline: Instant,
    ) -> Result<Json> {
        if pattern.len() > 1024 {
            return Err(crate::Diagnostic::new(
                "INVALID_ARGUMENT",
                "Glob exceeds 1024 bytes",
                None,
            )
            .into());
        }
        let pattern = glob::Pattern::new(pattern)?;
        let dwarf = self
            .sections
            .borrow(|bytes| EndianSlice::new(bytes, LittleEndian));
        let mut units = dwarf.units();
        let mut items = Vec::new();
        let mut matched = 0;
        let mut scanned = 0;
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                scanned += 1;
                if scanned > MAX_DIES || (scanned % 128 == 0 && Instant::now() >= deadline) {
                    return Err(failure(
                        "limit_reached",
                        "DWARF type discovery exceeded its budget",
                    ));
                }
                let kind = match entry.tag() {
                    gimli::DW_TAG_structure_type => "struct",
                    gimli::DW_TAG_class_type => "class",
                    gimli::DW_TAG_union_type => "union",
                    gimli::DW_TAG_enumeration_type => "enum",
                    gimli::DW_TAG_typedef => "typedef",
                    gimli::DW_TAG_base_type => "scalar",
                    _ => continue,
                };
                let Some(name) = name(&dwarf, &unit, entry)?.filter(|name| pattern.matches(name))
                else {
                    continue;
                };
                matched += 1;
                if matched <= offset {
                    continue;
                }
                if items.len() == limit {
                    return Ok(
                        json!({"items": items, "next_offset": offset + limit, "warnings": []}),
                    );
                }
                let layout = match entry.tag() {
                    gimli::DW_TAG_structure_type
                    | gimli::DW_TAG_class_type
                    | gimli::DW_TAG_union_type => fields(&dwarf, &unit, entry).map(Some),
                    _ => Ok(None),
                };
                let (layout, issue) = match layout {
                    Ok(fields) => (fields, None),
                    Err(error) => (None, Some(error.to_string())),
                };
                items.push(json!({
                    "name": name, "kind": kind, "module": self.path,
                    "fields": layout, "layout_issue": issue,
                    "byte_size": type_size(&unit, entry, 0).ok(),
                    "unit_offset": gimli::UnitOffset(0).to_debug_info_offset(&unit.header).map(|offset| offset.0),
                }));
            }
        }
        Ok(json!({"items": items, "next_offset": null, "warnings": []}))
    }

    pub fn inspect(
        &self,
        text: &str,
        memory: &dyn UnwindMemory,
        regs: Registers,
        pc: Option<u64>,
        cfa: Option<u64>,
        deadline: Instant,
        expand: Option<crate::rpc::InspectExpansion>,
    ) -> Json {
        let outcome = inspect_projection(text, expand, deadline, |text| {
            if text.is_empty() || text.len() > 512 {
                return Err(failure(
                    "invalid_expression",
                    "expected an expression of 1–512 bytes",
                ));
            }
            let parsed = expression::Expression::parse(text)
                .map_err(|e| failure("invalid_expression", e))?;
            let mut lookups = 0;
            parsed.evaluate(&mut |target, operations| {
                lookups += 1;
                if lookups > 16 {
                    return Err(failure(
                        "limit_reached",
                        "expression exceeds 16 variable lookups",
                    ));
                }
                self.lookup(target, pc, None, deadline, |dwarf, unit, candidate| {
                    let eval = Eval {
                        dwarf,
                        unit,
                        memory,
                        regs,
                        link_pc: pc,
                        cfa,
                        bias: i128::from(self.bias),
                        preview_deadline: Some(deadline),
                    };
                    let entry = unit.entry(candidate.offset)?;
                    evaluate_variable(
                        &eval,
                        &entry,
                        candidate.frame_base,
                        operations,
                        self.path.clone(),
                    )
                })?
                .ok_or_else(|| failure("not_found", "variable not found in the selected scope"))
            })
        });
        json!(outcome)
    }

    pub fn preflight(&self, text: &str, memory: &dyn UnwindMemory, pc: Option<u64>) -> Validation {
        if text.is_empty() || text.len() > 512 {
            return Validation::invalid(
                "INVALID_EXPRESSION",
                "expected an expression of 1–512 bytes",
                0..text.len(),
            );
        }
        let mut parser = Parser::new(text);
        let target = match parser.expression(0) {
            Ok(target) if parser.rest.trim().is_empty() => target,
            _ => return Validation::unchecked("UNSUPPORTED_EXPRESSION"),
        };
        let mut shadowed = false;
        let shadow = (pc.is_none() && !target.starts_with("::")).then_some(&mut shadowed);
        let result = self.lookup(&target, pc, shadow, Instant::now() + Duration::from_millis(100), |dwarf, unit, candidate| {
            let entry = unit.entry(candidate.offset)?;
            let mut ty = typedef_target(unit, &entry)?;
            let eval = Eval {
                dwarf,
                unit,
                memory,
                regs: Registers::empty(),
                link_pc: pc,
                cfa: None,
                bias: 0,
                preview_deadline: None,
            };
            let mut pointer_index = false;
            for (operation, span) in parser.operations.iter().zip(parser.spans.iter()) {
                let entry = underlying(unit, ty)?;
                ty = match operation {
                    Access::Deref if entry.tag() == gimli::DW_TAG_pointer_type => {
                        typedef_target(unit, &entry)?
                    }
                    Access::Index(index) => match index_type(&eval, &entry, *index, false) {
                        Ok(Some((element, _))) => {
                            pointer_index |= entry.tag() == gimli::DW_TAG_pointer_type;
                            element
                        }
                        Err(e)
                            if e.downcast_ref::<Failure>()
                                .is_some_and(|f| f.0 == "out_of_bounds") =>
                        {
                            return Ok(Validation::invalid(
                                "OUT_OF_BOUNDS",
                                "array index exceeds the DWARF bound",
                                span.clone(),
                            ));
                        }
                        Err(e) => return Err(e),
                        Ok(None) => {
                            return Ok(Validation::invalid(
                                "TYPE_MISMATCH",
                                "expression operation does not match the DWARF type",
                                span.clone(),
                            ));
                        }
                    },
                    Access::Member(field)
                        if matches!(
                            entry.tag(),
                            gimli::DW_TAG_structure_type
                                | gimli::DW_TAG_class_type
                                | gimli::DW_TAG_union_type
                        ) =>
                    {
                        if matches!(
                            entry.attr_value(gimli::DW_AT_declaration),
                            Some(AttributeValue::Flag(true))
                        ) {
                            return Ok(Validation::unchecked("INCOMPLETE_TYPE"));
                        }
                        let Some((member, _)) = find_member(&eval, &entry, field, 0, false)? else {
                            return Ok(Validation::invalid(
                                "UNKNOWN_MEMBER",
                                unknown_member(&eval, &entry, field),
                                span.clone(),
                            ));
                        };
                        member
                    }
                    _ => {
                        return Ok(Validation::invalid(
                            "TYPE_MISMATCH",
                            "expression operation does not match the DWARF type",
                            span.clone(),
                        ));
                    }
                };
                let entry = underlying(unit, ty)?;
                if matches!(
                    entry.tag(),
                    gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type
                ) {
                    ty = typedef_target(unit, &entry)?;
                }
            }
            let entry = underlying(unit, ty)?;
            if matches!(
                entry.attr_value(gimli::DW_AT_declaration),
                Some(AttributeValue::Flag(true))
            ) {
                return Ok(Validation::unchecked("INCOMPLETE_TYPE"));
            }
            Ok(Validation {
                status: "verified",
                code: if pointer_index {
                    "POINTER_BOUNDS_DEFERRED"
                } else {
                    "OK"
                },
                message: String::new(),
                span: None,
            })
        });
        if shadowed {
            return Validation::unchecked("NO_FRAME_CONTEXT");
        }
        match result {
            Ok(Some(result)) => result,
            Ok(None) if pc.is_some() || target.starts_with("::") => Validation::invalid(
                "UNKNOWN_GLOBAL",
                "variable not found in the selected DWARF scope",
                parser.root_span,
            ),
            Ok(None) => Validation::unchecked("NO_FRAME_CONTEXT"),
            Err(_) => Validation::unchecked("INCOMPLETE_TYPE"),
        }
    }
}
