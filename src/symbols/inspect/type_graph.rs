use super::*;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Graph {
    root: usize,
    nodes: Vec<Node>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Node {
    Void,
    Scalar {
        scalar: String,
    },
    Pointer {
        element: usize,
    },
    Array {
        element: usize,
        dimensions: Vec<u64>,
    },
    Aggregate {
        union: bool,
        size: usize,
        align: usize,
        fields: Vec<Member>,
    },
    Function {
        args: Vec<usize>,
        returns: usize,
        variadic: bool,
    },
    Opaque {
        size: usize,
        align: usize,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct Member {
    name: String,
    offset: u64,
    ty: usize,
    bit: Option<(u64, u64)>,
}

pub(crate) fn live_type_graphs(
    root: &Path,
    pattern: &str,
    exact: bool,
    offset: usize,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<(String, Graph)>> {
    let exe = fs::metadata(root.join("exe")).ok();
    let mut images = modules::read(root)?;
    if let Ok(main) = fs::read_link(root.join("exe")) {
        images.sort_by_key(|module| module.path() != main);
    }
    let mut result = Vec::new();
    let mut skip = offset;
    for module in images {
        if Instant::now() >= deadline {
            break;
        }
        let Ok(cached) = cache::live_image(root, &module, exe.as_ref()) else {
            continue;
        };
        let Some(data) = cached.separate.as_ref().or(cached.primary.as_ref()) else {
            continue;
        };
        let dwarf = offline::DwarfImage {
            data: data.clone(),
            bias: 0,
            path: module.path(),
        };
        let rows = dwarf.type_graphs(
            pattern,
            exact,
            skip,
            limit.saturating_sub(result.len()),
            deadline,
        )?;
        skip = skip.saturating_sub(rows.1);
        for row in rows.0 {
            if !result.contains(&row) {
                result.push(row);
            }
        }
        if result.len() >= limit || (exact && !result.is_empty()) {
            break;
        }
    }
    Ok(result)
}

impl offline::DwarfImage {
    pub(crate) fn type_graphs(
        &self,
        pattern: &str,
        exact: bool,
        offset: usize,
        limit: usize,
        deadline: Instant,
    ) -> Result<(Vec<(String, Graph)>, usize)> {
        let matcher = (!exact).then(|| glob::Pattern::new(pattern)).transpose()?;
        let dwarf = self.data.borrow();
        let mut units = dwarf.units();
        let mut results = Vec::new();
        let mut scanned = 0;
        let mut matched = 0;
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                scanned += 1;
                if scanned > MAX_DIES || (scanned % 128 == 0 && Instant::now() >= deadline) {
                    return Ok((results, matched));
                }
                if !matches!(
                    entry.tag(),
                    gimli::DW_TAG_base_type
                        | gimli::DW_TAG_typedef
                        | gimli::DW_TAG_structure_type
                        | gimli::DW_TAG_class_type
                        | gimli::DW_TAG_union_type
                        | gimli::DW_TAG_enumeration_type
                        | gimli::DW_TAG_subprogram
                ) || entry
                    .attr_value(gimli::DW_AT_declaration)
                    .is_some_and(|attr| matches!(attr, AttributeValue::Flag(true)))
                {
                    continue;
                }
                let Some(name) = name(&dwarf, &unit, entry)? else {
                    continue;
                };
                if !matcher
                    .as_ref()
                    .map_or(name == pattern, |glob| glob.matches(&name))
                {
                    continue;
                }
                matched += 1;
                if matched <= offset {
                    continue;
                }
                let mut builder = Builder {
                    dwarf: &dwarf,
                    unit: &unit,
                    nodes: vec![Node::Void],
                    seen: BTreeMap::new(),
                    deadline,
                };
                let graph = builder.entry(entry.offset(), 0).map(|root| Graph {
                    root,
                    nodes: builder.nodes,
                });
                if let Ok(graph) = graph
                    && !results.contains(&(name.clone(), graph.clone()))
                {
                    results.push((name, graph));
                    if results.len() >= limit {
                        return Ok((results, matched));
                    }
                }
            }
        }
        Ok((results, matched))
    }
}

struct Builder<'a, 'b> {
    dwarf: &'b Dwarf<Reader<'a>>,
    unit: &'b Unit<Reader<'a>>,
    nodes: Vec<Node>,
    seen: BTreeMap<Offset, usize>,
    deadline: Instant,
}

impl Builder<'_, '_> {
    fn entry(&mut self, offset: Offset, depth: usize) -> Result<usize> {
        if depth > 32 || self.nodes.len() >= 512 || Instant::now() >= self.deadline {
            return Err(error("DWARF type graph is too large"));
        }
        let entry = underlying(self.unit, offset)?;
        let offset = entry.offset();
        if let Some(&known) = self.seen.get(&offset) {
            return Ok(known);
        }
        let id = self.nodes.len();
        self.nodes.push(Node::Void);
        self.seen.insert(offset, id);
        let tag = entry.tag();
        let size = type_size(self.unit, &entry, 0).ok();
        let of = |entry: &Die<'_>| reference(self.unit, entry.attr_value(gimli::DW_AT_type));
        let node = match tag {
            gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type => {
                let element = of(&entry)
                    .map(|offset| self.entry(offset, depth + 1))
                    .transpose()?
                    .unwrap_or(0);
                Node::Pointer { element }
            }
            gimli::DW_TAG_array_type => {
                let element = self.entry(typedef_target(self.unit, &entry)?, depth + 1)?;
                let dimensions = array_dimensions(self.unit, &entry).unwrap_or_default();
                Node::Array {
                    element,
                    dimensions,
                }
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type => {
                let union = tag == gimli::DW_TAG_union_type;
                let size = size.ok_or_else(|| error("incomplete DWARF aggregate"))?;
                let mut fields = Vec::new();
                let mut natural = 1;
                let mut offsets = size as u64;
                let mut cursor = self.unit.entries_at_offset(offset)?;
                let root_depth = cursor.next_dfs()?.map_or(0, |root| root.depth());
                while let Some(child) = cursor.next_dfs()? {
                    if child.depth() <= root_depth {
                        break;
                    }
                    if child.depth() != root_depth + 1 || child.tag() != gimli::DW_TAG_member {
                        continue;
                    }
                    let Some(name) = name(self.dwarf, self.unit, child)? else {
                        continue;
                    };
                    let ty = self.entry(typedef_target(self.unit, child)?, depth + 1)?;
                    let bit_size = child
                        .attr_value(gimli::DW_AT_bit_size)
                        .and_then(|value| value.udata_value());
                    let location = child
                        .attr_value(gimli::DW_AT_data_member_location)
                        .and_then(|value| value.udata_value());
                    let (offset, bit) = match bit_size {
                        Some(width) if (1..=64).contains(&width) => {
                            if let Some(bit) = child
                                .attr_value(gimli::DW_AT_data_bit_offset)
                                .and_then(|value| value.udata_value())
                            {
                                (bit / 8, Some((bit % 8, width)))
                            } else if let Some(bit) = child
                                .attr_value(gimli::DW_AT_bit_offset)
                                .and_then(|value| value.udata_value())
                            {
                                let storage = (self.size(ty).unwrap_or(0) as u64)
                                    .checked_mul(8)
                                    .ok_or_else(|| error("invalid bitfield"))?;
                                let shift = storage
                                    .checked_sub(bit.saturating_add(width))
                                    .ok_or_else(|| error("invalid bitfield"))?;
                                (location.unwrap_or(0) + shift / 8, Some((shift % 8, width)))
                            } else {
                                continue;
                            }
                        }
                        Some(_) => continue,
                        None => {
                            if let Some(offset) = location.or(union.then_some(0)) {
                                (offset, None)
                            } else {
                                continue;
                            }
                        }
                    };
                    if offset > size as u64 {
                        return Err(error("DWARF member lies outside its aggregate"));
                    }
                    if fields.len() >= 128 {
                        return Err(error("DWARF aggregate has too many members"));
                    }
                    natural = natural.max(self.align(ty));
                    if bit.is_none() {
                        offsets |= offset;
                    }
                    fields.push(Member {
                        name,
                        offset,
                        ty,
                        bit,
                    });
                }
                let layout_align = if offsets == 0 {
                    natural
                } else {
                    natural.min(1usize << offsets.trailing_zeros().min(30))
                };
                let align = entry
                    .attr_value(gimli::DW_AT_alignment)
                    .and_then(|value| value.udata_value())
                    .and_then(|value| usize::try_from(value).ok())
                    .filter(|value| value.is_power_of_two())
                    .unwrap_or(layout_align);
                Node::Aggregate {
                    union,
                    size,
                    align,
                    fields,
                }
            }
            gimli::DW_TAG_base_type | gimli::DW_TAG_enumeration_type => {
                if tag == gimli::DW_TAG_enumeration_type
                    && let Some(target) = of(&entry)
                {
                    let target = self.entry(target, depth + 1)?;
                    self.nodes[target].clone()
                } else {
                    let encoding = match entry.attr_value(gimli::DW_AT_encoding) {
                        Some(AttributeValue::Encoding(encoding)) => encoding,
                        _ => gimli::DW_ATE_unsigned,
                    };
                    let size = size.ok_or_else(|| error("unknown DWARF scalar size"))?;
                    let prefix = match encoding {
                        gimli::DW_ATE_signed | gimli::DW_ATE_signed_char => "i",
                        gimli::DW_ATE_float if matches!(size, 4 | 8) => "f",
                        gimli::DW_ATE_unsigned
                        | gimli::DW_ATE_unsigned_char
                        | gimli::DW_ATE_boolean
                        | gimli::DW_ATE_address => "u",
                        _ => "",
                    };
                    if matches!(size, 1 | 2 | 4 | 8) && !prefix.is_empty() {
                        Node::Scalar {
                            scalar: format!("{prefix}{}", size * 8),
                        }
                    } else {
                        Node::Opaque {
                            size,
                            align: size.next_power_of_two().min(16),
                        }
                    }
                }
            }
            gimli::DW_TAG_subroutine_type | gimli::DW_TAG_subprogram => {
                let returns = of(&entry)
                    .map(|offset| self.entry(offset, depth + 1))
                    .transpose()?
                    .unwrap_or(0);
                let mut args = Vec::new();
                let mut variadic = false;
                let mut cursor = self.unit.entries_at_offset(offset)?;
                let root_depth = cursor.next_dfs()?.map_or(0, |root| root.depth());
                while let Some(child) = cursor.next_dfs()? {
                    if child.depth() <= root_depth {
                        break;
                    }
                    if child.depth() != root_depth + 1 {
                        continue;
                    }
                    if child.tag() == gimli::DW_TAG_formal_parameter {
                        args.push(self.entry(typedef_target(self.unit, child)?, depth + 1)?);
                    } else if child.tag() == gimli::DW_TAG_unspecified_parameters {
                        variadic = true;
                    }
                }
                Node::Function {
                    args,
                    returns,
                    variadic,
                }
            }
            _ => {
                let size = size.ok_or_else(|| error("unsupported DWARF storage type"))?;
                Node::Opaque {
                    size,
                    align: size.next_power_of_two().min(16),
                }
            }
        };
        self.nodes[id] = node;
        Ok(id)
    }

    fn size(&self, id: usize) -> Option<usize> {
        match &self.nodes[id] {
            Node::Scalar { scalar } => scalar[1..].parse::<usize>().ok().map(|bits| bits / 8),
            Node::Pointer { .. } => Some(8),
            Node::Aggregate { size, .. } | Node::Opaque { size, .. } => Some(*size),
            Node::Array {
                element,
                dimensions,
            } if !dimensions.is_empty() => dimensions
                .iter()
                .try_fold(self.size(*element)?, |size, &count| {
                    size.checked_mul(count as usize)
                }),
            _ => None,
        }
    }

    fn align(&self, id: usize) -> usize {
        match &self.nodes[id] {
            Node::Aggregate { align, .. } | Node::Opaque { align, .. } => *align,
            Node::Pointer { .. } => 8,
            Node::Array { element, .. } => self.align(*element),
            _ => self.size(id).unwrap_or(1),
        }
    }
}

impl Graph {
    pub(crate) fn signature(&self) -> Option<(Vec<&str>, &str, bool)> {
        let Node::Function {
            args,
            returns,
            variadic,
        } = &self.nodes[self.root]
        else {
            return None;
        };
        let scalar = |id: usize| match &self.nodes[id] {
            Node::Void => Some("void"),
            Node::Scalar { scalar } => Some(scalar.as_str()),
            Node::Pointer { .. } => Some("ptr"),
            _ => None,
        };
        Some((
            args.iter()
                .map(|&id| scalar(id))
                .collect::<Option<Vec<_>>>()?,
            scalar(*returns)?,
            *variadic,
        ))
    }

    pub(crate) fn typescript(&self, prefix: &str) -> (String, String) {
        use std::fmt::Write;
        let api = "import(\"aidbg\")";
        let key = |id| format!("{prefix}_{id}");
        let scalar = |kind: &str| {
            if kind.ends_with("64") && !kind.starts_with('f') {
                "bigint"
            } else {
                "number"
            }
        };
        let mut definitions = String::new();
        for (id, node) in self.nodes.iter().enumerate() {
            let ty = match node {
                Node::Void => format!("{api}.Type.Base<void>"),
                Node::Scalar { scalar: kind } => format!("{api}.Type.Scalar<{}>", scalar(kind)),
                Node::Pointer { element } => format!("{api}.Type.Pointer<{}>", key(*element)),
                Node::Array {
                    element,
                    dimensions,
                } => {
                    let mut result = key(*element);
                    for _ in 0..dimensions.len().max(1) {
                        result = format!("{api}.Type.Array<{result}>");
                    }
                    result
                }
                Node::Aggregate { fields, .. } => {
                    let mut members = String::new();
                    for field in fields {
                        let field_name = serde_json::to_string(&field.name).unwrap();
                        let ty = match (&field.bit, &self.nodes[field.ty]) {
                            (Some(_), Node::Scalar { scalar: kind }) => {
                                format!("{api}.Type.Base<{api}.Value.Bitfield<{}>>", scalar(kind))
                            }
                            _ => key(field.ty),
                        };
                        let _ = write!(members, "{field_name}: {ty}; ");
                    }
                    format!("{api}.Type.Aggregate<{{{members}}}>")
                }
                Node::Function {
                    args,
                    returns,
                    variadic,
                } => format!(
                    "{api}.Type.Base<{api}.Value.Fn<[{}],{},{}>>",
                    args.iter().map(|&id| key(id)).collect::<Vec<_>>().join(","),
                    key(*returns),
                    variadic
                ),
                Node::Opaque { .. } => {
                    format!("{api}.Type.Base<{api}.Value.Base & {api}.Address & {api}.Bytes>")
                }
            };
            let _ = writeln!(definitions, "type {} = {ty};", key(id));
        }
        (key(self.root), definitions)
    }
}
