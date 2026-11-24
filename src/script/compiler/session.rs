use super::*;
use crate::symbols::inspect::type_graph::Graph;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

const API: &str = "import(\"aidbg\")";

struct Edit {
    start: usize,
    end: usize,
    text: String,
}

struct Source {
    text: String,
    positions: Vec<u32>,
}

impl Source {
    fn new(text: &str) -> Self {
        Self {
            text: text.into(),
            positions: (0..=text.encode_utf16().count() as u32).collect(),
        }
    }

    fn edit(&self, mut edits: Vec<Edit>) -> Self {
        edits.sort_by_key(|edit| (edit.start, edit.end));
        let mut result = Self {
            text: String::new(),
            positions: Vec::new(),
        };
        let mut previous = 0;
        let mut units = 0;
        for edit in edits {
            if edit.start < previous {
                continue;
            }
            let kept = &self.text[previous..edit.start];
            result.text.push_str(kept);
            let len = kept.encode_utf16().count();
            result
                .positions
                .extend_from_slice(&self.positions[units..units + len]);
            units += len;
            result.text.push_str(&edit.text);
            result.positions.extend(std::iter::repeat_n(
                self.positions[units],
                edit.text.encode_utf16().count(),
            ));
            units += self.text[edit.start..edit.end].encode_utf16().count();
            previous = edit.end;
        }
        result.text.push_str(&self.text[previous..]);
        result.positions.extend_from_slice(&self.positions[units..]);
        result
    }

    fn map_diagnostics(&self, source: &str, diagnostics: &mut [Diagnostic]) {
        let mut lines = vec![0];
        let mut index = 0;
        for character in source.chars() {
            index += character.len_utf16() as u32;
            if character == '\n' {
                lines.push(index);
            }
        }
        for diagnostic in diagnostics {
            if diagnostic.file.as_deref() != Some(INPUT) {
                continue;
            }
            let Some(range) = &mut diagnostic.range else {
                continue;
            };
            let original = |offset| {
                let offset = self
                    .positions
                    .get(offset as usize)
                    .copied()
                    .unwrap_or(index)
                    .min(index);
                let line = lines.partition_point(|&start| start <= offset);
                (offset, line as u32, offset - lines[line - 1] + 1)
            };
            (range.start, range.line, range.column) = original(range.start);
            (range.end, range.end_line, range.end_column) = original(range.end);
        }
    }
}

fn bounds(file: P<SourceFile>, node: P<Node>) -> Option<(usize, usize)> {
    Some((
        skip_trivia(file.text(), node.pos().source_offset()?) as usize,
        node.end().source_offset()? as usize,
    ))
}

fn insert(edits: &mut Vec<Edit>, at: usize, text: impl Into<String>) {
    edits.push(Edit {
        start: at,
        end: at,
        text: text.into(),
    });
}

fn nodes(file: P<SourceFile>) -> Vec<P<Node>> {
    let mut stack = vec![file.as_node()];
    let mut result = Vec::new();
    while let Some(node) = stack.pop() {
        result.push(node);
        let first = stack.len();
        node.for_each_child(&mut |child| {
            stack.push(child);
            false
        });
        stack[first..].reverse();
    }
    result
}

fn method(node: P<Node>) -> Option<(&'static str, P<Node>)> {
    if node.kind() != SyntaxKind::CallExpression {
        return None;
    }
    let expression = node.as_call_expression().expression;
    if expression.kind() != SyntaxKind::PropertyAccessExpression {
        return None;
    }
    let property = expression.as_property_access_expression();
    if property.expression.kind() != SyntaxKind::Identifier
        || property.expression.as_identifier().text() != "m"
    {
        return None;
    }
    Some((property.name.as_identifier().text(), property.name))
}

fn key(node: P<Node>) -> Option<&'static str> {
    match node.kind() {
        SyntaxKind::Identifier => Some(node.as_identifier().text()),
        SyntaxKind::StringLiteral => Some(string_text(node)),
        _ => None,
    }
}

fn aggregate_parent(mut node: P<Node>) -> Option<P<Node>> {
    while let Some(parent) = node.parent() {
        if method(parent).is_some_and(|(name, _)| matches!(name, "struct" | "union")) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn record(
    file: P<SourceFile>,
    node: P<Node>,
    code: &str,
    message: impl Into<String>,
) -> Diagnostic {
    let (start, end) = bounds(file, node).unwrap_or_default();
    Diagnostic {
        source: "aidbg",
        code: code.into(),
        severity: "error",
        message: message.into(),
        file: Some(INPUT.into()),
        range: Some(range(file, start as u32, end as u32)),
    }
}

type Span = (usize, usize);

struct Layouts {
    file: P<SourceFile>,
    dwarf: BTreeMap<Span, String>,
    aggregates: BTreeMap<Span, String>,
    variables: BTreeMap<&'static str, String>,
}

impl Layouts {
    fn aggregate(&self, node: P<Node>) -> Option<&str> {
        self.aggregates
            .get(&bounds(self.file, node)?)
            .map(String::as_str)
    }

    fn ty(&self, node: P<Node>, depth: usize) -> Option<String> {
        if depth > 32 {
            return None;
        }
        if let Some(ty) = self.dwarf.get(&bounds(self.file, node)?) {
            return Some(ty.clone());
        }
        if let Some(ty) = self.aggregate(node) {
            return Some(ty.to_owned());
        }
        if node.kind() == SyntaxKind::Identifier {
            let name = node.as_identifier().text();
            return Some(
                self.variables
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| format!("typeof {name}")),
            );
        }
        if node.kind() == SyntaxKind::ParenthesizedExpression {
            return self.ty(node.as_parenthesized_expression().expression(), depth + 1);
        }
        let (name, _) = method(node)?;
        let args = node.as_call_expression().arguments.nodes();
        Some(match name {
            "void" => format!("{API}.Type.Base<void>"),
            "u64" | "i64" => format!("{API}.Type.Scalar<bigint>"),
            "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "f32" | "f64" => {
                format!("{API}.Type.Scalar<number>")
            }
            "self" => self.aggregate(aggregate_parent(node)?)?.to_owned(),
            "array" | "pointer" => {
                let element = self.ty(*args.first()?, depth + 1)?;
                let kind = if name == "array" { "Array" } else { "Pointer" };
                format!("{API}.Type.{kind}<{element}>")
            }
            "lazy" => {
                let getter = *args.first()?;
                if getter.kind() != SyntaxKind::ArrowFunction {
                    return None;
                }
                self.ty(getter.as_arrow_function().body()?, depth + 1)?
            }
            _ => return None,
        })
    }

    fn aliases(&self, nodes: &[P<Node>], edits: &[Edit]) -> String {
        let mut aliases = BTreeMap::new();
        for &node in nodes {
            let Some(alias) = self.aggregate(node) else {
                continue;
            };
            let args = node.as_call_expression().arguments.nodes();
            let Some(fields) = args
                .first()
                .filter(|fields| fields.kind() == SyntaxKind::ObjectLiteralExpression)
            else {
                continue;
            };
            let mut members = String::new();
            for &field in fields.as_object_literal_expression().properties.nodes() {
                let (key, descriptor) = match field.kind() {
                    SyntaxKind::PropertyAssignment => {
                        let property = field.as_property_assignment();
                        (key(property.name()), property.initializer())
                    }
                    SyntaxKind::ShorthandPropertyAssignment => {
                        let name = field.as_shorthand_property_assignment().name();
                        (key(name), name)
                    }
                    _ => continue,
                };
                if let Some(key) = key {
                    let key = serde_json::to_string(key).unwrap();
                    let ty = self
                        .ty(descriptor, 0)
                        .unwrap_or_else(|| format!("{API}.Type.Base<unknown>"));
                    let _ = write!(members, "{key}: {ty}; ");
                }
            }
            aliases.insert(
                alias,
                format!("type {alias} = {API}.Type.Aggregate<{{ {members} }}>;\n"),
            );
        }
        let mut output = String::new();
        let mut used = BTreeSet::new();
        for edit in edits {
            for &alias in aliases.keys() {
                if edit
                    .text
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|key| key == alias)
                {
                    used.insert(alias);
                }
            }
        }
        let mut seen = BTreeSet::new();
        while let Some(alias) = used.pop_first() {
            if !seen.insert(alias) {
                continue;
            }
            let definition = &aliases[alias];
            output.push_str(definition);
            for token in definition.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                if let Some((&name, _)) = aliases.get_key_value(token)
                    && !seen.contains(name)
                {
                    used.insert(name);
                }
            }
        }
        output
    }

    fn context(&self, node: P<Node>, depth: usize) -> Option<String> {
        if depth > 16 {
            return None;
        }
        let aggregate = aggregate_parent(node)?;
        let alias = self.aggregate(aggregate)?;
        let mut text = format!("{API}.Infer<{alias}>");
        if let Some(parent) = self.context(aggregate, depth + 1) {
            let _ = write!(text, " & {{ readonly $parent: {parent} }}");
        }
        Some(text)
    }
}

impl Compiler {
    pub(in super::super) fn session_compile(
        &mut self,
        source: &str,
        globals: &str,
        id: u64,
        lookup: impl Fn(&str) -> Result<Graph>,
    ) -> Result<(Vec<Diagnostic>, Option<(String, String, String)>)> {
        let base = Source::new(source);
        let input = base.edit(vec![Edit {
            start: source.len(),
            end: source.len(),
            text: "\nexport {};\n".into(),
        }]);
        let (context_edits, mut diagnostics) =
            self.context_edits(&input.text, globals, id, lookup)?;
        if diagnostics.iter().any(Diagnostic::is_error) {
            input.map_diagnostics(source, &mut diagnostics);
            return Ok((diagnostics, None));
        }
        let contextual = input.edit(context_edits);
        let (assignment_edits, mut policy) = self.assignment_edits(&contextual.text, globals)?;
        contextual.map_diagnostics(source, &mut policy);
        let checked = contextual.edit(assignment_edits);
        let (mut diagnostics, _) = self.check_with_globals(&checked.text, globals, None, false)?;
        checked.map_diagnostics(source, &mut diagnostics);
        diagnostics.extend(policy);
        if diagnostics.iter().any(Diagnostic::is_error) {
            return Ok((diagnostics, None));
        }
        let declarations = self.emit_declarations()?;
        self.load(&input.text, globals)?;
        let js = self.emit()?;
        Ok((
            diagnostics,
            Some((js, declarations, self.emit_source_map()?)),
        ))
    }

    fn context_edits(
        &mut self,
        source: &str,
        globals: &str,
        id: u64,
        lookup: impl Fn(&str) -> Result<Graph>,
    ) -> Result<(Vec<Edit>, Vec<Diagnostic>)> {
        let snapshot_id = self.load(source, globals)?;
        let snapshot = self.session.snapshot_data(snapshot_id)?;
        let program = snapshot.get_program(&ID(self.project.clone()))?;
        let file = program
            .get_source_file(INPUT)
            .ok_or_else(|| error("script AST unavailable"))?;
        let context = Context::background();
        let mut checker = program.get_type_checker_for_file_exclusive(&context, file);
        let nodes = nodes(file);
        let mut layouts = Layouts {
            file,
            dwarf: BTreeMap::new(),
            aggregates: BTreeMap::new(),
            variables: BTreeMap::new(),
        };
        let mut edits = Vec::new();
        let mut errors = Vec::new();
        let mut aliases = String::new();
        let mut graphs = BTreeMap::<&str, (String, String)>::new();
        for &node in &nodes {
            let Some((name, _)) = method(node) else {
                continue;
            };
            let Some(span) = bounds(file, node) else {
                continue;
            };
            let call = node.as_call_expression();
            if matches!(name, "struct" | "union")
                && call
                    .arguments
                    .nodes()
                    .first()
                    .is_some_and(|arg| arg.kind() == SyntaxKind::ObjectLiteralExpression)
            {
                let alias = format!("__AidbgLayout{id}_{}", span.0);
                layouts.aggregates.insert(span, alias.clone());
                if let Some(declaration) = node
                    .parent()
                    .filter(|node| node.kind() == SyntaxKind::VariableDeclaration)
                    && let Some(name) = key(declaration.as_variable_declaration().name())
                {
                    layouts.variables.insert(name, alias);
                }
            }
            if name != "fromDwarf" {
                continue;
            }
            let Some(arg) = call.arguments.nodes().first().copied() else {
                continue;
            };
            let name = constant_string(arg, &mut |node| {
                checker.get_symbol_at_location_exported(node)
            })
            .map(string_text);
            let Some(name) = name else {
                errors.push(record(
                    file,
                    arg,
                    "DWARF_CONSTANT",
                    "fromDwarf requires a known string literal",
                ));
                continue;
            };
            if !graphs.contains_key(name) {
                match lookup(name) {
                    Ok(graph) => {
                        let (ty, defs) = graph.typescript(&format!("__AidbgDwarf{id}_{}", span.0));
                        aliases.push_str(&defs);
                        graphs.insert(name, (ty, defs));
                    }
                    Err(err) => {
                        errors.push(record(file, arg, "DWARF_TYPE", err.to_string()));
                        continue;
                    }
                }
            }
            let ty = &graphs[name].0;
            layouts.dwarf.insert(span, ty.clone());
            insert(&mut edits, span.0, "(");
            insert(&mut edits, span.1, format!(" as {ty})"));
        }
        let mut annotated = BTreeSet::new();
        for &node in &nodes {
            let Some((method, method_name)) = method(node) else {
                continue;
            };
            let call = node.as_call_expression();
            match method {
                "self" => {
                    if let Some((start, end)) = bounds(file, node) {
                        if let Some(ty) = layouts.ty(node, 0) {
                            insert(&mut edits, start, "(");
                            insert(&mut edits, end, format!(" as unknown as {ty})"));
                        } else {
                            errors.push(record(
                                file,
                                node,
                                "RECURSIVE_TYPE",
                                "self() requires an enclosing aggregate",
                            ));
                        }
                    }
                }
                "lazy" if call.type_arguments().is_none() => {
                    if let Some(ty) = layouts.ty(node, 0)
                        && let Some((_, end)) = bounds(file, method_name)
                    {
                        insert(&mut edits, end, format!("<{ty}>"));
                        if let Some(getter) = call
                            .arguments
                            .nodes()
                            .first()
                            .filter(|getter| getter.kind() == SyntaxKind::ArrowFunction)
                            && let Some(body) = getter
                                .as_arrow_function()
                                .body()
                                .filter(|body| body.kind() == SyntaxKind::Identifier)
                            && let Some(decl) = checker
                                .get_symbol_at_location_exported(body)
                                .and_then(|symbol| symbol.value_declaration())
                            && decl.kind() == SyntaxKind::VariableDeclaration
                            && let decl = decl.as_variable_declaration()
                            && decl.type_().is_none()
                            && let Some(alias) =
                                decl.initializer().and_then(|node| layouts.aggregate(node))
                            && let Some((_, end)) = bounds(file, decl.name())
                            && annotated.insert(end)
                        {
                            insert(&mut edits, end, format!(": {alias}"));
                        }
                    }
                }
                "array" | "pointer" => {
                    let Some(callback) = call.arguments.nodes().get(1) else {
                        continue;
                    };
                    let Some(ty) = layouts.context(node, 0) else {
                        continue;
                    };
                    let params = match callback.kind() {
                        SyntaxKind::ArrowFunction => callback.as_arrow_function().parameters(),
                        SyntaxKind::FunctionExpression => {
                            callback.as_function_expression().parameters()
                        }
                        _ => None,
                    };
                    if let Some(&parameter) = params.and_then(|params| params.nodes().first())
                        && parameter.as_parameter_declaration().type_.get().is_none()
                        && let Some((start, end)) = bounds(file, parameter)
                    {
                        let implicit = callback.kind() == SyntaxKind::ArrowFunction
                            && bounds(file, *callback)
                                .is_some_and(|(begin, _)| !file.text()[begin..start].contains('('));
                        if implicit {
                            insert(&mut edits, start, "(");
                        }
                        insert(
                            &mut edits,
                            end,
                            format!(": {ty}{}", if implicit { ")" } else { "" }),
                        );
                    }
                }
                _ => {}
            }
        }
        aliases.push_str(&layouts.aliases(&nodes, &edits));
        if !aliases.is_empty() {
            insert(&mut edits, source.len(), format!("\n{aliases}\n"));
        }
        Ok((edits, errors))
    }

    fn assignment_edits(
        &mut self,
        source: &str,
        globals: &str,
    ) -> Result<(Vec<Edit>, Vec<Diagnostic>)> {
        let id = self.load(source, globals)?;
        let snapshot = self.session.snapshot_data(id)?;
        let program = snapshot.get_program(&ID(self.project.clone()))?;
        let file = program
            .get_source_file(INPUT)
            .ok_or_else(|| error("script AST unavailable"))?;
        let context = Context::background();
        let mut checker = program.get_type_checker_for_file_exclusive(&context, file);
        let mut edits = Vec::new();
        let mut diagnostics = Vec::new();
        for node in nodes(file) {
            let kind = node.kind();
            if kind != SyntaxKind::BinaryExpression {
                continue;
            }
            let binary = node.as_binary_expression();
            if !tsrs_ast::is_assignment_operator(binary.operator_token.kind()) {
                continue;
            }
            let left = binary.left;
            let (object, property) = match left.kind() {
                SyntaxKind::PropertyAccessExpression => {
                    let property = left.as_property_access_expression();
                    (property.expression, key(property.name))
                }
                SyntaxKind::ElementAccessExpression => {
                    let property = left.as_element_access_expression();
                    (
                        property.expression,
                        if property.argument_expression.kind() == SyntaxKind::StringLiteral {
                            key(property.argument_expression)
                        } else {
                            None
                        },
                    )
                }
                _ => continue,
            };
            if property.is_some_and(|key| key.starts_with('$')) {
                continue;
            }
            let receiver = checker.get_type_at_location(object);
            if checker
                .get_property_of_type_exported(receiver, "$type")
                .is_none()
                || checker
                    .get_property_of_type_exported(receiver, "$dumpString")
                    .is_none()
            {
                continue;
            }
            let ty = checker.get_type_at_location(left);
            if checker.get_property_of_type_exported(ty, "$type").is_none() {
                continue;
            }
            if binary.operator_token.kind() != SyntaxKind::EqualsToken {
                diagnostics.push(record(
                    file,
                    binary.operator_token,
                    "VALUE_ASSIGNMENT",
                    "C Values require simple assignment or explicit $read/$write",
                ));
                continue;
            }
            let Some((start, end)) = bounds(file, node) else {
                continue;
            };
            let Some((op_start, op_end)) = bounds(file, binary.operator_token) else {
                continue;
            };
            insert(&mut edits, start, "__aidbgAssign(");
            edits.push(Edit {
                start: op_start,
                end: op_end,
                text: ",".into(),
            });
            insert(&mut edits, end, ")");
        }
        if !edits.is_empty() {
            insert(
                &mut edits,
                source.len(),
                format!("\ndeclare const __aidbgAssign: typeof {API}.__assign;\n"),
            );
        }
        Ok((edits, diagnostics))
    }
}
