mod session;
use super::{Diagnostic, ExpressionCheck, Range, Target};
use crate::{Result, error};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    ops::Range as ByteRange,
    sync::Arc,
    time::{Duration, Instant},
};
use tsrs_api::{Handler, Response, Session, SessionOptions};
use tsrs_ast::{
    Kind as SyntaxKind, Node, NodeFlags, SourceFile, Symbol, get_source_file_of_node,
    is_declaration_name,
};
use tsrs_core::{P, context::Context};
use tsrs_project::ID;
use tsrs_scanner::{get_ecma_line_and_utf16_character_of_position, skip_trivia};
use tsrs_vfs::{bundled, vfstest};

const ROOT: &str = "/aidbg";
const CONFIG: &str = "/aidbg/tsconfig.json";
const HOST: &str = "/aidbg/aidbg.d.ts";
const INPUT: &str = "/aidbg/script.ts";
const OUTPUT: &str = "/aidbg/script.js";
const GLOBALS: &str = "/aidbg/globals.d.ts";

pub(super) struct Compiler {
    session: Arc<Session>,
    snapshot: Option<u64>,
    project: String,
    source: String,
    globals: String,
    session_api: bool,
}

impl Compiler {
    pub(super) fn new(declarations: &str) -> Self {
        Self::with_session_api(declarations, false)
    }

    pub(super) fn with_session_api(declarations: &str, session_api: bool) -> Self {
        // The session's fallback is another memory FS, so references and imports
        // from submitted scripts cannot access the host's filesystem.
        let lib_dir = bundled::lib_path();
        let mut files = vec![
            (HOST.to_owned(), declarations.to_owned()),
            (INPUT.to_owned(), String::new()),
            (GLOBALS.to_owned(), String::new()),
        ];
        let mut roots = vec![HOST.to_owned(), INPUT.to_owned(), GLOBALS.to_owned()];
        // Select declarations for ECMAScript intrinsics only. Shared memory
        // and the Intl object are outside the script runtime.
        for name in [
            "es5",
            "es2015.core",
            "es2015.collection",
            "es2015.iterable",
            "es2015.generator",
            "es2015.promise",
            "es2015.proxy",
            "es2015.reflect",
            "es2015.symbol",
            "es2015.symbol.wellknown",
            "es2016.array.include",
            "es2017.object",
            "es2017.string",
            "es2017.typedarrays",
            "es2018.asynciterable",
            "es2018.asyncgenerator",
            "es2018.promise",
            "es2018.regexp",
            "es2019.array",
            "es2019.object",
            "es2019.string",
            "es2019.symbol",
            "es2020.bigint",
            "es2020.promise",
            "es2020.string",
            "es2020.symbol.wellknown",
        ] {
            let name = format!("lib.{name}.d.ts");
            let contents = bundled::embedded_file(&format!("{lib_dir}/{name}"))
                .expect("tsrs embedded ECMAScript declaration");
            let contents = if name == "lib.es5.d.ts" {
                // This namespace advertises an Intl global, which QuickJS
                // does not provide. Retain its types for locale method signatures.
                let (before, after) = contents
                    .split_once("declare namespace Intl {")
                    .expect("tsrs es5 Intl declarations");
                let (namespace, rest) = after.split_once("\n}").expect("end of Intl namespace");
                let namespace = namespace
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("var "))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!("{before}declare namespace Intl {{{namespace}\n}}{rest}")
            } else {
                contents.to_owned()
            };
            let path = format!("{ROOT}/{name}");
            roots.push(path.clone());
            files.push((path, contents));
        }
        files.push((
            CONFIG.to_owned(),
            json!({
                "compilerOptions": {
                    "target": "ES2020", "module": "ES2022", "strict": true,
                    "noLib": true, "types": [], "skipLibCheck": true,
                    "noEmitOnError": !session_api, "sourceMap": session_api, "declaration": session_api, "disableSizeLimit": true
                },
                "files": roots,
            })
            .to_string(),
        ));
        let fs = Arc::new(vfstest::from_map(files, true));
        Self {
            session: Session::new(SessionOptions::new(ROOT.into(), lib_dir, fs, false)),
            snapshot: None,
            project: String::new(),
            source: String::new(),
            globals: String::new(),
            session_api,
        }
    }

    fn request(&self, method: &str, request: Value) -> Result<Value> {
        let response = self
            .session
            .handle_request(method, &serde_json::to_vec(&request)?)?;
        match response {
            Response::Json(text) => Ok(serde_json::from_str(&text)?),
            Response::Binary(_) => Err(error("unexpected binary tsrs response")),
        }
    }

    fn load(&mut self, source: &str, globals: &str) -> Result<u64> {
        if let Some(id) = self.snapshot
            && self.source == source
            && self.globals == globals
        {
            return Ok(id);
        }
        let changes = json!({
            "ensurePrograms": true,
            "fileSystem": { "kind": "layer", "files": { INPUT: source, GLOBALS: globals } },
            "fileNotifications": { "changed": [INPUT, GLOBALS] },
        });
        let previous = self.snapshot;
        let response = if let Some(id) = previous {
            self.request(
                "updateSnapshot",
                json!({"snapshot": id, "changes": changes}),
            )?
        } else {
            let mut changes = changes;
            changes["openProjects"] = json!([CONFIG]);
            self.request("createSnapshot", changes)?
        };
        let id = response["snapshot"]
            .as_u64()
            .ok_or_else(|| error("tsrs returned no snapshot"))?;
        self.snapshot = Some(id);
        if let Some(previous) = previous {
            self.request("release", json!({"snapshot": previous}))?;
        } else {
            self.project = response["projects"][0]["id"]
                .as_str()
                .ok_or_else(|| error("tsrs returned no script project"))?
                .to_owned();
        }
        self.source = source.to_owned();
        self.globals = globals.to_owned();
        Ok(id)
    }

    pub(super) fn check(
        &mut self,
        source: &str,
        target: Option<&Target>,
        preflight: bool,
    ) -> Result<(Vec<Diagnostic>, Vec<ExpressionCheck>)> {
        self.check_with_globals(source, "", target, preflight)
    }

    pub(super) fn check_with_globals(
        &mut self,
        source: &str,
        globals: &str,
        target: Option<&Target>,
        preflight: bool,
    ) -> Result<(Vec<Diagnostic>, Vec<ExpressionCheck>)> {
        let id = self.load(source, globals)?;
        let params = json!({"snapshot": id, "project": self.project});
        let snapshot = self.session.snapshot_data(id)?;
        let program = snapshot.get_program(&ID(self.project.clone()))?;
        let file = program
            .get_source_file(INPUT)
            .ok_or_else(|| error("tsrs returned no script AST"))?;
        let mut diagnostics = Vec::new();
        for method in [
            "getConfigFileParsingDiagnostics",
            "getProgramDiagnostics",
            "getSyntacticDiagnostics",
            "getGlobalDiagnostics",
            "getSemanticDiagnostics",
        ] {
            let wire: Vec<TsDiagnostic> =
                serde_json::from_value(self.request(method, params.clone())?)?;
            diagnostics.extend(wire.into_iter().map(Diagnostic::from));
        }
        for directive in file.comment_directives.get() {
            diagnostics.push(policy(
                file,
                directive.loc.source_pos(),
                directive.loc.source_end(),
            ));
        }
        if let Some(directive) = file.check_js_directive().filter(|d| !d.enabled) {
            diagnostics.push(policy(
                file,
                Some(directive.range.pos()),
                Some(directive.range.end()),
            ));
        }
        if self.session_api {
            let mut stack = vec![file.as_node()];
            while let Some(node) = stack.pop() {
                if node.kind() == SyntaxKind::Identifier
                    && is_declaration_name(node)
                    && matches!(
                        node.as_identifier().text(),
                        "$" | "m" | "dbg" | "console" | "fmt" | "__aidbgOutput"
                    )
                    && node.parent().is_some_and(|parent| {
                        !matches!(
                            parent.kind(),
                            SyntaxKind::PropertyAssignment
                                | SyntaxKind::ShorthandPropertyAssignment
                                | SyntaxKind::PropertySignature
                                | SyntaxKind::MethodDeclaration
                                | SyntaxKind::MethodSignature
                                | SyntaxKind::PropertyDeclaration
                        )
                    })
                {
                    let start = skip_trivia(file.text(), node.pos().source_offset().unwrap_or(0));
                    let end = node.end().source_offset().unwrap_or(start);
                    diagnostics.push(Diagnostic {
                        source: "aidbg",
                        code: "RESERVED_GLOBAL".into(),
                        severity: "error",
                        message: format!(
                            "{} is a reserved debugger global",
                            node.as_identifier().text()
                        ),
                        file: Some(INPUT.into()),
                        range: Some(range(file, start, end)),
                    });
                }
                node.for_each_child(&mut |child| {
                    stack.push(child);
                    false
                });
            }
        }
        diagnostics.dedup();

        let mut expressions = Vec::new();
        if preflight && !diagnostics.iter().any(Diagnostic::is_error) {
            let ctx = Context::background();
            let mut checker = program.get_type_checker_for_file_exclusive(&ctx, file);
            let mut stack = vec![file.as_node()];
            let deadline = Instant::now() + Duration::from_millis(500);
            while let Some(node) = stack.pop() {
                let first = stack.len();
                node.for_each_child(&mut |child| {
                    stack.push(child);
                    false
                });
                stack[first..].reverse();
                if let Some(check) = expression_check(
                    file,
                    node,
                    target,
                    deadline,
                    &mut |node| checker.get_symbol_at_location_exported(node),
                    &mut diagnostics,
                ) {
                    expressions.push(check);
                }
            }
        }
        Ok((diagnostics, expressions))
    }

    pub(super) fn emit(&self) -> Result<String> {
        self.emit_output(1, OUTPUT)
    }

    pub(super) fn emit_source_map(&self) -> Result<String> {
        self.emit_output(1, "/aidbg/script.js.map")
    }

    pub(super) fn emit_declarations(&self) -> Result<String> {
        self.emit_output(2, "/aidbg/script.d.ts")
    }

    fn emit_output(&self, emit_only: u8, path: &str) -> Result<String> {
        let value = self.request(
            "emitToString",
            json!({
                "snapshot": self.snapshot, "project": self.project, "emitOnly": emit_only,
            }),
        )?;
        value["outputFiles"]
            .as_array()
            .and_then(|files| files.iter().find(|file| file["fileName"] == path))
            .and_then(|file| file["text"].as_str())
            .map(str::to_owned)
            .ok_or_else(|| error(format!("tsrs did not emit {path}: {value}")))
    }
}

impl Drop for Compiler {
    fn drop(&mut self) {
        self.session.close();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TsDiagnostic {
    code: u32,
    text: String,
    category: u8,
    file_name: Option<String>,
    pos: i64,
    end: i64,
    start_position: Option<Position>,
    end_position: Option<Position>,
    #[serde(default)]
    message_chain: Vec<TsDiagnostic>,
}

#[derive(Deserialize)]
struct Position {
    line: u32,
    character: u32,
}

impl TsDiagnostic {
    fn message(&self) -> String {
        let mut result = self.text.clone();
        for child in &self.message_chain {
            result.push_str("\n  ");
            result.push_str(&child.message());
        }
        result
    }
}

impl From<TsDiagnostic> for Diagnostic {
    fn from(value: TsDiagnostic) -> Self {
        let message = value.message();
        let range = match (value.start_position, value.end_position) {
            (Some(start), Some(end)) => Some(Range {
                start: value.pos as u32,
                end: value.end as u32,
                line: start.line + 1,
                column: start.character + 1,
                end_line: end.line + 1,
                end_column: end.character + 1,
            }),
            _ => None,
        };
        Self {
            source: "typescript",
            code: value.code.to_string(),
            severity: if value.category == 1 {
                "error"
            } else {
                "warning"
            },
            message,
            file: value.file_name,
            range,
        }
    }
}

fn policy(file: P<SourceFile>, pos: Option<u32>, end: Option<u32>) -> Diagnostic {
    Diagnostic {
        source: "aidbg",
        code: "CHECK_SUPPRESSION".into(),
        severity: "error",
        message: "TypeScript diagnostic suppression directives are disabled".into(),
        file: Some(INPUT.into()),
        range: Some(range(file, pos.unwrap_or(0), end.unwrap_or(0))),
    }
}

fn range(file: P<SourceFile>, pos: u32, end: u32) -> Range {
    let (line, col) = get_ecma_line_and_utf16_character_of_position(&*file, pos);
    let (end_line, end_col) = get_ecma_line_and_utf16_character_of_position(&*file, end);
    let map = file.get_position_map();
    Range {
        start: map.utf8_to_utf16(pos),
        end: map.utf8_to_utf16(end),
        line: line as u32 + 1,
        column: col + 1,
        end_line: end_line as u32 + 1,
        end_column: end_col + 1,
    }
}

fn const_initializer(symbol: P<Symbol>) -> Option<P<Node>> {
    let declaration = symbol.value_declaration()?;
    if declaration.kind() == SyntaxKind::VariableDeclaration
        && declaration.parent()?.flags().intersects(NodeFlags::Const)
    {
        return declaration.as_variable_declaration().initializer();
    }
    None
}

fn string_text(node: P<Node>) -> &'static str {
    if node.kind() == SyntaxKind::StringLiteral {
        node.as_string_literal().text()
    } else {
        node.as_no_substitution_template_literal().text()
    }
}

fn host_method(
    mut node: P<Node>,
    symbol_at: &mut impl FnMut(P<Node>) -> Option<P<Symbol>>,
) -> bool {
    for _ in 0..16 {
        let name = match node.kind() {
            SyntaxKind::PropertyAccessExpression => node.as_property_access_expression().name,
            SyntaxKind::ElementAccessExpression => {
                node.as_element_access_expression().argument_expression
            }
            SyntaxKind::ParenthesizedExpression => {
                node = node.as_parenthesized_expression().expression();
                continue;
            }
            SyntaxKind::Identifier => {
                let Some(initializer) = symbol_at(node).and_then(const_initializer) else {
                    return false;
                };
                node = initializer;
                continue;
            }
            _ => return false,
        };
        let text = match name.kind() {
            SyntaxKind::Identifier => name.as_identifier().text(),
            SyntaxKind::StringLiteral => name.as_string_literal().text(),
            _ => return false,
        };
        return matches!(text, "inspect" | "printVal")
            && symbol_at(name).is_some_and(|symbol| {
                symbol.declarations().iter().any(|&decl| {
                    get_source_file_of_node(decl).is_some_and(|file| file.file_name() == HOST)
                })
            });
    }
    false
}

fn frame_argument(
    options: P<Node>,
    symbol_at: &mut impl FnMut(P<Node>) -> Option<P<Symbol>>,
) -> std::result::Result<Option<&'static str>, ()> {
    if options.kind() != SyntaxKind::ObjectLiteralExpression {
        return Err(());
    }
    // Computed keys and spreads can override the frame.
    let mut frame = None;
    for &node in options.as_object_literal_expression().properties.nodes() {
        if node.kind() != SyntaxKind::PropertyAssignment {
            return Err(());
        }
        let property = node.as_property_assignment();
        let name = property.name();
        let key = match name.kind() {
            SyntaxKind::Identifier => name.as_identifier().text(),
            SyntaxKind::StringLiteral => name.as_string_literal().text(),
            _ => return Err(()),
        };
        if key == "frame" {
            frame = Some(
                constant_string(property.initializer(), symbol_at)
                    .map(string_text)
                    .ok_or(())?,
            );
        }
    }
    Ok(frame)
}

// Map a cooked TS substring to the bytes spelling it in the original token.
fn raw_span(raw: &str, cooked: &str, span: ByteRange<usize>) -> Option<ByteRange<usize>> {
    if raw == cooked {
        return Some(span);
    }
    let (mut raw_pos, mut cooked_pos) = (0, 0);
    let (mut start, mut end) = (None, None);
    while raw_pos < raw.len() {
        let rest = raw.get(raw_pos..)?;
        let first = rest.chars().next()?;
        let (raw_width, cooked_width) = if let Some(tail) = rest.strip_prefix('\\') {
            let escape = tail.chars().next()?;
            let newline = matches!(escape, '\r' | '\n' | '\u{2028}' | '\u{2029}');
            let width = match escape {
                '\r' if tail.starts_with("\r\n") => 3,
                'u' if tail.starts_with("u{") => tail.find('}')? + 2,
                'u' => {
                    let high = u16::from_str_radix(tail.get(1..5)?, 16).ok()?;
                    if (0xd800..=0xdbff).contains(&high) && tail.get(5..7) == Some("\\u") {
                        let low = u16::from_str_radix(tail.get(7..11)?, 16).ok()?;
                        if (0xdc00..=0xdfff).contains(&low) {
                            12
                        } else {
                            6
                        }
                    } else {
                        6
                    }
                }
                'x' => 4,
                _ => escape.len_utf8() + 1,
            };
            let cooked_width = if newline {
                0
            } else {
                cooked.get(cooked_pos..)?.chars().next()?.len_utf8()
            };
            (width, cooked_width)
        } else if rest.starts_with("\r\n") {
            (2, 1)
        } else {
            (first.len_utf8(), first.len_utf8())
        };
        if cooked_width > 0 && cooked_pos == span.start {
            start = Some(raw_pos);
        }
        raw_pos += raw_width;
        cooked_pos += cooked_width;
        if cooked_width > 0 && cooked_pos == span.end {
            end = Some(raw_pos);
        }
    }
    if cooked_pos != cooked.len() {
        return None;
    }
    Some(start?..end?)
}

fn constant_string(
    mut node: P<Node>,
    symbol_at: &mut impl FnMut(P<Node>) -> Option<P<Symbol>>,
) -> Option<P<Node>> {
    for _ in 0..16 {
        node = match node.kind() {
            SyntaxKind::StringLiteral | SyntaxKind::NoSubstitutionTemplateLiteral => {
                return Some(node);
            }
            SyntaxKind::ParenthesizedExpression => node.as_parenthesized_expression().expression(),
            SyntaxKind::Identifier => const_initializer(symbol_at(node)?)?,
            _ => return None,
        };
    }
    None
}

fn expression_check(
    file: P<SourceFile>,
    node: P<Node>,
    target: Option<&Target>,
    deadline: Instant,
    symbol_at: &mut impl FnMut(P<Node>) -> Option<P<Symbol>>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<ExpressionCheck> {
    if node.kind() != SyntaxKind::CallExpression {
        return None;
    }
    let call = node.as_call_expression();
    if !host_method(call.expression, symbol_at) {
        return None;
    }
    let argument = *call.arguments.nodes().first()?;
    let start = skip_trivia(file.text(), argument.pos().source_offset()?);
    let end = argument.end().source_offset()?;
    let mut check = ExpressionCheck {
        status: "unchecked",
        expression: None,
        code: "DYNAMIC_EXPRESSION",
        range: range(file, start, end),
    };
    let frame = call
        .arguments
        .nodes()
        .get(1)
        .map_or(Ok(None), |&options| frame_argument(options, symbol_at));
    if frame.is_err() {
        check.status = "runtime_only";
        check.code = "RUNTIME_FRAME";
    }
    let Some(literal) = constant_string(argument, symbol_at) else {
        return Some(check);
    };
    let start = skip_trivia(file.text(), literal.pos().source_offset()?) + 1;
    let end = literal.end().source_offset()?.checked_sub(1)?;
    let raw = file.text().get(start as usize..end as usize)?;
    let cooked = string_text(literal);
    check.expression = Some(cooked.to_owned());
    check.range = range(file, start, end);
    let frame = match frame {
        Ok(frame) => frame,
        Err(()) => return Some(check),
    };
    let Some(target) = target else {
        check.code = "NO_TARGET";
        return Some(check);
    };
    if Instant::now() >= deadline {
        check.code = "PREFLIGHT_LIMIT";
        return Some(check);
    }
    let result = target.preflight(cooked, frame);
    check.status = result.status;
    check.code = result.code;
    if let Some(span) = result.span.and_then(|span| raw_span(raw, cooked, span)) {
        check.range = range(file, start + span.start as u32, start + span.end as u32);
    }
    if result.status == "error" {
        diagnostics.push(Diagnostic {
            source: "dwarf",
            code: result.code.into(),
            severity: "error",
            message: result.message,
            file: Some(INPUT.into()),
            range: Some(check.range),
        });
    }
    Some(check)
}
