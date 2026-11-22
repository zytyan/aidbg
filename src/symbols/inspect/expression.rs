use super::{Access, Datum, Parser, Type, failure, word};
use crate::{Result, error, modules::id_hex};
use serde_json::json;

#[derive(Clone, Copy)]
pub(super) enum Number {
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    Bool(bool),
}

impl Number {
    pub(super) fn dwarf(bytes: &[u8], encoding: Option<gimli::DwAte>) -> Option<Self> {
        let bits = word(bytes).ok()?;
        let signed = || {
            let shift = (8 - bytes.len()) * 8;
            ((bits << shift) as i64) >> shift
        };
        Some(match (encoding?, bytes.len()) {
            (gimli::DW_ATE_boolean, _) => Self::Bool(bits != 0),
            (gimli::DW_ATE_float, 4) => Self::F32(f32::from_bits(bits as u32)),
            (gimli::DW_ATE_float, 8) => Self::F64(f64::from_bits(bits)),
            (gimli::DW_ATE_signed | gimli::DW_ATE_signed_char, 1..=4) => Self::I32(signed() as i32),
            (gimli::DW_ATE_signed | gimli::DW_ATE_signed_char, 8) => Self::I64(signed()),
            (gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char, 1..=2) => Self::I32(bits as i32),
            (gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char, 4) => Self::U32(bits as u32),
            (gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char, 8) => Self::U64(bits),
            _ => return None,
        })
    }

    fn truth(self) -> bool {
        match self {
            Self::F32(v) => v != 0.0,
            Self::F64(v) => v != 0.0,
            _ => self.integer().is_some_and(|v| v != 0),
        }
    }

    fn integer(self) -> Option<i128> {
        Some(match self {
            Self::I32(v) => v.into(),
            Self::U32(v) => v.into(),
            Self::I64(v) => v.into(),
            Self::U64(v) => v.into(),
            Self::Bool(v) => i128::from(v),
            _ => return None,
        })
    }

    fn float(self) -> f64 {
        match self {
            Self::F32(v) => v.into(),
            Self::F64(v) => v,
            _ => self.integer().expect("integer number") as f64,
        }
    }

    fn ty(self) -> ScalarType {
        match self {
            Self::I32(_) | Self::Bool(_) => ScalarType::I32,
            Self::U32(_) => ScalarType::U32,
            Self::I64(_) => ScalarType::I64,
            Self::U64(_) => ScalarType::U64,
            Self::F32(_) => ScalarType::F32,
            Self::F64(_) => ScalarType::F64,
        }
    }

    fn datum(self) -> Datum {
        let (name, size, bits, value) = match self {
            Self::I32(v) => ("int", 4, v as u64, json!(v)),
            Self::U32(v) => ("unsigned int", 4, v.into(), json!(v)),
            Self::I64(v) => ("long", 8, v as u64, json!(v)),
            Self::U64(v) => ("unsigned long", 8, v, json!(v)),
            Self::F32(v) => ("float", 4, v.to_bits().into(), json!(v)),
            Self::F64(v) => ("double", 8, v.to_bits(), json!(v)),
            Self::Bool(v) => ("bool", 1, u64::from(v), json!(v)),
        };
        Datum {
            ty: Type {
                name: Some(name.into()),
                kind: "scalar",
                byte_size: size,
                fields: vec![],
                element_count: None,
                dimensions: None,
            },
            address: None,
            bytes: id_hex(&bits.to_le_bytes()[..size]),
            value,
            module: None,
            preview: None,
            symbol: None,
            number: Some(self),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ScalarType {
    Bool,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
}

impl ScalarType {
    fn parse(text: &str) -> Option<Self> {
        Some(
            match text
                .split_ascii_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .as_str()
            {
                "bool" => Self::Bool,
                "int" | "signed" | "signed int" => Self::I32,
                "unsigned" | "unsigned int" => Self::U32,
                "long" | "long int" => Self::I64,
                "unsigned long" | "unsigned long int" => Self::U64,
                "float" => Self::F32,
                "double" => Self::F64,
                _ => return None,
            },
        )
    }

    fn cast(self, value: Number) -> Result<Number> {
        if self == Self::Bool {
            return Ok(Number::Bool(value.truth()));
        }
        if self >= Self::F32 {
            return Ok(if self == Self::F32 {
                Number::F32(value.float() as f32)
            } else {
                Number::F64(value.float())
            });
        }
        let bits = if matches!(self, Self::I32 | Self::U32) {
            32
        } else {
            64
        };
        let signed = matches!(self, Self::I32 | Self::I64);
        let integer = if let Some(v) = value.integer() {
            v
        } else {
            let v = value.float().trunc();
            let upper = 2f64.powi(bits - i32::from(signed));
            if !v.is_finite() || v >= upper || v < if signed { -upper } else { 0.0 } {
                return Err(failure(
                    "invalid_expression",
                    "floating-to-integer conversion out of range",
                ));
            }
            v as i128
        };
        Ok(self.truncate(integer))
    }

    fn truncate(self, value: i128) -> Number {
        match self {
            Self::I32 => Number::I32(value as i32),
            Self::U32 => Number::U32(value as u32),
            Self::I64 => Number::I64(value as i64),
            Self::U64 => Number::U64(value as u64),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Op {
    Or,
    And,
    Eq,
    Ne,
    Le,
    Ge,
    Lt,
    Gt,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

const OPS: &[(&str, u8, Op)] = &[
    ("||", 1, Op::Or),
    ("&&", 2, Op::And),
    ("==", 3, Op::Eq),
    ("!=", 3, Op::Ne),
    ("<=", 4, Op::Le),
    (">=", 4, Op::Ge),
    ("<", 4, Op::Lt),
    (">", 4, Op::Gt),
    ("+", 5, Op::Add),
    ("-", 5, Op::Sub),
    ("*", 6, Op::Mul),
    ("/", 6, Op::Div),
    ("%", 6, Op::Rem),
];

pub(super) enum Expression {
    Variable(String, Vec<Access>),
    Literal(Number),
    Unary(char, Box<Self>),
    Cast(ScalarType, Box<Self>),
    Binary(Op, Box<Self>, Box<Self>),
}

impl Expression {
    pub(super) fn parse(text: &str) -> Result<Self> {
        Self::parse_at(text.trim(), 0)
    }

    fn parse_at(text: &str, depth: usize) -> Result<Self> {
        if text.is_empty() || depth >= 24 {
            return Err(error("empty operand or expression nesting exceeds limit"));
        }
        if let Some(value) = literal(text) {
            return Ok(Self::Literal(value));
        }
        let mut split = None;
        let mut nesting = Vec::new();
        let mut first_close = None;
        let mut cursor = 0;
        let mut expect_operand = true;
        while cursor < text.len() {
            let c = text.as_bytes()[cursor];
            if c == b'(' || c == b'[' {
                nesting.push(c);
                cursor += 1;
                continue;
            }
            if c == b')' || c == b']' {
                let wanted = if c == b')' { b'(' } else { b'[' };
                if nesting.pop() != Some(wanted) {
                    return Err(error("unbalanced parentheses or brackets in expression"));
                }
                if nesting.is_empty() {
                    first_close.get_or_insert(cursor);
                    expect_operand = false;
                }
                cursor += 1;
                continue;
            }
            if !nesting.is_empty() || c.is_ascii_whitespace() {
                cursor += 1;
                continue;
            }
            if text.as_bytes()[cursor..].starts_with(b"->") {
                cursor += 2;
                expect_operand = true;
                continue;
            }
            if c.is_ascii_digit() && expect_operand {
                // A decimal exponent sign belongs to the literal.
                let start = cursor;
                let hex = text.as_bytes()[start..].starts_with(b"0x");
                cursor += 1;
                while cursor < text.len() {
                    let next = text.as_bytes()[cursor];
                    if !hex
                        && matches!(next, b'e' | b'E')
                        && text
                            .as_bytes()
                            .get(cursor + 1)
                            .is_some_and(|b| matches!(b, b'+' | b'-'))
                    {
                        cursor += 2;
                    } else if next.is_ascii_alphanumeric() || next == b'.' {
                        cursor += 1;
                    } else {
                        break;
                    }
                }
                expect_operand = false;
                continue;
            }
            if let Some(&(token, precedence, op)) = OPS
                .iter()
                .find(|(op, _, _)| text.as_bytes()[cursor..].starts_with(op.as_bytes()))
            {
                if !expect_operand && split.is_none_or(|(_, _, old, _)| precedence <= old) {
                    split = Some((cursor, token.len(), precedence, op));
                }
                expect_operand = true;
                cursor += token.len();
            } else {
                expect_operand = c == b'!';
                cursor += 1;
            }
        }
        if !nesting.is_empty() {
            return Err(error("unbalanced parentheses or brackets in expression"));
        }
        // A cast prefix is a unary operand, even when followed by unary minus.
        if text.starts_with('(')
            && let Some(end) = first_close
            && let Some(ty) = ScalarType::parse(&text[1..end])
            && !text[end + 1..].trim().is_empty()
            && split.is_none_or(|(index, _, _, _)| {
                index == end + 1 + text[end + 1..].len() - text[end + 1..].trim_start().len()
            })
        {
            return Ok(Self::Cast(
                ty,
                Box::new(Self::parse_at(text[end + 1..].trim_start(), depth + 1)?),
            ));
        }
        if let Some((index, len, _, op)) = split {
            return Ok(Self::Binary(
                op,
                Box::new(Self::parse_at(text[..index].trim_end(), depth + 1)?),
                Box::new(Self::parse_at(text[index + len..].trim_start(), depth + 1)?),
            ));
        }
        if text.starts_with('(') && first_close == Some(text.len() - 1) {
            return Self::parse_at(text[1..text.len() - 1].trim(), depth + 1);
        }
        if let Some(op @ ('+' | '-' | '!')) = text.chars().next() {
            return Ok(Self::Unary(
                op,
                Box::new(Self::parse_at(text[1..].trim_start(), depth + 1)?),
            ));
        }
        let mut parser = Parser::new(text);
        let name = parser.expression(0)?;
        if !parser.rest.trim().is_empty() {
            return Err(error(
                "expected a read-only scalar expression or variable access",
            ));
        }
        Ok(Self::Variable(name, parser.operations))
    }

    pub(super) fn evaluate(
        &self,
        lookup: &mut impl FnMut(&str, &[Access]) -> Result<Datum>,
    ) -> Result<Datum> {
        if let Self::Variable(name, access) = self {
            return lookup(name, access);
        }
        Ok(self.number(lookup)?.datum())
    }

    fn number(&self, lookup: &mut impl FnMut(&str, &[Access]) -> Result<Datum>) -> Result<Number> {
        match self {
            Self::Variable(name, access) => lookup(name, access)?.number.ok_or_else(|| {
                failure(
                    "unsupported",
                    "arithmetic requires supported scalar operands",
                )
            }),
            Self::Literal(v) => Ok(*v),
            Self::Cast(ty, inner) => ty.cast(inner.number(lookup)?),
            Self::Unary(op, inner) => {
                let v = inner.number(lookup)?;
                match op {
                    '!' => Ok(Number::Bool(!v.truth())),
                    '+' => v.ty().cast(v),
                    '-' => binary(Op::Sub, Number::I32(0), v),
                    _ => unreachable!(),
                }
            }
            Self::Binary(op, a, b) => {
                let left = a.number(lookup)?;
                match op {
                    Op::And if !left.truth() => return Ok(Number::Bool(false)),
                    Op::Or if left.truth() => return Ok(Number::Bool(true)),
                    _ => {}
                }
                binary(*op, left, b.number(lookup)?)
            }
        }
    }
}

fn literal(text: &str) -> Option<Number> {
    if text == "true" || text == "false" {
        return Some(Number::Bool(text == "true"));
    }
    if !text.as_bytes().first()?.is_ascii_digit() && !text.starts_with('.') {
        return None;
    }
    let hex = text.strip_prefix("0x");
    if hex.is_none() && (text.contains('.') || text.contains('e') || text.contains('E')) {
        return if let Some(raw) = text.strip_suffix(['f', 'F']) {
            raw.parse::<f32>().ok().map(Number::F32)
        } else {
            text.parse::<f64>().ok().map(Number::F64)
        };
    }
    let (raw, unsigned) = text
        .strip_suffix(['u', 'U'])
        .map_or((text, false), |s| (s, true));
    let bits = if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()?
    } else if raw.len() > 1 && raw.starts_with('0') {
        u64::from_str_radix(raw, 8).ok()?
    } else {
        raw.parse::<u64>().ok()?
    };
    Some(if unsigned {
        u32::try_from(bits)
            .map(Number::U32)
            .unwrap_or(Number::U64(bits))
    } else if let Ok(value) = i32::try_from(bits) {
        Number::I32(value)
    } else if hex.is_some()
        && let Ok(value) = u32::try_from(bits)
    {
        Number::U32(value)
    } else if let Ok(value) = i64::try_from(bits) {
        Number::I64(value)
    } else if hex.is_some() {
        Number::U64(bits)
    } else {
        return None;
    })
}

fn compare<T: PartialEq + PartialOrd>(op: Op, a: T, b: T) -> Option<Number> {
    Some(Number::Bool(match op {
        Op::Eq => a == b,
        Op::Ne => a != b,
        Op::Le => a <= b,
        Op::Ge => a >= b,
        Op::Lt => a < b,
        Op::Gt => a > b,
        _ => return None,
    }))
}

fn binary(op: Op, left: Number, right: Number) -> Result<Number> {
    if matches!(op, Op::And | Op::Or) {
        return Ok(Number::Bool(right.truth()));
    }
    // Enum order implements LP64 usual arithmetic conversions after promotion.
    let ty = left.ty().max(right.ty());
    let left = ty.cast(left)?;
    let right = ty.cast(right)?;
    if ty >= ScalarType::F32 {
        let (a, b) = (left.float(), right.float());
        if let Some(result) = compare(op, a, b) {
            return Ok(result);
        }
        let value = match op {
            Op::Add => a + b,
            Op::Sub => a - b,
            Op::Mul => a * b,
            Op::Div => a / b,
            _ => {
                return Err(failure(
                    "invalid_expression",
                    "floating-point remainder requires an integer operand",
                ));
            }
        };
        return ty.cast(Number::F64(value));
    }
    let (a, b) = (left.integer().unwrap(), right.integer().unwrap());
    if let Some(result) = compare(op, a, b) {
        return Ok(result);
    }
    if matches!(op, Op::Div | Op::Rem) && b == 0 {
        return Err(failure("invalid_expression", "integer division by zero"));
    }
    if matches!(op, Op::Div | Op::Rem)
        && b == -1
        && ((ty == ScalarType::I32 && a == i32::MIN as i128)
            || (ty == ScalarType::I64 && a == i64::MIN as i128))
    {
        return Err(failure("invalid_expression", "signed division overflow"));
    }
    let value = match op {
        Op::Add => a.wrapping_add(b),
        Op::Sub => a.wrapping_sub(b),
        Op::Mul => a.wrapping_mul(b),
        Op::Div => a / b,
        Op::Rem => a % b,
        _ => unreachable!(),
    };
    if (ty == ScalarType::I32 && i32::try_from(value).is_err())
        || (ty == ScalarType::I64 && i64::try_from(value).is_err())
    {
        return Err(failure("invalid_expression", "signed arithmetic overflow"));
    }
    Ok(ty.truncate(value))
}
