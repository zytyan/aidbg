use crate::{Result, error};
use serde::Serialize;
use std::{collections::BTreeMap, sync::LazyLock};

#[derive(Clone, Copy)]
struct Position {
    generated: u64,
    line: u64,
    column: u64,
}

pub(super) struct SourceMap(Vec<Vec<Position>>);

impl SourceMap {
    pub fn parse(map: &str) -> Result<Self> {
        let map: serde_json::Value = serde_json::from_str(map)?;
        let mappings = map["mappings"]
            .as_str()
            .ok_or_else(|| error("missing source map mappings"))?;
        let (mut source, mut line, mut column) = (0i64, 0i64, 0i64);
        let mut lines = Vec::new();
        for generated_line in mappings.split(';') {
            let mut generated = 0i64;
            let mut positions = Vec::new();
            for segment in generated_line.split(',').filter(|s| !s.is_empty()) {
                let mut segment = segment.bytes();
                generated += vlq(&mut segment)?;
                if segment.len() == 0 {
                    continue;
                }
                source += vlq(&mut segment)?;
                line += vlq(&mut segment)?;
                column += vlq(&mut segment)?;
                if source == 0 && generated >= 0 && line >= 0 && column >= 0 {
                    positions.push(Position {
                        generated: generated as u64,
                        line: line as u64 + 1,
                        column: column as u64 + 1,
                    });
                }
            }
            lines.push(positions);
        }
        Ok(Self(lines))
    }

    fn original(&self, line: u64, column: u64) -> Option<(u64, u64)> {
        // The injected console binding occupies one generated line.
        let positions = self.0.get(usize::try_from(line.checked_sub(2)?).ok()?)?;
        let index = positions
            .partition_point(|position| position.generated < column)
            .checked_sub(1)?;
        let position = positions[index];
        Some((position.line, position.column))
    }
}

fn vlq(input: &mut std::str::Bytes<'_>) -> Result<i64> {
    let mut bits = 0u64;
    for shift in (0..60).step_by(5) {
        let digit = match input.next() {
            Some(byte) => byte,
            None => return Err(error("truncated source map segment")),
        };
        let digit = match digit {
            b'A'..=b'Z' => digit - b'A',
            b'a'..=b'z' => digit - b'a' + 26,
            b'0'..=b'9' => digit - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(error("invalid source map digit")),
        };
        bits |= u64::from(digit & 31) << shift;
        if digit & 32 == 0 {
            let value = (bits >> 1) as i64;
            return Ok(if bits & 1 != 0 { -value } else { value });
        }
    }
    Err(error("source map segment overflow"))
}

#[derive(Serialize)]
pub(super) struct Location {
    pub file: String,
    pub line: u64,
    pub column: Option<u64>,
}

static FRAME: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"script-(\d+)\.js:(\d+)(?::(\d+))?").unwrap());

pub(super) fn origin(stack: &str, active: impl Fn(u64) -> bool) -> Option<u64> {
    let mut nearest = None;
    for frame in FRAME.captures_iter(stack) {
        let id = frame[1].parse().ok()?;
        if active(id) {
            return Some(id);
        }
        nearest = nearest.or(Some(id));
    }
    nearest
}

pub(super) fn remap(
    stack: &str,
    maps: &BTreeMap<u64, SourceMap>,
) -> (String, Option<u64>, Option<Location>) {
    let mut script = None;
    let mut location = None;
    let mapped = FRAME
        .replace_all(stack, |captures: &regex::Captures<'_>| {
            let id = captures[1].parse::<u64>().unwrap_or_default();
            let line = captures[2].parse::<u64>().unwrap_or_default();
            let column = captures
                .get(3)
                .and_then(|column| column.as_str().parse().ok());
            let (line, column) = maps
                .get(&id)
                .and_then(|map| map.original(line, column.unwrap_or(1)))
                .or_else(|| maps.get(&id).and_then(|map| map.original(line, u64::MAX)))
                .map_or((line.saturating_sub(1).max(1), column), |(line, column)| {
                    (line, Some(column))
                });
            let file = format!("script-{id}.ts");
            if script.is_none() {
                script = Some(id);
                location = Some(Location {
                    file: file.clone(),
                    line,
                    column,
                });
            }
            column.map_or_else(
                || format!("{file}:{line}"),
                |col| format!("{file}:{line}:{col}"),
            )
        })
        .into_owned();
    (mapped, script, location)
}
