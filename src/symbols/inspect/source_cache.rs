//! Unit-local source indexes. A lookup materializes only units that cover its PC.
use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

const MAX_UNITS: usize = 4;
const MAX_COVERAGE_UNITS: usize = 4096;
const MAX_UNIT_RANGES: usize = 32;
const MAX_ROWS: usize = 8192;
const MAX_INLINE_ITEMS: usize = 8192;
type UnitId = gimli::DebugInfoOffset<usize>;

type Units<T> = Mutex<BTreeMap<UnitId, Arc<T>>>;

#[derive(Default)]
pub(super) struct Sources {
    coverage: Units<Vec<gimli::Range>>,
    variable_units: OnceLock<Option<UnitDirectory>>,
    lines: Units<Lines>,
    inline: Units<Vec<InlineRange>>,
}

fn get<T>(cache: &Units<T>, id: UnitId) -> Option<Arc<T>> {
    cache
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .get(&id)
        .cloned()
}

fn insert<T>(cache: &Units<T>, id: UnitId, value: T) -> Arc<T> {
    let mut cache = cache.lock().unwrap_or_else(|err| err.into_inner());
    if let Some(existing) = cache.get(&id) {
        return existing.clone();
    }
    if cache.len() >= MAX_UNITS {
        cache.pop_first();
    }
    let value = Arc::new(value);
    cache.insert(id, value.clone());
    value
}

fn covers(dwarf: &Dwarf<Reader<'_>>, unit: &Unit<Reader<'_>>, pc: u64) -> Result<bool> {
    let mut ranges = dwarf.unit_ranges(unit)?;
    let mut empty = true;
    while let Some(range) = ranges.next()? {
        empty = false;
        if (range.begin..range.end).contains(&pc) {
            return Ok(true);
        }
    }
    Ok(empty)
}

impl Sources {
    pub(super) fn excludes(&self, header: &gimli::UnitHeader<Reader<'_>>, pc: u64) -> bool {
        gimli::UnitOffset(0)
            .to_debug_info_offset(header)
            .and_then(|id| get(&self.coverage, id))
            .is_some_and(|ranges| !matches_pc(&ranges, pc))
    }

    fn remember_coverage(
        &self,
        dwarf: &Dwarf<Reader<'_>>,
        unit: &Unit<Reader<'_>>,
        id: UnitId,
        pc: u64,
    ) -> Result<bool> {
        let mut entries = dwarf.unit_ranges(unit)?;
        let mut ranges = Vec::new();
        while let Some(range) = entries.next()? {
            if ranges.len() == MAX_UNIT_RANGES {
                return covers(dwarf, unit, pc);
            }
            ranges.push(range);
        }
        let contains = matches_pc(&ranges, pc);
        let mut cache = self.coverage.lock().unwrap_or_else(|err| err.into_inner());
        if cache.len() < MAX_COVERAGE_UNITS {
            cache.entry(id).or_insert_with(|| Arc::new(ranges));
        }
        Ok(contains)
    }
}

// Only publish the directory after visiting every unit. Missing coverage is
// retained as a candidate so an incomplete range table cannot hide a variable.
#[derive(Default)]
struct UnitDirectory {
    spans: Vec<(gimli::Range, UnitId)>,
    max_ends: Vec<u64>,
    unknown: Vec<UnitId>,
}

impl UnitDirectory {
    fn matching(&self, pc: u64) -> Vec<UnitId> {
        let end = self.spans.partition_point(|(range, _)| range.begin <= pc);
        let start = self.max_ends[..end].partition_point(|&max| max <= pc);
        let mut units = self.unknown.clone();
        units.extend(
            self.spans[start..end]
                .iter()
                .filter_map(|(range, id)| (pc < range.end).then_some(*id)),
        );
        units.sort_unstable();
        units.dedup();
        units
    }
}

impl Sources {
    pub(super) fn variable_units(
        &self,
        dwarf: &Dwarf<Reader<'_>>,
        pc: u64,
        deadline: Instant,
    ) -> Result<Option<Vec<UnitId>>> {
        if let Some(directory) = self.variable_units.get() {
            return Ok(directory.as_ref().map(|directory| directory.matching(pc)));
        }
        let directory = self.build_variable_units(dwarf, deadline)?;
        let directory = self.variable_units.get_or_init(|| directory);
        Ok(directory.as_ref().map(|directory| directory.matching(pc)))
    }

    fn build_variable_units(
        &self,
        dwarf: &Dwarf<Reader<'_>>,
        deadline: Instant,
    ) -> Result<Option<UnitDirectory>> {
        const MAX_SPANS: usize = MAX_COVERAGE_UNITS * 8;
        let mut directory = UnitDirectory::default();
        let mut headers = dwarf.units();
        let mut count = 0;
        while let Some(header) = headers.next()? {
            if Instant::now() >= deadline {
                return Err(error("DWARF unit directory deadline reached"));
            }
            count += 1;
            if count > MAX_COVERAGE_UNITS {
                return Ok(None);
            }
            let Some(id) = gimli::UnitOffset(0).to_debug_info_offset(&header) else {
                return Ok(None);
            };
            let start = directory.spans.len();
            if let Some(ranges) = get(&self.coverage, id) {
                directory
                    .spans
                    .extend(ranges.iter().map(|range| (*range, id)));
            } else {
                let unit = dwarf.unit(header)?;
                let mut ranges = dwarf.unit_ranges(&unit)?;
                while let Some(range) = ranges.next()? {
                    if directory.spans.len() >= MAX_SPANS {
                        return Ok(None);
                    }
                    directory.spans.push((range, id));
                }
            }
            if directory.spans.len() > MAX_SPANS {
                return Ok(None);
            }
            if directory.spans.len() == start {
                directory.unknown.push(id);
            }
        }
        directory
            .spans
            .sort_unstable_by_key(|(range, _)| range.begin);
        let mut max = 0;
        directory
            .max_ends
            .extend(directory.spans.iter().map(|(range, _)| {
                max = max.max(range.end);
                max
            }));
        Ok(Some(directory))
    }
}

fn matches_pc(ranges: &[gimli::Range], pc: u64) -> bool {
    ranges.is_empty()
        || ranges
            .iter()
            .any(|range| (range.begin..range.end).contains(&pc))
}

struct LineRow {
    address: u64,
    file: usize,
    line: Option<u64>,
    column: Option<u64>,
}

struct LineSequence {
    start: u64,
    end: u64,
    rows: Vec<LineRow>,
}

#[derive(Default)]
struct Lines {
    sequences: Vec<LineSequence>,
    files: Vec<PathBuf>,
}

impl Lines {
    fn load(dwarf: &Dwarf<Reader<'_>>, unit: &Unit<Reader<'_>>) -> Result<Option<Self>> {
        let Some(program) = unit.line_program.clone() else {
            return Ok(Some(Self::default()));
        };
        let mut result = Self::default();
        let mut filenames = BTreeMap::new();
        let mut rows = program.rows();
        let mut sequence = Vec::new();
        let mut start = None;
        let mut previous = 0;
        let mut total = 0;
        let mut path_bytes = 0;
        while let Some((header, row)) = rows.next_row()? {
            total += 1;
            if total > MAX_ROWS {
                return Ok(None);
            }
            let address = row.address();
            if row.end_sequence() {
                if let Some(start) = start.take() {
                    result.sequences.push(LineSequence {
                        start,
                        end: address,
                        rows: std::mem::take(&mut sequence),
                    });
                }
                continue;
            }
            if start.is_some() && address < previous {
                // The original lookup stops at the first row beyond the PC.
                return Ok(None);
            }
            start.get_or_insert(address);
            previous = address;
            let Some(file) = row.file(header) else {
                continue;
            };
            let file = if let Some(&index) = filenames.get(&row.file_index()) {
                index
            } else {
                let path = super::super::source_path(dwarf, unit, header, file)?;
                path_bytes += path.as_os_str().len();
                if path_bytes > 128 * 1024 {
                    return Ok(None);
                }
                let index = result.files.len();
                result.files.push(path);
                filenames.insert(row.file_index(), index);
                index
            };
            sequence.push(LineRow {
                address,
                file,
                line: row.line().map(|n| n.get()),
                column: match row.column() {
                    gimli::ColumnType::LeftEdge => None,
                    gimli::ColumnType::Column(n) => Some(n.get()),
                },
            });
        }
        Ok(Some(result))
    }

    fn find(&self, pc: u64) -> Option<Line> {
        self.sequences
            .iter()
            .filter(|seq| (seq.start..seq.end).contains(&pc))
            .find_map(|seq| {
                let end = seq.rows.partition_point(|row| row.address <= pc);
                let row = seq.rows.get(end.checked_sub(1)?)?;
                Some(Line {
                    file: self.files[row.file].clone(),
                    line: row.line,
                    column: row.column,
                    source: None,
                })
            })
    }
}

struct InlineRange {
    entry: Offset,
    end: usize,
    ranges: Vec<gimli::Range>,
}

fn inline_ranges(
    dwarf: &Dwarf<Reader<'_>>,
    unit: &Unit<Reader<'_>>,
    budget: &mut ScanBudget,
) -> Result<Option<Vec<InlineRange>>> {
    let mut nodes: Vec<InlineRange> = Vec::new();
    let mut open = Vec::new();
    let mut entries = unit.entries();
    let mut items = 0;
    while let Some(entry) = entries.next_dfs()? {
        budget.entry()?;
        while open
            .last()
            .is_some_and(|&(depth, _)| depth >= entry.depth())
        {
            let (_, index): (_, usize) = open.pop().unwrap();
            let end = nodes.len();
            nodes[index].end = end;
        }
        if entry.tag() != gimli::DW_TAG_inlined_subroutine {
            continue;
        }
        let mut ranges = dwarf.die_ranges(unit, entry)?;
        let mut spans = Vec::new();
        items += 1;
        while let Some(range) = ranges.next()? {
            items += 1;
            if items > MAX_INLINE_ITEMS {
                return Ok(None);
            }
            spans.push(range);
        }
        if items > MAX_INLINE_ITEMS {
            return Ok(None);
        }
        open.push((entry.depth(), nodes.len()));
        nodes.push(InlineRange {
            entry: entry.offset(),
            end: usize::MAX,
            ranges: spans,
        });
    }
    Ok(Some(nodes))
}

fn inline_chain(nodes: &[InlineRange], pc: u64, budget: &mut ScanBudget) -> Result<Vec<Offset>> {
    let mut active = Vec::new();
    let mut best = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        budget.entry()?;
        active.retain(|&(end, _)| end > index);
        if node
            .ranges
            .iter()
            .any(|range| (range.begin..range.end).contains(&pc))
        {
            active.push((node.end, node.entry));
            if active.len() > best.len() {
                best = active.iter().rev().map(|&(_, entry)| entry).collect();
            }
        }
    }
    Ok(best)
}

impl Sources {
    pub fn line(&self, dwarf: &Dwarf<Reader<'_>>, pc: u64) -> Result<Option<Line>> {
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let Some(id) = gimli::UnitOffset(0).to_debug_info_offset(&header) else {
                return super::super::line_for_pc(dwarf, pc);
            };
            let coverage = get(&self.coverage, id);
            if coverage
                .as_ref()
                .is_some_and(|ranges| !matches_pc(ranges, pc))
            {
                continue;
            }
            let unit = dwarf.unit(header)?;
            if unit.line_program.is_none() {
                continue;
            }
            if coverage.is_none() && !self.remember_coverage(dwarf, &unit, id, pc)? {
                continue;
            }
            let lines = match get(&self.lines, id) {
                Some(lines) => lines,
                None => match Lines::load(dwarf, &unit) {
                    Ok(Some(lines)) => insert(&self.lines, id, lines),
                    _ => return super::super::line_for_pc(dwarf, pc),
                },
            };
            if let Some(line) = lines.find(pc) {
                return Ok(Some(line));
            }
        }
        Ok(None)
    }

    pub fn inline(
        &self,
        dwarf: &Dwarf<Reader<'_>>,
        pc: u64,
        deadline: Instant,
    ) -> Result<Vec<InlineFrame>> {
        let mut units = dwarf.units();
        let mut budget = ScanBudget::foreground(deadline);
        while let Some(header) = units.next()? {
            budget.entry()?;
            let Some(id) = gimli::UnitOffset(0).to_debug_info_offset(&header) else {
                return super::inline_frames(dwarf, pc, deadline);
            };
            let coverage = get(&self.coverage, id);
            if coverage
                .as_ref()
                .is_some_and(|ranges| !matches_pc(ranges, pc))
            {
                continue;
            }
            let unit = dwarf.unit(header)?;
            if coverage.is_none() && !self.remember_coverage(dwarf, &unit, id, pc)? {
                continue;
            }
            let nodes = match get(&self.inline, id) {
                Some(nodes) => nodes,
                None => match inline_ranges(dwarf, &unit, &mut budget)? {
                    Some(nodes) => insert(&self.inline, id, nodes),
                    None => return super::inline_frames(dwarf, pc, deadline),
                },
            };
            let chain = inline_chain(&nodes, pc, &mut budget)?;
            if !chain.is_empty() {
                return chain
                    .into_iter()
                    .map(|offset| {
                        let entry = unit.entry(offset)?;
                        super::inline_frame(dwarf, &unit, &entry)
                    })
                    .collect();
            }
        }
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_unit_lookup_preserves_overlaps_gaps_and_unknown_coverage() {
        let id = gimli::DebugInfoOffset;
        let range = |begin, end, offset| (gimli::Range { begin, end }, id(offset));
        let directory = UnitDirectory {
            spans: vec![
                range(10, 30, 40),
                range(12, 15, 20),
                range(13, 18, 40),
                range(35, 40, 50),
            ],
            max_ends: vec![30, 30, 30, 40],
            unknown: vec![id(25)],
        };
        assert_eq!(directory.matching(13), [id(20), id(25), id(40)]);
        assert_eq!(directory.matching(15), [id(25), id(40)]);
        assert_eq!(directory.matching(29), [id(25), id(40)]);
        assert_eq!(directory.matching(30), [id(25)]);
        assert_eq!(directory.matching(35), [id(25), id(50)]);
        assert_eq!(directory.matching(40), [id(25)]);
    }

    #[test]
    fn line_sequences_keep_gaps_and_the_last_row_at_a_shared_address() {
        let row = |address, line| LineRow {
            address,
            file: 0,
            line: Some(line),
            column: None,
        };
        let lines = Lines {
            files: vec![PathBuf::from("fixture.c")],
            sequences: vec![
                LineSequence {
                    start: 4,
                    end: 8,
                    rows: vec![row(4, 1), row(4, 2), row(6, 3)],
                },
                LineSequence {
                    start: 10,
                    end: 12,
                    rows: vec![row(10, 4)],
                },
            ],
        };
        assert_eq!(lines.find(4).unwrap().line, Some(2));
        assert_eq!(lines.find(7).unwrap().line, Some(3));
        assert!(lines.find(8).is_none());
        assert_eq!(lines.find(11).unwrap().line, Some(4));
    }

    #[test]
    fn inline_lookup_respects_nesting_and_keeps_the_first_equal_chain() -> Result<()> {
        let node = |entry, end, begin, limit| InlineRange {
            entry: gimli::UnitOffset(entry),
            end,
            ranges: vec![gimli::Range { begin, end: limit }],
        };
        let nodes = [
            node(10, 4, 10, 30),
            node(20, 3, 16, 20),
            node(21, 3, 17, 19),
            node(30, 4, 16, 20),
        ];
        let mut budget = ScanBudget::foreground(Instant::now() + Duration::from_secs(1));
        assert_eq!(
            inline_chain(&nodes, 17, &mut budget)?,
            [
                gimli::UnitOffset(21),
                gimli::UnitOffset(20),
                gimli::UnitOffset(10)
            ]
        );
        assert_eq!(
            inline_chain(&nodes, 16, &mut budget)?,
            [gimli::UnitOffset(20), gimli::UnitOffset(10)]
        );
        assert!(inline_chain(&nodes, 30, &mut budget)?.is_empty());
        Ok(())
    }
}
