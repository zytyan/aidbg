use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const PAGE_ITEMS: usize = 256;
const PAGE_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
pub(crate) struct Cursor {
    pub module: usize,
    pub instance: usize,
    pub entry: usize,
}

impl Cursor {
    pub fn next_module(&mut self) {
        self.module += 1;
        self.instance = 0;
        self.entry = 0;
    }

    pub fn next_instance(&mut self) {
        self.instance += 1;
        self.entry = 0;
    }
}

pub(crate) fn read(
    object: &object::File<'_>,
    debug: Option<&DebugFile>,
    module: &Path,
    cursor: &mut Cursor,
    address: impl Fn(u64) -> Option<u64>,
) -> Option<Vec<Value>> {
    let parsed = debug.and_then(DebugFile::parse);
    let mut symbols = symbol_entries(object, parsed.as_ref()).skip(cursor.entry);
    let mut rows = Vec::new();
    for _ in 0..PAGE_ENTRIES {
        let Some((symbol, _, _)) = symbols.next() else {
            cursor.next_instance();
            return (!rows.is_empty()).then_some(rows);
        };
        cursor.entry += 1;
        if !has_elf_address(&symbol) {
            continue;
        }
        let (Ok(name), Some(address)) = (symbol.name(), address(symbol.address())) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        rows.push(
            json!({ "name":name, "address":hex(address), "size":symbol.size(), "module":module,
                "kind":format!("{:?}",symbol.kind()).to_ascii_lowercase() }),
        );
        if rows.len() == PAGE_ITEMS {
            break;
        }
    }
    Some(rows)
}

pub(crate) fn live(pid: i32, mut cursor: Cursor) -> Result<(Vec<Value>, Option<Cursor>)> {
    let process = Process::open(pid)?;
    while let Some(module) = process.modules.get(cursor.module) {
        let Ok(bytes) = module.read_image(&process.root, process.exe.as_ref(), IMAGE_LIMIT) else {
            cursor.next_module();
            continue;
        };
        let Ok(image) = object::File::parse(&*bytes) else {
            cursor.next_module();
            continue;
        };
        if !modules::is_executable_module(&image) {
            cursor.next_module();
            continue;
        }
        let layout = Layout::new(&image, module)?;
        let Some(&instance) = layout.instances.get(cursor.instance) else {
            cursor.next_module();
            continue;
        };
        let debug = DebugFile::discover(&process.root, module, &image);
        if let Some(rows) = read(
            &image,
            debug.as_ref(),
            &module.path(),
            &mut cursor,
            |address| layout.runtime(instance, address, module, &process.anonymous),
        ) {
            return Ok((rows, Some(cursor)));
        }
    }
    Ok((Vec::new(), None))
}
