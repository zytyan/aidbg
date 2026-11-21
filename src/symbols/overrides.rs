use super::*;
use serde::Deserialize;
use std::io::Write;
use std::sync::{Mutex, MutexGuard};

const MAX_RULES: usize = 256;
const MAX_STORE: u64 = 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
enum Identity {
    BuildId {
        build_id: String,
    },
    Session {
        pid: i32,
        start_ticks: u64,
        module: ModuleIdentity,
        instance: u64,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Rule {
    id: String,
    name: String,
    offset: u64,
    length: u64,
    #[serde(flatten)]
    identity: Identity,
}

impl Rule {
    fn valid(&self) -> bool {
        self.id.len() == 32
            && self.id.bytes().all(|byte| byte.is_ascii_hexdigit())
            && valid_name(&self.name)
            && self.length != 0
            && self.offset.checked_add(self.length).is_some()
    }

    pub(super) fn matches(
        &self,
        pid: i32,
        start_ticks: Option<u64>,
        module: &ModuleIdentity,
        instance: u64,
    ) -> bool {
        match &self.identity {
            Identity::BuildId { build_id } => module.build_id.as_ref() == Some(build_id),
            Identity::Session {
                pid: owner,
                start_ticks: start,
                module: source,
                instance: base,
            } => {
                pid == *owner
                    && start_ticks == Some(*start)
                    && module == source
                    && instance == *base
            }
        }
    }

    pub(super) fn covers(&self, offset: u64) -> bool {
        offset
            .checked_sub(self.offset)
            .is_some_and(|delta| delta < self.length)
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn offset(&self) -> u64 {
        self.offset
    }

    pub(super) fn symbol(&self, elf_address: u64, executable: bool) -> Symbol {
        Symbol {
            names: crate::cpp_names::names(&self.name),
            name: self.name.clone(),
            elf_address: hex(elf_address),
            size: self.length,
            kind: if executable { "text" } else { "data" }.into(),
            binding: "local",
            visibility: "default",
            elf_type: if executable { 2 } else { 1 },
            sources: vec![Source {
                table: "aidbg_override",
                debug_file: None,
            }],
        }
    }
}

pub struct Overrides {
    file: PathBuf,
    session: Mutex<Vec<Rule>>,
}

fn valid_name(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 512 && !name.chars().any(char::is_control)
}

impl Overrides {
    pub fn open(state_dir: &Path) -> Result<Self> {
        let store = Self {
            file: state_dir.join("symbol-overrides.json"),
            session: Mutex::new(Vec::new()),
        };
        store.persistent()?;
        Ok(store)
    }

    fn persistent(&self) -> Result<Vec<Rule>> {
        Ok(match File::open(&self.file) {
            Ok(f) => {
                let mut bytes = Vec::new();
                f.take(MAX_STORE + 1).read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_STORE {
                    return Err(error("symbol override store exceeds size limit"));
                }
                let rules: Vec<Rule> = serde_json::from_slice(&bytes)?;
                if rules.len() > MAX_RULES || rules.iter().any(|rule| {
                    !rule.valid() || !matches!(&rule.identity, Identity::BuildId { build_id }
                        if !build_id.is_empty() && build_id.len() <= 128 && may_be_build_id(build_id))
                }) {
                    return Err(error("invalid persistent symbol override"));
                }
                for (index, rule) in rules.iter().enumerate() {
                    if rules[..index]
                        .iter()
                        .any(|other| other.id == rule.id || overlaps(other, rule))
                    {
                        return Err(error("overlap or duplicate ID in symbol override store"));
                    }
                }
                rules
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Vec<Rule>>> {
        self.session
            .lock()
            .map_err(|_| error("symbol override store lock poisoned"))
    }

    fn lock_persistent(&self) -> Result<File> {
        // The separate lock inode remains stable across atomic store replacement.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.file.with_extension("lock"))?;
        file.lock()?;
        Ok(file)
    }

    pub fn list(&self) -> Result<Vec<Rule>> {
        let session = self.lock()?;
        let mut rules = self.persistent()?;
        rules.extend(session.iter().cloned());
        Ok(rules)
    }

    fn save(&self, rules: &[Rule]) -> Result<()> {
        let parent = self
            .file
            .parent()
            .ok_or_else(|| error("missing symbol override state directory"))?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(&mut file, rules)?;
        file.write_all(b"\n")?;
        file.as_file().sync_all()?;
        file.persist(&self.file)?;
        Ok(())
    }

    pub fn set(&self, pid: i32, address: u64, length: u64, name: String) -> Result<Rule> {
        if !valid_name(&name) || length == 0 {
            return Err(error(
                "expected a nonempty symbol name of up to 512 bytes and a nonzero length",
            ));
        }
        let last = address
            .checked_add(length - 1)
            .ok_or_else(|| error("override range overflows"))?;
        let process = Process::open(pid)?;
        let (module, map) = process
            .modules
            .iter()
            .find_map(|module| module.mapping_at(address).map(|map| (module, map)))
            .ok_or_else(|| error("override must begin in a file-backed module mapping"))?;
        if !map.contains(last) {
            return Err(error("override must fit in one loaded module mapping"));
        }
        let bytes = module.read_image(&process.root, process.exe.as_ref(), IMAGE_LIMIT)?;
        let image = object::File::parse(&*bytes)?;
        let layout = Layout::new(&image, module)?;
        let (instance, link) = layout
            .for_address(map, address)
            .ok_or_else(|| error("no ELF segment for override"))?;
        if !layout
            .for_address(map, last)
            .is_some_and(|(end_instance, end)| {
                end_instance.base == instance.base && end.checked_sub(link) == Some(length - 1)
            })
        {
            return Err(error("override must fit in one loaded ELF segment"));
        }
        let offset = link
            .checked_sub(layout.elf_base)
            .ok_or_else(|| error("invalid module offset"))?;
        let identity = if let Some(id) = image.build_id()?.filter(|id| (1..=64).contains(&id.len()))
        {
            Identity::BuildId {
                build_id: id_hex(id),
            }
        } else {
            Identity::Session {
                pid,
                start_ticks: crate::procfs::start_ticks(&process.root)?,
                module: module.identity(None),
                instance: instance.base,
            }
        };
        let mut random = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let rule = Rule {
            id: id_hex(&random),
            name,
            length,
            offset,
            identity,
        };
        if !rule.valid() {
            return Err(error("invalid symbol override range"));
        }
        if matches!(rule.identity, Identity::BuildId { .. }) {
            let _lock = self.lock_persistent()?;
            let mut rules = self.persistent()?;
            insert(&mut rules, &rule)?;
            self.save(&rules)?;
        } else {
            let mut session = self.lock()?;
            insert(&mut session, &rule)?;
        }
        Ok(rule)
    }

    pub fn remove(&self, id: &str) -> Result<Rule> {
        {
            let mut session = self.lock()?;
            if let Some(index) = session.iter().position(|rule| rule.id == id) {
                return Ok(session.remove(index));
            }
        }
        let _lock = self.lock_persistent()?;
        let mut rules = self.persistent()?;
        let index = rules
            .iter()
            .position(|rule| rule.id == id)
            .ok_or_else(|| error("symbol override ID not found"))?;
        let removed = rules.remove(index);
        self.save(&rules)?;
        Ok(removed)
    }
}

fn insert(rules: &mut Vec<Rule>, rule: &Rule) -> Result<()> {
    if rules.len() >= MAX_RULES {
        return Err(error("symbol override limit reached"));
    }
    if rules.iter().any(|other| overlaps(other, rule)) {
        return Err(error("symbol override overlaps an existing rule"));
    }
    rules.push(rule.clone());
    Ok(())
}

fn overlaps(a: &Rule, b: &Rule) -> bool {
    a.identity == b.identity && (a.covers(b.offset) || b.covers(a.offset))
}
