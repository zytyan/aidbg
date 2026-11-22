use super::{Callback, Command, Control, Engine, ExportModule, Limits};
use crate::Result;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU8, AtomicU64, Ordering},
    mpsc,
};
use std::{collections::BTreeMap, rc::Rc};

struct RuleIdentity {
    pub id: u64,
    hits: AtomicU64,
    attachments: Mutex<Vec<Weak<Attachment>>>,
}

#[derive(Clone)]
pub struct CallbackSource {
    identity: Arc<RuleIdentity>,
    revision: u64,
    js: Arc<str>,
    source: Arc<str>,
    export: Option<String>,
    exports: bool,
}

struct Attachment {
    id: u64,
    sender: Weak<mpsc::SyncSender<Command>>,
}

const PREPARING: u8 = 0;
const COMMITTED: u8 = 1;
const ABORTED: u8 = 2;

pub(super) struct Update {
    revision: u64,
    js: Arc<str>,
    source: Arc<str>,
    state: AtomicU8,
}

pub(super) struct AttachedCallback {
    registration: Option<(Arc<RuleIdentity>, Arc<Attachment>)>,
    export: Option<String>,
    revision: u64,
    pub runtime: Callback,
    revision_offset: u64,
    source: Option<Arc<str>>,
    budget_ms: u32,
    staged: Option<(Arc<Update>, Callback)>,
}

impl CallbackSource {
    pub fn new(id: u64, js: String, source: String) -> Self {
        Self {
            identity: Arc::new(RuleIdentity {
                id,
                hits: AtomicU64::new(0),
                attachments: Mutex::default(),
            }),
            revision: 1,
            js: js.into(),
            source: source.into(),
            export: None,
            exports: false,
        }
    }

    pub fn new_exports(id: u64, js: String, source: String) -> Self {
        Self {
            exports: true,
            ..Self::new(id, js, source)
        }
    }

    pub fn select(&self, name: String) -> Self {
        Self {
            export: Some(name),
            ..self.clone()
        }
    }

    pub fn exports(&self) -> bool {
        self.exports
    }

    pub fn validate_exports(js: &str) -> Result<Vec<String>> {
        let module = ExportModule::load(Engine::new()?, js)?;
        Ok(module.names().map(str::to_owned).collect())
    }

    pub fn validate(js: &str) -> Result<()> {
        Callback::load(js, 500).map(drop)
    }

    pub fn id(&self) -> u64 {
        self.identity.id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn hits(&self) -> u64 {
        self.identity.hits.load(Ordering::Relaxed)
    }

    pub fn in_use(&self) -> bool {
        let mut attachments = self.identity.attachments.lock().unwrap();
        attachments.retain(|attachment| attachment.strong_count() != 0);
        !attachments.is_empty()
    }

    // The service serializes installs, updates and removals. Worker exits
    // can still remove attachments while a new revision is being prepared.
    pub fn update(&mut self, js: String, source: String) -> Result<()> {
        let update = Arc::new(Update {
            revision: self.revision + 1,
            js: js.into(),
            source: source.into(),
            state: AtomicU8::new(PREPARING),
        });
        let mut attachments = self.identity.attachments.lock().unwrap();
        attachments.retain(|attachment| attachment.strong_count() != 0);
        // Release the lock before sending commands to tracer threads.
        let live = attachments.clone();
        drop(attachments);

        for weak in live {
            let Some(attachment) = weak.upgrade() else {
                continue;
            };
            let id = attachment.id;
            let sender = attachment.sender.upgrade();
            // The worker's only strong reference determines attachment lifetime.
            drop(attachment);
            if let Some(sender) = sender {
                if let Err(issue) = Control(sender).stage_rule(id, Arc::clone(&update)) {
                    if weak.strong_count() != 0 {
                        update.state.store(ABORTED, Ordering::Release);
                        return Err(issue);
                    }
                }
            }
        }
        self.revision = update.revision;
        self.js = Arc::clone(&update.js);
        self.source = Arc::clone(&update.source);
        update.state.store(COMMITTED, Ordering::Release);
        Ok(())
    }

    pub(super) fn attach(
        self,
        id: u64,
        sender: Weak<mpsc::SyncSender<Command>>,
        budget_ms: u32,
        load_export: impl FnOnce(ExportRequest<'_>) -> Result<Callback>,
    ) -> Result<AttachedCallback> {
        let runtime = match self.export.as_deref() {
            Some(name) => load_export(ExportRequest {
                owner: &self.identity,
                revision: self.revision,
                name,
                js: &self.js,
                budget_ms,
                update: None,
            })?,
            None => Callback::load(&self.js, budget_ms)?,
        };
        let attachment = Arc::new(Attachment { id, sender });
        let mut attachments = self.identity.attachments.lock().unwrap();
        attachments.retain(|attachment| attachment.strong_count() != 0);
        attachments.push(Arc::downgrade(&attachment));
        drop(attachments);
        Ok(AttachedCallback {
            registration: Some((self.identity, attachment)),
            export: self.export,
            revision: self.revision,
            revision_offset: 0,
            source: Some(self.source),
            runtime,
            budget_ms,
            staged: None,
        })
    }
}

pub(super) struct ExportRequest<'a> {
    owner: &'a Arc<RuleIdentity>,
    revision: u64,
    name: &'a str,
    js: &'a str,
    budget_ms: u32,
    update: Option<&'a Arc<Update>>,
}

struct CachedModule {
    owner: Weak<RuleIdentity>,
    module: ExportModule,
    update: Option<Arc<Update>>,
}

#[derive(Default)]
pub(super) struct ExportCache(BTreeMap<(u64, u64), CachedModule>);

impl ExportCache {
    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn prune(&mut self) {
        self.0.retain(|_, item| {
            item.owner.strong_count() != 0
                && item
                    .update
                    .as_ref()
                    .is_none_or(|update| update.state.load(Ordering::Acquire) != ABORTED)
        });
    }

    pub fn callback(&mut self, engine: Rc<Engine>, request: ExportRequest<'_>) -> Result<Callback> {
        let id = request.owner.id;
        if request.update.is_none() {
            self.0
                .retain(|&(owner, revision), _| owner != id || revision >= request.revision);
        }
        let module = match self.0.entry((id, request.revision)) {
            std::collections::btree_map::Entry::Occupied(entry) => &entry.into_mut().module,
            std::collections::btree_map::Entry::Vacant(entry) => {
                let module = ExportModule::load(engine, request.js)?;
                module.handler(request.name)?;
                &entry
                    .insert(CachedModule {
                        owner: Arc::downgrade(request.owner),
                        module,
                        update: request.update.cloned(),
                    })
                    .module
            }
        };
        Ok(Callback::new(
            module.handler(request.name)?,
            Rc::clone(&module.realm),
            Limits {
                max_hits: None,
                pause_budget_ms: request.budget_ms,
            },
        ))
    }

    pub fn remove(&mut self, key: (u64, u64)) {
        self.0.remove(&key);
    }
}

impl AttachedCallback {
    pub fn inline(runtime: Callback) -> Self {
        Self {
            registration: None,
            revision: 0,
            revision_offset: 0,
            source: None,
            export: None,
            budget_ms: runtime.limits.pause_budget_ms,
            runtime,
            staged: None,
        }
    }

    pub fn version(&self) -> Option<(u64, u64)> {
        self.registration
            .as_ref()
            .map(|(rule, _)| (rule.id, self.revision.saturating_add(self.revision_offset)))
    }

    pub fn follow_revision(&mut self, previous: u64) {
        let next = previous.saturating_add(1);
        self.revision_offset = self.revision_offset.max(next.saturating_sub(self.revision));
    }

    pub fn replay_source(&self) -> Option<(&str, Option<&str>)> {
        self.source
            .as_deref()
            .map(|source| (source, self.export.as_deref()))
    }

    pub fn count_hit(&self) {
        if let Some((identity, _)) = &self.registration {
            identity.hits.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn stage(
        &mut self,
        update: Arc<Update>,
        load_export: impl FnOnce(ExportRequest<'_>) -> Result<Callback>,
    ) -> Result<()> {
        let runtime = if let Some(name) = &self.export {
            let (owner, _) = self.registration.as_ref().expect("registered export");
            load_export(ExportRequest {
                owner,
                revision: update.revision,
                name,
                js: &update.js,
                budget_ms: self.budget_ms,
                update: Some(&update),
            })?
        } else {
            Callback::load(&update.js, self.budget_ms)?
        };
        self.staged = Some((update, runtime));
        Ok(())
    }

    pub fn refresh(&mut self, batch: &mut BTreeMap<u64, u8>) -> Option<(u64, u64)> {
        let (update, _) = self.staged.as_ref()?;
        let (id, _) = self.version().expect("registered version");
        let revision = self.revision;
        let state = *batch
            .entry(id)
            .or_insert_with(|| update.state.load(Ordering::Acquire));
        match state {
            COMMITTED => {
                let (update, runtime) = self.staged.take().unwrap();
                if !self.runtime.exhausted() {
                    self.revision = update.revision;
                    self.source = Some(Arc::clone(&update.source));
                    if self.export.is_some() {
                        self.runtime.replace_handler(runtime);
                    } else {
                        self.runtime = runtime;
                    }
                }
                self.export.as_ref().map(|_| (id, revision))
            }
            ABORTED => {
                let (update, _) = self.staged.take().unwrap();
                self.export.as_ref().map(|_| (id, update.revision))
            }
            _ => None,
        }
    }
}
