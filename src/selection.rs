use crate::{Result, error, rpc::Selection};
use serde_json::Value;

// These fields describe the capture even when the caller requests only a leaf.
const ENVELOPE: &[&str] = &[
    "schema_version",
    "snapshot_id",
    "status",
    "freeze_requested",
    "freeze_achieved",
    "started_unix_ms",
    "capture_finished_unix_ms",
    "trace_window_ms",
    "all_threads_stopped_during_capture",
];

const ROOTS: &[&str] = &[
    "process", "memory", "modules", "threads", "issues", "cleanup",
];

#[derive(Default)]
struct Projection {
    all: bool,
    children: std::collections::BTreeMap<String, Projection>,
}

impl Projection {
    fn insert(&mut self, parts: &[&str]) {
        if self.all {
            return;
        }
        if let Some((first, rest)) = parts.split_first() {
            self.children
                .entry((*first).into())
                .or_default()
                .insert(rest);
        } else {
            self.all = true;
            self.children.clear();
        }
    }

    fn apply(&self, value: &Value) -> Value {
        if self.all || value.is_null() {
            return value.clone();
        }
        match value {
            Value::Object(obj) => Value::Object(
                self.children
                    .iter()
                    .filter_map(|(k, p)| obj.get(k).map(|v| (k.clone(), p.apply(v))))
                    .collect(),
            ),
            Value::Array(rows) => Value::Array(rows.iter().map(|v| self.apply(v)).collect()),
            _ => Value::Null,
        }
    }
}

pub struct Filter {
    projection: Option<Projection>,
    tid: Option<i32>,
    frames: Option<usize>,
}

impl Filter {
    pub fn parse(selection: Option<Selection>) -> Result<Self> {
        let selection = selection.unwrap_or_default();
        if selection.fields.len() > 64 {
            return Err(error("at most 64 fields can be selected"));
        }
        if selection.tid.is_some_and(|tid| tid <= 0) {
            return Err(error("tid must be positive"));
        }
        if selection.frames.is_some_and(|n| n > 32) {
            return Err(error("frames must be in 0..=32"));
        }
        let projection = if selection.fields.is_empty() {
            None
        } else {
            let mut p = Projection::default();
            for path in selection.fields {
                let parts: Vec<_> = path.split('.').collect();
                if parts.len() > 12
                    || parts.iter().any(|part| {
                        part.is_empty()
                            || part.len() > 64
                            || !part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    })
                {
                    return Err(error(format!("invalid selection path {path:?}")));
                }
                if !ROOTS.contains(&parts[0]) && !ENVELOPE.contains(&parts[0]) {
                    return Err(error(format!("unknown selection root {:?}", parts[0])));
                }
                p.insert(&parts);
            }
            for field in ENVELOPE {
                p.insert(&[field]);
            }
            Some(p)
        };
        Ok(Self {
            projection,
            tid: selection.tid,
            frames: selection.frames.map(|n| n as usize),
        })
    }

    pub fn apply(&self, mut doc: Value) -> Value {
        if let Some(threads) = doc.get_mut("threads").and_then(Value::as_array_mut) {
            if let Some(tid) = self.tid {
                threads.retain(|t| t["tid"].as_i64() == Some(i64::from(tid)));
            }
            if let Some(n) = self.frames {
                for thread in threads {
                    if let Some(stack) = thread.get_mut("stack").and_then(Value::as_object_mut)
                        && let Some(frames) = stack.get_mut("frames").and_then(Value::as_array_mut)
                        && frames.len() > n
                    {
                        frames.truncate(n);
                        stack.insert("frames_filtered".into(), Value::Bool(true));
                    }
                }
            }
        }
        if let Some(projection) = &self.projection {
            let mut value = projection.apply(&doc);
            // Preserve the identity of every projected thread.
            if let Some(threads) = value.get_mut("threads").and_then(Value::as_array_mut)
                && let Some(original) = doc.get("threads").and_then(Value::as_array)
            {
                for (out, src) in threads.iter_mut().zip(original) {
                    if let Some(out) = out.as_object_mut() {
                        out.entry("tid").or_insert_with(|| src["tid"].clone());
                        if src["stack"]["frames_filtered"] == true
                            && let Some(stack) = out.get_mut("stack").and_then(Value::as_object_mut)
                            && stack.contains_key("frames")
                        {
                            stack.insert("frames_filtered".into(), Value::Bool(true));
                        }
                    }
                }
            }
            value
        } else {
            doc
        }
    }
}

pub fn with_id(doc: &mut Value, id: &str) {
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("snapshot_id".into(), Value::String(id.into()));
    }
}

pub fn requested(fields: Vec<String>, tid: Option<i32>, frames: Option<u32>) -> Option<Selection> {
    (!fields.is_empty() || tid.is_some() || frames.is_some()).then_some(Selection {
        fields,
        tid,
        frames,
    })
}
