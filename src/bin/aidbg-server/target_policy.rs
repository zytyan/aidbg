use aidbg::{Diagnostic, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowlist {
    allow: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    build_id: String,
    symbol: String,
}

pub(super) struct Policy {
    allow: Option<Allowlist>,
    audit: Mutex<File>,
    next_attempt: AtomicU64,
}

impl Policy {
    pub fn open(state: &Path, path: Option<&Path>) -> Result<Self> {
        let allow = path
            .map(|path| -> Result<_> {
                let allow: Allowlist = serde_json::from_reader(File::open(path)?.take(256 * 1024))?;
                if allow.allow.iter().any(|rule| {
                    rule.build_id.is_empty()
                        || !rule.build_id.len().is_multiple_of(2)
                        || !rule.build_id.bytes().all(|byte| byte.is_ascii_hexdigit())
                        || rule.symbol.is_empty()
                        || rule.symbol.len() > 1024
                }) {
                    return Err(io::Error::other(
                        "invalid build ID or symbol in target_call policy",
                    )
                    .into());
                }
                Ok(allow)
            })
            .transpose()?;
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(state.join("target-call-audit.jsonl"))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { nix::libc::geteuid() }
        {
            return Err(io::Error::other(
                "target_call audit file must be private and owned by the service user",
            )
            .into());
        }
        Ok(Self {
            allow,
            audit: Mutex::new(file),
            next_attempt: AtomicU64::new(1),
        })
    }

    pub fn next_attempt(&self) -> u64 {
        self.next_attempt.fetch_add(1, Ordering::Relaxed)
    }

    pub fn check(&self, build_id: Option<&str>, symbols: &[String]) -> Result<()> {
        if self.allow.as_ref().is_none_or(|allow| {
            allow.allow.iter().any(|rule| {
                build_id.is_some_and(|id| id.eq_ignore_ascii_case(&rule.build_id))
                    && symbols.contains(&rule.symbol)
            })
        }) {
            Ok(())
        } else {
            Err(Diagnostic::new(
                "TARGET_CALL_DENIED",
                "The resolved build ID and function are absent from the target_call allowlist",
                Some("Use a function authorized by the server's target_call policy."),
            )
            .into())
        }
    }

    pub fn record(&self, event: &str, context: &Value, detail: Value) -> Result<()> {
        let mut file = self
            .audit
            .lock()
            .map_err(|_| io::Error::other("target_call audit lock is unavailable"))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let mut line = serde_json::to_vec(&json!({
            "event": event, "unix_ms": now, "context": context, "detail": detail,
        }))?;
        line.push(b'\n');
        file.write_all(&line)?;
        file.sync_data()?;
        Ok(())
    }
}
