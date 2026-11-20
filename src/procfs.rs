use crate::{Result, error};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default, Serialize)]
pub struct Signals {
    pub thread_pending: Option<String>,
    pub shared_pending: Option<String>,
    pub blocked: Option<String>,
    pub ignored: Option<String>,
    pub caught: Option<String>,
}

#[derive(Default, Serialize)]
pub struct Memory {
    pub rss_bytes: Option<u64>,
    pub peak_rss_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub source: &'static str,
}

pub struct Status(String);

impl Status {
    pub fn read(base: &Path) -> Result<Self> {
        Ok(Self(
            String::from_utf8_lossy(&fs::read(base.join("status"))?).into_owned(),
        ))
    }

    pub fn field(&self, name: &str) -> Option<&str> {
        self.0.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key == name).then(|| value.trim())
        })
    }

    pub fn name(&self) -> Option<String> {
        self.field("Name").map(str::to_owned)
    }

    pub fn state(&self) -> Option<String> {
        self.field("State")
            .and_then(|s| s.split_whitespace().next())
            .map(str::to_owned)
    }

    pub fn signals(&self) -> Signals {
        let mask = |key| self.field(key).map(|m| format!("0x{m}"));
        Signals {
            thread_pending: mask("SigPnd"),
            shared_pending: mask("ShdPnd"),
            blocked: mask("SigBlk"),
            ignored: mask("SigIgn"),
            caught: mask("SigCgt"),
        }
    }

    pub fn memory(&self) -> Memory {
        let bytes = |key| {
            let mut parts = self.field(key)?.split_whitespace();
            let kib = parts.next()?.parse::<u64>().ok()?;
            (parts.next()? == "kB").then_some(())?;
            kib.checked_mul(1024)
        };
        Memory {
            rss_bytes: bytes("VmRSS"),
            peak_rss_bytes: bytes("VmHWM"),
            virtual_bytes: bytes("VmSize"),
            source: "proc_status",
        }
    }
}

pub fn start_ticks(base: &Path) -> Result<u64> {
    let bytes = fs::read(base.join("stat"))?;
    let stat = String::from_utf8_lossy(&bytes);
    // comm is in parentheses and may itself contain spaces and ')' characters.
    let (_, rest) = stat
        .rsplit_once(')')
        .ok_or_else(|| error("invalid proc stat"))?;
    Ok(rest
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| error("missing proc stat starttime"))?
        .parse()?)
}

pub fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn task_ids(base: &Path) -> Result<Vec<i32>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(base.join("task"))? {
        let entry = entry?;
        if let Ok(id) = entry.file_name().to_string_lossy().parse::<i32>() {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

pub fn task_path(base: &Path, tid: i32) -> std::path::PathBuf {
    base.join("task").join(tid.to_string())
}
