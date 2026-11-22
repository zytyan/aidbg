use crate::{Result, error, rpc::CoreMode};
use sha2::{Digest, Sha256};
use std::io::Read;

#[cfg(target_os = "linux")]
pub(super) const MIB: usize = 1024 * 1024;

pub const DEFAULT_TIMEOUT_MS: u32 = 60_000;

pub fn valid_dump_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

pub fn hash_reader(mut reader: impl Read, hash: &mut Sha256) -> std::io::Result<u64> {
    let mut buffer = vec![0; 256 * 1024];
    let mut bytes = 0;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            return Ok(bytes);
        }
        hash.update(&buffer[..n]);
        bytes += n as u64;
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct CaptureOptions {
    pub(super) timeout_ms: u32,
    pub(super) buffer_mib: u32,
    pub(super) block_bytes: usize,
    pub(super) expected_start_ticks: Option<u64>,
}

impl CaptureOptions {
    pub fn new(
        mode: CoreMode,
        timeout_ms: u32,
        buffer_mib: Option<u32>,
        block_kib: Option<u32>,
    ) -> Result<Self> {
        let default_buffer = match mode {
            CoreMode::CoreLite => 0,
            CoreMode::CoreStack4k => 2,
            _ => 16,
        };
        let buffer_mib = buffer_mib.unwrap_or(default_buffer);
        let block_kib = block_kib.unwrap_or(1024);
        if buffer_mib > 64 {
            return Err(error("coredump buffer must be between 0 and 64 MiB"));
        }
        if !(64..=4096).contains(&block_kib) || !block_kib.is_power_of_two() {
            return Err(error(
                "coredump block must be a power of two between 64 and 4096 KiB",
            ));
        }
        Ok(Self {
            timeout_ms,
            buffer_mib,
            block_bytes: block_kib as usize * 1024,
            expected_start_ticks: None,
        })
    }

    pub fn for_process(mut self, start_ticks: u64) -> Self {
        self.expected_start_ticks = Some(start_ticks);
        self
    }
}
