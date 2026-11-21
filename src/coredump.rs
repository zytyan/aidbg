mod elf;
mod loader;
mod memory;

use crate::procfs::start_ticks;
use crate::rpc::CoreMode;
use crate::trace::Trace;
use crate::{Result, error};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, Instant};

const MIB: usize = 1024 * 1024;
const COMPRESSION_LEVEL: i32 = 1;
pub const DEFAULT_TIMEOUT_MS: u32 = 60_000;

pub fn valid_dump_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

// An exclusive advisory lock, held for the lifetime of the open descriptor.
pub fn try_lock(file: &File) -> std::io::Result<()> {
    nix::errno::Errno::result(unsafe {
        nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB)
    })
    .map(|_| ())
    .map_err(std::io::Error::from)
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

pub struct CaptureOptions {
    timeout_ms: u32,
    buffer_mib: u32,
    block_bytes: usize,
    expected_start_ticks: Option<u64>,
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

pub fn target_identity(pid: i32) -> Result<u64> {
    start_ticks(&std::path::PathBuf::from(format!("/proc/{pid}")))
}

impl CoreMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::CoreLite => "lite",
            Self::CoreStack4k => "stack-4k",
            Self::CoreStack => "stack",
            Self::CoreStandard => "standard",
            Self::CoreExtended => "extended",
            Self::CoreFull => "full",
        }
    }

    fn includes_data(self) -> bool {
        matches!(self, Self::CoreStandard | Self::CoreExtended)
    }

    fn needs_elf_memory(self) -> bool {
        !matches!(self, Self::CoreLite | Self::CoreFull)
    }
}

#[derive(Default, Serialize)]
struct Coverage {
    missing: Vec<Missing>,
    issues: Vec<String>,
    conservative_shared_mappings: usize,
}

#[derive(Serialize)]
struct Missing {
    start: u64,
    end: u64,
    reason: &'static str,
}

impl Coverage {
    fn missing(&mut self, start: u64, end: u64, reason: &'static str) {
        if let Some(last) = self.missing.last_mut()
            && last.end == start
            && last.reason == reason
        {
            last.end = end;
        } else {
            self.missing.push(Missing { start, end, reason });
        }
    }
}

#[derive(Serialize)]
pub struct Summary {
    pid: i32,
    mode: &'static str,
    status: &'static str,
    threads: usize,
    captured_bytes: u64,
    staged_bytes: u64,
    missing_bytes: u64,
    missing_ranges: usize,
    issues: usize,
    conservative_shared_mappings: usize,
    compressed_bytes: u64,
    pause_ms: u64,
    pause_us: u64,
    timing_us: CaptureTimings,
    buffer_bytes: usize,
    block_bytes: usize,
    image_cache_hits: usize,
    compression_level: i32,
    parallel_compression: bool,
}

#[derive(Default, Serialize)]
struct CaptureTimings {
    preflight: u64,
    freeze: u64,
    maps: u64,
    registers: u64,
    images: u64,
    smaps: u64,
    selection: u64,
    memory_read: u64,
    buffering: u64,
    staging: u64,
    detach: u64,
}

fn micros(start: Instant) -> u64 {
    start.elapsed().as_micros() as u64
}

pub struct Dump {
    pub header: Vec<u8>,
    pub payload: tempfile::NamedTempFile,
    pub summary: Summary,
}

struct CaptureLimit<'a> {
    deadline: Instant,
    cancelled: &'a (dyn Fn() -> bool + Sync),
    expected_start_ticks: Option<u64>,
}

enum CompressionInput {
    Block(Vec<u8>),
    StagedTail(File),
}

impl CaptureLimit<'_> {
    fn check(&self) -> Result<()> {
        if (self.cancelled)() {
            return Err(error("coredump cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(error("coredump capture deadline reached"));
        }
        Ok(())
    }
}

pub fn prepare(
    pid: i32,
    mode: CoreMode,
    options: CaptureOptions,
    state_dir: &Path,
    cancelled: &(dyn Fn() -> bool + Sync),
    after_capture: impl FnOnce(),
) -> Result<Dump> {
    let limit = CaptureLimit {
        deadline: Instant::now() + Duration::from_millis(options.timeout_ms.into()),
        cancelled,
        expected_start_ticks: options.expected_start_ticks,
    };
    let blocks_in_pool = options.buffer_mib as usize * MIB / options.block_bytes;
    let parallel = mode != CoreMode::CoreLite
        && blocks_in_pool >= 2
        && std::thread::available_parallelism().is_ok_and(|n| n.get() >= 2);
    let buffer_bytes = if parallel {
        blocks_in_pool * options.block_bytes
    } else if mode != CoreMode::CoreLite {
        options.block_bytes
    } else {
        0
    };
    let block = || {
        let mut buffer = vec![0; options.block_bytes];
        // Commit the buffer pages before freezing the target.
        std::hint::black_box(&mut buffer[..]).fill(0);
        buffer
    };
    let output = tempfile::NamedTempFile::new_in(state_dir)?;
    let mut staging_us = 0;
    let (capture, mut payload, staged_bytes) = if parallel {
        let mut raw = tempfile::tempfile_in(state_dir)?;
        let mut spilling = false;
        std::thread::scope(|scope| -> Result<_> {
            let (blocks, input) = mpsc::sync_channel(blocks_in_pool);
            let (recycle, available) = mpsc::sync_channel(blocks_in_pool);
            for _ in 1..blocks_in_pool {
                limit.check()?;
                recycle.send(block())?;
            }
            let (ready, initialized) = mpsc::channel();
            let compressor = scope.spawn(move || -> Result<tempfile::NamedTempFile> {
                let mut writer = encoder(BufWriter::with_capacity(256 * 1024, output))?;
                let _ = ready.send(());
                while let Ok(input) = input.recv() {
                    if cancelled() {
                        return Err(error("coredump cancelled"));
                    }
                    match input {
                        CompressionInput::Block(block) => {
                            writer.write_all(&block)?;
                            let _ = recycle.try_send(block);
                        }
                        CompressionInput::StagedTail(raw) => {
                            compress_staged(raw, &mut writer, cancelled)?;
                        }
                    }
                }
                finish(writer)
            });
            initialized
                .recv()
                .map_err(|_| error("coredump compressor could not initialize"))?;
            let capture = capture(
                pid,
                mode,
                &limit,
                block(),
                Some(&mut |block| {
                    limit.check()?;
                    if !spilling {
                        match available.try_recv() {
                            Ok(next) => {
                                blocks.try_send(CompressionInput::Block(block))?;
                                return Ok(next);
                            }
                            Err(TryRecvError::Empty) => {
                                // Reuse the last buffer for the file-staged tail.
                                spilling = true;
                            }
                            Err(TryRecvError::Disconnected) => {
                                return Err(error("coredump compressor stopped"));
                            }
                        }
                    }
                    let started = Instant::now();
                    stage(&mut raw, &block)?;
                    staging_us += micros(started);
                    Ok(block)
                }),
            );
            drop(available);
            after_capture();
            let staged = (|| -> Result<u64> {
                if capture.is_ok() && spilling {
                    let length = seal_stage(&mut raw)?;
                    blocks.send(CompressionInput::StagedTail(raw))?;
                    return Ok(length);
                }
                Ok(0)
            })();
            drop(blocks);
            let payload = compressor
                .join()
                .map_err(|_| error("coredump compressor panicked"))?;
            Ok((capture?, payload?, staged?))
        })?
    } else if mode == CoreMode::CoreLite {
        let capture = capture(pid, mode, &limit, Vec::new(), None);
        after_capture();
        (capture?, output, 0)
    } else {
        let mut raw = tempfile::tempfile_in(state_dir)?;
        let capture = capture(
            pid,
            mode,
            &limit,
            block(),
            Some(&mut |block| {
                let started = Instant::now();
                stage(&mut raw, &block)?;
                staging_us += micros(started);
                Ok(block)
            }),
        );
        after_capture();
        let capture = capture?;
        let length = seal_stage(&mut raw)?;
        let mut writer = encoder(BufWriter::with_capacity(256 * 1024, output))?;
        compress_staged(raw, &mut writer, cancelled)?;
        (capture, finish(writer)?, length)
    };
    if cancelled() {
        return Err(error("coredump cancelled"));
    }
    let mut capture = capture;
    capture.timings.staging = staging_us;
    let mut writer = encoder(Vec::new())?;
    elf::write_header(&mut writer, &capture)?;
    let header = writer.finish()?;
    let compressed_bytes = header.len() as u64 + payload.as_file().metadata()?.len();
    payload.rewind()?;
    let missing_bytes = capture
        .coverage
        .missing
        .iter()
        .map(|gap| gap.end - gap.start)
        .sum();
    let status = if missing_bytes == 0 && capture.coverage.issues.is_empty() {
        "complete"
    } else {
        "partial"
    };
    Ok(Dump {
        header,
        payload,
        summary: Summary {
            pid,
            mode: mode.name(),
            status,
            threads: capture.threads,
            captured_bytes: capture.captured_bytes,
            staged_bytes,
            missing_bytes,
            missing_ranges: capture.coverage.missing.len(),
            issues: capture.coverage.issues.len(),
            conservative_shared_mappings: capture.coverage.conservative_shared_mappings,
            compressed_bytes,
            pause_ms: capture.pause_us / 1000,
            pause_us: capture.pause_us,
            timing_us: capture.timings,
            buffer_bytes,
            block_bytes: options.block_bytes,
            image_cache_hits: capture.image_cache_hits,
            compression_level: COMPRESSION_LEVEL,
            parallel_compression: parallel,
        },
    })
}

fn stage(file: &mut File, block: &[u8]) -> Result<()> {
    if block.iter().all(|&byte| byte == 0) {
        file.seek(SeekFrom::Current(block.len().try_into()?))?;
    } else {
        file.write_all(block)?;
    }
    Ok(())
}

fn seal_stage(file: &mut File) -> Result<u64> {
    let length = file.stream_position()?;
    file.set_len(length)?;
    file.rewind()?;
    Ok(length)
}

fn compress_staged(
    mut file: File,
    writer: &mut impl Write,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let mut buffer = vec![0; MIB];
    loop {
        if cancelled() {
            return Err(error("coredump cancelled"));
        }
        let n = file.read(&mut buffer)?;
        if n == 0 {
            return Ok(());
        }
        writer.write_all(&buffer[..n])?;
    }
}

fn encoder<W: Write>(output: W) -> Result<zstd::stream::write::Encoder<'static, W>> {
    let mut writer = zstd::stream::write::Encoder::new(output, COMPRESSION_LEVEL)?;
    writer.include_checksum(true)?;
    Ok(writer)
}

fn finish(
    writer: zstd::stream::write::Encoder<'static, BufWriter<tempfile::NamedTempFile>>,
) -> Result<tempfile::NamedTempFile> {
    Ok(writer.finish()?.into_inner()?)
}

struct Capture {
    maps: Vec<(crate::modules::Backing, crate::modules::Mapping)>,
    notes: Vec<u8>,
    coverage: Coverage,
    stored: Vec<memory::Stored>,
    threads: usize,
    captured_bytes: u64,
    pause_us: u64,
    timings: CaptureTimings,
    image_cache_hits: usize,
}

fn capture(
    pid: i32,
    mode: CoreMode,
    limit: &CaptureLimit<'_>,
    buffer: Vec<u8>,
    sink: Option<&mut dyn FnMut(Vec<u8>) -> Result<Vec<u8>>>,
) -> Result<Capture> {
    let root = std::path::PathBuf::from(format!("/proc/{pid}"));
    let started = Instant::now();
    let identity = start_ticks(&root)?;
    if limit
        .expected_start_ticks
        .is_some_and(|expected| expected != identity)
    {
        return Err(error("target identity changed before coredump capture"));
    }
    let page = u64::try_from(unsafe { nix::libc::sysconf(nix::libc::_SC_PAGESIZE) })?;
    if !page.is_power_of_two() {
        return Err(error("invalid page size"));
    }
    let mut images = Some(memory::prepare_images(&root, mode, limit)?);
    let mut timings = CaptureTimings {
        preflight: micros(started),
        ..Default::default()
    };
    let mut trace = Trace::new(pid, &root, identity);
    let collected = (|| {
        limit.check()?;
        trace.freeze_checked(limit.deadline, &|| limit.check())?;
        timings.freeze = trace.started.map_or(0, micros);
        let started = Instant::now();
        let maps = crate::modules::map_entries(&root)?;
        timings.maps = micros(started);
        let mut coverage = Coverage::default();
        let started = Instant::now();
        let (notes, stacks) = elf::thread_notes(&root, pid, &trace, &mut coverage, limit)?;
        timings.registers = micros(started);
        let (modules, image_cache_hits) = if mode.needs_elf_memory() {
            let started = Instant::now();
            let result =
                images
                    .take()
                    .unwrap()
                    .resolve(&root, mode, page, &maps, &mut coverage, || limit.check())?;
            timings.images = micros(started);
            result
        } else {
            (Vec::new(), 0)
        };
        let memory = if let Some(sink) = sink {
            memory::capture(
                &trace,
                pid,
                &root,
                mode,
                page,
                &maps,
                &stacks,
                &modules,
                &mut coverage,
                limit,
                buffer,
                sink,
                &mut timings,
            )?
        } else {
            memory::Captured::default()
        };
        limit.check()?;
        if start_ticks(&root)? != identity {
            return Err(error("target identity changed during coredump"));
        }
        Ok((
            maps,
            notes,
            coverage,
            memory,
            stacks.len(),
            modules,
            image_cache_hits,
        ))
    })();
    let started = Instant::now();
    let cleanup = trace.close();
    let pause_us = trace.started.map_or(0, micros);
    timings.detach = micros(started);
    if !cleanup.ok() {
        return Err(error(format!(
            "coredump detach failed: {}",
            serde_json::to_string(&cleanup)?
        )));
    }
    let (maps, mut notes, mut coverage, memory, threads, mut modules, mut image_cache_hits) =
        collected?;
    if let Some(images) = images {
        (modules, image_cache_hits) =
            images.resolve(&root, mode, page, &maps, &mut coverage, || {
                if (limit.cancelled)() {
                    return Err(error("coredump cancelled"));
                }
                Ok(())
            })?;
    }
    elf::mapping_notes(&mut notes, mode, &maps, &modules, &coverage, page)?;
    Ok(Capture {
        maps,
        notes,
        coverage,
        stored: memory.stored,
        threads,
        captured_bytes: memory.bytes,
        pause_us,
        timings,
        image_cache_hits,
    })
}
