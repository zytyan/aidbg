mod ffi;
mod unicorn;

pub use unicorn::emulate;

use crate::{Result, disassembly, error, hex, modules, regs, rpc};
use ffi::*;
use serde::Serialize;
use std::ffi::{CStr, CString, c_char, c_int};
use std::ops::Range;
use std::ptr;

pub(crate) const MAX_CODE: usize = 64 * 1024;

struct Keystone(Handle);

impl Keystone {
    fn open() -> Result<Self> {
        let (arch, mode) = if cfg!(target_arch = "x86_64") {
            (4, 8)
        } else {
            (2, 0)
        };
        let mut handle = ptr::null_mut();
        let code = unsafe { ks_open(arch, mode, &mut handle) };
        if code != 0 || handle.is_null() {
            return Err(engine_error("Keystone open", ks_strerror, code));
        }
        Ok(Self(handle))
    }

    fn encode(&self, address: u64, source: &str) -> Result<(Vec<u8>, usize)> {
        if source.trim().is_empty() || source.len() > 8192 {
            return Err(error("assembly source must contain 1–8192 bytes"));
        }
        // Inline instructions and labels need no assembler directives or files.
        for statement in source.split(['\n', ';']) {
            let mut statement = statement.trim_start();
            while let Some((label, rest)) = statement.split_once(':') {
                if label.is_empty()
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.$".contains(&b))
                {
                    break;
                }
                statement = rest.trim_start();
            }
            if statement.starts_with('.')
                || statement.starts_with('%')
                || statement.starts_with('#') && statement.contains("include")
            {
                return Err(error("assembler directives are unsupported"));
            }
        }
        if cfg!(target_arch = "aarch64") && !address.is_multiple_of(4) {
            return Err(error("AArch64 assembly address must be four-byte aligned"));
        }
        let source = CString::new(source)?;
        let mut bytes = ptr::null_mut();
        let (mut size, mut statements) = (0, 0);
        let result = unsafe {
            ks_asm(
                self.0,
                source.as_ptr(),
                address,
                &mut bytes,
                &mut size,
                &mut statements,
            )
        };
        let encoding = if result != 0 {
            let code = unsafe { ks_errno(self.0) };
            Err(engine_error("Keystone assembly", ks_strerror, code))
        } else if bytes.is_null() || size == 0 || size > MAX_CODE {
            Err(error(
                "Keystone emitted no code or exceeded the code size limit",
            ))
        } else {
            Ok((
                unsafe { std::slice::from_raw_parts(bytes, size) }.to_vec(),
                statements,
            ))
        };
        if !bytes.is_null() {
            unsafe { ks_free(bytes) };
        }
        encoding
    }
}

impl Drop for Keystone {
    fn drop(&mut self) {
        unsafe { ks_close(self.0) };
    }
}

fn engine_error(
    action: &str,
    strerror: unsafe extern "C" fn(c_int) -> *const c_char,
    code: c_int,
) -> Box<dyn std::error::Error + Send + Sync> {
    let message = unsafe { strerror(code) };
    if message.is_null() {
        error(format!("{action}: engine error {code}"))
    } else {
        error(format!(
            "{action}: {}",
            unsafe { CStr::from_ptr(message) }.to_string_lossy()
        ))
    }
}

#[derive(Serialize)]
pub struct Assembly {
    architecture: &'static str,
    address: String,
    bytes: String,
    statements: usize,
}

pub fn assemble(address: u64, source: &str) -> Result<Assembly> {
    let (bytes, statements) = Keystone::open()?.encode(address, source)?;
    Ok(Assembly {
        architecture: regs::ARCH,
        address: hex(address),
        bytes: modules::id_hex(&bytes),
        statements,
    })
}

fn range(address: u64, length: u64) -> Result<Range<u64>> {
    if length == 0 {
        return Err(error("address range must be nonempty"));
    }
    Ok(address
        ..address
            .checked_add(length)
            .ok_or_else(|| error("address range overflows"))?)
}

fn intersects(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

fn contains(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start <= b.start && a.end >= b.end
}

#[derive(Serialize)]
pub struct Patch {
    architecture: &'static str,
    base: String,
    address: String,
    end: String,
    original_bytes: String,
    replacement_bytes: String,
    patched_image: String,
}

pub fn patch(request: rpc::PatchRequest) -> Result<Patch> {
    let rpc::PatchRequest {
        base,
        address,
        mut original,
        source,
        existing,
        ..
    } = request;
    if original.is_empty() || original.len() > MAX_CODE || existing.len() > 256 {
        return Err(error(
            "expected 1–65536 original bytes and at most 256 existing ranges",
        ));
    }
    let image = range(base, original.len() as u64)?;
    let (replacement, _) = Keystone::open()?.encode(address, &source)?;
    let patch = range(address, replacement.len() as u64)?;
    if !contains(&image, &patch) {
        return Err(error("replacement exceeds allowed original byte window"));
    }
    for other in existing {
        if intersects(&patch, &range(other.address, other.length)?) {
            return Err(error("replacement overlaps an existing patch"));
        }
    }
    if cfg!(target_arch = "aarch64") && !base.is_multiple_of(4) {
        return Err(error(
            "AArch64 original instruction window must be four-byte aligned",
        ));
    }
    let lo = (patch.start - base) as usize;
    let hi = (patch.end - base) as usize;
    let (engine, _) = disassembly::decoder(regs::ARCH)?;
    let instructions = engine.disasm_all(&original[..hi], base)?;
    if !instructions.iter().any(|insn| insn.address() == address)
        || instructions
            .iter()
            .last()
            .is_none_or(|insn| insn.address() + insn.len() as u64 != patch.end)
    {
        return Err(error("patch would cross an original instruction boundary"));
    }
    let original_bytes = modules::id_hex(&original[lo..hi]);
    original[lo..hi].copy_from_slice(&replacement);
    Ok(Patch {
        architecture: regs::ARCH,
        base: hex(base),
        address: hex(address),
        end: hex(patch.end),
        original_bytes,
        replacement_bytes: modules::id_hex(&replacement),
        patched_image: modules::id_hex(&original),
    })
}
