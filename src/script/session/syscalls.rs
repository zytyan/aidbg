use crate::{Result, error, hex};
use nix::{errno::Errno, libc};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Clone, Copy)]
pub(super) struct Catch {
    id: u64,
    entry: bool,
    exit: bool,
}

impl Catch {
    pub(super) fn parse(args: &Value) -> Result<Self> {
        let id = args["catchId"]
            .as_u64()
            .ok_or_else(|| error("expected syscall catch ID"))?;
        let (entry, exit) = match args["phase"].as_str() {
            Some("entry") => (true, false),
            Some("exit") => (false, true),
            Some("both") => (true, true),
            _ => return Err(error("expected entry, exit, or both")),
        };
        Ok(Self { id, entry, exit })
    }
}

pub(super) struct Entry {
    number: u64,
    arch: u32,
    args: [u64; 6],
    pathname: Option<String>,
}

// Linux UAPI for PTRACE_GET_SYSCALL_INFO. libc exposes this only for glibc.
#[repr(C)]
#[derive(Default)]
struct SyscallInfo {
    op: u8,
    reserved: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: [u64; 8],
}

fn syscall_info(tid: i32) -> nix::Result<(SyscallInfo, usize)> {
    const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
    let mut info = SyscallInfo::default();
    let length = Errno::result(unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO as _,
            tid,
            std::mem::size_of_val(&info),
            &mut info,
        )
    })?;
    Ok((info, length as usize))
}

pub(super) fn verify_supported(tid: i32) -> Result<()> {
    match syscall_info(tid) {
        Ok(_) => Ok(()),
        Err(Errno::EIO | Errno::EINVAL) => Err(error(
            "NotSupport: syscall capture requires Linux PTRACE_GET_SYSCALL_INFO",
        )),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn read_stop(
    tid: i32,
    entries: &mut BTreeMap<i32, Entry>,
    catches: [Option<&Catch>; 2],
) -> Result<Vec<Value>> {
    if catches.iter().all(Option::is_none) {
        return Ok(Vec::new());
    }
    let (info, length) = match syscall_info(tid) {
        Err(Errno::ESRCH) => return Ok(Vec::new()),
        result => result?,
    };
    match info.op {
        1 if length >= 80 => {
            let number = info.data[0];
            let args: [u64; 6] = info.data[1..7].try_into().unwrap();
            let pathname = native_signature(info.arch, number)
                .and_then(|entry| {
                    entry.parameters.iter().position(|parameter| {
                        parameter.is_some_and(|(name, _)| {
                            matches!(name, "pathname" | "filename" | "path")
                        })
                    })
                })
                .and_then(|index| read_pathname(tid, args[index]));
            let entry = Entry {
                number,
                arch: info.arch,
                args,
                pathname,
            };
            let result = rows(tid, &entry, None, catches);
            entries.insert(tid, entry);
            Ok(result)
        }
        2 if length >= 33 => {
            let Some(entry) = entries.remove(&tid) else {
                return Ok(Vec::new());
            };
            let value = info.data[0] as i64;
            let failed = info.data[1].to_ne_bytes()[0] != 0;
            Ok(rows(tid, &entry, Some((value, failed)), catches))
        }
        _ => Ok(Vec::new()),
    }
}

fn read_pathname(tid: i32, address: u64) -> Option<String> {
    if address == 0 {
        return None;
    }
    let mut bytes = [0; 4096];
    let len = crate::trace::read_process_prefix(tid, address, &mut bytes, || true).ok()?;
    let end = bytes[..len].iter().position(|&byte| byte == 0)?;
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn rows(
    tid: i32,
    entry: &Entry,
    result: Option<(i64, bool)>,
    catches: [Option<&Catch>; 2],
) -> Vec<Value> {
    let signature = native_signature(entry.arch, entry.number);
    catches
        .into_iter()
        .flatten()
        .filter(|catch| {
            if result.is_some() {
                catch.exit
            } else {
                catch.entry
            }
        })
        .map(|catch| {
            json!({
                "kind":"syscall", "reason":"syscall", "tid":tid, "paused":true, "catchId":catch.id,
                "phase":if result.is_some() {"exit"} else {"entry"},
                "number":entry.number, "abi":entry.arch,
                "name":signature.map(|entry| entry.name),
                "parameterNames":signature.map(|entry| entry.parameters.iter().flatten().map(|(name, _)| name).filter(|name| !name.is_empty()).collect::<Vec<_>>()),
                "parameters":signature.map(Signature::parameter_slots),
                "args":entry.args.map(hex),
                "pathname":entry.pathname,
                "result":result.map(|(value, _)| value.to_string()),
                "failed":result.map(|(_, failed)| failed),
            })
        })
        .collect()
}

const X86_64: u32 = 0xc000_003e;
const AARCH64: u32 = 0xc000_00b7;

struct Signature {
    id: u64,
    name: &'static str,
    parameters: [Option<(&'static str, &'static str)>; 6],
}

impl Signature {
    fn parameter_slots(&self) -> [Value; 6] {
        self.parameters.map(|parameter| match parameter {
            Some(("", "")) => json!({"name":null,"type":null}),
            Some((name, ty)) => json!({"name":name,"type":ty}),
            None => Value::Null,
        })
    }
}

fn parse_table(table: &'static str) -> Vec<Signature> {
    table
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split('\t');
            let id = fields.next().unwrap().parse().unwrap();
            let name = fields.next().unwrap();
            let parameters = std::array::from_fn(|_| {
                fields.next().map(|field| {
                    if field == "?" {
                        ("", "")
                    } else {
                        field.split_once(':').unwrap()
                    }
                })
            });
            assert!(fields.next().is_none());
            Signature {
                id,
                name,
                parameters,
            }
        })
        .collect()
}

fn table(arch: u32) -> Option<&'static [Signature]> {
    static X86: OnceLock<Vec<Signature>> = OnceLock::new();
    static ARM: OnceLock<Vec<Signature>> = OnceLock::new();
    match arch {
        X86_64 => Some(X86.get_or_init(|| parse_table(include_str!("syscalls-x86_64.tsv")))),
        AARCH64 => Some(ARM.get_or_init(|| parse_table(include_str!("syscalls-aarch64.tsv")))),
        _ => None,
    }
}

fn native_signature(arch: u32, number: u64) -> Option<&'static Signature> {
    let table = table(arch)?;
    table
        .binary_search_by_key(&number, |entry| entry.id)
        .ok()
        .map(|index| &table[index])
}

pub(super) fn query(id: Option<u64>, name: Option<&str>) -> Value {
    let arch = if crate::regs::ARCH == "x86_64" {
        X86_64
    } else {
        AARCH64
    };
    let rows: Vec<_> = table(arch)
        .unwrap()
        .iter()
        .filter(|entry| {
            id.is_none_or(|id| entry.id == id) && name.is_none_or(|name| entry.name == name)
        })
        .map(|entry| json!({"id":entry.id,"name":entry.name,"parameters":entry.parameter_slots()}))
        .collect();
    json!({"architecture":crate::regs::ARCH,"abi":arch,"linux":"6.18","syscalls":rows})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tables_preserve_ids_and_register_order() {
        for (arch, read, openat, mmap, clone, tls) in
            [(X86_64, 0, 257, 9, 56, 4), (AARCH64, 63, 56, 222, 220, 3)]
        {
            let rows = table(arch).unwrap();
            assert!(rows.len() > 300);
            assert!(rows.windows(2).all(|rows| rows[0].id < rows[1].id));
            assert_eq!(native_signature(arch, read).unwrap().name, "read");
            assert_eq!(native_signature(arch, openat).unwrap().name, "openat");
            assert!(
                native_signature(arch, mmap)
                    .unwrap()
                    .parameters
                    .iter()
                    .all(Option::is_some)
            );
            assert_eq!(
                native_signature(arch, clone).unwrap().parameters[tls]
                    .unwrap()
                    .0,
                "tls"
            );
            assert!(native_signature(arch, 9999).is_none());
        }
    }
}
