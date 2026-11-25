"""Generate debugger syscall metadata from the Linux v6.18 source tree."""

import argparse
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
TABLES = ROOT / "src/script/session"


def signature(declaration):
    if declaration.strip() == "void":
        return []
    arguments = []
    for parameter in declaration.split(","):
        parameter = " ".join(parameter.replace("__user", "").split())
        match = re.fullmatch(r"(.*[ *])([A-Za-z_]\w*)", parameter)
        if match and match[2] not in {"int", "long", "short", "char", "void"} and match[1].strip() not in {"struct", "enum", "union"}:
            arguments.append(f"{match[2]}:{match[1].strip()}")
        else:
            arguments.append(f"arg{len(arguments) + 1}:{parameter}")
    return arguments


def generate(output, table, abis, definitions, arm):
    rows = []
    overrides = {
        "clone": [
            "flags:unsigned long", "stack:unsigned long", "parent_tid:int *",
            *(
                ["tls:unsigned long", "child_tid:int *"] if arm
                else ["child_tid:int *", "tls:unsigned long"]
            ),
        ],
        "mmap": [
            "addr:unsigned long", "length:unsigned long", "prot:unsigned long",
            "flags:unsigned long", "fd:unsigned long", "offset:unsigned long",
        ],
        "rt_sigreturn": [],
        "arch_prctl": ["code:int", "addr:unsigned long"],
    }
    for line in table.splitlines():
        fields = line.split("#", 1)[0].split()
        if not fields or fields[1] not in abis:
            continue
        number, _, name, *entry = fields
        symbol = entry[0] if entry and entry[0] != "sys_ni_syscall" else f"sys_{name}"
        declared = definitions.get(symbol, definitions.get(f"sys_{name}"))
        arguments = overrides.get(name)
        if arguments is None and declared is not None:
            arguments = signature(declared)
        # Preserve the number and name of reserved or historical entries.
        if arguments is None:
            arguments = ["?"] * 6
        if len(arguments) > 6:
            raise ValueError(f"too many syscall arguments for {name}")
        rows.append((int(number), name, arguments))
    numbers = [number for number, _, _ in rows]
    if len(numbers) != len(set(numbers)):
        raise ValueError(f"duplicate syscall IDs in {output}")
    contents = ["# Generated from Linux v6.18 syscall tables and prototypes."]
    for number, name, arguments in sorted(rows):
        contents.append("\t".join([str(number), name, *arguments]))
    output.write_text("\n".join(contents) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("linux", type=Path, help="Linux v6.18 source tree")
    args = parser.parse_args()
    linux = args.linux
    declarations = (linux / "include/linux/syscalls.h").read_text()
    definitions = dict(re.findall(r"asmlinkage long (sys_\w+)\(([^;]*)\);", declarations))
    generate(
        TABLES / "syscalls-x86_64.tsv",
        (linux / "arch/x86/entry/syscalls/syscall_64.tbl").read_text(),
        {"common", "64"}, definitions, False,
    )
    generate(
        TABLES / "syscalls-aarch64.tsv",
        (linux / "scripts/syscall.tbl").read_text(),
        {"common", "64", "renameat", "rlimit", "memfd_secret"}, definitions, True,
    )


if __name__ == "__main__":
    main()
