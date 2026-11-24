#!/usr/bin/env python3
"""Exercise the retained D01 core using the debugger alone after launch."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time

from scripts import mcp

SIGNAL = 'dbg.onSignal(builtins.SIGSEGV, () => { dbg.coredump("full"); });'
DISCOVER = """export default function main() {
    const thread: DebugThread = dbg.threads()[0];
    const frame: DebugFrame = dbg.frames(thread.tid)[0];
    const locals = dbg.locals(frame);
    const globals = dbg.globals();
    console.log("wide", 18446744073709551615n);
    dbg.printVal("account->id", { frame: frame.handle });
    dbg.printVal("account->profile", { frame: frame.handle });
    return { frame, locals, globals, types: dbg.types("*Profile*"), modules: dbg.modules() };
}
"""


def verify(tool, socket, fixture, waiting, work):
    connected = tool("connect", socket=str(socket))
    assert connected["server"]["name"] == "aidbg-server", connected
    api = tool("script_api")
    assert tool("script_check", source=api["discovery_example"])["status"] == "complete"
    args = {"executable": str(fixture), "signal_source": SIGNAL}
    run = tool("run", **args)
    assert run["stop_reason"] == "signaled", run
    dump = run["signals"][0]["coredump"]
    summary = dump["summary"]
    assert summary["executable"]["build_id"], summary
    assert summary["missing_ranges"] == len(summary["missing_range_details"]), summary
    for gap in summary["missing_range_details"]:
        assert gap["start"] < gap["end"] and gap["reason"], gap
    if summary["status"] == "partial":
        assert any(entry["code"] == "PARTIAL_CORE" for entry in summary["warnings"]), summary
    elif summary["status"] == "complete_without_vvar":
        assert "commonly unreadable" in summary["comment"], summary
        assert any(entry["code"] == "VVAR_UNAVAILABLE" for entry in summary["warnings"]), summary
    else:
        assert summary["status"] == "complete", summary
    opened = tool("core_open", dump_id=dump["dump_id"])
    assert opened["dwarf_available"] and opened["symbol_match"] == "matched", opened
    assert opened["missing_range_details"] == summary["missing_range_details"], opened
    target = opened["target_id"]
    report = tool("script_run", target_id=target, source=DISCOVER)
    assert report["stop_reason"] == "completed", report
    found = report["return_value"]
    assert any(row["name"] == "account" and row["kind"] == "parameter" for row in found["locals"]["items"]), found
    assert {"accounts", "default_profile"} <= {row["name"] for row in found["globals"]["items"]}, found
    assert any(row["name"] == "Profile" for row in found["types"]["items"]), found
    assert any(row["path"] == str(fixture) for row in found["modules"]), found
    assert report["output"][0]["values"] == ["wide", {"$bigint": "18446744073709551615"}], report
    assert [entry["value"]["result"]["value"] for entry in report["output"][1:]] == [9, "0x0"], report
    frame = found["frame"]
    assert frame["file"].endswith("/D01.c") and frame["line"] == 17, frame
    symbols = tool("symbols", target_id=target, pattern="default_profile")
    default_profile = symbols["matches"][0]["runtime_address"]
    account_table = tool("symbols", target_id=target, pattern="accounts")["matches"][0]["runtime_address"]
    profile_pointer = hex(int(account_table, 16) + 8)
    chain = tool("pointer_chain", target_id=target, base=account_table, offsets=[8])
    assert chain["steps"] == [{"address": profile_pointer, "value": default_profile}], chain
    scan = {"target_id": target, "start": account_table, "end": hex(int(account_table, 16) + 32)}
    pointer = tool("xref", **scan, address=default_profile)
    assert pointer["kind"] == "pointer_value" and pointer["matches"] == [profile_pointer], pointer
    pattern = int(default_profile, 16).to_bytes(8, "little").hex()
    search = tool("search_memory", **scan, pattern=pattern)
    assert search["matches"] == [profile_pointer], search
    main = tool("symbols", target_id=target, pattern="main")["matches"][0]
    quota = tool("symbols", target_id=target, pattern="quota_for")["matches"][0]
    call_sites = tool("xref", target_id=target, address=quota["runtime_address"],
                      start=main["runtime_address"], end=hex(int(main["runtime_address"], 16) + main["size"]),
                      instruction_references=True)
    assert any(row["kind"] == "branch_target" for row in call_sites["matches"]), call_sites
    libc = tool("symbols", target_id=target, pattern="__libc_start_main", module="libc.so.6")
    assert libc["matches"], libc
    libc_address = libc["matches"][0]["runtime_address"]
    assert tool("resolve_address", target_id=target, address=libc_address)["symbol"]["name"] == "__libc_start_main"
    resolved = tool("resolve_address", target_id=target, address=frame["pc"])
    assert resolved["source_line"]["line"] == frame["line"], resolved
    disassembled = tool("disassemble", target_id=target, address=frame["pc"])
    assert disassembled["byte_source"] == "core", disassembled
    instruction = next(row for row in disassembled["instructions"] if row["address"] == frame["pc"])
    assert instruction["mnemonic"], disassembled
    length = len(bytes.fromhex(instruction["bytes"]))
    address = frame["pc"]
    patch = tool("plan_patch", target_id=target, base=address, address=address,
                 original_length=length,
                 source="nop" if disassembled["architecture"] == "aarch64" else "; ".join(["nop"] * length))
    assert patch["original_bytes"] == instruction["bytes"], patch
    source_register = re.search(r"\[([a-z0-9]+)\]", instruction["operands"]).group(1)
    simulated = tool("emulate", target_id=target, frame=frame["handle"], address=address,
                     code_length=length, registers={source_register: default_profile},
                     core_memory=[{"address": default_profile, "length": 4}])
    # The copied load writes the uint32 quota to its destination GP register.
    architecture = disassembled["architecture"]
    assert simulated.get("status") == "complete", simulated
    dest = instruction["operands"].split(",")[0]
    dest = ("r" + dest[1:]) if architecture == "x86_64" else ("x" + dest[1:])
    assert simulated["registers"][dest] == "0x40", simulated

    typo_source = f'dbg.printVal("account->proflie", {{frame: {json.dumps(frame["handle"])}}});'
    typo = tool("script_check", target_id=target, source=typo_source)
    assert any("Did you mean profile" in error["message"] for error in typo["diagnostics"]), typo
    bundle_dir = work / "replay"
    bundle = tool("export_bundle", dump_id=dump["dump_id"], output=str(bundle_dir),
                  script_source=DISCOVER, script_output=report["output"], conclusion="account 9 has no profile")
    manifest = json.loads(Path(bundle["manifest"]).read_text())
    assert manifest["executable"]["build_id"] == summary["executable"]["build_id"], manifest
    assert manifest["core"]["missing_range_details"] == summary["missing_range_details"], manifest
    replay = tool("core_open", path=str(bundle_dir / manifest["replay"]["core"]),
                  executable=str(bundle_dir / manifest["replay"]["executable"]))
    replayed = tool("script_run", target_id=replay["target_id"], source=(bundle_dir / manifest["script"]).read_text())
    assert replayed["stop_reason"] == "completed", replayed
    assert [entry["value"]["result"]["value"] for entry in replayed["output"][1:]] == [9, "0x0"], replayed
    assert replayed["return_value"]["frame"]["pc"] == frame["pc"], replayed
    tool("core_close", target_id=replay["target_id"])
    tool("core_close", target_id=target)
    stale = tool("resolve_address", target_id=target, address=frame["pc"])
    assert stale["code"] == "TARGET_GONE", stale

    if waiting:
        job = tool("run", executable=str(waiting), arguments=["wait"], detach=True)
        run_id = job["run_id"]
        for _ in range(100):
            job = tool("run_status", run_id=run_id)
            if job["status"] != "starting":
                break
            time.sleep(0.01)
        assert job["status"] == "running" and job["pid"] > 0, job
        snapshot = tool("snapshot", run_id=run_id, freeze="required")
        assert snapshot["freeze_achieved"] == "all" and snapshot["threads"][0]["registers"], snapshot
        denied = tool("target_call", pid=job["pid"], module=str(waiting), symbol="main",
                      return_type="i32", scratch_address="0x1000", scratch_length=4096,
                      allow_side_effects=True)
        assert denied["code"] == "TARGET_CALL_DENIED", denied
        audit = [json.loads(line) for line in (work / "state/target-call-audit.jsonl").read_text().splitlines()]
        assert [row["event"] for row in audit] == ["requested", "denied", "finished"], audit
        assert audit[1]["context"]["peer_uid"] == os.getuid() and audit[1]["detail"]["build_id"], audit
        assert tool("run_cancel", run_id=run_id)["cancel_requested"]
        for _ in range(100):
            job = tool("run_status", run_id=run_id)
            if job["status"] == "finished":
                break
            time.sleep(0.01)
        assert job["result"]["stop_reason"] == "cancelled", job


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    parser.add_argument("server", type=Path)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("waiting", nargs="?", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="aidbg-core-workflow-") as temp:
        work = Path(temp)
        socket = work / "server.sock"
        state = work / "state"
        state.mkdir(mode=0o700)
        # The binaries and fixture are absolute, so no helper programs can be
        # found by either debugger once the test starts.
        env = {**os.environ, "PATH": str(work / "no-helpers")}
        policy = work / "target-call-policy.json"
        policy.write_text('{"allow": []}')
        with subprocess.Popen([args.server.resolve(), "--socket", socket, "--state-dir", state,
                               "--target-call-policy", policy], env=env) as daemon:
            try:
                for _ in range(100):
                    if socket.exists():
                        break
                    assert daemon.poll() is None
                    time.sleep(0.025)
                with mcp(args.client.resolve(), env=env) as tool:
                    verify(tool, socket, args.fixture.resolve(), args.waiting.resolve() if args.waiting else None, work)
            finally:
                daemon.terminate()
    print("PASS retained core workflow")


if __name__ == "__main__":
    main()
