#!/usr/bin/env python3
"""Collect cold, warm and cross-target D04 snapshot samples as JSON Lines."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from session import Client

PREFIX = "aidbg snapshot timing "


def run_target(client, fixture):
    pid = client.tool("run", path=str(fixture))["result"]["pid"]
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if "Threads: 3" in client.tool("status")["result"]:
            time.sleep(0.05)
            return pid
        time.sleep(0.01)
    raise RuntimeError(f"D04 did not start both workers (PID {pid})")


def snapshot(client, round_number, kind):
    start = time.monotonic_ns()
    reply = client.tool("snapshot")
    elapsed = time.monotonic_ns() - start
    result = reply["result"]
    assert not reply["paused_threads"], reply["paused_threads"]
    assert result["threadCount"] == len(result["threads"]) == 3, result.get("incomplete")
    assert "State: running" in client.tool("status")["result"]
    frames = [frame for thread in result["threads"] for frame in thread["frames"]]
    assert {"refresh", "reconcile"} <= {frame.get("symbol") for frame in frames}
    return {"round": round_number, "kind": kind, "client_ns": elapsed,
            "threads": len(result["threads"]), "frames": len(frames),
            "readable_variables": sum(len(frame.get(key) or {}) for frame in frames
                                      for key in ("locals", "parameters")),
            "source_frames": sum(bool(frame.get("file")) and frame.get("line") is not None
                                 for frame in frames),
            "partial_stages": sorted({row["stage"] for row in result.get("incomplete", [])})}


def run_round(args, round_number, mode):
    timing = mode != "0"
    with tempfile.TemporaryDirectory(prefix="aidbg-timing-") as directory:
        work = Path(directory)
        socket = work / "server.sock"
        log = work / "stderr"
        env = {**os.environ, "AIDBG_SNAPSHOT_TIMING": mode}
        with log.open("w") as output, subprocess.Popen(
            [args.server, "--state-dir", work, "--socket", socket], env=env, stderr=output
        ) as daemon:
            try:
                for _ in range(100):
                    if socket.exists():
                        break
                    assert daemon.poll() is None, log.read_text()
                    time.sleep(0.02)
                client = Client(args.client, str(socket), "snapshot-timing-session-000001")
                try:
                    run_target(client, args.fixture)
                    rows = [snapshot(client, round_number, "cold")]
                    rows.extend(snapshot(client, round_number, "warm") for _ in range(4))
                    client.tool("script_run", src="await dbg.kill();", wait_ms=5000)
                    run_target(client, args.fixture)
                    rows.append(snapshot(client, round_number, "new_target"))
                    client.tool("script_run", src="await dbg.kill();", wait_ms=5000)
                finally:
                    client.close()
            finally:
                daemon.terminate()
                daemon.wait(timeout=5)
        reports = [json.loads(line[len(PREFIX):]) for line in log.read_text().splitlines()
                   if line.startswith(PREFIX)]
        assert len(reports) == (len(rows) if timing else 0), log.read_text()
        for index, row in enumerate(rows):
            if timing:
                report = reports[index]
                assert report["baseline"] == (mode == "baseline")
                assert report["scope_baseline"] == (mode in {"baseline", "scope-baseline"})
                assert sum(report["phases_ns"].values()) == report["worker_ns"]
                assert report["details"]["restore_ok"]
                assert report["details"]["stopped_before"] == report["details"]["stopped_after"]
                row.update(report)
            print(json.dumps({"timing": timing, "mode": mode, **row}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "server", "fixture"):
        parser.add_argument(name, type=lambda path: Path(path).resolve())
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--control-rounds", type=int, default=3)
    parser.add_argument("--baseline-rounds", type=int, default=0)
    parser.add_argument("--scope-baseline-rounds", type=int, default=0)
    args = parser.parse_args()
    rounds = max(args.rounds, args.control_rounds, args.baseline_rounds, args.scope_baseline_rounds)
    for index in range(rounds):
        if index < args.rounds:
            run_round(args, index + 1, "1")
        if index < args.baseline_rounds:
            run_round(args, index + 1, "baseline")
        if index < args.scope_baseline_rounds:
            run_round(args, index + 1, "scope-baseline")
        if index < args.control_rounds:
            run_round(args, index + 1, "0")


if __name__ == "__main__":
    main()
