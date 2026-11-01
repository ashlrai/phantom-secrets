#!/usr/bin/env python3
"""Build and run both ASan fuzz targets; keep a receipt even on failure."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
TARGETS = ("placeholder_parsing", "body_injection")


def run_command(command, *, timeout, check=False, **kwargs):
    # Cargo spawns cargo-fuzz, cargo, rustc and finally libFuzzer. Killing only
    # the wrapper leaves descendants alive and can retain build locks forever.
    process = subprocess.Popen(command, start_new_session=True, **kwargs)
    try:
        code = process.wait(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # The process group may have exited just before cleanup.
        process.wait()
        raise
    result = subprocess.CompletedProcess(command, code)
    if check:
        result.check_returncode()
    return result


def positive_seconds(value):
    seconds = int(value)
    if seconds <= 0:
        raise argparse.ArgumentTypeError("seconds must be positive")
    return seconds


def run_target(target, seconds, toolchain, env, log_dir):
    corpus = ROOT / "corpus" / target
    artifacts = ROOT / "artifacts" / log_dir.name / target
    corpus.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    for seed in sorted((ROOT / "seeds" / target).iterdir()):
        shutil.copyfile(seed, corpus / seed.name)
    log = log_dir / f"{target}.log"
    command = [
        "cargo", f"+{toolchain}", "fuzz", "run", "--sanitizer", "address",
        "--fuzz-dir", str(ROOT), target, str(corpus), "--",
        f"-max_total_time={seconds}", "-max_len=16384", "-timeout=10",
        "-rss_limit_mb=2048", f"-dict={ROOT / 'dictionary.txt'}",
        f"-artifact_prefix={artifacts}/", "-print_final_stats=1", "-verbosity=1",
    ]
    started = time.monotonic()
    error = None
    with log.open("w") as output:
        try:
            result = run_command(
                command, cwd=ROOT.parent, env=env, stdout=output,
                stderr=subprocess.STDOUT, timeout=seconds + 180, check=False,
            )
            code = result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            code = -1
            # Do not serialize the subprocess environment or arbitrary errors.
            error = type(exc).__name__
    elapsed = time.monotonic() - started
    contents = log.read_text(errors="replace")
    counts = re.findall(r"stat::number_of_executed_units:\s*(\d+)", contents)
    executions = int(counts[-1]) if counts else 0
    completed = re.findall(r"Done (\d+) runs in (\d+) second\(s\)", contents)
    fuzz_seconds = int(completed[-1][1]) if completed else 0
    completed_runs = int(completed[-1][0]) if completed else 0
    crash_artifacts = sum(1 for path in artifacts.iterdir() if path.is_file())
    passed = (code == 0 and elapsed >= seconds and fuzz_seconds >= seconds
              and executions > 0 and completed_runs == executions and crash_artifacts == 0)
    return {
        "target": target, "status": "PASS" if passed else "FAIL",
        "requested_seconds": seconds, "elapsed_seconds": round(elapsed, 3),
        "fuzz_seconds": fuzz_seconds,
        "executions": executions, "exit_code": code, "error": error,
        "crash_artifacts": crash_artifacts, "log": log.name,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=positive_seconds, default=600,
                        help="seconds per target; default 600, both run concurrently")
    parser.add_argument("--toolchain", default="nightly",
                        help="installed nightly toolchain name (no installation performed)")
    parser.add_argument("--build-timeout", type=positive_seconds, default=1800,
                        help="timeout for each dependency-fetch/build step; default 1800 seconds")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("this runner requires POSIX process groups (macOS or Linux)")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    log_dir = ROOT / "logs" / stamp
    log_dir.mkdir(parents=True)
    receipt = {"started_utc": stamp, "sanitizer": "address", "max_len": 16384,
               "seconds_per_target": args.seconds, "status": "FAIL", "targets": []}
    lock_before = (ROOT / "Cargo.lock").read_bytes()
    receipt["lock_sha256"] = hashlib.sha256(lock_before).hexdigest()
    inputs = [ROOT / "Cargo.toml", ROOT / "dictionary.txt"]
    for directory in ("src", "fuzz_targets", "seeds"):
        inputs.extend(sorted(path for path in (ROOT / directory).rglob("*") if path.is_file()))
    receipt["source_sha256"] = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in inputs
    }
    original_home = Path.home()
    env = os.environ.copy()
    # Isolate personal state while preserving the actual installed toolchain.
    env.setdefault("CARGO_HOME", str(original_home / ".cargo"))
    env.setdefault("RUSTUP_HOME", str(original_home / ".rustup"))
    with tempfile.TemporaryDirectory(prefix="phantom-fuzz-home-") as home:
        env["HOME"] = home
        with (log_dir / "build.log").open("w") as output:
            try:
                # cargo-fuzz has no --locked option. Fetch with --locked, build
                # offline, and reject any lock drift before reporting success.
                fetch = run_command(
                    ["cargo", f"+{args.toolchain}", "fetch", "--locked",
                     "--manifest-path", str(ROOT / "Cargo.toml")],
                    cwd=ROOT.parent, env=env, stdout=output, stderr=subprocess.STDOUT,
                    check=True, timeout=args.build_timeout,
                )
                receipt["fetch_exit_code"] = fetch.returncode
                env["CARGO_NET_OFFLINE"] = "true"
                build = run_command(
                    ["cargo", f"+{args.toolchain}", "fuzz", "build",
                     "--sanitizer", "address",
                     "--fuzz-dir", str(ROOT)],
                    cwd=ROOT.parent, env=env, stdout=output, stderr=subprocess.STDOUT,
                    check=False, timeout=args.build_timeout,
                )
                receipt["build_exit_code"] = build.returncode
            except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
                receipt["build_exit_code"] = -1
                receipt["build_error"] = type(exc).__name__
        if receipt["build_exit_code"] == 0:
            print("Built both targets; starting concurrent fuzz runs.", flush=True)
            with ThreadPoolExecutor(max_workers=len(TARGETS)) as pool:
                jobs = [pool.submit(run_target, target, args.seconds, args.toolchain,
                                    env, log_dir) for target in TARGETS]
                for target, job in zip(TARGETS, jobs):
                    try:
                        receipt["targets"].append(job.result())
                    except Exception as exc:
                        receipt["targets"].append({
                            "target": target, "status": "FAIL", "error": type(exc).__name__,
                        })
            if all(target["status"] == "PASS" for target in receipt["targets"]):
                receipt["status"] = "PASS"
    receipt["lock_unchanged"] = (ROOT / "Cargo.lock").read_bytes() == lock_before
    if not receipt["lock_unchanged"]:
        receipt["status"] = "FAIL"
    receipt["acceptance_10_minutes"] = receipt["status"] == "PASS" and args.seconds >= 600
    receipt_path = log_dir / "receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"{receipt['status']}: {receipt_path.relative_to(ROOT.parent)}", flush=True)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
