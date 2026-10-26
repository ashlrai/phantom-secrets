"""Runner contract tests; no compiler, network, vault, or personal state."""

import argparse
import importlib.util
import json
import os
import select
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("fuzz_runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def exercise(self, code=0, elapsed=601, executions=123, artifact=False, error=None,
                 fuzz_seconds=601):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seeds = root / "seeds" / "body_injection"
            seeds.mkdir(parents=True)
            (seeds / "seed").write_bytes(b"synthetic")
            logs = root / "logs" / "test"
            logs.mkdir(parents=True)

            def fake_run(command, **kwargs):
                self.assertIn("-max_total_time=600", command)
                self.assertEqual(kwargs["env"].get("CARGO_NET_OFFLINE"), "true")
                self.assertEqual(command[command.index("--sanitizer") + 1], "address")
                self.assertEqual((root / "corpus/body_injection/seed").read_bytes(), b"synthetic")
                if error:
                    raise error
                if executions is not None:
                    kwargs["stdout"].write(f"stat::number_of_executed_units: {executions}\n")
                    if fuzz_seconds is not None:
                        kwargs["stdout"].write(f"Done {executions} runs in {fuzz_seconds} second(s)\n")
                if artifact:
                    (root / "artifacts/test/body_injection/crash-input").write_bytes(b"fake")
                return subprocess.CompletedProcess(command, code)

            with patch.object(runner, "ROOT", root), \
                 patch.object(runner, "run_command", side_effect=fake_run), \
                 patch.object(runner.time, "monotonic", side_effect=[0, elapsed]):
                return runner.run_target("body_injection", 600, "nightly",
                                         {"CARGO_NET_OFFLINE": "true"}, logs)

    def test_clean_full_duration(self):
        self.assertEqual(self.exercise()["status"], "PASS")

    def test_nonzero_exit_fails(self):
        self.assertEqual(self.exercise(code=77)["status"], "FAIL")

    def test_short_run_fails(self):
        self.assertEqual(self.exercise(elapsed=599)["status"], "FAIL")

    def test_build_time_cannot_substitute_for_fuzz_time(self):
        self.assertEqual(self.exercise(elapsed=700, fuzz_seconds=5)["status"], "FAIL")

    def test_missing_completion_fails(self):
        self.assertEqual(self.exercise(fuzz_seconds=None)["status"], "FAIL")

    def test_no_executions_fails(self):
        for executions in (None, 0):
            with self.subTest(executions=executions):
                self.assertEqual(self.exercise(executions=executions)["status"], "FAIL")

    def test_artifact_fails_even_with_zero_exit(self):
        self.assertEqual(self.exercise(artifact=True)["status"], "FAIL")

    def test_launch_error_fails(self):
        self.assertEqual(self.exercise(error=OSError())["status"], "FAIL")

    def test_timeout_fails(self):
        result = self.exercise(error=subprocess.TimeoutExpired("cargo", 780))
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["error"], "TimeoutExpired")

    def test_rejects_unbounded_duration(self):
        for value in ("0", "-1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                runner.positive_seconds(value)

    def main_receipt(self, build_code=0, drift=False, worker_error=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("Cargo.toml", "Cargo.lock", "dictionary.txt"):
                (root / name).write_text("synthetic")

            def fake_run(command, **kwargs):
                self.assertNotEqual(kwargs["env"]["HOME"], str(Path.home()))
                if "fetch" in command:
                    self.assertIn("--locked", command)
                return subprocess.CompletedProcess(command, build_code)

            def fake_target(*args):
                if worker_error:
                    raise OSError("synthetic worker error")
                if drift:
                    (root / "Cargo.lock").write_text("changed")
                return {"target": args[0], "status": "PASS"}

            with patch.object(runner, "ROOT", root), \
                 patch.object(runner, "run_command", side_effect=fake_run), \
                 patch.object(runner, "run_target", side_effect=fake_target), \
                 patch("sys.argv", ["run.py", "--seconds", "1"]), \
                 patch("builtins.print"):
                code = runner.main()
            receipt = json.loads(next((root / "logs").glob("*/receipt.json")).read_text())
            return code, receipt

    def test_smoke_never_claims_ten_minute_acceptance(self):
        code, receipt = self.main_receipt()
        self.assertEqual(code, 0)
        self.assertFalse(receipt["acceptance_10_minutes"])

    def test_build_failure_retains_failing_receipt(self):
        code, receipt = self.main_receipt(build_code=1)
        self.assertEqual(code, 1)
        self.assertEqual(receipt["status"], "FAIL")

    def test_worker_error_retains_failing_receipt(self):
        code, receipt = self.main_receipt(worker_error=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(receipt["targets"]), 2)

    def test_lock_drift_fails(self):
        code, receipt = self.main_receipt(drift=True)
        self.assertEqual(code, 1)
        self.assertFalse(receipt["lock_unchanged"])

    def test_command_uses_own_process_group(self):
        process = Mock(pid=123, **{"wait.return_value": 0})
        with patch.object(runner.subprocess, "Popen", return_value=process) as launch:
            self.assertEqual(runner.run_command(["cargo"], timeout=10).returncode, 0)
        launch.assert_called_once_with(["cargo"], start_new_session=True)

    def test_command_timeout_kills_group_and_reaps(self):
        process = Mock(pid=123)
        process.wait.side_effect = [subprocess.TimeoutExpired("cargo", 10), -9]
        with patch.object(runner.subprocess, "Popen", return_value=process), \
             patch.object(runner.os, "killpg") as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run_command(["cargo"], timeout=10)
        kill.assert_called_once_with(123, signal.SIGKILL)
        self.assertEqual(process.wait.call_count, 2)

    def test_command_cleanup_handles_already_exited_group(self):
        process = Mock(pid=123)
        process.wait.side_effect = [subprocess.TimeoutExpired("cargo", 10), -9]
        with patch.object(runner.subprocess, "Popen", return_value=process), \
             patch.object(runner.os, "killpg", side_effect=ProcessLookupError):
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run_command(["cargo"], timeout=10)
        self.assertEqual(process.wait.call_count, 2)

    def test_command_check_rejects_nonzero_exit(self):
        process = Mock(pid=123, **{"wait.return_value": 1})
        with patch.object(runner.subprocess, "Popen", return_value=process):
            with self.assertRaises(subprocess.CalledProcessError):
                runner.run_command(["cargo"], timeout=10, check=True)

    def test_timeout_closes_real_grandchild_pipe(self):
        # A surviving grandchild keeps the pipe open even after Cargo's
        # equivalent wrapper dies. EOF proves cleanup reached the descendant.
        with tempfile.TemporaryDirectory() as directory:
            group_file = Path(directory) / "group"
            read_fd, write_fd = os.pipe()
            parent = (
                "import os,pathlib,subprocess,sys,time; "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
                "subprocess.Popen([sys.executable,'-c',"
                "'import os,sys,time; os.write(int(sys.argv[1]),b\"child-started\"); time.sleep(60)',"
                "sys.argv[2]],pass_fds=(int(sys.argv[2]),)); time.sleep(60)"
            )
            try:
                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        runner.run_command(
                            [sys.executable, "-c", parent, str(group_file), str(write_fd)],
                            timeout=3, pass_fds=(write_fd,),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                finally:
                    os.close(write_fd)
                received = b""
                eof = False
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([read_fd], [], [], max(0, deadline - time.monotonic()))
                    if not ready:
                        break
                    chunk = os.read(read_fd, 4096)
                    if not chunk:
                        eof = True
                        break
                    received += chunk
                self.assertIn(b"child-started", received)
                self.assertTrue(eof, "grandchild survived command timeout")
            finally:
                os.close(read_fd)
                if group_file.exists():
                    try:
                        os.killpg(int(group_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
