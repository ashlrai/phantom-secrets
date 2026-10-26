#!/usr/bin/env python3
"""The abort-row guard must fail closed and emit only a verdict."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "bridge_check", Path(__file__).with_name("bridge-prepublish-check.py")
)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class BridgePrepublishCheckTests(unittest.TestCase):
    def run_guard(self, source, expected, ref="HEAD"):
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.object(guard.sys, "argv", ["guard", ref]),
            patch.object(guard.subprocess, "run") as run,
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout=b"a" * 40 + b"\n"),
                subprocess.CompletedProcess([], 0, stdout=source),
            ]
            status = guard.main()
        self.assertEqual(status, 0 if expected else 1)
        self.assertEqual(output.getvalue(), "pass\n" if expected else "fail\n")
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(run.call_args_list[0].args[0][-1], f"{ref}^{{commit}}")
        self.assertIn("--end-of-options", run.call_args_list[0].args[0])
        self.assertEqual(
            run.call_args_list[1].args[0][-1],
            "a" * 40 + ":crates/phantom-cli/src/commands/check.rs",
        )

    def test_exact_base_line_passes_without_source_output(self):
        self.run_guard(b"\n" * 1795 + b"REGION_\n", True, "reviewed-base")

    def test_nearby_match_does_not_clear_the_requested_line(self):
        self.run_guard(b"\n" * 1795 + b"ordinary\nREGION_\n", False)

    def test_short_source_fails(self):
        self.run_guard(b"REGION_\n", False)

    def test_carriage_returns_do_not_shift_git_line_numbers(self):
        self.run_guard(b"\r" * 1795 + b"REGION_\n", False)

    def test_git_errors_and_unavailable_git_fail_without_diagnostics(self):
        for error in (
            subprocess.CalledProcessError(128, "git", stderr=b"withheld diagnostic"),
            FileNotFoundError("git"),
        ):
            with self.subTest(error=type(error).__name__):
                output, errors = io.StringIO(), io.StringIO()
                with (
                    patch.object(guard.sys, "argv", ["guard"]),
                    patch.object(guard.subprocess, "run", side_effect=error),
                    redirect_stdout(output),
                    redirect_stderr(errors),
                ):
                    self.assertEqual(guard.main(), 1)
                self.assertEqual(output.getvalue(), "fail\n")
                self.assertEqual(errors.getvalue(), "")

    def test_extra_arguments_fail_without_running_git(self):
        output = io.StringIO()
        with (
            patch.object(guard.sys, "argv", ["guard", "HEAD", "extra"]),
            patch.object(guard.subprocess, "run") as run,
            redirect_stdout(output),
        ):
            self.assertEqual(guard.main(), 1)
        self.assertEqual(output.getvalue(), "fail\n")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
