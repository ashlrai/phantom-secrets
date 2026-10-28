#!/usr/bin/env python3
"""Deterministic fixture and command tests without network or Cargo compilation."""
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).with_name("affected-tests")
loader = importlib.machinery.SourceFileLoader("affected_tests", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
METADATA = json.loads((SCRIPT.parent / "fixtures/affected-tests/metadata.json").read_text())


class AffectedTests(unittest.TestCase):
    def test_leaf(self):
        self.assertEqual(module.select_packages(["crates/app/src/lib.rs"], METADATA), ["fixture-app"])

    def test_core_transitive_build_dev_and_alias(self):
        self.assertEqual(module.select_packages(["crates/core/src/lib.rs"], METADATA),
                         ["fixture-app", "fixture-core", "fixture-leaf"])

    def test_docs_only(self):
        self.assertEqual(module.select_packages(["docs/guide.md", "README.md"], METADATA), [])

    def test_global_triggers(self):
        for filename in ["Cargo.lock", "Cargo.toml", ".cargo/config.toml", "rust-toolchain.toml", "build.rs", "crates/leaf/Cargo.toml", "crates/leaf/tests/fixture.json", "scripts/build.sh", "docs/example.rs"]:
            with self.subTest(filename=filename):
                self.assertIsNone(module.select_packages([filename], METADATA))

    def test_deleted_crate(self):
        self.assertIsNone(module.select_packages(["crates/deleted/src/lib.rs"], METADATA))

    def test_crate_manifest_and_non_rust_fixture(self):
        for filename in ["crates/leaf/tests/fixture.txt", "crates/leaf/README.md"]:
            self.assertEqual(module.select_packages([filename], METADATA), ["fixture-app", "fixture-leaf"])

    def test_multiple_owners_and_unusual_filename(self):
        self.assertEqual(module.select_packages(
            ['crates/core/src/old\n"$name.rs', 'crates/leaf/src/new.rs'], METADATA),
            ["fixture-app", "fixture-core", "fixture-leaf"])

    def test_unknown_and_embedded_inputs_fail_safe(self):
        for filename in ["scripts/helper", "docs/example.rs", "new-input"]:
            with self.subTest(filename=filename):
                self.assertIsNone(module.select_packages([filename], METADATA))
        self.assertEqual(module.select_packages(["crates/core/src/help.md"], METADATA),
                         ["fixture-app", "fixture-core", "fixture-leaf"])

    def test_deduplicated_cycle(self):
        metadata = copy.deepcopy(METADATA)
        metadata["resolve"]["nodes"][0]["deps"] = [{"pkg": "app-id"}]
        self.assertEqual(module.select_packages(["crates/core/src/lib.rs", "crates/app/src/lib.rs"], metadata),
                         ["fixture-app", "fixture-core", "fixture-leaf"])

    def invoke(self, arguments, files, metadata=METADATA, status=0):
        output = io.StringIO()
        with patch("sys.argv", [str(SCRIPT), *arguments]), patch.object(module.subprocess, "check_output") as read, \
                patch.object(module.subprocess, "call", return_value=status) as run, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            read.side_effect = [files.encode(), json.dumps(metadata).encode() if metadata else subprocess.CalledProcessError(1, "cargo")]
            result = module.main()
        return result, output.getvalue(), read, run

    def test_print_and_nul_paths(self):
        result, output, read, run = self.invoke(["main", "branch"], "crates/app/tests/a \"quoted\".rs\0")
        self.assertEqual((result, output), (0, "fixture-app\n"))
        self.assertIn("main...branch", read.call_args_list[0].args[0])
        self.assertIn("--no-renames", read.call_args_list[0].args[0])
        run.assert_not_called()

    def test_run_and_failure_status(self):
        result, _, _, run = self.invoke(["--run"], "crates/app/src/lib.rs\0", status=7)
        self.assertEqual(result, 7)
        self.assertEqual(run.call_args.args[0], ["cargo", "test", "--locked", "--all-targets", "--no-fail-fast", "--package", "fixture-app"])

    def test_metadata_failure_selects_all(self):
        self.assertEqual(self.invoke([], "crates/app/src/lib.rs\0", metadata=None)[1], "ALL\n")
        _, _, _, run = self.invoke(["--run"], "crates/app/src/lib.rs\0", metadata=None)
        self.assertIn("--workspace", run.call_args.args[0])

    def test_global_and_docs_skip_metadata(self):
        for filename, expected in [("Cargo.lock", "ALL\n"), ("README.md", "")]:
            _, output, read, _ = self.invoke([], filename + "\0")
            self.assertEqual(output, expected)
            self.assertEqual(read.call_count, 1)

    def test_empty_diff_skips_metadata_and_tests(self):
        _, output, read, run = self.invoke(["--run"], "")
        self.assertEqual(read.call_count, 1)
        run.assert_not_called()
        self.assertEqual(output, "No affected Rust packages.\n")

    def test_docs_run_skips_tests(self):
        _, _, _, run = self.invoke(["--run"], "docs/guide.md\0")
        run.assert_not_called()

    def test_malformed_metadata_selects_all(self):
        result = self.invoke([], "crates/app/src/lib.rs\0", metadata={"bad": True})
        self.assertEqual(result[1], "ALL\n")

    def test_git_failure_does_not_run_tests(self):
        with patch("sys.argv", [str(SCRIPT), "--run"]), \
                patch.object(module.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, "git")), \
                patch.object(module.subprocess, "call") as run, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                module.main()
        self.assertEqual(raised.exception.code, 1)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
