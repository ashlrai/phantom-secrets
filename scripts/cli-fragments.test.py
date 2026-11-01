"""Exercise Git's three-way merge on real CLI source and test fragments.

No refs, commits, index, network, credentials, or worktree files are changed.
Run with: python3 scripts/cli-fragments.test.py
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'crates/phantom-cli/src'


def merge(ours, base, theirs):
    with tempfile.TemporaryDirectory() as directory:
        paths = [Path(directory) / name for name in ('ours', 'base', 'theirs')]
        for path, content in zip(paths, (ours, base, theirs)):
            path.write_text(content)
        result = subprocess.run(
            ['git', 'merge-file', '-p', *map(str, paths)],
            capture_output=True, text=True, check=False,
        )
        return result.returncode, result.stdout


class CliFragments(unittest.TestCase):
    def test_independent_command_and_test_changes_merge_in_both_orders(self):
        base = {}
        lanes = {}
        for family, enum in [('agent', 'AgentAction'), ('validate', 'ValidateAction')]:
            source = f'cli_actions/{family}.rs'
            tests = f'cli_tests/{family}.rs'
            base[source] = (SRC / source).read_text()
            base[tests] = (SRC / tests).read_text()
            # Add a clap alias and its parser regression without changing dispatch.
            lanes[family] = {
                source: base[source].replace(
                    f'pub(crate) enum {enum} {{',
                    f'pub(crate) enum {enum} {{\n    #[command(alias = "fragment-probe")]',
                    1,
                ),
                tests: base[tests] + (
                    '\n#[test]\nfn fragment_probe() {\n'
                    f'    assert!(Cli::try_parse_from(["phantom", "{family}", '
                    '"fragment-probe"]).is_ok());\n}\n'
                ),
            }
            self.assertNotEqual(lanes[family][source], base[source])
            # Both fragments must be wired into the compiled module tree.
            for folder in ['cli_actions', 'cli_tests']:
                self.assertIn(f'mod {family};', (SRC / folder / 'mod.rs').read_text())
        for first, second in [('agent', 'validate'), ('validate', 'agent')]:
            for path, original in base.items():
                ours = lanes[first].get(path, original)
                theirs = lanes[second].get(path, original)
                status, merged = merge(ours, original, theirs)
                self.assertEqual(status, 0, path)
                self.assertEqual(merged, lanes[first].get(path, lanes[second].get(path)))

    def test_same_insertion_point_still_conflicts(self):
        # Control: use Git's normal conflict semantics, never a union driver.
        status, _ = merge('header\nagent\n', 'header\n', 'header\nvalidate\n')
        self.assertEqual(status, 1)


if __name__ == '__main__':
    unittest.main()
