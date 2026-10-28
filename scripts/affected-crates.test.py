import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('affected', Path(__file__).with_name('affected-crates.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def package(name, deps=()):
    return {'id': name, 'name': name, 'manifest_path': f'/repo/crates/{name}/Cargo.toml',
            'dependencies': [{'path': f'/repo/crates/{dep}'} for dep in deps]}


class MappingTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {'workspace_root': '/repo', 'workspace_members': ['a', 'b', 'c', 'd'],
                         'packages': [package('a'), package('b', ['a']),
                                      package('c', ['b']), package('d')]}

    def select(self, *paths):
        return module.select(self.metadata, paths)

    def test_transitive_reverse_dependencies(self):
        self.assertEqual(self.select('crates/a/src/lib.rs'), ['a', 'b', 'c'])
        self.assertEqual(self.select('crates/d/src/main.rs'), ['d'])
        self.assertEqual(self.select('crates/b/src/lib.rs', 'crates/d/src/main.rs'), ['b', 'c', 'd'])

    def test_full_fallback(self):
        for path in ('Cargo.lock', 'crates/a/Cargo.toml', 'crates/a/build.rs',
                     'crates/a/tests/example.rs', 'crates/a/src/test_helpers/mod.rs',
                     'crates/a/fixtures/data', '.cargo/config.toml', 'README.md',
                     'crates/a/src/settings.toml', 'unknown.rs'):
            with self.subTest(path=path):
                self.assertIsNone(self.select(path))

    def test_empty_and_mixed(self):
        self.assertEqual(self.select(), [])
        self.assertIsNone(self.select('crates/a/src/lib.rs', 'unknown.rs'))


if __name__ == '__main__':
    unittest.main()
