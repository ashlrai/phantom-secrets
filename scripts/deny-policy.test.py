import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class KeyringMigrationPolicyTests(unittest.TestCase):
    def test_tracking_note_identifies_the_existing_keyring_ignores(self):
        source = (ROOT / "deny.toml").read_text(encoding="utf-8")
        policy = tomllib.loads(source)
        ignores = {entry["id"]: entry["reason"] for entry in policy["advisories"]["ignore"]}
        note = "\n".join(line for line in source.splitlines() if line.lstrip().startswith("#"))

        self.assertIn("#242", note)
        self.assertIn("docs/design/keyring-4-migration-scoping.md", note)
        for advisory, crate in (
            ("RUSTSEC-2026-0370", "zvariant"),
            ("RUSTSEC-2026-0371", "zbus_names"),
            ("RUSTSEC-2026-0372", "zvariant_derive"),
        ):
            with self.subTest(advisory=advisory):
                self.assertRegex(note, re.escape(advisory) + r"\s*(?:#\s*)?\(" + crate + r"\)")
                self.assertIn(crate, ignores[advisory])


if __name__ == "__main__":
    unittest.main()
