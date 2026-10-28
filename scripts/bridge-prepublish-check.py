#!/usr/bin/env python3
"""Check the cleared abort-row location without disclosing source content."""

from pathlib import Path
import subprocess
import sys


def base_line_is_cleared(base_ref: str = "HEAD") -> bool:
    root = Path(__file__).resolve().parent.parent
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}"],
            cwd=root,
            capture_output=True,
            check=True,
        ).stdout.strip().decode("ascii")
        source = subprocess.run(
            ["git", "show", f"{commit}:crates/phantom-cli/src/commands/check.rs"],
            cwd=root,
            capture_output=True,
            check=True,
        ).stdout.split(b"\n")
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        return False

    # The clearance is for this exact base line, never a nearby match.
    return len(source) >= 1796 and b"REGION_" in source[1795]


def main() -> int:
    passed = len(sys.argv) <= 2 and base_line_is_cleared(
        sys.argv[1] if len(sys.argv) == 2 else "HEAD"
    )
    print("pass" if passed else "fail")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
