#!/usr/bin/env bash
# Print a cargo-nextest filterset covering only the workspace crates affected by
# the diff BASE...HEAD (each changed crate plus every crate that depends on it).
# Prints "all()" when anything workspace-wide changed (manifests, lockfile,
# toolchain, CI config, build scripts outside a crate) so nothing is missed.
# Prints "none()" when no Rust-relevant file changed.
set -euo pipefail
base="${1:?base sha}"; head="${2:?head sha}"
files="$(git diff --name-only "$base...$head")"
[ -n "$files" ] || { echo "none()"; exit 0; }
meta="$(cargo metadata --no-deps --format-version 1 --locked)"
python3 - "$meta" <<PY
import json, os, sys
meta = json.loads(sys.argv[1])
root = meta["workspace_root"]
crates = {}
for p in meta["packages"]:
    d = os.path.relpath(os.path.dirname(p["manifest_path"]), root)
    crates[d] = p["name"]
files = """$files""".split()
global_triggers = ("Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml",
                   ".cargo/", ".config/nextest", ".github/", "deny.toml", "clippy.toml", "rustfmt.toml")
hit = set()
for f in files:
    if f in global_triggers or any(f.startswith(t) for t in global_triggers if t.endswith("/")):
        print("all()"); sys.exit(0)
    owner = max((d for d in crates if d != "." and (f == d or f.startswith(d + "/"))), key=len, default=None)
    if owner:
        if f.endswith(".md"):
            continue
        hit.add(crates[owner])
    elif "." in crates and f.endswith(".rs"):
        hit.add(crates["."])
print(" | ".join(f"rdeps(={c})" for c in sorted(hit)) if hit else "none()")
PY
