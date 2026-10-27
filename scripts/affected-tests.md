# Affected Cargo tests

Run `scripts/affected-tests BASE` from a Git worktree with Node.js and Cargo on
PATH. The script compares the merge base of `BASE` and `HEAD` to `HEAD`.
Uncommitted changes are excluded.

Output is one line: a sorted JSON array of Cargo package names, `[]` for no
changes or documentation-only changes, or the literal `ALL` for lockfiles,
manifests, configuration, and unknown shared inputs. For a package list, run
`cargo test --locked -p NAME --all-targets` for each name. For `ALL`, run
`cargo test --workspace --all-targets --locked --no-fail-fast`.

Module and test-file changes select the owning package plus every transitive
workspace dependent, including dev, build, optional, and platform dependencies.
Package names come from offline Cargo metadata, not directory names. Renames
select both source and destination owners. Files inside a crate, including
embedded documentation and fixtures, select that crate. Only root Markdown,
license/notice files, and Markdown/text documentation under `docs/` are excluded.
Unknown paths deliberately select the full suite. No workflows are changed.

Errors return nonzero with no selection on stdout. Callers must fail the job or
run the full suite on errors, never interpret an error as an empty selection.
The script does not read changed file contents or execute tests.

Run its fixture and temporary-repository tests with:

```sh
HOME=$(mktemp -d) node --test scripts/affected-tests.test.cjs
```

Keep `CARGO_HOME` and `RUSTUP_HOME` pointed at the installed toolchain when
running with a temporary home. Tests create only local fixture commits.
