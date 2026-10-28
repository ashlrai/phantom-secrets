# Affected Cargo tests

Run `scripts/affected-tests BASE` to compare the merge base of BASE and HEAD
against HEAD. With no BASE, tracked staged and unstaged changes are compared
against HEAD. An optional second revision selects a different head. Output is
one package name per line, `ALL` for the full workspace, or empty for no
relevant changes. Add `--run` to execute the selected Cargo tests.

Changes select the owning package and its transitive workspace dependents.
Renames are treated as a deletion and an addition, so both owners are selected.
Cargo manifests, lockfiles, configuration files, and unknown shared inputs
select the full workspace. Only root Markdown and license/notice files, and
Markdown, reStructuredText, or text files under `docs/`, are treated as
unconditionally documentation-only. Files within packages, including embedded
Markdown and fixtures, affect their owning package unless they trigger the full
workspace rule. A failed Cargo metadata lookup selects the full workspace; a
failed Git diff exits nonzero and does not run tests.

Run selector tests with `HOME=$(mktemp -d) python3 scripts/affected-tests.test.py`.
