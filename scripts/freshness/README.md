# Freshness generator

Source-of-truth regeneration for versioned documentation blocks. The
release version is read from the `Cargo.toml` `[workspace.package]`
version and cross-checked against `npm/package.json`,
`npm-mcp/package.json`, and the latest released `CHANGELOG.md` section.
When those sources disagree the tools fail closed.

## Invocation

This is a Cargo workspace with no root `package.json`, so the scripts are
run directly with Node:

```bash
node scripts/freshness/sync.mjs    # rewrite stale blocks in place
node scripts/freshness/check.mjs   # exit 0 when fresh, 1 on drift
node --test scripts/freshness/freshness.test.mjs
```

`check.mjs` is the CI hook: call it in a workflow to fail the build when a
release version bump leaves generated documentation behind. Both commands
accept `--root DIR` to run against a different repository root, which the
test suite uses for fixtures.

## Markers

A block is a `fresh:begin`/`fresh:end` marker pair on their own lines:

```markdown
<!-- fresh:begin readme-release-badges -->
...generated content...
<!-- fresh:end -->
```

Everything between the markers is generated; everything outside them is
left byte-for-byte untouched. Unknown block names, missing `fresh:end`
markers, nested blocks, and stray `fresh:end` lines are hard errors.

## Block types

Each registered block name has a type (`scripts/freshness/blocks.mjs`):

| Type | Purpose | Example block |
|------|---------|---------------|
| `version-badge` | Shields badges carrying the release tag and changelog anchor | `readme-release-badges` in `README.md` |
| `install-snippet` | Install/verify commands with an exact version pin | `npm-cli-install` in `npm/README.md` |
| `version-table` | Tables whose rows embed the release tag in URLs | `readme-release-asset-table` in `README.md` |
| `version-pin` | Prose or link references that pin the release version | `changelog-unreleased-compare` in `CHANGELOG.md` |

## Seeded blocks

| File | Block |
|------|-------|
| `README.md` | `readme-release-badges`, `readme-release-asset-table` |
| `docs/getting-started.md` | `docs-release-asset-table`, `docs-verify-version-output` |
| `examples/github-actions/README.md` | `examples-gate-verified-release` |
| `npm/README.md` | `npm-cli-wrapper-version`, `npm-cli-install` |
| `npm-mcp/README.md` | `npm-mcp-wrapper-version`, `npm-mcp-install` |
| `CHANGELOG.md` | `changelog-unreleased-compare` |

To add a block, register a generator in `GENERATORS`, wrap the target
region in markers, run `sync.mjs`, and extend `freshness.test.mjs`.
