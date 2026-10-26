# Site freshness generator

Source-of-truth regeneration for versioned blocks on the public site
(`apps/web`) and the machine-readable docs files it serves (`docs/llms*.txt`,
`docs/sitemap.xml`). This is the site-local counterpart of
`scripts/freshness/` (RQ-FRESH-GEN-PS); it shares the `fresh:begin`/`fresh:end`
marker contract so the two can merge once that stack lands.

## Invocation

Run from the repository root or this directory:

```bash
node apps/web/scripts/freshness/sync.mjs    # rewrite stale blocks in place
node apps/web/scripts/freshness/check.mjs   # exit 0 when fresh, 1 on drift
```

Both accept `--root DIR` to run against a different repository root (the test
suite uses this for fixtures). `npm run freshness` and `npm run freshness:sync`
in `apps/web` wrap the same commands, and `tests/freshness.test.cjs` runs the
drift check under `node --test`.

## Sources

`sources.mjs` loads everything a generated block may use and fails closed on
disagreement:

- Release version: `Cargo.toml` `[workspace.package]` version, cross-checked
  against `npm/package.json`, `npm-mcp/package.json`, `apps/web/package.json`,
  `mcp-registry/server.json`, and the latest released `CHANGELOG.md` section.
- MCP tool names, parameters, and descriptions: `mcp-registry/server.json`
  (the file CI pins to the runtime `tools/list`).
- `phantom setup --client` ids, labels, and config paths: the `Client` enum in
  `crates/phantom-cli/src/commands/setup.rs`.
- CLI command groups (`phantom --help` headings): the `Commands` enum in
  `crates/phantom-cli/src/main.rs`.
- Release evidence (source commit, tag object, workflow URL): the bound
  `PUBLIC_RELEASE_*` constants in `apps/web/src/lib/public-release.ts`,
  verified against `git rev-parse v<tag>` when the tag resolves locally.
- Sitemap `lastmod` dates: `git log -1 --format=%cs` per page source file.
  Routes whose source file is itself a freshness target use the release date
  instead, so a sync commit does not immediately stale them.

## Markers

A block is a `fresh:begin`/`fresh:end` pair on their own lines, in the file's
comment style (`<!-- ... -->` for text/markup, `//` for TypeScript, `#` for
shell/config):

```
<!-- fresh:begin release-receipt -->
...generated content...
<!-- fresh:end -->
```

Unknown block names, missing or nested markers, stray `fresh:end` lines, and
blocks a file does not register in `TARGETS` are hard errors.

## Coverage

Generated: version strings and release pins, Homebrew/GitHub/source install
commands, `phantom setup --client` tables and lists, the complete MCP tool
catalog, the grouped CLI surface line, release-identity receipts, and sitemap
dates in the files listed under `TARGETS` in `blocks.mjs`.

Hand-maintained: verified-evidence prose around the markers (readback dates,
registry snapshots, Homebrew tap state, governance observations), all curated
documentation, and everything in files without markers. To add a block,
register a generator in `GENERATORS`, wrap the target region in markers, run
`sync.mjs`, and extend `tests/freshness.test.cjs`.
