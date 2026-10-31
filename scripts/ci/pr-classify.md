# PR classification: suites, OS matrix, CodeQL languages

`scripts/ci/pr-classify.mjs` computes every changed-file classification that
`ci.yml` and `codeql.yml` need, in one unit-tested engine. It reworks #547 on
the post-diet main (reworks-#547): the pull-request Test matrix that #547
thinned no longer runs on PRs, but three of its hardening changes still matter
and none of them were landed:

1. **`full-ci` label alias** — `full-ci` now means `ci:full-os`.
2. **Tier-1 owned paths select the OS matrix** — any path matched by the base
   ref's `.github/CODEOWNERS` (merged in #545 after #547 branched) selects the
   macOS/Windows legs.
3. **Unreadable diff fails closed** — a failed `git diff` selects every suite,
   the full matrix, and every CodeQL language instead of failing the Classify
   job. Today's inline bash dies under `set -e`; a transient fetch or object
   error would fail the required `CI Gate`.
4. **CodeQL config widen** — any `.github/` or build/dependency-config change
   (`Cargo.*`, `rust-toolchain`, `build.rs`, `package-lock.json`, `tsconfig*`,
   `pyproject.toml`, `requirements*`, `Gemfile*`, `*.gemspec`, `.cargo/`) scans
   all five languages, closing gaps on main where a `rust-toolchain.toml`-only
   or `.github/CODEOWNERS`-only diff scanned nothing.

One rule is deliberately stricter than the inline bash it replaces: an
unreadable (e.g. deleted) `.rs` is platform-relevant, matching
`daily-matrix.mjs`'s fail-closed direction; the workflow's `[ -f "$f" ] && grep`
silently skips it.

## Usage

```bash
node scripts/ci/pr-classify.mjs [classify] [opts]
```

```
--event NAME            github.event_name (default $EVENT, else pull_request)
--base SHA [--head SHA] git diff --name-only BASE...HEAD
--files PATH|-          newline-separated changed paths ('-' reads stdin)
--labels a,b,c          pull_request label names (default $LABELS)
--codeowners PATH       CODEOWNERS text; default is BASE:.github/CODEOWNERS
--no-codeowners         skip Tier-1 matching entirely
--github-output         append every output to $GITHUB_OUTPUT
--explain               per-output reasons on stderr
```

Emitted keys (`languages` is a JSON array for `fromJSON`):

```
rust web temporal_example docs_commands   # ci.yml `classify` step
platform                                  # ci.yml `platform` step
code languages                            # codeql.yml `classify` step
```

Non-`pull_request` events emit the full surface (`docs_commands=false`, the
same as today's early exit). A `pull_request` with no `--files`/`--base` exits
2 rather than guessing.

## Selection rules (fail closed toward more coverage)

- **platform**: `ci:full-os`/`full-ci` label, platform-relevant path regex
  (manifests, toolchain, `.cargo/`, workflows, installers, `npm*/`,
  `windows|macos|unix|platform` segments), a Tier-1 CODEOWNERS match, an
  OS-gated `cfg(...)`/`cfg!(...)` in a changed `.rs`, an unreadable `.rs`, or
  an unreadable diff.
- **CODEOWNERS** (ported from #547's reviewed awk): comments and blank lines
  skipped; leading `*` -> substring, leading `/` or a mid-pattern `/` ->
  repo-root prefix, otherwise a path-segment match; leading `*`/`/` stripped,
  pattern cut at the next `*`; a bare `*` owns every path. `*` patterns are
  kept, so `*.c` also matches `.cpp` — over-selection is the safe direction.
  Missing CODEOWNERS only removes a trigger that can widen coverage.
- **codeql languages**: docs-only diffs scan nothing; any all-config path
  scans all five; otherwise each language's file patterns select it; an empty
  language set means `code=false` (the Analyze job is skipped).

## Wiring (G1-gated workflow patch; `.github/` is not touched by this change)

`ci.yml` — replace the inline `classify` and `platform` step bodies:

```yaml
      - id: classify
        env:
          EVENT: ${{ github.event_name }}
          BASE: ${{ github.event.pull_request.base.sha }}
          HEAD: ${{ github.event.pull_request.head.sha }}
        run: |
          set -euo pipefail
          node scripts/ci/pr-classify.mjs --event "$EVENT" --base "$BASE" --head "$HEAD" --github-output
          # Then forward the four suite outputs exactly as today, e.g.
          # grep '^rust=' and re-emit, or emit all keys in one step.
```

```yaml
      - id: platform
        env:
          EVENT: ${{ github.event_name }}
          LABELS: ${{ join(github.event.pull_request.labels.*.name, ',') }}
          BASE: ${{ github.event.pull_request.base.sha }}
          HEAD: ${{ github.event.pull_request.head.sha }}
        run: |
          set -euo pipefail
          node scripts/ci/pr-classify.mjs --event "$EVENT" --base "$BASE" --head "$HEAD" \
            --labels "$LABELS" --github-output --explain
```

`codeql.yml` — same call inside `classify`; the job keeps its
`languages -> fromJSON` matrix, or adopts #547's skip-step matrix unchanged
(`contains(langs, format(',{0},', matrix.language))`) — both consume the same
emitted keys.

Two notes for the G1 reviewer:

- On the post-diet main the `platform` output is only consumed by jobs that
  never run on `pull_request`; wiring Tier-1/label PR OS legs back in also
  needs the `test` job's `if:` relaxed for labelled PRs. That re-opens the
  Oct-28 "merge fast, test later" decision, so this engine lands the tested
  semantics and leaves that policy switch to the workflow patch.
- `--labels` uses `join(...)`; a label containing a comma is ignored (GitHub
  label names cannot contain commas).

## Tests

```bash
node --test scripts/ci/pr-classify.test.mjs
```

The suite covers every output of both workflows' classify steps, label
aliases, Tier-1 mode semantics against the repository's real
`.github/CODEOWNERS`, cfg gating, and every fail-closed fallback. It runs in
`scripts/fast-check.sh` alongside `daily-matrix.test.mjs`.
