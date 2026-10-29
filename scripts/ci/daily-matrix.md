# Daily matrix: off-peak cron and affected-only OS legs

`scripts/ci/daily-matrix.mjs` is the engine for the daily full-suite run's
queue-wait fix (RQ-FULLSUITE-QUEUE-PS). The nightly run measured at a 7035s
wall against job times of 410s (windows), 324s (macos) and 228s (ubuntu): nearly
all of it was runner queue inside the org's nightly cluster. Two levers fix it:

1. **Additive off-peak cron** — a second `schedule:` entry inside the off-peak
   window declared in `offpeak-schedule.json` (currently `43 3 * * *`,
   02:00–05:30 UTC). The existing `7 8 * * *` run stays as the full-matrix
   backstop; the new entry is purely additive, as is every `pull_request` and
   `merge_group` trigger and job.
2. **Affected-only matrix** — the off-peak run runs only the OS legs the day's
   diff can affect. Every emitted label is one of the exact `matrix.os` values
   `ci.yml` already uses, so `Test (${{ matrix.os }})` check names — and `CI
   Gate`, the single required check — are unchanged.

`estimate` projects the run's wall time from measured leg durations; the
schedule file's `wallBudgetSeconds` is the 900s acceptance target and the test
suite asserts every leg selection meets it.

## Usage

```bash
node scripts/ci/daily-matrix.mjs [matrix] [opts]  # JSON OS array for fromJSON(...)
node scripts/ci/daily-matrix.mjs estimate [opts]  # projected off-peak wall seconds
node scripts/ci/daily-matrix.mjs cron             # the configured off-peak cron
node scripts/ci/daily-matrix.mjs cron --check "7 8 * * *"  # in-window? exit 1 if not
node scripts/ci/daily-matrix.mjs cron --yaml      # the additive schedule: block
node scripts/ci/daily-matrix.mjs check-schedule   # validate offpeak-schedule.json
```

File selection (first wins; no selector means the full matrix):

```
--files PATH|-     newline-separated changed paths ('-' reads stdin)
--base SHA [--head SHA]   git diff --name-only BASE...HEAD
--since HOURS      diff HEAD against `git rev-list -n1 --before="N hours ago"`
--full             all three legs (escape hatch)
--github-output    append os_matrix=<json> to $GITHUB_OUTPUT
--explain          per-leg reasons and the wall estimate on stderr
```

## Leg selection rules (fail closed toward more coverage)

- Workspace-global inputs select all three legs: manifests, lockfiles,
  toolchains, `.github/workflows|actions`, `build.rs`, `deny.toml`, npm
  wrappers, `mcp-registry/`, installer scripts and their verifiers, this tool.
- Every `.rs` change selects `ubuntu-latest` plus whatever legs its `cfg`
  expressions name: `windows`/`unix`/`macos`/`linux` idents,
  `target_os`/`target_family`, `not(X)` complements, `any(...)` unions.
  `target_arch`/`target_env` and unknown cfg atoms select all three; an
  unreadable (e.g. deleted) `.rs` selects all three.
- Non-Rust paths route by name (`*.ps1` → windows, `*.plist` → macos,
  `unix/` → macos+ubuntu, `platform` → all three); everything else lands on
  the canonical `ubuntu-latest` leg.
- Documentation (`*.md`, `docs/`, `changelog.d/`, `LICENSE`), `apps/web/`,
  `scripts/supabase|seo/`, `video/` and `seo/` select no legs: no matrix leg
  can observe them. Files that compile into no crate are verified by
  `grep -rn 'include_str!' crates/` returning no `.md` references.

## Wiring (G1-gated workflow patch; `.github/` is not touched by this change)

Since RQ-CI-SECONDS (#576) the `Test` job never runs on `pull_request` or
`merge_group` — the PR-path runner savings #562 asked for are already in
place and locked by `scripts/ci/pr-path-contract.test.mjs`. The lever this
tool still powers is the daily run's queue wait: an additive off-peak cron
in `nightly-full.yml`, with `ci.yml` consulting an affected-only matrix only
on that run.

`nightly-full.yml` — add the off-peak cron and mark the call affected-only:

```yaml
on:
  schedule:
    - cron: "7 8 * * *"    # kept: existing full-matrix run
    - cron: "43 3 * * *"   # added: off-peak affected-only run
  workflow_dispatch:

jobs:
  ci:
    uses: ./.github/workflows/ci.yml
    with:
      affected_only: ${{ github.event.schedule == '43 3 * * *' }}
```

`ci.yml` — declare the input on `workflow_call`, emit `os_matrix` from
`changes`, and consult it on the affected run only:

```yaml
on:
  workflow_call:
    inputs:
      affected_only: { type: boolean, default: false }

# jobs.changes.outputs: add
#   os_matrix: ${{ steps.osmatrix.outputs.os_matrix }}

      - id: osmatrix
        env:
          AFFECTED: ${{ inputs.affected_only }}
        run: |
          set -euo pipefail
          # 25h diffs overlap the previous off-peak run by an hour; a failed
          # or empty base resolution selects the full matrix (fail closed).
          if [ "$AFFECTED" = "true" ]; then
            node scripts/ci/daily-matrix.mjs --since 25 --github-output --explain
          else
            node scripts/ci/daily-matrix.mjs --full --github-output
          fi

# jobs.test.strategy.matrix.os: the affected run uses os_matrix verbatim;
# every other event keeps the complete matrix. `platform` is constant-true
# on every event that can reach this job (its only PR consumers are gone),
# so the fallback is the literal three-leg array.
        os: ${{ fromJSON(inputs.affected_only && needs.changes.outputs.os_matrix
              || '["macos-latest", "ubuntu-latest", "windows-latest"]') }}
```

The `changes` job already checks out with `fetch-depth: 0`, so
`rev-list --before` resolves on every event.

### The empty selection is `skipped`, not `success`

A docs-only day legitimately emits `[]`, and a zero-cell matrix concludes the
Test job `skipped` — the gate's `full && rust` expectation requires
`success`, so the patch must extend it on the affected run only:

```yaml
# gate expect table:
#   'test': full && rust && !(affected && osMatrix === '[]')  — and accept
#           'skipped' from test when affected && osMatrix === '[]'
#   'windows-arm-source-check':
#       full && rust && platform && (!affected || osMatrix.includes('windows-latest'))
#   'coverage' stays ungated, but its if gains
#       && (!affected || osMatrix.includes('ubuntu-latest'))
```

`windows-arm-source-check` gets the same affected gate in its job `if`
(`&& (!inputs.affected_only || contains(fromJSON(needs.changes.outputs.os_matrix), 'windows-latest'))`)
so a windows-less selection skips the ARM64 runner, and `coverage` needs the
matching `ubuntu-latest` clause because the lcov artifact is produced only on
the Linux leg — without it a non-ubuntu selection fails the
`test -s coverage/lcov.info` step.

### Cleanup the same patch can land

The `platform` classify step, its `changes` output, the `ci:full-os` label
plumbing (`FULL_OS` env), and the `affected`/`filterset` machinery are
vestigial: `platform` is constant-true and `filterset` unread on every event
where their only consumers run, so removing them is behavior-identical.
`scripts/ci/affected-filterset.sh` is deleted with the `affected` step.

Optionally, feed the same `--since 25` file list to the existing `classify`
step's regexes on the affected run so the `web`/`temporal-codec-example`/
`docs-commands`/`crate-publication-contract` jobs also deselect like a pull
request — that is a refinement, not a requirement.

## Tests

```bash
node --test scripts/ci/daily-matrix.test.mjs scripts/ci/pr-path-contract.test.mjs
```

The suite covers leg routing, cfg complement semantics, cron parsing and the
off-peak window, schedule-data validation, the 900s estimate for every leg
selection, fail-closed fallbacks, and a read-only contract that every emitted
OS label is a check name `ci.yml` already produces.
`pr-path-contract.test.mjs` is the sibling read-only contract locking the
pull-request/merge-queue fast-path split and the diff-scoped CodeQL matrix
described above.
