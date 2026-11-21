# Contributing to Phantom

Thanks for helping make safe agentic development practical. Phantom accepts focused bug fixes, tests, platform hardening, service integrations, documentation, and carefully scoped feature work.

Please read the [Code of Conduct](CODE_OF_CONDUCT.md), [security policy](SECURITY.md), and [threat model](THREAT_MODEL.md) before changing a trust boundary. Report vulnerabilities privately; do not open a public issue for them.

## Agents and the Ashlr ecosystem

Phantom Secrets is one of the open-source tools from [Ashlr](https://ashlr.ai).
Together they aim to be an autonomous, code-first, agent-native software
factory: coding agents write, test, review, and ship the code, and the human
acts as a passive board member. The long-term goal is open-source recursive
self-improvement (RSI), where agents improve the tools they build with. The
[README](README.md#part-of-the-ashlr-ecosystem) lists the other tools and how
each one fits.

Most changes here come from coding agents. They use the same branches, pull
requests, and CI as human contributors, and this guide applies to both:

- Agents read [AGENTS.md](AGENTS.md) first. It holds their operating rules, the
  security floor, and how to use Phantom without seeing vault values.
  [CLAUDE.md](CLAUDE.md) lists the build, test, lint, and format commands.
- An agent never needs a real secret value to work on this repository. Use the
  value-free commands such as `phantom status --json` and
  `phantom why OPENAI_API_KEY --json`, and use fake values in tests.
- Agent-authored pull requests must pass the same [verification](#verification)
  gates and follow the same [security guidelines](#coding-and-security-guidelines)
  as any other change.

### Contribute with an agent

The shortest path from a fork to a merged pull request, for a person or a
coding agent. Each step links to the detail further down.

1. **Fork and clone.** Fork `ashlrai/phantom-secrets` on GitHub, clone your
   fork, add this repository as `upstream`, and branch from its current
   `main`. Point your agent at [AGENTS.md](AGENTS.md) and
   [CLAUDE.md](CLAUDE.md) before it edits anything.

   ```bash
   git clone https://github.com/<your-user>/phantom-secrets.git
   cd phantom-secrets
   git remote add upstream https://github.com/ashlrai/phantom-secrets.git
   git fetch upstream
   git switch -c my-change upstream/main
   ```

   The later checks diff against `main`. On a fork, pass `upstream/main`
   instead (for example `scripts/fast-check.sh upstream/main`) or keep your
   local `main` in sync with it.
2. **Set up.** Install the toolchain under
   [Development setup](#development-setup). The workspace is Rust and has no
   root `package.json`, but every change also needs Node.js and Perl for the
   two pre-push checks, and `scripts/fast-check.sh` needs Bash and Python 3.
   npm is needed only for the npm wrappers and `apps/web`.
3. **Check what you changed.** `scripts/fast-check.sh main` runs format,
   Clippy, and tests for only the crates your branch touches plus their
   dependents, and it includes uncommitted and untracked files, so you can
   run it before you commit. The narrowing applies only when every changed
   file is Rust source under a crate's `src/`; any other changed path, such
   as a doc, a script, a `Cargo.toml`, or a file under `tests/`, checks the
   whole workspace (it needs Cargo, Node.js, and Python 3; see
   [Testing affected Rust packages](#testing-affected-rust-packages)). For a
   docs-only change, skip it and run the docs drift checks, which pull
   request CI also skips:
   `node --test scripts/release/readme-mcp-catalog.test.mjs`,
   `node --test scripts/docs-distribution.test.mjs`,
   `node --test scripts/hot-file-rule.test.mjs`, and
   `cargo test --locked -p phantom-secrets --test docs_command_flags_test`
   (see [README.md](README.md#contributing) for what each one checks), plus
   every suite that reads the file you edited. Not all of them are under
   `scripts/`: suites in `apps/web/tests/` also check root files such as
   `CONTRIBUTING.md`, `README.md`, and the PR template, and only the daily
   web job runs them. List them by the edited file's name, for example
   `git grep -l -F CONTRIBUTING.md -- '*.test.*'`, and run each with
   `node --test <file>`. A web suite that loads a package, such as
   `apps/web/tests/public-claims.test.cjs` (which needs `typescript`), fails
   with `Cannot find module` until you run `(cd apps/web && npm ci --no-audit)`.
   For an `apps/web` change, run the web
   application commands under [Verification](#verification): pull request CI
   skips the web job, which runs only in the daily full run. When the change
   shows a `phantom` command in `apps/web/src` or `apps/web/public/llms*.txt`,
   also run `cargo test --locked -p phantom-secrets --test docs_command_flags_test`,
   which checks those commands against the CLI help.
4. **Run the full gate once** before you open the pull request: the three
   commands under [Verification](#verification). Pull request CI does not run
   the Rust test suite, so this local run is the test evidence reviewers see.
   To predict `CI Gate` before you push, see
   [Reproduce the pull request jobs locally](#reproduce-the-pull-request-jobs-locally).
5. **Add a changelog fragment** in [`changelog.d/`](changelog.d/README.md)
   instead of editing `CHANGELOG.md`, and keep shared index files out of the
   diff per the [hot-file rule](AGENTS.md#hot-file-rule-avoid-merge-conflicts).
   Before you push, run the two pre-push checks under
   [Pull requests](#pull-requests): the fragment check and the secret-shape
   scan that `CI Gate` requires. Then push to your fork with
   `git push -u origin my-change` and open the pull request against `main`
   with the
   [template](.github/PULL_REQUEST_TEMPLATE.md) filled in, including the exact
   commands you ran. The template has one command block for code changes and
   one for documentation-only changes; keep the one that applies. The
   `publish.sh` push wrapper that [AGENTS.md](AGENTS.md) mentions belongs to
   the Ashlr fleet's own agents and is not in this repository; from a fork,
   plain `git push` is the whole step (see
   [Agents working for an outside contributor](AGENTS.md#agents-working-for-an-outside-contributor)).
6. **Merge.** `CI Gate` is the only required check. A pull request that passes
   it is merged through the merge queue, which reruns `CI Gate` on the queued
   merge commit. Someone with merge rights merges it or enables GitHub
   auto-merge. Fork contributors never need write access or repository
   secrets. If the gate fails, see [When `CI Gate` fails](#when-ci-gate-fails).
   A change to a path in [`.github/CODEOWNERS`](.github/CODEOWNERS), such as a
   workflow, a security-sensitive crate, or the web API and auth code, also
   requests a review from its code owner;
   [GOVERNANCE.md](GOVERNANCE.md#roles) explains that whether that review is
   required is repository state.

Current release state changes with every release, so this file does not pin
it. See the [latest GitHub release](https://github.com/ashlrai/phantom-secrets/releases/latest),
the [changelog](CHANGELOG.md), and the [roadmap](ROADMAP.md) for the evidence
gates. A GitHub release receipt alone does not establish an npm, crates.io,
MCP Registry, or Homebrew publication, deployment, provider integration,
hosted entitlement, certification, or customer acceptance.

## Before you start

- Search [existing issues](https://github.com/ashlrai/phantom-secrets/issues) and [discussions](https://github.com/ashlrai/phantom-secrets/discussions).
- Open an issue or discussion before a large architectural change, new network/provider integration, new secret-reveal path, compatibility break, or change to the authority model.
- Keep pull requests reviewable. Separate mechanical refactors from behavioral or security changes.
- Never use production credentials in development, tests, fixtures, screenshots, logs, or issue reports. Use obviously fake values and throwaway accounts.

## Development setup

Prerequisites:

- Git
- Rust `1.95.0` with `rustfmt` and `clippy` (pinned by `rust-toolchain.toml`)
- Node.js 22 (the version CI uses) for every change: the pre-push changelog
  fragment check, the docs drift checks, and the `scripts/*.mjs` suites need
  it; npm is needed only when changing npm wrappers or `apps/web`
- Perl 5 for the local `Secret-shape scan` (core modules only; macOS and most
  Linux distributions ship it, and Git for Windows includes it)
- Bash and Python 3 for `scripts/fast-check.sh` and the affected-package
  selectors
- A platform keychain only for explicitly ignored/manual keychain tests

Clone your fork as shown in
[Contribute with an agent](#contribute-with-an-agent), or clone this
repository directly if you only want to build and test:

```bash
git clone https://github.com/ashlrai/phantom-secrets.git
cd phantom-secrets

cargo build --workspace --locked
cargo test --workspace --all-targets --locked --no-fail-fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

On a machine where `cargo` is not on `PATH`, invoke the same commands through your rustup installation (for example, `~/.cargo/bin/cargo` on many Unix systems).

## Repository map

| Area | Purpose |
|------|---------|
| `crates/phantom-cli` | Operator CLI and command integration tests. |
| `crates/phantom-core` | Configuration, dotenv handling, cloud/auth clients, audit, validation, shared policy, and test-only provider protocol scaffolding. Production issuance is disabled. |
| `crates/phantom-cli/src/commands/grant` | Value-free grant metadata plus compatibility commands that hard-deny enrollment and remote revocation. |
| `crates/phantom-vault` | OS-keychain and encrypted-file vault backends. |
| `crates/phantom-proxy` | Authenticated loopback proxy, exact route-owned auth-header injection, inert client headers/bodies, response scrubbing, and streaming. |
| `crates/phantom-mcp` | MCP server, closed parameter schemas, the governed conversation facade, and separately gated compatibility tools. |
| `crates/phantom-workspace` | Value-blind workspace planning and trusted-terminal setup transactions. |
| `crates/phantom-authority` | Closed authority contracts; production verification remains deny-all. |
| `crates/phantom-locus-contract` | Inactive compatibility requirements for a future Locus integration. |
| `crates/phantom-broker` | Inactive broker protocol and durable replay/accounting foundations. |
| `crates/phantom-runtime` | Closed engineering actions and deny-all production execution boundary. |
| `crates/phantom-session` | Inactive crash-explicit session coordination foundation. |
| `crates/phantom-evidence` | Inactive value-free evidence and receipt foundation. |
| `npm`, `npm-mcp` | Native-binary download and launch wrappers. |
| `apps/web` | Next.js application and Phantom Cloud API. |
| `docs` | User guides, integration guides, static site assets, and the [documentation map](docs/README.md). |
| `mcp-registry` | MCP Registry manifest (`server.json`), which must match the runtime `tools/list`, and the registry listing README. |
| `examples` | Value-free examples and recipes; the [examples index](examples/README.md) states each one's status. |
| `integrations` | GitHub Actions, Homebrew, Railway, and Vercel integration notes. Each README states what works today; the GitHub Action is disabled in this release. |
| `eval/leak-rate` | Reproducible leak-rate harness and its results table. |
| `scripts` | Installers (`install.sh`, `install.ps1`), local check helpers (`fast-check.sh`, the affected-package selectors, `changelog-fold.mjs`), and the `*.test.mjs` docs and installer suites. `scripts/ci` holds CI change classification, `scripts/release` release and publication checks, and `scripts/freshness` the generator for versioned doc blocks. |
| `.github` | Workflows (`ci.yml` defines `CI Gate`), the pull request and issue templates, `CODEOWNERS`, and the secret-shape scanner in `.github/tests/secret-shape`. |
| `changelog.d` | One changelog fragment per pull request; see [Pull requests](#pull-requests). |
| `seo`, `video` | Search-observation experiment config read by `scripts/seo`, and the Remotion demo-video project. Neither is part of the shipped CLI. |

Do not infer production activation from a crate's presence. The execution-kernel
foundations must stay fail closed until the activation boundaries in
[`docs/architecture.md`](docs/architecture.md) and
[`THREAT_MODEL.md`](THREAT_MODEL.md) are resolved and accepted.

The word **grant** has two distinct meanings. Historical provider-grant source
models credential and renewal metadata, while an authority grant is an inactive
value-free execution-kernel type. Current releases create no live provider
grant: enrollment and remote revocation hard-deny before credentials or network
(see `crates/phantom-cli/src/commands/grant/`). A
provider-grant record must never be accepted as a Locus credential, broker
lease, or execution permit. Current behavior is specified in
[`docs/grants-spec.md`](docs/grants-spec.md); the root
[`ISSUANCE_CONTRACT.md`](ISSUANCE_CONTRACT.md) is the original design contract.

### Root files

The repository root also holds files that tools other than Cargo read. Most
changes touch none of them.

| File | Purpose |
|------|---------|
| `README.md`, `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `llms.txt` | Entry points for people and agents. `scripts/agent-entry-points-pre-push.test.mjs` checks that each one names the contributor path and the pre-push checks. |
| `SECURITY.md`, `THREAT_MODEL.md`, `GOVERNANCE.md`, `SUPPORT.md`, `CODE_OF_CONDUCT.md`, `LICENSE` | Project policy. A documentation pull request does not change what a policy means. |
| `CHANGELOG.md`, `ROADMAP.md`, `CITATION.cff` | Release history (add a `changelog.d/` fragment instead of editing it), the roadmap and its evidence gates, and citation metadata. |
| `INTEGRATION.md` | How this repository connects to the Phantom workbench through the CLI, the MCP server, and versioned JSON contracts. |
| `ISSUANCE_CONTRACT.md`, `DESIGN-connector-packs.md`, `DESIGN-onboarding-wizard.md` | A historical design contract and two proposals. None of them describes shipped behavior. |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`, `Makefile` | The workspace, the pinned toolchain, the `cargo deny` policy, and the `make test-affected` shortcut. |
| `.cursorrules`, `.devin/wiki.json` | The Cursor agent entry point and the DeepWiki outline; the same test checks both, along with `.github/copilot-instructions.md`. |
| `.pre-commit-hooks.yaml` | The `phantom-check` hook that other repositories install with pre-commit. It is not a hook for developing this repository. |
| `.gitattributes`, `.gitleaks.toml`, `.gitleaksignore` | The union merge for `CHANGELOG.md` and line-ending pins, and the `Source secret scan` configuration. |
| `.coderabbit.yaml`, `.sonarcloud.properties`, `codecov.yml`, `renovate.json`, `socket.yml` | Configuration for external review, analysis, coverage, dependency-update, and supply-chain services. None of them is a required check. |
| `glama.json`, `smithery.yaml` | MCP directory listing metadata. |
| `ashlr.verify.json` | A verification command list for the Ashlr fleet's own tooling. No workflow in this repository reads it; `CI Gate` and [Verification](#verification) are the contract. |
| `CODEOWNERS` | Inactive. GitHub reads [`.github/CODEOWNERS`](.github/CODEOWNERS) first; see [GOVERNANCE.md](GOVERNANCE.md#roles). |
| `.bridge-evidence/`, `.security/` | Dated triage notes from fleet agents and point-in-time security audit snapshots. They are records, not instructions or release attestations. |

## Making a change

These steps apply inside the
[Contribute with an agent](#contribute-with-an-agent) path; they describe the
change itself rather than the fork and merge mechanics.

1. Create a branch from the current `main` of this repository (`upstream/main`
   in a fork).
2. Find and reuse the existing parsing, filesystem, confirmation, error, and test patterns for the affected surface.
3. Add tests that demonstrate both the intended behavior and important failure modes.
4. Update user, agent, registry, and security documentation when a public contract changes.
5. Run the proportional checks under [Verification](#verification).
6. Add a [`changelog.d/`](changelog.d/README.md) fragment and run the two
   pre-push checks under [Pull requests](#pull-requests).
7. Record the exact commands and results in the
   [pull request template](.github/PULL_REQUEST_TEMPLATE.md).

The project generally uses focused conventional commit subjects such as
`fix:`, `docs:`, `test:`, and `chore:`. Git history is the current convention;
there is no claim that a commit-message bot enforces it.

Security-sensitive code must fail closed. Unexpected input, missing state, unsupported platforms, failed authentication, ambiguous crash recovery, and stale authority should not silently downgrade to permissive behavior.

## Verification

Every Rust change should pass these source gates. The tag release workflow
enforces the same locked all-target test, format, and strict Clippy contract;
contributors should run it before opening a pull request:

```bash
cargo test --workspace --all-targets --locked --no-fail-fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Pull requests and the merge queue run only the fast checks, so run the tests
above yourself. CI classifies the changed paths first. Every pull request runs
`Lint` (format and strict Clippy; its Rust steps skip when only docs or web
paths change), `Rust dependency policy`, `Source secret scan`, and
`Secret-shape scan`; a change outside docs and web paths also runs the npm
wrapper tests. The single required `CI Gate` job fails if any selected job did
not succeed or a deselected job ran. Three other workflows also run on pull
request code; none is a required check.
[First-run scorecard](.github/workflows/first-run.yml) runs on a pull request
only when that workflow or `scripts/bench/first-run.sh` changes.
[CodeQL](.github/workflows/codeql.yml) classifies each pull request and
analyzes only the languages whose files changed: a docs-only pull request
skips analysis, and Rust is analyzed on a pull request only when a workflow
file changes. Each push to `main`, a weekly security-extended run, and a
manual dispatch scan all five languages (Actions, JavaScript/TypeScript,
Python, Ruby, and Rust). In the merge queue,
[`pair-secrets`](.github/workflows/pair-secrets.yml) runs an integration test
when `phantom exec`, MCP, or posture code changes. That test fails closed
until the `ashlrai/phantom` side of it is wired in (the TODO is in
[`scripts/integration/pair-secrets.sh`](scripts/integration/pair-secrets.sh)),
so expect it to be red when it runs. Pushes to `main` run no `CI`
workflow jobs. The full matrix (tests on macOS, Linux, and Windows, the
Windows ARM64 source check, the web app, crate publication, the Temporal codec
example tests, and the docs command check) runs daily on `main` through
[`nightly-full.yml`](.github/workflows/nightly-full.yml) and on manual
dispatch; a red daily run is fixed forward.

### Reproduce the pull request jobs locally

Each job that `CI Gate` requires on a pull request maps to commands you can
run before you push. The job definitions in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) are the source of
truth, including the pinned `cargo-deny` and `gitleaks` versions; install
those two tools yourself to run their commands locally.

| Job (ID in the `CI Gate` log) | When it runs its checks | Local commands |
|-------------------------------|-------------------------|----------------|
| `Lint` (`lint`) | Any change outside docs and web paths | `node --test scripts/installer-syntax.test.mjs scripts/installer-unwritable-tempdir.test.mjs scripts/installer-path-success-cleanup.test.mjs`, then `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| `npm wrapper tests and package inspection` (`npm-wrappers`) | Same scope as the Rust steps of `Lint` | `(cd npm && npm test && npm pack --dry-run)` and `(cd npm-mcp && npm test && npm pack --dry-run)`; CI runs the tests on Node 22 and 24 |
| `Secret-shape scan` (`secret-shape`) | Every pull request | `git diff main...HEAD \| perl .github/tests/secret-shape/scrub.pl --check --allow-fixtures` |
| `Rust dependency policy` (`dependency-policy`) | Every pull request | `node --test scripts/ci/mcp-registry-publisher.test.mjs .github/tests/mcp-registry-publication.test.mjs`, `git ls-files -z \| node scripts/release/check-dependency-index.mjs`, and `cargo deny --all-features --locked check --deny warnings advisories licenses bans sources` |
| `Source secret scan` (`secret-scan`) | Every pull request | `node --test scripts/ci/verified-download.test.mjs`, `gitleaks dir . --config .gitleaks.toml --redact --no-banner --max-target-megabytes 5 --timeout 60`, `git fetch --no-tags --prune origin '+refs/heads/*:refs/remotes/origin/*'`, `node --test scripts/release/validate-gitleaks-ignore.test.mjs`, `node scripts/release/validate-gitleaks-ignore.mjs .gitleaksignore HEAD`, and the history scan `gitleaks git . --log-opts='HEAD --remotes=origin' --config .gitleaks.toml --gitleaks-ignore-path .gitleaksignore --redact --no-banner --max-target-megabytes 5 --timeout 120` |

"Docs and web paths" are the ones `scripts/ci/rust-scope.sh` excludes:
`docs/`, any root `*.md` or nested `README.md`, `LICENSE`, the issue and pull
request templates, `apps/web/`, `scripts/supabase/`, `scripts/seo/`, and
`video/`. Any change under `.github/workflows/` turns the Rust steps back on.

`Source secret scan` checks every commit, not only the final tree. CI checks
out full history, fetches every branch head of this repository into
`refs/remotes/origin/`, and scans `HEAD` plus those heads, so a token you
committed and then deleted on your branch still fails the job. Remove it from
your branch history (for example, drop or edit the commit that added it with
an interactive rebase), then force-push your branch; never force-push `main`.
Treat a real credential that reached a pushed commit as exposed and rotate it
at the provider.

The `.gitleaksignore` validator reads the same `origin` heads and fails when
none are fetched. In a fork, `origin` is your fork, so the local run checks
your fork's branches rather than this repository's; keep your fork's `main`
in sync with `upstream/main` for a close match. Run the history scan from a
full clone: in a shallow clone (`git rev-parse --is-shallow-repository`
prints `true`) the oldest fetched commit appears to add every file, so the
scan reports the repository's test fixtures as findings. Run
`git fetch --unshallow` first.

The dependency-policy job matters most when you add or upgrade a crate: a new
advisory, a disallowed license or source, or a banned duplicate fails
`cargo deny` under the policy in [`deny.toml`](deny.toml).

### When `CI Gate` fails

`CI Gate` runs no checks of its own. It reads the result of every other job in
[`ci.yml`](.github/workflows/ci.yml) and fails when a job that
`Classify changes` selected for your diff did not succeed, or when a job it
deselected ran anyway. Its error lists each mismatch as
`<job-id>=<result> (selected=<true|false>)`, for example
`secret-shape=failure (selected=true)`. The table above maps each job ID to
its check name and local commands.

1. Open the named job on the pull request's checks page and read its first
   failed step.
2. Run that job's local commands, fix the cause, and push again. A new push
   cancels the pull request's superseded run, so you do not need to cancel it.
3. If the error says `changes: failure`, the `Classify changes` job itself
   failed; read its log instead. `gate inventory drift` means a change to
   `ci.yml` added or removed a job without updating the gate's job list.

Only `CI Gate` blocks a merge. A red check from another workflow on the pull
request or in the merge queue, such as CodeQL, the first-run scorecard, or
`pair-secrets` (which fails closed today, as described under
[Verification](#verification)), does not hold the pull request. Read it for
real findings, but it does not need to be green for the merge.

The merge queue reruns the same jobs on the queued merge commit. If `CI Gate`
fails there, GitHub removes the pull request from the queue. This usually
means your change breaks when combined with one queued or merged ahead of it:
rebase onto `upstream/main`, rerun the checks, and push.

### Testing affected Rust packages

Two local iteration aids narrow the Rust checks to what your branch touched.
Neither replaces the full workspace gate above before you open a pull request.

`scripts/fast-check.sh [BASE [HEAD]]` selects packages with
`scripts/affected-crates.sh`, then runs `cargo fmt --all -- --check`, plus
`cargo check`, strict Clippy, and `cargo test` for the affected packages. It
also runs the selector's Python fixture tests, the `scripts/ci/*.test.mjs`
and `scripts/test-sleep-budget.test.mjs` suites, and the `copy_security_test`
integration test. It needs Cargo, Node.js, and Python 3.

With one `BASE` argument, the selection covers the working tree against
`BASE`, including staged, unstaged, and untracked files; with `BASE HEAD`, it
covers only committed changes in `BASE...HEAD`; with no argument, it covers
uncommitted changes against `HEAD`. The one-argument form compares with the
tip of `BASE`, not the merge base, so after `git fetch upstream` moves
`upstream/main`, files changed upstream since you branched count as yours and
the selection widens, often to the whole workspace. Rebase onto the new base
first (`git rebase upstream/main`), or run
`scripts/fast-check.sh upstream/main HEAD` to check only your committed
changes since the merge base. The selector is deliberately
conservative: it narrows to packages only when every changed file is a `.rs`
file under a crate's `src/` directory. Any other path selects the whole
workspace, including docs, scripts, a `Cargo.toml` or `Cargo.lock`, a
`build.rs`, and any path with a segment such as `tests` or `fixtures` or a
name that contains `test`, `helper`, or `config`. An empty selection also
checks the whole workspace. The selector's cases are in
`scripts/affected-crates.test.py`.

`scripts/affected-tests BASE [HEAD]` prints Cargo package names, one per line,
for changed workspace crates and their transitive dependents. It uses Cargo's
resolved graph, including build, development, renamed and optional dependencies.
An empty list means no Rust packages are affected. Workspace configuration
changes, unknown crate paths, and unavailable metadata select `ALL`.

Run `make test-affected BASE=main` to test that selection, or `make test-affected`
to inspect tracked staged and unstaged changes against HEAD. Untracked files are
excluded; add new files to Git before using this shortcut. Cargo and Python 3
must be on PATH. Run the selector's fixture tests with
`python3 scripts/affected-tests.test.py`.

`scripts/ci/daily-matrix.mjs` is a proposed refinement of the daily run, not
part of it yet. It computes an affected-only OS matrix for
`Test (${{ matrix.os }})` from a diff (per-leg `cfg` routing, failing closed
to all three legs) and the additive off-peak cron in
`scripts/ci/offpeak-schedule.json`, emitting only the existing
`macos-latest`/`ubuntu-latest`/`windows-latest` labels so check names would
not change. No workflow calls it today: `nightly-full.yml` has the single
daily schedule and always runs the full matrix. The workflow patch that would
wire it in is in [scripts/ci/daily-matrix.md](scripts/ci/daily-matrix.md).
`scripts/fast-check.sh` runs its suite with the other `scripts/ci/*.test.mjs`
files; run it alone with `node --test scripts/ci/daily-matrix.test.mjs`.

### Additional checks by surface

Run additional checks for the surface you changed:

```bash
# MCP release binary
cargo build --release --locked -p phantom-secrets-mcp --bin phantom-mcp

# MCP catalog: mcp-registry/server.json must match the runtime tools/list
cargo build --locked -p phantom-secrets-mcp --bin phantom-mcp
node scripts/release/mcp-stdio-smoke.mjs target/debug/phantom-mcp 54

# Changelog headings, dates, ordering, and compare links
node scripts/release/lint-changelog.mjs

# Markdown fence balance: docs/internal/notes.md and every tracked *.md
node --test scripts/internal-notes-fences.test.mjs

# Provider grant and rotation hard-denial, plus exact cfg(test) transaction-scaffolding tests
cargo test --locked -p phantom-secrets --test grant_add_denial_test
cargo test --locked -p phantom-secrets --test grant_github_app_test
cargo test --locked -p phantom-secrets --test grant_vercel_integration_test
cargo test --locked -p phantom-secrets --test grant_sentry_test
cargo test --locked -p phantom-secrets --test grant_supabase_test
cargo test --locked -p phantom-secrets --test grant_stripe_test
cargo test --locked -p phantom-secrets --test grant_revoke_test
cargo test --locked -p phantom-secrets --test rotate_provider_test

# npm wrappers: the same steps as CI's npm wrapper job
(cd npm && npm test && npm pack --dry-run)
(cd npm-mcp && npm test && npm pack --dry-run)

# Web application: the credential-free steps of the daily web job
(cd apps/web && node --test ../../scripts/supabase/verify-migrations.test.mjs && npm ci --no-audit && npm audit --omit=dev --audit-level=moderate && npm run lint && npm test && node --test ../../scripts/seo/observe.test.mjs ../../scripts/seo/observe-sort.test.mjs && npm run build)

# Temporal codec example (Python 3): the tests of the daily example job
(cd examples/temporal-codec-python && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python -m unittest -v)
```

Pull request and merge-queue CI never run the Temporal codec example job,
so run its tests yourself when you change `examples/temporal-codec-python/`.
The daily job installs the hash-pinned `requirements-ci.txt` instead and fails
if any test is skipped, so check the `unittest` output for skips. The
repository does not ignore that directory's `.venv/` or `__pycache__/`; leave
them out of your commit.

The daily web job also pins its npm audit CLI version and then replays every
Supabase migration against a local database with a pinned Supabase CLI. Both
pins are in [`.github/workflows/ci.yml`](.github/workflows/ci.yml); that replay
needs the Supabase CLI and a container runtime, so run it only when you change
`apps/web/supabase/`.

When an MCP catalog intentionally changes, update the server declarations,
closed parameter schemas, generated/mirrored registry surfaces, and packaged
stdio smoke together. After reviewing the runtime effects, regenerate the
registry file with
`node scripts/release/mcp-stdio-smoke.mjs target/debug/phantom-mcp 54 mcp-registry/server.json --write-registry`;
the Linux leg of the daily full test run runs the same smoke without
`--write-registry`. Do not hard-code a catalog count in prose unless release
automation enforces it.

Ignored keychain tests touch the host OS keychain. Run them only on a disposable test identity after reviewing the test:

```bash
cargo test --workspace -- --ignored
```

The daily full run tests the normal Rust suite on macOS, Linux, and Windows;
pull requests do not. A successful cross-compile or CI matrix does not prove native installer trust, keychain UX, code signing/notarization, shell integration, or end-to-end acceptance on every device; describe exactly what you tested.

### Keyring advisory exceptions

The unmaintained-crate advisories RUSTSEC-2026-0370 (`zvariant`),
RUSTSEC-2026-0371 (`zbus_names`), and RUSTSEC-2026-0372
(`zvariant_derive`) reached the graph through keyring 3's zbus-based Linux
Secret Service backend. [Issue #242](https://github.com/ashlrai/phantom-secrets/issues/242)
eliminated the dependencies rather than upgraded them: the workspace now links
`keyring-core` plus per-backend store crates, and Linux Secret Service runs on
`dbus-secret-service-keyring-store` (the blocking `dbus` implementation) so no
zbus version remains in the resolved graph. `cargo deny check` must pass with
no ignores for these advisories. See the
[migration scoping note](docs/design/keyring-4-migration-scoping.md) for the
evaluated options.
Run `node --test scripts/keyring-advisory-docs.test.mjs` when changing this note
or the related policy.

## Coding and security guidelines

- Use `thiserror` for reusable library errors and `anyhow` for CLI orchestration where appropriate.
- Keep secret values out of `Debug`, `Display`, serialization, logs, URLs, argv, receipts, MCP responses, telemetry, and error messages.
- Wrap secret-bearing memory in the repository's zeroization patterns and test error/early-return paths.
- Use the hardened filesystem helpers for secret or authority state; defend against symlinks, unsafe permissions, partial writes, and crash recovery.
- Keep proxy listeners loopback-only and authenticate every request before
  route matching. Client-controlled headers and bodies must remain inert; only
  the exact matched route may inject its vault value into its fixed auth header.
- MCP tools must use closed input schemas. A mutation requires the surface's explicit confirmation and out-of-band approval contract; a request ID or digest is not authority.
- `phantom_do` remains proposal-only. Do not connect its reserved `execute` phase to a shell or production executor.
- Do not add a plaintext secret argument to MCP. New values must be collected out of band in a trusted terminal.
- Keep all production provider issuance, enrollment, refresh, renewal,
  rotation, and revocation paths hard-denied before credential access and
  network I/O. Exact `cfg(test)` mocks may exercise local transaction
  scaffolding but are not provider acceptance or activation evidence.
- Keep provider-grant lifecycle separate from authority-grant verification.
  Remote revoke must fail before local mutation until provider revocation is
  implemented and accepted end to end.
- Put focused unit tests near the implementation and end-to-end/integration tests under the crate or application test directory.
- Comment non-obvious invariants and the reason for a safety check, not a narration of the code.

## Documentation guidelines

- Treat code, schemas, tests, and release automation as the source of truth.
- Label active behavior, experimental/fail-closed foundations, and roadmap proposals explicitly.
- Avoid volatile counts or version claims unless a test or release script enforces them.
- Include macOS, Linux, and Windows differences when they affect commands, storage, permissions, shells, packaging, or support.
- Keep links relative inside the repository so they work in forks and release source archives.
- Follow the [hot-file rule](AGENTS.md#hot-file-rule-avoid-merge-conflicts):
  a pull request that adds a guide does not also edit the
  [documentation map](docs/README.md), and a new web test goes in a new file
  under `apps/web/tests/`. Update the map in a separate, dedicated pull request
  when guides are added, moved, or retired.

## Pull requests

Do not edit `CHANGELOG.md` directly. Add one fragment file to
[`changelog.d/`](changelog.d/README.md) named `<pr-number-or-slug>.md` with a
level-3 heading that starts with `Added`, `Changed`, `Fixed`, `Security`,
`Removed`, `Deprecated`, or `CI`, an optional `(topic)`, and bullets. Fragments are folded into the Unreleased section at
release time with `node scripts/changelog-fold.mjs`, so queued pull requests
no longer conflict on the changelog.

Run these two checks before you push. Neither needs a build:

```bash
# Validate changelog fragments without writing anything
node scripts/changelog-fold.mjs --check

# Secret-shape scan: the same scanner and flags as CI's required job
git diff main...HEAD | perl .github/tests/secret-shape/scrub.pl --check --allow-fixtures
```

Pull request and merge-queue CI do not validate fragments; only the daily full
run does, so a malformed fragment merges and then turns that run red. The
`Secret-shape scan` job runs on every pull request and `CI Gate` requires it.
It scans the lines your branch adds, fails on any token-shaped string, and
prints only a count, never the match. In test paths (`test/`, `tests/`, `fixtures/`,
`benches/`, `examples/`, `*_test.*`, `*.test.*`, `*.spec.*`) it allows a
token that contains `FAKE`, `EXAMPLE`, `DUMMY`, `TEST`, or `XXXX`, so build
fake values that way. Diff against the branch you forked from; use
`upstream/main` if your local `main` is stale.

When a rebase or merge still stops on `CHANGELOG.md`, `CLAUDE.md`, `README.md`,
or a lockfile, `scripts/resolve-merge-conflicts.sh` resolves those paths
mechanically: `CHANGELOG.md` is union-merged (`.gitattributes` sets
`merge=union`, which GitHub's server-side merge ignores but local and
lane-side merges honor), `CLAUDE.md`/`README.md` take the upstream version and
re-apply the lane's hunks that still apply, and `Cargo.lock`/`bun.lock`/
`package-lock.json` are regenerated by the package manager rather than
hand-merged. Run it, review any reported rejected hunks, then continue the
rebase. Conflicts on any other path remain manual.

Use the pull request template. A strong description explains the user problem, trust-boundary impact, exact verification evidence, platform coverage, and remaining limitations. Screenshots are helpful for UI changes but are not substitutes for behavioral tests.

Project decisions and review authority are described in
[GOVERNANCE.md](GOVERNANCE.md). For a bounded first contribution, improve a
documented example, reproduce an existing issue with a test, or propose a small
documentation correction; the project does not promise that a particular
`good first issue` queue is populated.

By contributing, you confirm that you have the right to submit the work and
agree that your contribution is licensed under the repository's
[MIT License](LICENSE). The project does not currently enforce a Contributor
License Agreement or Developer Certificate of Origin sign-off; adopting either
is a separate maintainer and legal-policy decision, not an implied requirement.

## Questions

Use [GitHub Discussions](https://github.com/ashlrai/phantom-secrets/discussions) for design and usage questions, [GitHub Issues](https://github.com/ashlrai/phantom-secrets/issues) for reproducible defects and accepted work, and [SUPPORT.md](SUPPORT.md) to choose the right public or private route.
