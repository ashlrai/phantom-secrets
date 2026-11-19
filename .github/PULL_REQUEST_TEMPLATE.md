<!-- Keep the description evidence-bounded. Source, artifact, publication,
deployment, provider activation, and user acceptance are separate outcomes. -->

## What this changes

<!-- What user or maintainer problem does this solve? -->

Closes #

## Change and trust boundary

<!-- Check all that apply and explain any authority expansion. -->

- [ ] Documentation or metadata only
- [ ] Local read-only behavior
- [ ] Local mutation or secret handling
- [ ] Network, provider, cloud, or deployment behavior
- [ ] Release, installer, package, or supply-chain behavior

Authority, values, rollback, and failure-mode notes:

<!-- What values cross a boundary? Who authorizes effects? What happens on partial failure? -->

## How to verify

<!-- Record exact commands, results, platform, and any skipped/blocked gate.
Pull request CI does not run the Rust test suite or the docs drift checks, so
the commands you list here are the test evidence reviewers see. Keep the block
that matches your change and delete the other. See "Contribute with an agent"
in CONTRIBUTING.md. -->

Rust or other code change:

```
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked --no-fail-fast
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Documentation-only change (plus any `scripts/*.test.mjs` that reads the file you edited):

```
node --test scripts/release/readme-mcp-catalog.test.mjs
node --test scripts/docs-distribution.test.mjs
node --test scripts/hot-file-rule.test.mjs
cargo test -p phantom-secrets --test docs_command_flags_test
```

Pre-push checks, for every change (no build needed; `CI Gate` requires the
`Secret-shape scan`, and pull request CI does not validate fragments; on a
fork, diff against `upstream/main`):

```
node scripts/changelog-fold.mjs --check
git diff main...HEAD | perl .github/tests/secret-shape/scrub.pl --check --allow-fixtures
```

| Evidence layer | Exact evidence or explicit limitation |
|---|---|
| Source and focused tests | |
| Native artifact | Not claimed / |
| Package publication | Not claimed / |
| Deployment or provider activation | Not claimed / |
| User or customer acceptance | Not claimed / |

## Checklist

- [ ] Proportional tests cover success and important failure/rollback paths
- [ ] Locked formatting and strict Clippy gates pass for changed Rust code
- [ ] Relevant npm/web/package checks pass for changed JavaScript or TypeScript
- [ ] Public docs, help, schemas, and generated mirrors agree with behavior
- [ ] A `changelog.d/` fragment replaces any direct `CHANGELOG.md` edit, and a new doc does not also edit `docs/README.md` (hot-file rule in AGENTS.md)
- [ ] No credentials, cookies, device codes, vault values, or persistent `phm_` mappings appear in the diff, fixtures, logs, or screenshots
- [ ] Secret-bearing buffers follow existing zeroization patterns on success and error paths
- [ ] Platform coverage, skipped checks, external gates, and remaining limitations are stated
- [ ] Security-sensitive changes include explicit authority, rollback, and recovery analysis
