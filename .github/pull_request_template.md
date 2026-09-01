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

<!-- Record exact commands, results, platform, and any skipped/blocked gate. -->

```
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked --no-fail-fast
cargo clippy --workspace --all-targets --locked -- -D warnings
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
- [ ] No credentials, cookies, device codes, vault values, or persistent `phm_` mappings appear in the diff, fixtures, logs, or screenshots
- [ ] Secret-bearing buffers follow existing zeroization patterns on success and error paths
- [ ] Platform coverage, skipped checks, external gates, and remaining limitations are stated
- [ ] Security-sensitive changes include explicit authority, rollback, and recovery analysis
