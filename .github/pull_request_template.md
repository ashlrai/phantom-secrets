<!--
  Thanks for contributing! Please make sure your PR meets the checklist below
  before requesting review. Small PRs land fast — if this is large, consider
  splitting it.
-->

## What this changes

<!-- One paragraph: what does this PR do, and why? Link to the issue if applicable. -->

Closes #

## How to verify

<!-- Concrete steps a reviewer can run. CLI commands or test names preferred. -->

```
~/.cargo/bin/cargo test -p <crate>
```

## Checklist

- [ ] `~/.cargo/bin/cargo build` passes
- [ ] `~/.cargo/bin/cargo test` passes (103 tests + any new ones)
- [ ] `~/.cargo/bin/cargo clippy --all-targets -- -D warnings` is clean
- [ ] `~/.cargo/bin/cargo fmt --all` applied
- [ ] Docs updated if behavior changed (README, CLAUDE.md, llms.txt)
- [ ] No real secret values, API keys, or `.env` contents in the diff
- [ ] If touching `phantom-vault` or the proxy: secrets are `zeroize`d on every exit path
