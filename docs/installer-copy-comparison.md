# Unix installer copy comparison

[`scripts/install.sh`](../scripts/install.sh) is the repository installer;
[`apps/web/public/install.sh`](../apps/web/public/install.sh) is the checked-in
web-served copy. This compares repository files, not a deployed website or a
GitHub release asset. The web copy is bound to separately reviewed public
release evidence, so matching the repository copy is not by itself a reason to
replace it.

From the repository root, run this byte-for-byte comparison:

```sh
cmp -s scripts/install.sh apps/web/public/install.sh
status=$?
case "$status" in
  0) echo "Installer copies match" ;;
  1) echo "Installer copies differ" ;;
  *) echo "Comparison failed (exit $status)" >&2; exit "$status" ;;
esac
```

To inspect differences, run `diff -u scripts/install.sh apps/web/public/install.sh`.
`diff` exits 1 when it finds differences and greater than 1 on an error.

## Review snapshot

Reviewed **2026-11-06**: the files **match**. SHA-256 hashes identify the
exact bytes reviewed:

- `scripts/install.sh`: `44ab25b1a5b99d7a1a3bb484ea17b323f89a47e43092ca4de4903a9ede6ba72e`
- `apps/web/public/install.sh`: `44ab25b1a5b99d7a1a3bb484ea17b323f89a47e43092ca4de4903a9ede6ba72e`

Both copies pin the evidenced `v0.8.7` release with `CANDIDATE_TAG="v0.8.7"`. Both copies
extract the release archive with `tar --no-same-owner` and carry the same
explanatory comment, so a root-run install does not keep the release
runner's uid on the installed binaries. Both copies share the same guarded
staging block, so staging creation and permission failures are reported
identically.
See [installer staging](installer-staging.md) for the surrounding behavior.
Re-run the comparison and update this snapshot and its hashes whenever either
file changes; `node --test scripts/installer-copy-comparison.test.mjs` checks
that the snapshot still describes the checked-in bytes.
