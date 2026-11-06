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

Reviewed **2026-11-05**: the files **differ**. SHA-256 hashes identify the
exact bytes reviewed:

- `scripts/install.sh`: `866cdd3c2ee186af7fa7cbc01e41c013440427601e54545a2c7ee857a8990bd7`
- `apps/web/public/install.sh`: `3a7996d8292e8fca18f222f257d103a5ead5b32c6fe93a82eb91cbefe65caaba`

The repository copy targets the next candidate with `CANDIDATE_TAG="v0.8.1"`;
the web copy stays bound to the evidenced `v0.7.9` release. The repository
copy also extracts with `tar --no-same-owner`; the web copy omits that
option, which can affect ownership when run as root.
See [installer staging](installer-staging.md) for the surrounding behavior.
Re-run the comparison and update this snapshot and its hashes whenever either
file changes; `node --test scripts/installer-copy-comparison.test.mjs` checks
that the snapshot still describes the checked-in bytes.
