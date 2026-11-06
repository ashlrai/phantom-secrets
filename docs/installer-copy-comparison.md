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

- `scripts/install.sh`: `fc9a199632a036402d0885f69ce14f96b307e93be40179ff19865d073dd5e62b`
- `apps/web/public/install.sh`: `36492564008f5501798f780a4801d4db41345469518693f5f6142535eaca13f0`

The repository copy targets the next candidate with `CANDIDATE_TAG="v0.8.1"`;
the web copy stays bound to the evidenced `v0.7.9` release. The repository
copy also extracts with `tar --no-same-owner`; the web copy omits that
option, which can affect ownership when run as root. Both copies share the
same guarded staging block, so staging creation and permission failures are
reported identically.
See [installer staging](installer-staging.md) for the surrounding behavior.
Re-run the comparison and update this snapshot and its hashes whenever either
file changes; `node --test scripts/installer-copy-comparison.test.mjs` checks
that the snapshot still describes the checked-in bytes.
