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

Reviewed **2026-11-02**: the files **differ**. SHA-256 hashes identify the
exact bytes reviewed:

- `scripts/install.sh`: `a6c413223f5a27e8df170805a7343ac60d55828b28c9281a15eff7d205d126c0`
- `apps/web/public/install.sh`: `a430c238fd92a8a2481973c3c56750553b550f897663eaebe992e729ef311e04`

The repository copy targets the next candidate with `CANDIDATE_TAG="v0.8.0"`;
the web copy stays bound to the evidenced `v0.7.9` release. The repository
copy emits explicit errors if staging directory creation or permission
changes fail; the web copy relies on Bash error handling and command
diagnostics. The repository copy also extracts with `tar --no-same-owner`;
the web copy omits that option, which can affect ownership when run as root.
See [installer staging](installer-staging.md) for the surrounding behavior.
Re-run the comparison and update this snapshot and its hashes whenever either
file changes; `node --test scripts/installer-copy-comparison.test.mjs` checks
that the snapshot still describes the checked-in bytes.
