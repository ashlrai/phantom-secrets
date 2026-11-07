# Keeping the Unix installer copies in sync

[`scripts/install.sh`](../scripts/install.sh) is the repository's Unix
installer. [`apps/web/public/install.sh`](../apps/web/public/install.sh) is
the checked-in copy served by the web application. Compare the files from the
repository root before and after changing either one:

```sh
diff -u scripts/install.sh apps/web/public/install.sh
```

Exit status 0 means the files match, 1 means they differ, and a status greater
than 1 means the comparison failed. The output is a unified diff, with the
repository copy on the minus side and the web copy on the plus side.

The copies currently have a reviewed difference in release pinning only. See the dated [comparison and hashes](installer-copy-comparison.md)
and [source map](installer-copy-source-map.md) for the exact review. The web
copy is bound to separately reviewed release evidence: do not overwrite it
just to make the comparison pass. A local comparison does not verify the
deployed website or an immutable release asset.

When changing an installer, review the diff and decide which changes belong in
each copy, including their security and release implications. Preserve any
intentional differences until the appropriate release review supports changing
them. Update the comparison, hashes, source map, and approved-difference tests
when their reviewed state changes. Run the relevant installer behavior tests
and the copy checks, including:

```sh
node --test scripts/installer-copy-comparison.test.mjs scripts/installer-copy-consistency.test.mjs scripts/installer-copy-parity.test.mjs scripts/installer-copy-byte-consistency.test.mjs scripts/installer-copy-source-map.test.mjs scripts/installer-copy-sync.test.mjs
```
