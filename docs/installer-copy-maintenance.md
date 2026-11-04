# Maintaining the Unix installer copies

[`scripts/install.sh`](../scripts/install.sh) is the repository installer;
[`apps/web/public/install.sh`](../apps/web/public/install.sh) is the checked-in
web copy. Compare these files after editing either one. This review concerns
checked-in source, not the deployed site or an immutable release asset. The
web copy is tied to separately reviewed release evidence; do not overwrite it
merely to make the files match.

## Review after an edit

1. From the repository root, run:

   ```sh
   diff -u scripts/install.sh apps/web/public/install.sh
   ```

   Exit 0 means the files match, 1 means they differ, and a higher status
   means comparison failed. Review the whole diff, including changes outside
   the templates below. The current reviewed differences cover the candidate
   release tag and `tar --no-same-owner` in the repository copy; see the
   [copy comparison](installer-copy-comparison.md). Do not assume all
   differences are mistakes or silently approve new ones.
2. Compare staging in both files: destination selection and physical parent
   resolution, the `mktemp` template, permissions, download and candidate
   directories, lock, backup, promotion, rollback and cleanup. The staging
   directory is a sibling of the install destination, not a `TMPDIR` path.
   Its current template in both copies is:

   ```text
   $install_parent/.${install_name}.install.XXXXXX
   ```

   Both copies use the same guarded staging block with explicit failure
   diagnostics around stage creation. Review a change in behavior as well as
   a change to the template.
3. Compare `add_to_user_path` and its call site in both files. Check shell
   selection, the physically resolved startup-file parent, both temporary
   templates, marker and shell-specific PATH commands, file checks, replacement,
   failure handling and cleanup. The current temporary templates in both copies
   are:

   ```text
   $rc_parent/.phantom-path.before.XXXXXX
   $rc_parent/.phantom-path.candidate.XXXXXX
   ```

   These are siblings of the shell startup file, separate from the binary
   stage. PATH setup runs after promotion and warns on failure; the stage exit
   trap does not clean up PATH temporary files. Cleanup is best effort. See
   the [PATH review](installer-path-review.md) and
   [staging review](installer-staging.md) for details and limits.
4. Review and update the [source map](installer-copy-source-map.md),
   [comparison snapshot](installer-copy-comparison.md), and other affected
   staging or PATH documentation. If a difference is intentional, document its
   effect and update the reviewed differences in
   [`lib/installer-copy-differences.mjs`](../scripts/lib/installer-copy-differences.mjs)
   only after review. Follow the separate release process for any change to
   release-bound evidence; a local comparison is not publication evidence.
5. Run the focused checks below and the relevant behavioral installer tests:

   ```sh
   node --test scripts/installer-copy-maintenance.test.mjs scripts/installer-copy-consistency.test.mjs scripts/installer-copy-parity.test.mjs scripts/installer-copy-comparison.test.mjs scripts/installer-copy-source-map.test.mjs scripts/installers.test.js
   ```

The focused maintenance test checks that the three templates recorded above
match each checked-in copy. It does not replace the full diff or behavioral
tests, and matching templates alone does not establish equivalent behavior.
