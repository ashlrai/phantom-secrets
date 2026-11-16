# Security handoff: PR #1435 rebase

The requested PR head is e7a2f0df. Current origin/main fetched for this inspection is 2c93e578d8d1a8097b32c1cd89292e339681b77c. Their merge base is 25b297d778f2f45981963ed51e2e0ddec4ae71f5.

`git merge-tree --write-tree origin/main origin/pr-1435` reports content conflicts in these workflow files:

- `.github/workflows/ci.yml`
- `.github/workflows/codeql.yml`
- `.github/workflows/npm-candidate-acceptance.yml`
- `.github/workflows/release-rehearsal.yml`

It also reports a conflict in `scripts/release/extract-release-notes.test.mjs`, alongside numerous non-workflow conflicts. The PR commit 3638c703 changes five workflows and release-related scripts and deletes many tests and other files. Its merge-base diff also includes broad reversions of changes since the PR's original base. Review the intended scope before accepting any deletions.

Proposed resolution for Security review: retain current main's workflow and release behavior, including its security gates, permissions, pins, and current CI scheduling; apply only independently verified changes that implement the PR's intended dead-code cleanup without removing tests or reverting later main changes. This is a proposed direction, not a completed or validated resolution. Security must examine each conflict and determine whether any PR-side workflow change is appropriate.

No rebase, conflict resolution, commit, push, or test run was performed. The merge-tree result was computed without changing the worktree. The user's instruction requires stopping when workflow or release-script conflicts occur. Local `gh` configuration was inaccessible, so PR metadata beyond the fetched Git ref was not checked.
