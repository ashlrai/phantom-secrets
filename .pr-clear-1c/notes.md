# Findings: RQ-PR-CLEAR-1C

- Worktree started clean on codex-bridge/RQ-PR-CLEAR-1C at a5317f45.
- origin push URL is no_push; fork points to masonwyatt23/phantom-secrets.
- Final task rules forbid commits, pushes, tags and publication.
- ~/.ashlr-runs directory reads returned EPERM; ledger-target setup returned FileExistsError (errno 17). No fleet lease was acquired or verified.
- GitHub CLI config read returned EPERM. Connected GitHub tools support the read-only metadata audit.
- Both observed snapshots: 66 open PRs, 63 DIRTY, 3 BEHIND, 0 CLEAN.
- The three BEHIND PRs are #1435, #1301, #1214. Each has a failing CI Gate.
- #140 is open DIRTY. #375 is open DIRTY and draft. Both released holds are included.
- #197, #168, #418, #136 and #500 are closed without merge. #1239 is merged.
- The 64 extractable task IDs are unique; #140 and #375 have no extractable task ID. No newest-wins closure candidate is proven by exact task ID among the open PRs.
- #1435 changes 181 files and removes 69, including tests and 3 migrations. Its small-fix description does not describe the full current diff.
- No source, workflow, test, security control or shared PR was changed.
- Four existing hot-file-rule tests pass. cargo fmt passes. Web lint cannot find eslint because dependencies are not installed.
- cargo check was interrupted during dependency compilation; no typecheck result. Host load averages observed: 283.53, 147.16, 102.21.
- Receipt and one-PR-per-line ledger are stored locally. The requested shared metrics path is unavailable.
