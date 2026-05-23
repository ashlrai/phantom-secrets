# Agent Loop Runbook

## Start Of Loop
1. Run `git status --short --branch`.
2. Run `entire resume <branch>` when resuming an existing branch.
3. Review recent commits touching the affected area.
4. Read `task_plan.md` and `notes.md`.
5. For changes touching three or more files, use focused parallel exploration where useful.

## During Loop
1. Keep implementation slices bounded by ownership area.
2. Avoid logging, writing, or requesting real secret values.
3. Update `notes.md` with findings that affect decisions.
4. Update `task_plan.md` after each phase.
5. Surface security assumptions and compatibility tradeoffs early.

## End Of Loop
1. Run targeted tests for the touched surface.
2. Run formatting or lint checks when practical.
3. Record unresolved risks and follow-up work.
4. Produce a concise readiness report with files changed and verification status.
