### Removed (agent scratch files at the repository root)

- Removed agent run scratch files that a bridge commit added at the
  repository root (`notes.md`, `task_plan.md`, `pr-clear-1c.tsv`,
  `.pr-clear-1c/`, and `handoff/`). Nothing referenced them, and a first-time
  contributor would mistake them for project docs. Root-anchored
  `.gitignore` entries keep them out of future commits;
  `docs/internal/notes.md` and `docs/internal/task_plan.md` are unaffected.
