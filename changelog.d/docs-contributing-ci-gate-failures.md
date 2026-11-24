### Changed (docs: reading a failed `CI Gate`)

- CONTRIBUTING.md now explains how to read a failed `CI Gate`: it lists each
  mismatched job as `<job-id>=<result> (selected=...)`, the reproduce table maps
  each job ID to its check name and local commands, and a failure in the merge
  queue removes the pull request from the queue. The merge step also notes
  that a change to a `.github/CODEOWNERS` path requests a code-owner review.
