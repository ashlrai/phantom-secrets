### Fixed (docs)

- The `Source secret scan` row in CONTRIBUTING.md's local reproduction table
  now matches `ci.yml`: fetch every branch head into `refs/remotes/origin/`
  first, then run the history scan with `--log-opts='HEAD --remotes=origin'`.
  The table previously scanned `HEAD` only and omitted the fetch the
  `.gitleaksignore` validator needs. A note explains that in a fork `origin`
  is the fork, so the local run only approximates CI.
