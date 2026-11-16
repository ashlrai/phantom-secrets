### Security (npm acceptance follows rehearsal)

- npm candidate acceptance checks the format of its seven inputs in a prior
  job and runs the host matrix from those outputs. The matrix starts only
  after the release rehearsal workflow succeeds on the default branch or a
  release tag. Rehearsal remains a single read-only job and is invoked with
  `workflow_call`.

### CI (CodeQL weekly schedule)

- CodeQL runs on default-branch pushes, pull requests, and one Sunday
  schedule. The CodeQL workflow name and analyze job name stay the same.
