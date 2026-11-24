### CI (affected tests on hosted runners)

- Pull requests and the merge queue run affected `cargo nextest` on
  GitHub-hosted Ubuntu. macOS and Windows run only when the platform path
  gate selects them. The first failing test is written to the step summary
  with its file and line. The daily full suite on all three operating systems
  is unchanged.
- A full local `cargo test --workspace --all-targets --locked --no-fail-fast`
  is optional before a pull request. Affected tests, or CI, cover that run.
