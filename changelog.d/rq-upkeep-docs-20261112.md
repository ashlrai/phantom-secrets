### Added (`phantom git-credential`)

- `phantom git-credential get`, `store` and `erase` implement the Git
  credential-helper protocol for HTTPS github.com. The helper hands the
  selected project vault credential only to a pipe; terminals and files are
  refused. Setup and the plaintext handoff boundary are in
  `docs/git-credential.md`.

### Added (`phantom redact --stream`)

- `phantom redact --stream` scrubs known credential shapes from stdin to
  stdout, flushing each line, with no vault access. Lines over 1 MiB are
  rejected. Shape detection cannot cover arbitrary or encoded secrets.

### Added (`phantom fleet-status`)

- `phantom fleet-status` is a read-only, value-free fleet posture report: each
  secret's name, expiry state, last stored validation result and
  rotation-schedule state, plus the names with overdue rotations. `--json`
  emits the schema in `docs/fleet-status.md`; `--strict` exits 2 when anything
  needs attention or the inventory is partial.

### Added (`phantom open`, `phantom logout`, `phantom completion`)

- `phantom open [page]` opens only the reviewed aliases `dashboard`,
  `billing`, `team`, `docs`, `pricing`, `github`, `issues` and `site`, from an
  attached trusted terminal. Arbitrary URLs and unknown aliases are rejected
  before any browser access.
- `phantom logout` deletes persistent cloud authorization from the OS keychain
  after approval in an attached trusted terminal.
- `phantom completion <shell>` prints a completion script for bash, zsh, fish,
  powershell or elvish.

### CI (changelog coverage)

- A docs-drift test fails when a visible CLI command is never mentioned in
  `CHANGELOG.md` or an unfolded `changelog.d/` fragment, so a shipped command
  cannot go unrecorded.
