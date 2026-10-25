# Changelog

Notable user-facing changes are recorded here. Phantom follows [Semantic Versioning](https://semver.org/) while pre-1.0: minor releases may change unstable interfaces, and breaking changes should be called out explicitly.

## [Unreleased]

### Fixed (`phantom wrap` / `phantom unwrap` no longer reformat package.json)

- `phantom wrap`, `phantom unwrap`, `phantom_wrap` and `phantom_unwrap`
  re-serialized the whole package.json, which sorted every key alphabetically,
  switched the indent to two spaces and always added a final newline, so one
  wrap produced a diff across unrelated fields. They now edit only the
  affected `scripts` members in the original text: a wrapped script keeps its
  position, its `NAME:raw` copy goes directly after it with the same layout,
  and key order, indentation (spaces or tabs, any width), line endings, string
  escapes and the trailing newline (or its absence) are kept. `phantom unwrap`
  is the exact inverse and restores the file byte for byte. The edited text is
  parsed again and must match the intended change; a package.json the editor
  cannot place the change in (for example a duplicate `scripts` key) is
  refused with no change written.

### Fixed (one hardened active-environment reader)

- `phantom_core::env_scope::read_active_env` and `resolve_env` still followed
  a symlinked `.phantom/env` and returned any name, including `../prod`, so
  only the CLI's own copy of the reader was hardened. They now are the one
  reader: the selector is read without following a symlink, must be UTF-8,
  and must hold a valid environment name; both return an error instead of a
  name, and `resolve_env` validates an explicit environment argument too. `phantom exec` and
  `phantom start` use this reader.
- The refusal for a symlinked, non-UTF-8 or invalid selector told users to
  run `phantom env use <name>`, which the CLI does not accept. It now names
  the working fix: replace `.phantom/env` with a regular file holding one
  valid name, or remove it to serve the default environment.

### Fixed (cloud and team pushes refused a locked vault only after consent)

- `phantom cloud push` and `phantom team vault-push` asked for the typed
  trusted-terminal confirmation before noticing that the project's
  encrypted-file vault was locked (passphrase absent or wrong) or that only a
  partial, keychain-only inventory was visible, so the consent was spent on a
  push that could never succeed. Both now refuse before any consent prompt,
  with the same "Vault locked:" / "Refusing to push ... from a partial
  inventory" errors as before; the check still runs again after consent,
  before any value is read. The MCP `phantom_cloud_push` and
  `phantom_team_vault_push` tools already refused before approval.

### Fixed (cloud push no longer copies a secret demoted to read-only; team push refuses before consent)

- `phantom cloud push` and `phantom_cloud_push` read every value with a plain
  vault retrieve, so a secret the expiry policy demoted to read-only was
  copied into the cloud snapshot, and every machine that later pulled it
  stored it read-write, where `phantom exec` injects it. Both now refuse the
  whole push when any entry is read-only or its lifecycle metadata cannot be
  read, naming entries only: the CLI before the trusted-terminal prompt and
  again after it, and MCP before the one-use approval is requested or
  consumed and again after it, in both cases before any value read, cloud
  passphrase access or network call. Values are then read with the injection
  check, so an entry demoted after the gate is never sent. Rotate or promote
  the entry, then push again.
- `phantom team vault-push` asked for the trusted-terminal confirmation and
  only then refused an overdue enforced secret, a read-only entry or
  unreadable lifecycle metadata, so the user typed the confirmation for a push
  that could not run. These refusals now come before the prompt, from names
  and metadata alone, and run again after it before any value read.
- The read-only lifecycle refusal is one shared function in
  `phantom_vault::rotation_gate` used by `phantom sync`, `phantom_sync`'s
  `live_gate_refusal`, team push and cloud push in the CLI and MCP, so their
  wording cannot drift. Messages are unchanged for sync and team push.
- Unchanged: `phantom reveal` (a trusted-terminal human read), encrypted
  export, and `phantom env copy`, whose copy keeps the source entry's
  read-only mode.

### Fixed (`phantom start` ignored the active environment)

- `phantom start` always served the default environment: after
  `.phantom/env` selected `prod` it quietly mapped the `default/` values (or
  the legacy bare entry), and refused a key that only had a `prod/` entry, while
  `phantom exec` in the same directory served `prod`. Start now resolves the
  environment exactly as exec does and applies the same per-environment
  rotation-on-access gate, read-only lifecycle check and retrieval path: the
  `<env>/NAME` entry, with the legacy bare entry only for the default
  environment. A non-default environment never falls back to default values.
  The "secret(s) mapped" line now names the environment.
- The active-environment selector `.phantom/env` is now read without
  following a symlink, and its contents must be a valid environment name
  (letters, digits, `-`, `_`). `phantom exec` and `phantom start` refuse a symlinked,
  non-UTF-8 or invalid selector before reading any secret value, instead of
  addressing vault entries under an arbitrary prefix.

### Fixed (`phantom wrap` no longer breaks scripts that are a shell command line)

- `phantom wrap` and MCP `phantom_wrap` prefixed each selected script with
  `phantom exec --`. `phantom exec` runs its arguments as one program without
  a shell, so a script such as `NODE_ENV=production node server.js` became a
  script that fails (`NODE_ENV=production` is not a program), and
  `next build && next start` or `node server.js | pino-pretty` ran only the
  first command under the proxy while the rest ran without it. Both now leave
  a script unchanged, with no `:raw` copy, when it is empty, starts with a
  `VAR=value` assignment, chains commands (`&&`, `||`, `|`, `;`, `&`, a line
  break) or uses a subshell; quoted operators and redirections such as
  `2>&1` do not count. The CLI warns once per skipped script (also under
  `--quiet`) and the MCP result lists them with the reason. Simple scripts are
  wrapped exactly as before, and `phantom unwrap` is unchanged. The MCP
  confirmation and approval gates are unchanged.

### Fixed (`phantom sync --dry-run` reports the refusal the live run would return)

- `phantom sync --dry-run` exited 0 and reported a ready plan for a
  selection that the live run refuses: it skipped the rotation-enforcement
  gate and the read-only lifecycle gate. The dry run now applies the same
  gate over the same per-target selection, from vault metadata alone (no
  value read, no prompt, no provider call). When the live run would refuse,
  the report's new `live_gate_refusal` field carries the refusal (names
  only), and the dry run exits non-zero. The `phantom_sync` MCP tool reports
  the same `live_gate_refusal` and says in `next_step` that the live run
  would refuse, instead of telling the agent to run `phantom sync`.

### Fixed (expiry-policy promotion and team push of read-only secrets)

- `phantom_apply_expiry_policy` promoted a read-only secret back to
  read-write whenever `rotated_at` was later than `expires_at`, without
  checking that this `expires_at` was still ahead. A secret rotated once
  after an old expiry whose current expiry had also passed was promoted
  while still expired, only to be demoted again on the next run. Promotion
  now also requires the secret to be unexpired under the same
  `now >= expires_at` rule that demotes it; demotion is unchanged.
- `phantom team vault-push` and `phantom_team_vault_push` read values with a
  plain vault retrieve, so a secret the expiry policy demoted to read-only
  was still encrypted to every team member. Both now refuse the whole push
  before any value read or network call (and, over MCP, before the one-use
  approval is requested or consumed, and again after it) when any entry is
  read-only or its lifecycle metadata cannot be read, naming entries only.
  Values are then read with the injection check, so an entry demoted after
  the gate is never sent. Cloud push, encrypted export, env copy and reveal
  are unchanged.

### Fixed (`phantom sync` no longer pushes a secret demoted to read-only)

- `phantom_apply_expiry_policy` demotes an expired secret to read-only so
  that it is not injected at runtime until it is rotated or promoted, and
  `phantom exec` and foreground `phantom start` refuse it. A live
  `phantom sync` still read it with a plain vault retrieval and pushed it to
  Vercel or Railway, where every deployment injects it. The live sync
  preflight now refuses the whole run when any selected entry is read-only
  (or its lifecycle metadata cannot be read), before the trusted-terminal
  review, any vault value read, or any provider call; the error names the
  entries only. The value read itself now uses the runtime-injection check,
  so an entry demoted between the preflight and the read is recorded as a
  retrieval failure and never sent. `--dry-run` is unchanged. Confirmations
  and the trusted-terminal challenge are unchanged.

### Fixed (a cross-project copy holds its source project's lock until it commits)

- `phantom copy` and MCP `phantom_copy_secret` verified the source project's
  entry before and after the destination writes but did not hold the source
  project's transaction lock, so a source change that landed and was reverted
  between the checks, or landed after the final check, was not excluded. The
  copy transaction now holds both projects' locks for the whole commit, taken
  in one global order (process-local shards by index, then each project's
  filesystem locks by the digest of its canonical path), so two copies in
  opposite directions wait for each other instead of deadlocking, and a
  source and destination that are one canonical project take its lock once.
  The before/after source checks stay as defence in depth.
  `commit_init_with_source_vault` now takes the source project directory, and
  a source change caught mid-commit is reported as
  `InitTransactionError::SourceChangedDuringCommit` with the same message the
  generic commit error carried. Confirmations, approvals and the
  trusted-terminal challenge are unchanged.

### Fixed (evidence verification, MCP approval, workspace-request, leak-profile and compliance-report state resolve through a retained directory)

- `phantom-evidence` receipt verification still opened the lock, integrity
  key and log by path, so renaming `~/.phantom` or `~/.phantom/evidence` away
  after the store opened and putting another directory there redirected the
  reads. Verification now opens each file read-only relative to the
  directories the store retained, through the new
  `PrivateStateDir::open_file_readonly`: never created, never chmod-ed, a
  symlink never followed, and a non-regular, multiply linked, foreign-owned
  or non-0600 file refused as unsafe storage.
- The MCP approval store and the workspace-request store opened their lock
  files by path after checking `~/.phantom`; the approval lock was chmod-ed
  through the handle, so a lock hard-linked to another file changed that
  file's mode, and the workspace-request lock accepted a hard link. Their
  keys (approval HMAC key, request HMAC key, plan-seal and journal roots),
  approval records, request records and the request directory listing and
  pruning were also resolved by path. Both stores now hold `~/.phantom` (and
  `workspace-requests/`, `workspace-journals/`) as `PrivateStateDir`s and
  open, create, replace and remove every file relative to them; a symlinked,
  hard-linked, non-regular or foreign-owned entry is refused with
  `InvalidData` and left unchanged. `load_existing_workspace_plan_key` opens
  `~/.phantom` with the new `PrivateStateDir::open_existing`, which neither
  creates nor tightens it.
- The contextual leak-profile store and saved compliance reports now stage,
  rename and create their files relative to the checked `~/.phantom` and
  `~/.phantom/reports` directories instead of by path.
- `PrivateStateDir` gains `open_existing`, `open_file_readonly`,
  `remove_file` and `file_names`, all relative to the retained descriptor on
  Unix; other platforms keep the path-based fallback that refuses symlinks and
  reparse points.

### Fixed (a copy is refused when its source changes before the commit)

- `phantom copy`, MCP `phantom_copy_secret` and `phantom env copy` read the
  source's metadata before its value, outside the copy transaction, and only
  the source value was checked again at commit (`phantom copy` and MCP copy,
  which write into another project's vault, did not recheck the source at
  all). A source demoted to read-only, given an expiry, or rotated between
  that read and the commit left the copy with stale, weaker metadata, or a
  rotation stamp that did not match its value. The inherited protection is
  now bound to its source entry: the transaction requires the source to
  still hold the copied value and exactly the metadata that was read, at
  preflight, atomically with the destination's inherited-metadata write when
  both live in one vault, and again after every vault write before the final
  dotenv commit. Any drift refuses the copy, rolls the destination back, and
  says to retry. `phantom env copy`'s source guard, which only re-wrote the
  same value, is replaced by this check. `InitSecret::inheriting_source_protection`
  now takes the source entry's name, and cross-project copies commit through
  `commit_init_with_source_vault`. Confirmations, approvals and the
  trusted-terminal challenge are unchanged.

### Fixed (session and evidence state use the shared private-directory helper)

- The inactive `phantom-session` journal and the `phantom-evidence` store
  kept their own copies of the private state-directory helpers. They created
  `sessions/`, `~/.phantom` and `~/.phantom/evidence` with umask permissions
  and then chmod-ed them by path after a separate symlink check, accepted a
  directory owned by another user whenever that chmod succeeded, re-walked
  the directory path for every later lock, state, key, log and receipt
  operation (so a directory renamed away and replaced by a symlink after the
  check redirected Phantom's writes outside it), and chmod-ed an existing
  hard-linked lock or state file, changing its target. Both now use the new
  `phantom_core::fs::PrivateStateDir`: on Unix the directory is created 0700,
  opened without following a symlink, required to be owned by the current
  user, tightened through that descriptor and retained, and every file is
  created, opened, replaced (staging file plus `renameat`) and fsynced
  relative to it. Files must be single-link regular files owned by the
  current user. Refusals keep mapping to each crate's `UnsafeStorage` error;
  nothing about either crate's fail-closed production posture changes.

### Fixed (proxy lifecycle lock file is opened through a verified directory descriptor)

- After checking that `<data dir>/phantom-secrets/proxy-locks` was a private
  real directory, the proxy lifecycle lock file was still opened by path, so
  swapping either directory for a link in that window redirected where the
  lock file was created and opened. On Unix the app directory and
  `proxy-locks` are now opened without following a symlink, must be owned by
  the current user (and private when acquiring), and the lock file is opened
  relative to that descriptor with `O_NOFOLLOW | O_CLOEXEC` (created 0600)
  and must be a regular file owned by the current user. `phantom status`
  inspection uses the same chain and still never creates anything.
  Non-Unix behavior is unchanged.
- New `phantom_core::fs::open_owned_directory` and
  `phantom_core::fs::open_owned_file_at` hold the shared descriptor-relative
  routine; the workspace setup lock now uses them instead of its own copy.

### Fixed (copies are never less protected than their source)

- `phantom copy`, MCP `phantom_copy_secret` and `phantom env copy` carried
  only the source's rotation anchor, so the destination came out read-write,
  with no expiry and no TTL policy even when the source was demoted to
  read-only, past its `expires_at`, or under a rotation policy. A copy of a
  read-only secret was therefore injectable by `phantom exec`, and an expired
  credential's duplicate passed `phantom expiry enforce`. The destination now
  inherits every lifecycle field of the source (`created_at`, `rotated_at`,
  `expires_at`, `rotation_policy` and `vault_mode`) by compare-and-swap inside
  the same create-only vault transaction (`InitSecret::inheriting_source_protection`,
  replacing `inheriting_rotation_anchor`). Validation metadata, the last
  provider check verdict, is deliberately not copied: the destination starts
  never-checked like any new entry. Confirmations, approvals and the
  trusted-terminal challenge are unchanged.

### Fixed (proxy lifecycle and workspace setup locks never follow a planted symlink)

- The workspace setup lock lived in a shared temp-dir folder
  (`phantom-workspace-locks`) created with `create_dir_all` and umask
  permissions, and its `<digest>.lock` file was opened with `O_CREAT`
  following symlinks. On a shared `/tmp`, another local user could pre-create
  that folder and plant a predictable link, so Phantom would create or open an
  arbitrary file the user can write. The folder is now created 0700 and must
  be a real directory owned by the current user with no group or other
  access (an owned one is tightened through a no-follow descriptor), and the
  lock file is opened relative to that descriptor with `O_NOFOLLOW`.
- The proxy lifecycle lock directory was chmod-ed by path after a separate
  symlink check, and its app directory (for example
  `~/.local/share/phantom-secrets`) was created with umask permissions and
  followed if it was a symlink. Both Phantom-owned directories are now
  created 0700, refused when they are symlinks or non-directories, and
  tightened through a no-follow descriptor. A symlinked `~/.local/share` or
  `XDG_DATA_HOME` (or temp directory) is still followed as before.
- New `phantom_core::fs::ensure_private_leaf_dir` holds the shared
  final-component routine; `ensure_private_dir` now calls it after its
  parent-chain checks.

### Fixed (audit tail and audit readers no longer follow a symlinked audit log or `~/.phantom`)

- `phantom audit tail` and `phantom audit anomalies --realtime` created
  `~/.phantom` with `create_dir_all` (umask permissions) and opened
  `audit.log` with a plain create-and-append open, which follows symlinks: a
  planted `audit.log` or `~/.phantom` symlink redirected the follow (and the
  file creation) somewhere else, and a dangling `audit.log` link created its
  target. Both now go through `phantom_core::audit::open_log_for_follow`,
  which creates `~/.phantom` 0700 and the log 0600, refuses a symlinked or
  non-directory `~/.phantom`, and refuses a symlink or non-regular file at
  the log path, failing with a clear error.
- `phantom audit show`, `phantom audit verify`, the analytics and windowed
  anomaly readers, and the MCP `phantom_audit_recent` tool decided whether
  the log existed with `Path::exists`, which follows symlinks: a dangling
  symlink at `audit.log` read as "no audit events yet" with success, and a
  log under a symlinked `~/.phantom` was read through the link. They now use
  `phantom_core::audit::log_present`, which follows nothing: a symlinked
  `~/.phantom` is refused, and anything at the log path is handed to the
  no-follow reader, which refuses it. A missing log still reads as empty.
  `phantom doctor` reports a symlinked or non-regular audit log as an issue.
  The JSONL schema and HMAC chain are unchanged.

### Fixed (copies keep their source's rotation age)

- `phantom copy`, MCP `phantom_copy_secret` and `phantom env copy` judged
  the source against `enforce_rotation_on_access` but stored the destination
  as new, so a secret 29 days into a 30-day window came out of the copy with
  a fresh 30-day clock. The destination entry now inherits the source's
  rotation anchor (`created_at` and `rotated_at`) inside the same vault
  transaction, so the gate judges the copy overdue exactly when the source
  is. A source with no recorded age gives a copy with no recorded age, which
  the gate refuses for an enforced secret. Confirmations, approvals and the
  trusted-terminal challenge are unchanged.

### Fixed (workspace-request and MCP approval state dirs use the shared private-dir helper; `.env.example` presence is never followed)

- The workspace-request store (`~/.phantom/workspace-requests`, the setup
  journal directory and its lock) and the MCP approval store kept their own
  copies of the private-directory routine: `create_dir_all` followed a
  symlinked `~/.phantom` ancestor and created state at its target, missing
  `.phantom` ancestors were created with umask permissions, and the final
  `chmod 0700` went by path to a directory of any owner. Both now call
  `phantom_core::fs::ensure_private_dir`, like the rest of Phantom's state:
  symlinked or non-directory components are refused, missing `.phantom`
  ancestors are created 0700, and only a directory the caller owns is
  tightened, through a no-follow handle. A refusal still reports
  `ErrorKind::InvalidData`.
- Workspace inspection judged `.env.example` with `Path::is_file`, which
  follows symlinks. A dangling link or a directory at that name read as
  absent, so setup planned to generate the file and the transaction's
  no-follow writer then refused the whole plan. Presence is now judged with
  `symlink_metadata`: any object at the name counts as present and is never
  followed or replaced. A symlink to a shared `.env.example` still counts as
  present, exactly as before.

### Fixed (`enforce_rotation_on_access` covers team, provider and competitor imports)

- The remaining inflows also gave a value of unknown age a fresh rotation
  anchor (or kept the local one on overwrite), laundering an overdue secret:
  `phantom team vault-pull`, MCP `phantom_team_vault_pull`, provider
  `phantom pull --from vercel|railway`, and `phantom import --from
  doppler|infisical|dotenvx|1password|env`. Each now refuses every entry it
  would write whose secret has `enforce_rotation_on_access = true`, before
  any vault or config write, with the same `Refusing to ...: rotation
  enforcement blocked N secret(s).` wording. `phantom import --from` judges
  names before the trusted-terminal challenge; team and provider pulls learn
  the names only from the download, so they judge them after it. Entries
  that are not written (an identical value, or an existing entry skipped
  without `--force`) keep their anchor and are not judged.
- Known limit: `phantom remove NAME` followed by `phantom add NAME` with the
  same old value still starts a fresh age. Telling a re-added old value from
  a genuine replacement would mean keeping a value-derived fingerprint of a
  removed secret, so it is left as is.

### Fixed (existing loose Phantom state directories are tightened to 0700)

- A `~/.phantom` or project `.phantom` directory that already existed with
  group/other permissions (for example 0755 from an older release or a loose
  umask) was never tightened: only newly created state directories and the
  final directory of `ensure_private_dir` were made 0700, so audit logs,
  leak incidents, validation reports and backups written beneath an existing
  loose `.phantom` stayed listable by other local users.
  `phantom_core::fs::ensure_real_parent` (and so `ensure_private_dir`,
  `atomic_write` and `write_new_file`) now chmods every existing directory
  from the outermost `.phantom` down to the target's parent to 0700 on Unix
  when it is a real directory owned by the current user. A symlinked
  `.phantom` is still refused and nothing reached through it is chmod-ed;
  directories owned by another user are left as they are; directories
  outside a `.phantom` tree (the home directory, the project root) and paths
  that step out with `..` are never tightened. Windows is unchanged.

### Fixed (proxy resolves upstream relative references before scoping them to the route)

- An upstream `Location`, `Content-Location` or `Link` target written as a
  relative reference (`next`, `../v2/x`, `?page=2`) was forwarded unchanged,
  so the client resolved it against its own local URL: `../` could climb out
  of the `/<route>` prefix (onto another route of the same proxy, which a 307
  or 308 would replay the request body to), and a route with a base path or
  SDK version prefix landed on the wrong upstream path. The proxy now
  resolves the reference against the upstream request URL first and maps the
  result like an absolute one, including the relative form under the
  `/<route>/_phantom/<session token>/` base. A same-origin reference the
  route cannot reach (outside its base path, or one the route would forward
  to a different upstream path) is now dropped with a warning instead of
  forwarded; absolute URLs on other origins are still left untouched.
- A `Link` `anchor` parameter naming the route's upstream is now mapped the
  same way as the link target (written back as a quoted string). A `Link`
  header with any unreachable target or anchor is dropped.

### Fixed (`enforce_rotation_on_access` covers cloud push/pull and encrypted backups)

- `phantom cloud push` and MCP `phantom_cloud_push` handed every vault value,
  overdue enforced secrets included, to the cloud copy. They now apply the
  rotation gate before consent or approval (names and metadata only) and
  again before any value is read, refusing with the same
  `Refusing to push to Phantom Cloud: rotation enforcement blocked N
  secret(s).` wording as `phantom exec`.
- `phantom export` carried overdue enforced values into a backup. It now
  refuses them before the trusted-terminal review and again before reading.
- A pulled or restored value carries no rotation anchor: a new entry was
  stamped as stored now and a forced overwrite kept the local anchor, so an
  overdue value round-tripped through the cloud or an old backup came back
  looking fresh. `phantom cloud pull`, MCP `phantom_cloud_pull` and
  `phantom import <backup>` now refuse to write any secret with
  `enforce_rotation_on_access = true` (its age is unknown) before any vault
  or config write; the encrypted restore refuses before its challenge.
  Values identical to the local entry (cloud pull) and entries skipped
  without `--force` are not written and are not gated.
- `phantom copy` now applies the rotation gate before the trusted-terminal
  challenge too, so the user is not asked to confirm a copy that will be
  refused. The challenge is unchanged and the gate still runs again just
  before the source value is read.

### Fixed (Phantom state ancestors are created private; discovery does not follow a `.phantom.toml` link)

- Creating a nested Phantom state directory (for example
  `~/.phantom/shadows/<project>`) made the final directory 0700 but created
  missing ancestors such as `~/.phantom` and `~/.phantom/shadows` with umask
  permissions (usually 0755). `phantom_core::fs::ensure_real_parent`, and so
  `ensure_private_dir` and `write_new_file`, now create any missing directory
  named `.phantom` or beneath one with mode 0700 on Unix. Directories outside
  a `.phantom` tree keep ordinary permissions, and existing directories (the
  home directory included) are never chmod-ed by this path.
- Workspace discovery reported `phantom_initialized` for a `.phantom.toml`
  that was a symlink (followed to its target) or a directory. It now uses the
  CLI's rule: only a regular, non-symlink file counts.

### Fixed (audit, hotspot-ack and shadow state files stay private and are never read or written through a symlink)

- The audit writer created `~/.phantom` with `create_dir_all`, so a fresh
  directory came out 0755 under the usual umask. It is now created owner-only
  (0700); an existing directory you own is tightened, and a symlink or
  non-directory at `~/.phantom` makes the write fail instead of being used.
- Hotspot acknowledgements (`~/.phantom/hotspot-alerts.jsonl`) were
  appended with umask permissions through any symlink at that path and read
  back through one. The file is now opened owner-only (0600, tightened when
  older), never through a symlink, and only a regular file is read; ack
  records behind a link are ignored, so the alert stays visible.
- `phantom audit verify`, `audit stats`, the context walk, hotspot detection,
  the recent-lines reader behind `audit tail`, and the HMAC key and head
  checkpoint loads read their files with `std::fs` calls that followed a
  symlink (and a dangling link read as "no log yet"). They now read regular
  files only and refuse a symlink, directory, FIFO, or device. The audit
  chain format and HMAC are unchanged.
- `ShadowStore` (`~/.phantom/shadows/<project>`) now creates its directory
  owner-only and refuses a symlinked one, writes metadata atomically (0600)
  instead of truncating through a symlink, and reads only regular files.

### Fixed (symlinked `.env` reads and `.phantom.toml` presence checks)

- `DotenvFile::parse_file` read `.env` through symlinks, so a `.env` symlink
  planted in a project made Phantom read a file outside it. It now reads the
  file only as a regular, non-symlink file and refuses a symlink (dangling or
  not), directory, FIFO or device with an error naming the path. A missing
  `.env` is still reported as not found.
- The before-image that `atomic_write_if_unchanged` reads back to compare
  (which can be `.env` plaintext) is now zeroized when dropped.
- `phantom init --multi` treated a directory or symlink named `.phantom.toml`
  as "already protected", and the "run from the project root" hint followed a
  symlinked ancestor `.phantom.toml`. Both now use the same regular-file rule
  as the config loader: such a repo is reported as refused instead of
  skipped, and only a regular ancestor config is named as the project root.

### Fixed (setup backups are created exclusively; leak profiles stay private)

- `phantom setup --client` checked that a `<config>.phantom-bak-<ms>` name was
  free and then renamed over it, so a backup created in between (by a second
  setup run or anything else) could be replaced. Backups are now published
  with a no-replace link/rename (`phantom_core::fs::write_new_file`); an
  object already at the name, even a dangling symlink, is skipped, never
  overwritten.
- The leak-profile store (`~/.phantom/leak-profiles.jsonl`) created
  `~/.phantom` with umask permissions, wrote the file with umask permissions
  through any symlink at the path, and read it through a symlink. The state
  directory is now created 0700 on Unix (an existing one owned by the user is
  tightened; `phantom_core::fs::ensure_private_dir`), the file is written with
  `atomic_write` (0600, replaces a link instead of following it), and it is
  read only as a regular file.

### Fixed (mapped upstream URIs keep the path-auth base; `Content-Location` and `Link` are mapped too)

- A route reached through the `/<route>/_phantom/<session token>/` base URL
  got its upstream redirects mapped to `/<route>/...`, which drops that base,
  so the client's follow-up request was refused as unauthenticated. Mapped
  URIs are now written relative to the request URL (for example
  `../v1/files/abc`), so the client resolves them under its own
  authenticated base and the proxy never echoes the session token, let
  alone a vault value, in a response header. A target with no exact
  relative form (the bare route base, or one whose dot segments would climb
  out of the base) falls back to `/<route>/...`, which fails closed with 401.
- `Content-Location` and every `<target>` of a `Link` header that names the
  route's own upstream are now mapped exactly like `Location`, so an
  upstream origin URL (for example a pagination `rel="next"` link) no longer
  reaches the client and sends it around the proxy. Targets on other
  origins, relative references, and `Link` parameters are left unchanged;
  a `Link` header that does not parse is forwarded as is.

### Fixed (competitor imports: UTF-16 exports and the 1Password format)

- `phantom import --from doppler|infisical|dotenvx|1password|env` failed on a
  UTF-16 export, which Windows PowerShell 5.1 writes for `>` and `Out-File`
  by default, with an unexplained JSON syntax or "not valid UTF-8" error. A
  UTF-16 or UTF-32 file (with a byte-order mark, or BOM-less UTF-16) is now
  refused with an error that names the encoding and how to re-save it as
  UTF-8; nothing is imported and nothing is transcoded silently.
- `phantom import --help`, where the 1Password parse error points, now
  states the expected `--file` format for every source, including the exact
  1Password contract (one flat JSON object of environment variable names) and
  the `op`/`jq` flattening command. Raw `op item get --format json` output is
  refused with that hint instead of a generic "array value" error, and
  `docs/troubleshooting.md` states the same contract. A doc-facts test keeps
  the help, its 1Password example, and the troubleshooting copy in sync with
  the parser.

### Fixed (library writers of `.phantom.toml` and rewritten `.env` files)

- `PhantomConfig::save` wrote `.phantom.toml` with a plain truncate-and-write:
  a crash could leave a truncated config, and a symlinked `.phantom.toml`
  (for example one planted in a cloned repository) was followed, so the TOML
  overwrote the file outside the project it pointed at. It now refuses a
  symlink or other non-regular target, writes atomically (same-directory
  staging file, fsync, rename), keeps an existing file's permissions, and
  creates a new file private.
- `DotenvFile::write_phantomized` replaced a symlinked `.env` with a regular
  file, reset an existing file's mode to 0600, and overwrote a file that had
  been edited after it was parsed with a rewrite of the stale image (silently
  dropping the edit). It now refuses a symlink or other non-regular target,
  keeps the existing mode, and refuses when the file no longer equals the
  source it was parsed from. The CLI and MCP write paths already used the
  anchored exact-before transactions and are unchanged; this hardens the
  public `phantom-secrets-core` API.

### Fixed (`enforce_rotation_on_access` was bypassable by switching commands)

- Only `phantom exec` and `phantom start` applied the rotation gate, so an
  overdue enforced secret could still be printed by `phantom reveal`, copied
  into another project by `phantom copy` or the `phantom_copy_secret` MCP tool,
  pushed to Vercel or Railway by `phantom sync`, sent to teammates by
  `phantom team vault-push` or `phantom_team_vault_push`, or re-stamped as new
  by `phantom env copy`. Each now refuses before any secret value is read, with
  the same per-secret message as `phantom exec` ("Refusing to reveal: ...",
  "Refusing to sync: ...", and so on). `env/NAME` entries are judged by the
  `[phantom.secrets.NAME]` policy and that entry's own age. The MCP tools refuse
  before a one-use approval is consumed and check again just before the read.
- Listing, status, validation, `phantom rotate` and the rotation tools stay
  ungated so an overdue secret can still be found and fixed.

### Fixed (audit log is owner-only and never follows a symlink)

- `~/.phantom/audit.log` and `audit.lock` were opened with plain
  `OpenOptions`: a new log took the process umask (typically 0644, so other
  local users could read secret names, process paths and pids), and a
  symlink planted at either path was followed, redirecting audit appends or
  locking into another file. Both are now opened with `O_NOFOLLOW` and
  created 0600; an existing log or lock with group/other bits is tightened
  to 0600 on the next write; a symlink, directory or FIFO at either path is
  refused (an error under `PHANTOM_AUDIT=required`, skipped under
  best-effort).

### Fixed (every remaining CLI command reads `.phantom.toml` only as a regular file)

- `phantom list`, `reveal`, `status`, `watch`, `add` (and `copy`), `expiry`
  (report, `set`, `enforce`, `rotate`), `rotate --all`, `env list`/`env new`,
  `validate` (and `schedule`, `history`), `grant list`/`status`/`revoke`,
  `leaks plan`, the `agent` readiness vault probe and the `doctor` config
  check still followed a `.phantom.toml` symlink or gated on `exists()`. A
  symlink to another project's config chose which dotenv `watch` and
  `expiry rotate` read, which vault `list`, `expiry` and `env` opened, which
  leak-response policy `leaks plan` applied, and what doctor reported as a
  valid config; a dangling one read as "not initialized" (or as the default
  leak policy); a FIFO hung `list`, `expiry`, `rotate --all` and `env`. They
  now share the regular, non-symlink read used by exec, sync and check, and
  fail closed with a message naming only `.phantom.toml`. `cloud`, `team` and
  `init` now parse the exact bytes they already read safely instead of
  reading the file a second time through the path. Regular files behave as
  before; `phantom reveal` now reports a broken config before its terminal
  prompt instead of after it.

### Fixed (URL query credentials hidden by encoding or a fragment)

- `phantom init` missed a credential in a URL's query string when the
  parameter name was percent-encoded (`?pass%77ord=`, `?api%5Fkey=sk_...`),
  for both public-prefixed and ordinary keys. Parameter names (and the
  values checked for a known secret prefix) are now percent-decoded once
  before matching, case-insensitively.
- A non-public URL checked an older, shorter parameter list than
  public-prefixed URLs, so `?client_secret=`, `?passwd=`,
  `?X-Amz-Signature=`, `?X-Goog-Signature=` and `?key=` holding a known
  secret prefix were left in plaintext under keys such as `CALLBACK_URL`.
  Both paths now share one parser and one credential list; non-public URLs
  keep the broader `auth`/`token`/`api_key` names.
- A non-public URL's `#fragment` was read as part of the last query value,
  so an OAuth implicit-flow credential (`?state=x#access_token=...`) was
  missed. The fragment is now split from the query and its parameters are
  checked on their own for non-public keys; public-prefixed keys ignore the
  fragment as before. Ordinary config such as `?ref=main` or `?lang=en`
  stays non-secret.

### Fixed (proxy redirects lost their route prefix; HEAD responses claimed an empty body)

- An upstream `Location` naming an absolute path, such as a `302` to
  `/v1/files/abc` or a `201` pointing at a new resource, was passed through
  unchanged. Every route shares the proxy's one origin, so the client
  resolved it to `http://127.0.0.1:PORT/v1/files/abc`, dropped the
  `/<route>` prefix and got "no route". A `Location` on the route's own
  upstream (an absolute path, or an absolute URL with the route's scheme,
  host and port, under its base path) is now mapped back to
  `/<route>/...`. Relative references, other hosts, `//host` references and
  paths outside the base path are left unchanged, so a redirect is never
  rewritten to carry the route's credential anywhere else; so is a path the
  route would forward to a different upstream path (its SDK version
  prefix). Upstream redirects are still not followed by the proxy.
- A response to `HEAD` was sent with `content-length: 0`, the length of the
  proxy's empty buffered body, instead of the upstream length of the
  representation a `GET` would return (RFC 9110 section 8.6), so clients
  probing a file's size saw zero. The proxy now forwards the upstream
  `content-length` for `HEAD`, or none when upstream sent none. 204 and 304
  responses were already correct and are now covered by tests.

### Fixed (`enforce_rotation_on_access` was never enforced)

- `enforce_rotation_on_access = true` under `[phantom.secrets.NAME]` was
  documented to block `phantom exec` once the secret was overdue for rotation,
  but nothing called the check, so the option did nothing. `phantom exec` and
  `phantom start` now refuse before any secret value is read when an enforced
  secret is at least one schedule period old (`rotate_every`,
  `rotation_schedule`, or `[phantom.rotation_policy]`; monthly is 30 days).
  The refusal names the secret, its age and the fix, never a value.
- Age is measured from machine-local vault metadata: the later of when the
  vault entry was stored and its last recorded provider rotation. A
  `last_rotated` written in `.phantom.toml` is ignored for this check, so a
  committed edit cannot unlock it. An enforced secret with no schedule, no
  recorded store time, or a store time in the future is refused rather than
  let through.
- The refusal no longer points at `phantom rotate NAME` or a
  `--skip-rotation-check` flag, neither of which replaces a credential or
  exists in this release. To unblock, rotate the credential at its provider
  and replace it with `phantom remove NAME` then `phantom add NAME`, or set
  `enforce_rotation_on_access = false`.

### Fixed (competitor imports: BOM-prefixed JSON and one-pass name fixes)

- `phantom import --from doppler|infisical|dotenvx|1password` refused a JSON
  export that started with a UTF-8 byte-order mark, as Windows PowerShell 5.1
  writes with `Out-File -Encoding utf8`; Infisical and dotenvx then misread
  the JSON as a malformed `.env`. A single leading BOM is now ignored.
- A JSON export with several names that are not environment keys (such as
  Infisical keys `db-host` and `app.port`) was refused one name at a time.
  The refusal now lists every such entry (up to 10, then a count) with a
  suggested name, for example `"db-host" (rename to "db_host")`. Nothing is
  renamed automatically and nothing is imported until the export is fixed.
- The import format table in `docs/troubleshooting.md` described 1Password
  input as `op item list` output (it is a flat `{"KEY": "value"}` object) and
  left out Infisical's JSON array and dotenvx's JSON object. The 1Password
  `jq` recipe produced several objects instead of one; it now builds one
  object and stops on duplicate field labels.

### Fixed (MCP tools read `.phantom.toml` only as a regular file)

- The MCP compliance `env_clean` check and `phantom_check` worktree scan
  treated a dangling `.phantom.toml` symlink as "no config" and could report
  clean while the configured `dotenv_path` went unscanned; followed a symlink
  to another project's config, whose `dotenv_path` then chose what was
  scanned; and blocked forever on a FIFO named `.phantom.toml`. They now read
  the config the way `phantom check` does: only as a regular, non-symlink
  file, with anything else making the result indeterminate (failing, never
  clean). The refusal text names `.phantom.toml` only, never an absolute or
  outside path.
- The same read now backs every MCP tool that loads the project config
  (status, why, cloud status, the vault tools and init), so a symlinked config
  is refused instead of followed, and a dangling one is no longer reported as
  "not initialized".

### Fixed (exec, start, sync, doctor and why read `.phantom.toml` only as a regular file)

- `phantom exec`, `phantom start`, `phantom sync`, `phantom doctor` and
  `phantom why` followed a `.phantom.toml` symlink. One pointing outside the
  project had that other file's `dotenv_path` and routes choose which dotenv
  exec protected and proxied, which file `doctor --fix` repaired, and what
  sync pushed; a dangling one read as "not initialized", so doctor and why
  judged `./.env` instead. A FIFO named `.phantom.toml` hung each command.
  They now share the regular, non-symlink read `phantom check` uses; anything
  else fails closed with a message naming `.phantom.toml` and no other path.

### Fixed (encrypted-file fallback passphrase left unscrubbed in memory)

- When the OS keychain was unavailable, the generated passphrase for the
  encrypted-file fallback vault (and a `PHANTOM_VAULT_PASSPHRASE` value) was
  read from secure storage, generated, verified and handed to the file vault
  as plain `String`s that were freed without being scrubbed, as were the raw
  random bytes it was generated from. Every copy on that path is now held in
  a buffer zeroized on drop, and the value is moved, not copied, into the
  file vault. Vault selection, read-after-write verification and the refusal
  to generate a replacement key for an existing vault are unchanged.

### Fixed (proxy forwarded upstream cookies unscoped across routes)

- Every proxy route is served from the same local origin
  (`127.0.0.1:PORT`), but the proxy passed an upstream's `Set-Cookie`
  through unchanged. A cookie with `Path=/` (or with no `Path`, set on a
  request to the bare route) was therefore stored by a client cookie jar
  for the whole proxy and sent with requests to every other route, and the
  proxy forwards client cookies, so one provider's session cookie reached
  another provider, and a hostile upstream could plant cookies on another
  route. The proxy now removes the upstream's `Domain` and `Path` and sets
  `Path=/<route>` on each `Set-Cookie`, keeping other attributes. Cookies
  that require `Path=/` (the `__Host-` prefix) are rejected by strict
  clients as a result, which keeps them on their route.

### Fixed (encrypted-file vault kept decrypted secrets in memory unscrubbed)

- Every encrypted-file vault operation, including `list` and metadata reads,
  decrypts the whole vault. The JSON buffer was scrubbed, but the parsed
  secret values were dropped without being zeroized, so every secret in the
  vault was left in freed heap memory after each call. The decrypted state
  could also be printed in full through `Debug`. Decrypted values are now
  overwritten when they drop, `Debug` shows names and metadata only, and the
  vault passphrase held by the backend is scrubbed when the backend drops.

### Fixed (browser-prefixed URLs carrying a query-string credential)

- `phantom init` left a public-prefixed URL in plaintext when its query
  string carried a credential, such as `?password=`, `?secret=`,
  `?client_secret=`, a request signature (`sig`, `signature`,
  `X-Amz-Signature`, `X-Goog-Signature`, as in signed S3, GCS or Azure SAS
  URLs), or a `token`/`key`/`api_key` parameter holding a known secret
  prefix. Those values are now classified as secrets. Browser-public tokens
  (Mapbox `pk.`, Google Maps browser keys), analytics params and empty
  placeholders stay public.

### Fixed (exact `rotate_every` intervals)

- A per-secret `rotate_every` longer than 7 days was rounded to monthly, so
  `rotate_every = "90d"` (or `"365d"`) made `phantom_rotation_schedule_next`
  report a monthly schedule and a rotation due about three times too often.
  Every length is now kept exactly as an interval schedule (`strategy =
  "interval"`, new `interval_days` field); `1d` and `7d`/`1w` keep the daily
  and weekly schedules. Weeks (`"12w"`) are accepted alongside days (`"90d"`).
- A `rotate_every` that did not parse (`"3mo"`, `"90 days"`, `"0d"`) was
  silently ignored, falling back to the global policy or to no schedule. It is
  now a config error naming the secret's section, without echoing the value.

### Fixed (imported names that are not environment keys)

- `phantom import --from doppler|infisical|dotenvx|1password` with a JSON
  export vaulted any string as a secret name, such as a 1Password field label
  (`API Key`), a name containing `=` or `-`, or an empty name, and reported
  success, although `phantom exec` can never inject such a name and
  `phantom add` refuses it. These imports now refuse the whole file when any
  name does not match `[A-Za-z_][A-Za-z0-9_]*`; the error names the entry,
  never a value. Doppler's `DOPPLER_*` metadata keys are still skipped first.

### Fixed (worktree check reads `.phantom.toml` only as a regular file)

- `phantom check` (without `--staged`) followed a `.phantom.toml` symlink.
  A dangling one was treated as "no config" and reported clean while a
  credential sat in the regular file its `dotenv_path` would name; one
  pointing outside the project had that other file choose which dotenv files
  were scanned. A FIFO or device named `.phantom.toml` hung the check.
  `.phantom.toml` is now read only as a regular, non-symlink file; anything
  else fails closed with a message naming `.phantom.toml`, as dotenv scan
  targets already did. Ordinary regular configs scan as before.

### Fixed (Vercel pull mixed values from different environments)

- `phantom pull --from vercel` read every Vercel variable for a name and kept
  whichever was listed last, so when a name existed as separate variables
  for several environments (say production and development) a pull could
  store the development value where production was expected, with no
  warning. Pull now keeps only project-wide variables that apply to the
  configured `targets` (those of the Vercel `[[sync]]` entry for the
  project, or production and preview when none names it, the same default
  `phantom sync` uses), and skips Git-branch-scoped preview variables. If
  several such variables for one name do not carry the same value, the pull
  is refused before any local change, naming the key and its environments,
  never a value. The approval plan now lists those `targets`. A name with a
  single matching variable is pulled as before; a name that exists only for
  environments outside the targets is no longer pulled.

### Fixed (browser-prefixed keys holding a private key or URL password)

- `phantom init` left a PEM private key or a connection URL with a password
  (`postgres://user:pass@host`, `redis://:pass@host`) in plaintext when its
  key had a framework public prefix (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`,
  `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`), because only a short list of
  vendor key prefixes overrode the public classification. Those values are
  now classified as secrets and replaced with phantom tokens. Certificates,
  public keys, public JWTs such as a Supabase anon key, and URLs without a
  password stay public.

### Fixed (pre-commit scan by staged entry type)

- `phantom check --staged` skipped every type-changed path (status `T`), so
  a symlink replaced by a regular file holding a credential, or a symlinked
  `.env` replaced by a real one, was reported clean. Type changes are now
  listed and scanned by their staged mode.
- A staged symlink whose name looks like a dotenv or `.phantom.toml` had its
  target path parsed as dotenv text and failed the hook on a commit holding
  no secret; its staged blob is now scanned for credential shapes like code.
  A staged submodule (gitlink) named like a dotenv or `.phantom.toml` made
  the hook fail reading a blob that does not exist; gitlinks are now skipped.
  The check reads only the staged index, never a symlink's target.

### Fixed (JSON imports with a repeated name)

- `phantom import --from 1password|dotenvx|doppler|infisical` now refuses a
  JSON export in which a secret name appears more than once, naming the entry
  (never a value), and imports nothing. Flat JSON objects previously collapsed
  the repeat to its last value with no warning, so a merged or hand-edited
  export could silently store a stale credential; Infisical arrays only
  warned. The dotenv path already refused duplicates.

### Fixed (Vercel sync matched variables by key only)

- `phantom sync` to Vercel matched an existing variable by name alone, but
  Vercel keeps one variable per name and environment set. When the name
  existed only for another environment (say development), sync overwrote
  that variable with the value meant for production and preview, reported
  "updated", and never created it where it was configured. When production
  and preview held separate variables, only the first one listed was
  updated. Sync now never touches a variable whose environments are all
  outside the configured `targets`, updates every project-wide variable
  that applies to a configured target, creates one for the targets nothing
  covers, and leaves Git-branch-scoped preview variables alone. A variable
  that also applies to other environments (Vercel's default is all three)
  is still updated, and sync prints a `warn` line naming those
  environments, e.g. "STRIPE_KEY: also applies to development".

### Fixed (pre-commit code scan under common git config)

- `phantom check --staged` (the pre-commit hook) reported clean for a
  credential added to a staged code file when git was set to
  `color.ui = always`, used an external diff tool (`diff.external`, as
  difftastic's setup does), had a textconv driver for the file, or when the
  check ran from a subdirectory (with or without `diff.relative`). The
  added-line scan now asks git for a plain, uncolored, root-relative diff
  with external diff and textconv turned off, so those settings no longer
  hide a staged key.

### Fixed (audit log durability and key creation)

- With `PHANTOM_AUDIT=1`, each audit line is now fsynced (and the directory
  when the log is created) before the head checkpoint that names it is
  written, so a power loss can no longer leave the checkpoint pointing past
  durable log content and `phantom audit verify` reporting a permanent
  mismatch.
- The audit HMAC key is now written to an owner-only staging file, fsynced,
  and linked into place without replacing an existing key, then the directory
  is fsynced. A crash mid-write no longer leaves a truncated key that breaks
  the whole chain.
- A batch rotation failure reason longer than 120 characters is cut on a
  character boundary; a multibyte character at the cut no longer panics.

### Fixed (init and workspace apply beside a locked file vault)

- Rerunning `phantom init` to protect a new dotenv value, and
  `phantom workspace apply`, stored the new secrets in the OS keychain when the
  project's secrets were in an encrypted-file vault the process could not open,
  splitting the project across two vaults. They now refuse before any vault or
  project file change: "Vault locked: …" when the keychain is empty, or
  "Refusing to … from a partial inventory" when it holds only some secrets,
  with the unlock step (set `PHANTOM_VAULT_PASSPHRASE`), as `phantom add`,
  `phantom cloud pull` and `phantom import` already do.

### Fixed (single-name lookups beside a locked file vault)

- `phantom rotate --name <KEY>` and the MCP tools `phantom_remove_secret`,
  `phantom_copy_secret` (source secret), `phantom_secrets_auto_rotate`,
  `phantom_validate_secret` and `phantom_rotation_schedule_next` reported
  "Secret '<KEY>' not found" when the secret was in an encrypted-file vault
  the process could not open and the OS keychain did not hold it. They now
  refuse with "Vault locked: …" and the unlock step (set
  `PHANTOM_VAULT_PASSPHRASE`), and change nothing. A GitHub grant rotation no
  longer plans a new target in the keychain beside a locked file vault.

### Added (agent doctor preflight)

- `phantom agent doctor --json` prints a value-free preflight
  (`phantom.agent.preflight`, schema version 1) with a verdict, readiness,
  risk level, check ids and severities, and whether an agent can be started.
  It never includes secret names, values, paths, project ids or messages. By
  default it does not open the vault or read the keychain and writes no audit
  lines; `--vault` opts in to the vault and cloud login probe. The exit code
  stays 0 unless `--strict` is set (0 ready, 2 degraded, 1 blocked, 3 could
  not evaluate). See `docs/agent-preflight-contract.md`.

### Security (proxy path auth position and multiply encoded paths)

- URL-carried proxy auth (`/_phantom/<token>/`) is accepted only directly
  after the route prefix, as the URLs `phantom exec` sets place it. A
  `_phantom` segment anywhere else is no longer silently cut out of the path
  (which sent the request to a different upstream endpoint) and can no longer
  ride upstream in the forwarded path; the request is refused with 400 before
  routing.
- Path segments are checked for dot segments and encoded separators at every
  percent-decoding layer, so `%252e%252e` or `%252f` is refused with 400
  instead of reaching an upstream that decodes twice.

### Security (proxy partial-echo redaction)

- The proxy now redacts any run of 12 or more consecutive characters of a
  managed key in response headers and bodies, not only the whole key, so an
  upstream that echoes part of the swapped-in key (first half, last half or a
  middle slice) no longer passes it to the child. Streams carry at most 11
  trailing bytes between chunks, and only while they could still start a run,
  so runs split across chunks are caught without delaying clean events.
  Masked displays such as `sk-ant-api03-...wxyz` pass unchanged. Partial
  matching applies to token-like values of 16 or more characters; connection
  strings and passphrases are still matched exactly only.

### Security (vendor error summaries)

- Rotation and issuance error summaries keep a vendor's `type`, `code` or
  `status` value only when it is a short structural code such as
  `invalid_request_error`. Any other value prints as `withheld`, so a key a
  vendor echoes into one of those fields no longer reaches CLI output, MCP
  responses or the audit log.

### CI (docs command check on docs-only PRs)

- New `Docs command check` job runs `docs_command_flags_test` on pull requests
  that change README.md, top-level `docs/*.md`, `apps/web/src/`,
  `apps/web/public/llms*.txt` or a workflow. Docs-only and web-only PRs skip
  the Test job, so until now the check that documented `phantom` commands and
  flags match the CLI never ran on the PRs that change those docs; drift could
  only show up on `main` after merge. It is part of `CI Gate`.
### Docs (Temporal: codec errors in the CLI)

- `docs/temporal.md`: explains why `temporal workflow show` reports
  `context deadline exceeded` after about 10 seconds when the Codec Server
  refuses: the Go SDK retries the codec error as gRPC `Unknown` inside the
  default 10 second RPC timeout. Links each step at CLI v1.9.1, SDK v1.47.0
  and api-go v1.63.5, and records a local measurement (5 decode calls, 10.0 s,
  for 400, 500, 422 and a bad 200). Upstream behavior; the example is unchanged.

### CI (Temporal codec example)

- New `Temporal codec example tests` job runs the example's 25 unit and local
  HTTP tests when `examples/temporal-codec-python/` or a workflow changes, and
  on every push to `main`; it is part of `CI Gate`. Dependencies come from
  `requirements-ci.txt`: exact versions, wheels only, `--require-hashes`. A
  skipped test fails the job.

### Fixed (Temporal codec example: Web UI calls)

- `examples/temporal-codec-python`: the codec server now routes on the URL
  path only. Temporal Web UI 2.54.1 calls `/decode?preserveStorageRefs=true`,
  which the sketch refused (preflight 403, POST 404). A malformed body now gets
  400. Adds `e2e_worker.py` and `e2e_start.py`, and `docs/temporal.md` records a
  local end-to-end run (CLI v1.9.1 dev server on 127.0.0.1, worker under
  `phantom exec`, payloads `binary/encrypted` in history, decoded through
  `--codec-endpoint`, CORS preflight checked with curl). The Web UI rendering
  was not checked.

### Changed (Temporal codec example: CORS allowlist and key delivery)

- `examples/temporal-codec-python`: the codec server gains an opt-in exact
  origin allowlist (`PHANTOM_TEMPORAL_CODEC_CORS_ORIGINS`, default none).
  `*`, `null` and patterns are refused at startup; allowed origins get only
  `POST`/`OPTIONS` on `/encode` and `/decode` with `Content-Type` and
  `X-Namespace`, and other origins get 403 with no CORS headers.
- Keys can now be read once from an inherited pipe
  (`PHANTOM_TEMPORAL_CODEC_KEYS_FD`) that is closed after reading, keeping
  them out of argv and the environment. Fixes the server failing at startup
  because `PHANTOM_TEMPORAL_CODEC_KEY_ID` was parsed as a key.

### Docs (Temporal)

- `docs/temporal.md`: configure an Authorizer (the default `noopAuthorizer`
  allows every request, per Temporal's security guide), pin Temporal Server
  v1.32.1 or newer (release page cited), a Codec Server section from
  Temporal's data encryption guide, and why workflow history should carry
  secret names rather than `phm_` placeholders (`phantom exec` placeholders
  are per run). It links the `examples/temporal-codec-python` sketch and
  restates its open question: `phantom exec` does not deliver a codec key.

### Added (proxy TLS key exchange: negotiation test and doctor line)

- New hermetic test `crates/phantom-proxy/tests/tls_pq_negotiation_test.rs`:
  a local rustls server on 127.0.0.1 that accepts only X25519MLKEM768, with a
  per-run self-signed certificate trusted only by the test, completes the
  handshake with the proxy's real upstream TLS client and records
  X25519MLKEM768 on the server side. A negative control server that accepts
  only MLKEM768, which the proxy does not offer, fails with
  `NoKxGroupsInCommon` and the proxy returns 502 `tls_handshake_failed`.
- `phantom doctor`, `phantom doctor --pq` and `phantom doctor --all --json`
  report the key exchange groups the proxy offers, read from the proxy's own
  provider config (`phantom_proxy::upstream_offered_key_exchange_groups`),
  for example "offers X25519MLKEM768 first ...; negotiated only if the
  upstream supports it". A test checks that this list equals the
  supported_groups the proxy sends in its ClientHello. The `--pq` JSON gains
  `proxy_tls_key_exchange`; its "not assessed" entry now names only the group
  negotiated with each real upstream.
- Test-only `ProxyServer::start_trusting_test_roots` (behind the existing
  `test-utils` feature) adds trust anchors for a local TLS upstream. Release
  builds keep webpki roots only. `aws-lc-rs` (already in the lockfile via
  rustls) is a new dev-dependency of the proxy crate.

### Docs and tests (LiteLLM gateway)

- `docs/litellm.md` is now the single LiteLLM guide: the example config
  inline (`phm_` placeholder, `api_base` from the Phantom proxy, run under
  `phantom exec -- litellm`), pinning to `1.83.0` or newer with the
  removed `1.82.7` and `1.82.8` releases and GHSA-5mg7-485q-xm76,
  `allow_client_side_credentials: false`, loopback only, never
  `phantom reveal`, and one "Connect an agent" section for Claude Code,
  Codex, Gemini CLI and Cursor. The Claude Code, Codex and Cursor guides
  now link to it instead of repeating it.
- New hermetic test `crates/phantom-proxy/tests/litellm_gateway_hermetic_test.rs`
  (no LiteLLM, 127.0.0.1 only): the test acts as the LiteLLM client against
  a mock OpenAI-compatible upstream and a second mock that no route names. It
  checks that the placeholder is swapped only at the proxy and only toward the
  configured upstream, that the second mock never receives a request (Host
  override, absolute-form URL, forwarding headers, upstream redirect), and
  that the real key never appears in error or reflected bodies, proxy logs or
  the audit ledger. `tracing-subscriber` (already a workspace dependency) is
  added as a dev-dependency of the proxy crate to capture its logs.

### Added (lease status classification library, no callers)

- `LeaseSummary::status(store_generation, now_unix)` returns a value-free
  `LeaseStatus` (`revoked_by_restart`, `revoked`, `not_yet_valid`, `expired`,
  `exhausted`, `current`, `inconsistent`) for status displays. It is pure and
  is not an authorization decision; `begin_use` keeps its own checks.
- `DurableReplayStore::stored_generation` reads the broker generation from the
  authenticated snapshot without an epoch and never writes, so a status view
  can tell leases revoked by a restart from leases revoked explicitly.
- Nothing calls either yet: no CLI command, and no lease issuance, revoke or
  rotate flow is enabled.

### Added (lease store key provisioning library, no callers)

- `phantom_vault::lease_key` provisions and loads the 32-byte key that
  authenticates the broker's lease store, per the decisions recorded in the
  #230 design note. Provisioning is an explicit call that generates the key
  from the OS CSPRNG, stores it in the OS credential store (macOS Keychain,
  Windows Credential Manager), reads it back, and never overwrites an existing
  entry. Loading never provisions. Linux fails closed until a reboot-durable
  Secret Service store exists. Key bytes are never printed or logged.
- `DurableReplayStore::list_leases` returns a value-free `LeaseSummary` per
  lease (ids, operation, generation, use counts, revoked flag, time window).
  It verifies the snapshot MAC, needs no broker epoch, and never writes.
- Nothing calls either yet: no CLI command, and no lease issuance, revoke or
  rotate flow is enabled.

### Added (`phantom setup --undo`)

- `phantom setup --undo` reads `~/.phantom/setup-manifest.json` and shows what
  it would restore from the backups or remove (files setup created). It is a
  dry run by default; `--undo --apply` performs it. Entries are undone newest
  first and marked undone in the manifest. Backups are kept.
- A file is acted on only if its SHA-256 still equals what setup wrote.
  Otherwise that file is refused and named, its backup is kept, and the other
  files still proceed (exit code is non-zero). `--force-undo` (with `--apply`)
  overrides only that check; it never overrides the symlink refusal or a backup
  that no longer matches the manifest. A missing backup is refused. No file
  contents are printed.

### Changed (`phantom setup --client` refuses to overwrite a differing entry)

- For Cursor, Windsurf, Gemini CLI and Codex, `phantom setup --client <c>` now
  refuses when a `phantom` entry already exists and differs from what setup
  would write (including an entry with extra keys such as `env`). The error
  names the entry and the file and never prints values. Pass `--replace` to
  overwrite it. An identical entry is left untouched.
- Before any write to an existing client config, setup copies it byte for byte
  to `<config>.phantom-bak-<ms>` (mode 0600) and records the change in
  `~/.phantom/setup-manifest.json`: path, backup path, timestamp, action, and
  SHA-256 hashes before and after. The manifest holds no config values. It
  prepares a later `--undo`.
- Behavior change: scripts that relied on setup silently replacing a stale
  entry must add `--replace`. `--replace` is not used for Claude Code, whose
  setup merges into its files, and cannot be combined with `--dry-run`.

### Fixed (audit HMAC key length)

- The audit HMAC key loader now rejects a key file that does not decode to
  exactly 32 bytes, with an error that states the expected and found
  lengths and never echoes key material. Phantom always writes 32 bytes, so
  only a hand-edited or corrupted file is affected. Delete `audit-hmac-key`
  to regenerate it (this starts a new chain). Fixes #270.

### Added (`phantom doctor --all`)

- `phantom doctor --all` (with optional `--json`) prints one read-only,
  value-free report that combines the health checks, the `--pq` report, agent
  readiness (`agent doctor`), MCP approval status (`agent status`) and which of
  `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` and `OLLAMA_HOST` are set and whether
  each points at a loopback host. It never prints a URL and fixes nothing; it
  conflicts with `--fix`, `--pq` and `--expiry`. Default `phantom doctor`
  behavior is unchanged.

### Added (`leaks plan` provider facts)

- `phantom leaks plan` now shows, for each incident with a matched provider,
  where a human rotates the credential and that live rotation is disabled in
  this build. `--json` adds `manual_rotation_location` and `live_rotation`
  (both null when no provider matched). Static text only, no values, no
  network, no writes.

### Fixed (`leaks plan` with `on_leak = "off"`)

- `on_leak = "off"` in a repository's `.phantom.toml` made `phantom leaks
  plan` answer "Nothing to plan" (and `plan: []` in `--json`) without
  reading the user's incidents, which live in `~/.phantom` and cover every
  project. It still plans nothing, but it now warns how many active
  incidents it left out and names `phantom audit incidents`; `--json` adds
  `suppressed_incidents` (null when the incidents could not be read).

### Fixed (`phantom_expiry_enforce` over a keychain-only view)

- With some secrets in the OS keychain beside an encrypted-file vault the
  MCP process could not open, `phantom_expiry_enforce` answered
  `pass: true` (with a `vault_note`) over the keychain alone, while
  `phantom expiry enforce`, whose answer it claims to match, refuses a
  partial inventory. The tool now refuses too (-32600, with the unlock step)
  instead of passing the gate over secrets it never read.

### Fixed (`phantom cloud status`)

- Any account lookup failure, including a network failure, a 5xx response or
  an unparseable reply, was reported as "token expired, run `phantom login`",
  so users were told to log in again when that would not help. Only an
  authentication rejection (HTTP 401) is reported that way now; other
  failures say the account status could not be checked and name the kind of
  failure (could not reach Phantom Cloud, server error, refused, unexpected
  response). The terminal prints only fixed text for that kind; MCP
  `phantom_cloud_status` also gives the HTTP status, using the classifier now
  in `phantom-secrets-core`.

### Fixed (cloud vault key and team keypair)

- Any failure to read the cloud vault key from the OS keychain (a locked or
  unreachable keychain, an access denial, an undecodable value) was treated as
  "no key yet", so `phantom cloud push`/`pull` and the matching MCP tools
  generated a fresh key and overwrote the stored one, leaving every vault
  already pushed under it undecryptable. The team-vault keypair had the same
  flaw and could overwrite the private key that existing team key shares are
  encrypted to. A new key or keypair is now created only when the keychain
  reports no entry; any other read failure is returned as an error and the
  stored key is left untouched.

### Added (`phantom doctor --pq`)

- `phantom doctor --pq` (with optional `--json`) prints a read-only,
  value-free post-quantum readiness report: which algorithms Phantom uses per
  surface, which are quantum-vulnerable (X25519, Ed25519) and which are
  resistant at their current 256-bit key size, and the state of the
  experimental, unaudited `pq-hybrid` feature. It reads no vault, key, or
  config and needs no project.

### Added (`phantom crypto inventory`)

- `phantom crypto inventory [--format text|json]` lists every algorithm and
  format tag Phantom names (AEAD, KDF, MAC, KEM, signature), with its status
  (default, experimental) and quantum class (vulnerable, resistant, hybrid),
  from the crypto-agility registry. It reads no vault, key, or config and
  needs no project. The JSON is Phantom's own shape, not a CycloneDX CBOM.

### Fixed (MCP `phantom_cloud_status`)

- A `.phantom.toml` that existed but could not be read or parsed was treated
  as no config, so the tool silently omitted the last synced version. It now
  says the config could not be loaded, that the local sync state is unknown,
  and how to recover. A missing config still reports nothing. A partial cloud
  reconciliation (blocked `phantom_cloud_push`) is now reported too, matching
  `phantom cloud status`.
- Any account lookup failure, including a network failure, a 5xx response or
  an unparseable reply, was reported as "token expired, run `phantom login`".
  Only an authentication rejection (HTTP 401) is reported that way now; other
  failures say the account status could not be checked and give the failure
  class (could not reach Phantom Cloud, server error with its HTTP status, and
  so on).

### Fixed (`phantom doctor` Claude Code settings check)

- A `.claude/settings.local.json` that exists but is not valid JSON was
  skipped with no row and no issue, so `phantom doctor` could finish with
  "All checks passed!" (and `--json` with `"ok": true`) while the dotenv
  read-grant and legacy MCP entry checks never ran. Doctor now reports it as
  a counted warning with a fix step, and does not print the "dotenv read
  grants remain closed" pass for it.

### Fixed (`phantom cloud status`)

- A `.phantom.toml` that existed but could not be read or parsed was treated
  as no config, so status silently omitted the last synced version and any
  partial-reconciliation warning (a blocked `phantom cloud push`). Status now
  warns that the config could not be loaded, that the local sync state is
  unknown, and how to recover. A missing config still prints nothing.

### Fixed (`phantom audit show --json`, `phantom audit stats --analytics --json`)

- With `--json` and no events, `phantom audit show` (including
  `--leaked-secrets`) printed "No audit events yet" or "No matching audit
  events" on stdout, so a script reading stdout as JSON Lines got prose. The
  hint now goes to stderr and stdout carries zero event lines.
  `phantom audit stats --analytics --json` had the same problem; it now
  prints its normal `{generated_at, secrets}` object with an empty `secrets`
  list. Output without `--json` is unchanged, and an unreadable audit log
  still fails with a nonzero exit.

### Fixed (`phantom audit show`)

- An audit log that existed but could not be read (for example a directory
  at `~/.phantom/audit.log`, or an I/O error) was reported as "No matching
  audit events" and the command exited 0, so `--json` consumers saw an empty
  result. `phantom audit show` now fails with the read error and a nonzero
  exit, matching the MCP `phantom_audit_recent` tool. A missing log still
  reports "No audit events yet", and a readable empty log still succeeds.

### Fixed (`phantom import --from doppler|dotenvx|1password`)

- JSON exports silently dropped entries they could not interpret (an array,
  a nested object, or a Doppler object without a usable `raw`/`computed`
  field; 1Password only printed a warning) and imported the rest, so the
  command reported `0 skipped, 0 failed` while a secret never reached the
  vault. Such an entry now refuses the whole import before any vault change,
  naming the entry and its JSON type but never a value. A Doppler entry
  with `"raw": null` now falls back to its `computed` value instead of being
  dropped; `null` and empty values are still skipped as unset.

### Fixed (`phantom doctor`, `phantom agent setup --apply`, `phantom env`)

- A `.phantom.toml` that existed but could not be read or parsed was treated
  as "no config". `phantom doctor` judged `./.env` instead of the managed
  dotenv the config names, and `--fix` wrote `.gitignore` and `.env.example`
  from it; `phantom agent setup --apply` and `phantom env` did the same.
  Doctor now reports the broken config as a failed check with a next step
  (fix or restore it), marks the managed dotenv as not checked, and `--fix`
  makes no repairs. `phantom agent setup --apply` and `phantom env` refuse
  before any change. A config that does not exist still means "not
  initialized".

### Fixed (`phantom why`)

- A `.phantom.toml` that existed but could not be read or parsed was
  treated as "not initialized": `phantom why` classified `./.env` instead of
  the managed dotenv, dropped the service and exec verdict, and exited 0, so
  a protected key read as fine (`--json`: `"protected": true`, `"exec":
  null`) while `phantom exec` refused to start. It is now an error saying
  protection status is indeterminate, matching MCP `phantom_why`; only a
  missing config still means the project is not initialized.

### Fixed (`phantom list --min-anomaly-score`)

- An audit log that existed but could not be read, or failed integrity
  verification, was treated as empty: every secret came back as
  `anomaly:normal`, the filter matched nothing at levels 1 and 2, and the
  command exited 0. It is now an error naming the audit log (run
  `phantom audit verify`); a log that does not exist yet still means no
  history. The flag is also compared as the documented level (0 = all,
  1 = caution and alert, 2 = alert only) against the anomaly class rather
  than the 0-100 heuristic score, so one retrieval no longer passes
  `--min-anomaly-score 2`, and values above 2 are refused by the parser.

### Fixed (`phantom_audit_anomalies`, `phantom_audit_anomalies_realtime`, `phantom_audit_hotspot_alerts`, `phantom_audit_incidents`, `phantom_leak_incidents_realtime`)

- These tools returned every finding, alert or incident they computed,
  bounded only by the size of the audit log and incident store. Each list
  now holds at most `max_records` entries (new optional parameter on the
  anomaly and incident tools: default 1000, max 10000; a fixed 10000 for
  `phantom_audit_hotspot_alerts`) within the 1 MiB MCP response ceiling
  `phantom_audit_analytics` uses, keeping the highest scores, the most
  urgent alerts (unacked first, then fastest) and the most confident
  incidents. `total_findings`, `total_alerts`, `incident_count` and
  `uncorrelated_count` stay exact; `<list>_returned`, `records_truncated`
  and `max_records` say what was left out. `phantom_audit_incidents` now
  lists incidents most confident first (then most recently seen).
  `ack: true` on `phantom_audit_hotspot_alerts` still acknowledges every
  matching alert, listed or not. Names and counts only, never values.

### Fixed (`phantom_audit_export_report` with `action: "report"`)

- The compliance report came back inline with no bound: one heatmap entry
  per secret (with every day), every leak incident, every rotation-audit
  and anomaly entry, however large the audit history. Each of those lists
  now holds at most `max_records` entries (default 1000, max 10000) within
  the same 1 MiB response ceiling as `action: "export"` and
  `phantom_audit_analytics`, keeping the most-accessed secrets, the newest
  incidents, the secrets longest since rotation and the highest anomaly
  scores. `total_events`, `distinct_secrets` and `high_severity_events`
  stay exact; `heatmap_total`/`heatmap_returned` (and the same pair for
  `leak_timeline`, `rotation_audit`, `anomaly_summary`),
  `records_truncated` and `max_records` say what was left out. A report
  saved with `save: true` is still complete on disk. Names and counts
  only, never values.

### Fixed (`phantom_expiry_enforce`, `phantom expiry enforce --json`)

- With `fail_closed=true` the MCP tool put the secrets that have no expiry
  into its `expired` array (status `no_expiry_policy`), while
  `phantom expiry enforce --fail-closed --json`, which the tool claimed to
  match, kept `expired` to secrets whose expiry has passed and named no
  one. Both now serialize one report,
  `phantom_vault::metadata::ExpiryEnforceReport`: `expired` holds only
  expired secrets, and the new `no_expiry_policy` array names the
  no-expiry violations under fail-closed (empty otherwise). `pass`,
  `ok_count` and `no_expiry_count` are unchanged. Names and timestamps
  only, never values.

### Fixed (`phantom_validate_secret`, `phantom doctor` validation check)

- A read error on a secret's stored validation results was turned into a
  default record and reported as `never_checked: true, is_valid: false`.
  `phantom_validate_secret` now returns `metadata_error: true` with a note
  and null status fields (`metadata_error` is `false` otherwise). The
  doctor validation check warns that those secrets' state is unknown
  instead of counting them as never checked, and no longer reports "All
  secrets passed" over unreadable results.

### Fixed (`phantom_audit_alerts`)

- `last` was passed through with no maximum, so a large value returned
  every persisted leak alert into the agent's context, and the alerts file
  was read whole into memory to pick them. The tool now clamps `last` to
  10000 (the `phantom_audit_analytics` maximum), keeps the newest alerts
  that fit a 1 MiB response, and reports `records_total` (every alert in
  the file), `records_returned`, `records_truncated`, `max_records` and
  `unparsable_lines`; `alert_count` still counts the alerts listed. The
  file is streamed once without following a symlink, holding at most
  `last` alerts and one 64 KiB line in memory, and `phantom audit alerts`
  reads it the same way. Names only, never values.

### Fixed (`phantom_compliance_status`)

- With this project's secrets in an encrypted-file vault the MCP process
  could not open (`PHANTOM_VAULT_PASSPHRASE` unset there) and an empty OS
  keychain selected instead, the badge reported `vault_accessible` and
  `secrets_have_ttl` as passing ("All secrets have an expiry or a rotation
  policy") and could report `compliant: true` over a vault it never read.
  With some keychain entries beside the locked file it reported the vault
  accessible and judged TTLs over the keychain alone. Both checks now fail
  in both states, with the unlock step in the detail, the same rule
  `phantom agent doctor` already applies to its vault probe. A secret
  lifecycle metadata read error now fails `secrets_have_ttl` without
  marking the vault inaccessible.
- The `secrets_have_ttl` detail listed every secret name lacking a TTL in
  one string. It now names at most 20 and always gives the exact count
  ("and N more"; `phantom_secret_rotation_due` lists every one). Names
  only, never values.

### Fixed (`phantom_audit_analytics`, `phantom audit analytics`)

- The analytics window was rounded to a neighbouring preset while the
  report still echoed the requested value. MCP `window_days` 1 to 29
  covered 30 days and 31 or more covered all history; CLI `--window` 1 to
  7 covered 7 days and 8 or more covered 30 days, so `--window 90`
  silently dropped days 31 to 90. Both now cover exactly the last N days
  (`0` is still all history), through one shared
  `phantom_core::analytics::Period::from_window_days`, so the MCP tool and
  the CLI agree. Analytics, records, time series and CSV all follow the
  window. Names and counts only, never values.
- `phantom_audit_analytics` returned every access record in the window
  inline, however many there were. It now returns only the newest
  `max_records` (new parameter: default 1000, at most 10000) within a
  1 MiB response, and reports `records_total`, `records_returned`,
  `records_truncated` and the effective `max_records`. `analytics` and
  `time_series` still cover the whole window. With `format: "csv"` the CSV
  stays the first text block, and the same counts come back in
  `structuredContent` and in a second JSON text block. The CLI keeps
  writing the full export to `--export FILE` or stdout.
- Anomaly-score thresholds now follow one rule everywhere: they are clamped
  to 0.0..=1.0 and NaN is refused with an invalid-params (MCP) or argument
  (CLI) error. The rule covers `min_anomaly_score` on
  `phantom_audit_stats` and `phantom_audit_analytics`, `min_score` on
  `phantom_audit_anomalies`, `threshold` on
  `phantom_audit_anomalies_realtime`, and the CLI's `--min-anomaly-score`
  on `audit stats`, `audit export` and `audit analytics` plus
  `--threshold` on `audit anomalies`. Before, NaN was accepted and
  silently matched nothing, and `phantom_audit_anomalies` echoed an
  out-of-range `min_score` back unchanged.
- The analytics summary and the access records used to come from two
  separate reads of the audit log, each with its own clock reading, so they
  could disagree about an event at the window edge or one appended between
  the reads. `phantom_audit_analytics` and `phantom audit analytics` now
  read once against one `now` (`phantom_core::analytics::export_analytics`),
  and `generated_at` is that same instant.

### Fixed (`phantom_audit_export_report` with `action: "export"`)

- The export returned every matching audit row inline, however many there
  were. It is now bounded like `phantom_audit_analytics`: only the newest
  `max_records` (new parameter: default 1000, at most 10000) within a
  1 MiB response. The CSV or JSON array stays the first text block, and
  `records_total`, `records_returned`, `records_truncated` and the
  effective `max_records` come back in `structuredContent` and a second
  JSON text block. `phantom audit export-range` still writes every row.
- An empty match returned a prose sentence even when `format: "json"` was
  requested. It now returns `[]` for JSON (as `phantom audit export-range`
  does) and a header-only CSV for CSV, with zero counts.

### Fixed (audit CSV exports and `phantom audit export-range`)

- Audit CSV exports did not quote a field containing a bare carriage
  return (`\r`); they only quoted commas, quotes and line feeds. CSV and
  spreadsheet readers treat a bare `\r` as a record break, so one audit
  row (for example a process or hostname field with a `\r`) was read as
  two, the second one forged. `phantom audit export --format csv`,
  `phantom audit analytics --format csv`, `phantom audit export-range
  --format csv`, `phantom_audit_analytics` and
  `phantom_audit_export_report` CSV now quote it, through one shared RFC
  4180 escaper instead of two copies.
- `phantom audit export-range --format json` printed nothing on stdout when
  no rows matched, so `| jq` and scripts got invalid JSON. It now prints
  `[]`, like `phantom audit export`. Names only, never values.

### Fixed (`phantom_secrets_expiry_check`, `phantom_secret_rotation_due`, `phantom_compliance_status`, `phantom secrets-expiring-soon`)

- `days_remaining` truncated toward zero, so a secret that expired less
  than 24 h ago reported `0`, which every consumer reads as "not expired
  yet" despite the documented "negative means already expired". It is now
  floored and strictly negative once a secret has expired (including the
  exact expiry instant): under 24 h ago reports `-1`. Expired values that
  are not a whole number of days shift by one (2.5 days ago: `-3`, was
  `-2`). `SecretMetadata::is_expiring_soon` no longer also returns true
  for a secret that expired under 24 h ago.
- `phantom_secret_rotation_due` put a secret with an `expires_at` but no
  rotation policy (for example a provider-issued expiry) under `no_ttl`,
  even once expired, so an agent never saw it as due. It is now classified
  by its expiry into `due`, `warning` or `ok`, matching `phantom rotate
  --batch` and `phantom doctor`; `no_ttl` holds only secrets with neither
  an expiry nor a policy. Each entry gains `has_rotation_policy`.
- `phantom_compliance_status` failed `secrets_have_ttl` for a secret with
  an `expires_at` but no rotation policy. A secret now passes when it has
  either, the same rule as `phantom_secret_rotation_due` and `phantom
  doctor`.
- `phantom_secrets_expiry_check` entries and `phantom secrets-expiring-soon
  --json` entries gain an `expired` boolean. Existing fields are unchanged.
  Names and lifecycle metadata only, never values.

### Fixed (`phantom_audit_incidents`, `phantom_leak_incidents_realtime`, `phantom audit incidents`)

- The proxy only appends `proxy.response_leak` audit events; incidents are
  persisted by the approval-gated `phantom audit alerts --backfill` (MCP
  `phantom_audit_alerts` with `backfill=true`). Until someone ran it, the
  read-only incident queries answered "No active leak incidents" while
  fresh leak events sat in the audit log. They now also correlate the last
  24 h of leak events in memory, without writing anything, and list the
  incidents no backfill has persisted in `uncorrelated_incidents` (MCP:
  plus `uncorrelated_count`), filtered like persisted incidents
  (`min_confidence`, 24 h window, cleared by a later store of the secret).
  Names only, never values. Each query parses the audit log once, keeping
  only the window's leak events and each name's latest store time.
- Both MCP tools now always return the same JSON object (also as
  structuredContent) with `audit_log_present` and a `next_step`, instead of
  plain text when nothing was found. "Set PHANTOM_AUDIT=1" is said only
  when no audit log exists.
- `phantom audit incidents --json` prints the same object whether or not
  anything was found (it printed a bare `[]` when empty), and the text
  output lists unpersisted incidents. `phantom leaks plan` warns on stderr
  when its plan omits them.

### Fixed (`phantom_audit_recent` and `phantom audit show`)

- Both read the whole audit log into memory to return the last few
  events, and the log is append-only and never rotated. They now read only
  the newest 8 MiB (seeking from the end, dropping the partial first line),
  so memory stays bounded however long the log grows. `phantom audit
  verify` still reads and checks the whole chain.
- Lines that are not audit events used to be skipped silently (MCP) or
  echoed to stderr (CLI). They are now counted, never echoed:
  `phantom_audit_recent` reports `unparsable_lines` and a note pointing at
  `phantom audit verify`, and `phantom audit show` prints the count.
- `phantom_audit_recent` reports `window_truncated` and
  `matched_in_window`; `total_in_log` is present only when the window
  covered the whole log. `phantom audit show` says when older events were
  not examined and fewer than `--last` matched.

### Fixed (`phantom check --runtime` and MCP `phantom_check` runtime mode)

- The runtime check looked only at a fixed list of well-known variable
  names, and the CLI and MCP server used two different lists. A phantom
  token in any other variable, such as one `phantom init` wrote for a
  custom key, was reported clean. Both now scan every environment variable
  through one shared function and report the names (never the values).
- A phantom token is now excused only when it belongs to a live proxy
  session. `PHANTOM_PROXY_PORT` and `PHANTOM_PROXY_TOKEN` must lead to a
  proxy whose health endpoint answers 200 with a body that identifies the
  Phantom proxy (a loopback request with a short timeout and a bounded
  read), and the variable must be named in `PHANTOM_SESSION_KEYS`.
  `phantom exec` now sets that for its child, listing only keys a route
  serves; `phantom start` prints it with its other exports, listing every
  dotenv key holding a phantom token (names only). Excused names are listed in the
  JSON report's `excused` field with `proxy_session: true`. Session
  variables with no live proxy behind them, such as exports left over from
  a stopped `phantom start`, excuse nothing and add a value-free
  `session_warning`. Before this, the check flagged a running session's
  own tokens as "proxy not running". Outside a session the report shape is
  unchanged.
- Variable names in the runtime check's text output have control
  characters escaped.

### Fixed (exec signals and `why` input)

- A SIGTERM, SIGHUP or SIGINT sent to `phantom exec` killed Phantom and left
  the child running, orphaned, against a proxy that was gone. Phantom now
  forwards the signal to the child, waits for it, shuts the proxy down, and
  exits with the child's status (128 + N when signal N ended it). A signal
  Phantom inherited as ignored (`nohup`, a background job started by a
  script) stays ignored and is not forwarded, so the child keeps ignoring it
  too. A SIGINT is not forwarded while Phantom is the foreground process
  group of its terminal, because a terminal Ctrl-C has already reached the
  child; a `kill -INT` from another process in that situation is not
  forwarded either. On Windows, Phantom now waits for the child after Ctrl-C
  instead of exiting first.
- `phantom why ""` (or a blank name) answered "not found" with exit 0. It now
  exits 1 and asks for the exact key name.
- `phantom why` hints named the MCP tool `phantom_status` where the CLI
  command `phantom status` belongs; they now name both.

### Changed (`phantom add --stdin` input handling)

- `phantom add NAME --stdin` used to store only the first line of piped
  input and report success, silently truncating PEM keys and JSON
  documents. Input that still has more than one line after trailing line
  endings are dropped is now refused before anything is stored, with a
  message that names the line count but never the input. Pass
  `--multiline` to store every line, or `--first-line` to keep the old
  first-line behaviour (for example `pass show svc/api | phantom add
  API_KEY --stdin --first-line`, since pass and gopass put metadata after
  the key). Both flags require `--stdin` and are mutually exclusive.
  Single-line input is stored exactly as before.
- `--stdin` reads at most 64 KiB; larger or non-UTF-8 input is refused
  before any write.
- `--stdin` is refused when stdin is a terminal, where the typed value
  would echo; omit it for the hidden prompt.

### Fixed (CLI consistency)

- `phantom why <KEY>` for a key that is not in the dotenv now exits non-zero
  instead of 0. Its `--json` report keeps exit 0, and its `next_step` names
  the `phantom status` command rather than the `phantom_status` MCP tool.
- `phantom doctor` now checks Gemini CLI's MCP config, the same clients
  `phantom setup --status` reports.
- The CLAUDE.md section `phantom init` writes now names the vault backend
  init used (for example the volatile linux-keyutils keyring or the encrypted
  file) instead of always saying "OS keychain".
- `list`, `reveal`, `start`, `expiry`, `rotate`, `export` and `grant` run
  from a project subdirectory now name the parent `.phantom.toml` and say to
  run from there, instead of "Run phantom init first."

### Added (agent status)

- `phantom agent status [--json]` is a read-only, value-free view of MCP
  approval state (pending, approved-and-unused, expired, and whether the
  approval key file exists). It takes no lock and creates no file, and never
  prints nonces, argument hashes, or parameter summaries. Lease state is
  reported as unavailable because the broker is not wired into the CLI.
  Revert: remove the `Status` variant of `AgentAction`; nothing else depends on it.

### Fixed (locked-vault paths missed by #220/#221)

- MCP `phantom_cloud_push` and `phantom_team_vault_push` built the pushed
  snapshot from the OS keychain beside an encrypted-file vault this process
  could not open: an empty keychain answered "No secrets to push", and a
  non-empty one requested approval for a push that would replace the remote
  copy without the file vault's secrets. Both now refuse with "Vault locked"
  and the unlock step, as `phantom cloud push` and `phantom team vault-push`
  do.
- `phantom rotate --batch` answered "No secrets in vault." (or nothing due)
  with exit 0 in that state; it now refuses like `phantom
  secrets-expiring-soon`, and notes a keychain-only answer.
- `phantom export` prepared a backup from that keychain-only view; it now
  refuses before review instead of writing a backup that leaves out the
  file vault's secrets.

### Fixed (broken pipe)

- `phantom <cmd> | head` (for `list`, `why`, `doctor`, `status`,
  `check --json`, `audit` and the rest) panicked with exit 101 and
  "failed printing to stdout: Broken pipe" when the reader closed early. A
  write to a closed stdout is now a quiet exit with status 141, as a shell
  reports SIGPIPE. The SIGPIPE disposition is unchanged, so `phantom exec`
  children and the in-process proxy behave as before. On Windows only the
  `println!` case exits 141; a broken-pipe error a command returns stays an
  error there, since it cannot be tied to stdout.

### Fixed (MCP expiry gate and sync platform; Gemini CLI setup)

- MCP `phantom_expiry_enforce` read TTLs only from `.phantom.toml` overrides,
  while `phantom expiry set` writes them to vault metadata. It returned
  `pass: true` for a secret whose TTL had expired, and with `fail_closed: true`
  it passed secrets with no TTL at all. It now reads vault metadata and gives
  the same answer as `phantom expiry enforce --json`, and it refuses a locked
  encrypted-file vault instead of passing over it.
- MCP `phantom_sync` answered an unsupported `platform` such as `"heroku"` with
  "No sync targets configured". It now returns invalid params naming the
  supported platforms (vercel, railway). Platform names match case-insensitively.
- `phantom setup --status` listed Gemini CLI, but `phantom setup --client
  gemini` was rejected. It now writes `mcpServers.phantom` into
  `~/.gemini/settings.json` (other settings are kept), and `--print` shows the
  snippet.

### Fixed (agent report)

- A malformed dotenv no longer hides a missing managed dotenv in
  `phantom agent report`/`doctor`.

### Fixed (audit verification and audit inputs)

- `phantom audit verify` printed "No audit log found" and exited 0 when
  `~/.phantom/audit.log` had been deleted but its signed head checkpoint
  remained. It now verifies, reports the head mismatch and the missing log,
  and exits 1, as the docs describe.
- `phantom audit verify --json` printed human text. It now prints a JSON
  object (`clean`, `log_present`, counts, `head`, and line numbers; no event
  names or HMACs) and keeps exit 1 on failure.
- `phantom audit report`, `phantom audit export-range` and the MCP tool
  `phantom_audit_export_report` read a malformed date (`notadate`,
  `2026-13-45`, `2026-02-30`) as "no bound", so a scoped report silently
  covered the whole history. A malformed date, or `from` after `to`, is now
  an error (exit 1, or `-32602` over MCP).
- `phantom audit incidents --min-confidence`, `phantom_audit_incidents` and
  `phantom_leak_incidents_realtime` accepted scores outside 0.0 to 1.0, so
  `5` hid every incident and answered "No active leak incidents". They now
  reject such values.
- `phantom exec` and `phantom start` refusing a protected key with no vault
  entry now give the next step: `phantom add KEY` from a trusted terminal,
  or remove the key from the dotenv (default environment only).

### Fixed (locked-vault follow-ups)

- `phantom exec` and `phantom start` said a protected key "has no vault entry"
  when the key was in an encrypted-file vault this process could not open.
  They still refuse, now with "Vault locked: …" and the unlock step.
- `phantom agent report`/`doctor` reported Protected when the configured
  managed dotenv was missing (or could not be resolved), although every
  `phantom exec` would refuse to launch. It is now a critical
  `managed-dotenv-unresolved` finding, as it is a failed check in
  `phantom doctor`.
- The locked-vault notice told users to set `PHANTOM_VAULT_PASSPHRASE` "to the
  passphrase used", which cannot be followed for a vault made by the automatic
  encrypted-file fallback: that passphrase was generated by Phantom and kept
  in the OS credential store. The notice now says so, names the stored entry,
  and says that no Phantom command opens such a file while the OS keychain
  works.
- With `PHANTOM_REQUIRE_KEYCHAIN=1`, Phantom uses only the OS keychain even
  when `PHANTOM_VAULT_PASSPHRASE` is set, but a set passphrase silenced the
  locked-vault notice, so an empty keychain read as "no secrets" beside an
  existing encrypted-file vault. The notice now covers that case and names
  `PHANTOM_REQUIRE_KEYCHAIN` as the reason.

### Fixed (CLI commands no longer answer "empty" for a locked vault)

- When the project's secrets are in an encrypted-file vault and
  `PHANTOM_VAULT_PASSPHRASE` is not set in the shell, Phantom selects the OS
  keychain instead. With nothing in it, several commands answered as if the
  project had no secrets, with exit 0: `phantom list --json` printed `[]`,
  `phantom expiry enforce` passed (even with `--fail-closed`), and
  `phantom secrets-expiring-soon`, `phantom validate --check-all` and
  `phantom sync --dry-run --json` reported nothing to do. `phantom agent
  report`/`doctor` called the vault accessible. Each now exits 1 with
  "Vault locked: …" and the step to unlock it (set `PHANTOM_VAULT_PASSPHRASE`);
  `phantom list` does the same instead of a warning with exit 0.
- When the keychain does hold some secrets beside a locked file vault, read
  answers are served with a `warn` that they cover only the keychain. Commands
  that must see every secret refuse instead: `phantom expiry enforce`,
  `phantom cloud push` and `phantom team vault-push` (a push from that view
  would replace the remote copy with a partial set).
- `phantom doctor` stopped with the resolver's error when the managed dotenv
  was missing (or could not be resolved). It now reports that as a failed check
  with a fix and finishes the other checks; `phantom doctor --fix` still makes
  no repairs in that state.

### Fixed (MCP errors for states the user can fix)

- With the project's secrets in an encrypted-file vault and
  `PHANTOM_VAULT_PASSPHRASE` unset in the MCP server's environment,
  `phantom_secrets_expiry_check`, `phantom_secret_rotation_due`,
  `phantom_validate_secret` and `phantom_rotation_schedule_next` answered from
  the empty OS keychain: nothing expiring, nothing due, or "secret not found".
  They now refuse with "Vault locked" and the unlock step, as
  `phantom_list_secrets` already reported; the notice also says to back up or
  move aside (not delete) the vault file if the secrets have since moved to
  the OS keychain. When the
  keychain does hold entries beside such a file vault, they answer with a
  `vault_note` saying the answer covers only the keychain.
- Before `phantom init`, with an unloadable `.phantom.toml`, with a wrong
  `PHANTOM_VAULT_PASSPHRASE`, or (for cloud push/pull) before `phantom login`,
  tools returned -32603, which a client shows as a server failure, some with
  no next step ("Project is not initialized", "Decryption failed — wrong
  passphrase or corrupt data"). These are now -32600 errors that name the
  step: `phantom init`, `phantom_doctor`, `phantom login`, or, for a vault
  that will not decrypt (a wrong passphrase or a corrupt vault file), the
  passphrase to set in the server's env config and the restore path.

### Security (dotenv reads check the file they read)

- Reading a dotenv value-blind (`phantom check`, `phantom why`, MCP
  `phantom_check`, `phantom_why` and compliance `env_clean`, and managed
  dotenv resolution) looked the path up to refuse a symlink, then opened it in
  a second step, so a file swapped for a symlink in between was followed. The
  file is now opened without following a final symlink (`O_NOFOLLOW` on Unix,
  `FILE_FLAG_OPEN_REPARSE_POINT` on Windows) and judged on the opened handle;
  a FIFO is refused rather than waited on. On Windows a symlink or junction
  is refused; any other reparse file (a OneDrive/Cloud Files file, a
  deduplicated file) is re-opened from the same handle without the reparse
  flag, so its real contents are read rather than its stub, and refused if
  that reopen fails. Refusals
  and the managed-dotenv "does not exist" / "contains no phantom tokens"
  errors name the file relative to the project instead of by absolute path.
- The remaining project dotenv reads read the same way: `phantom doctor`,
  `phantom watch`, the plaintext hint after `phantom import`, agent readiness,
  workspace discovery and MCP `phantom_status`. Before, they followed a
  symlinked dotenv and reported on its target. Now `phantom doctor` fails the
  `.env` check for a symlink, `phantom watch` refuses it at start-up and
  reports it after a change instead of skipping it silently, and agent
  readiness reports it as an `env-parse-error` finding. The `phantom doctor`
  `.env.example` repair and `phantom_status` reuse the copy already read
  instead of reading the path a second time; `phantom_status` refuses a
  symlinked or malformed managed dotenv as a state error (-32600) with a next
  step instead of -32603. The user-named import source was
  already refused when it is a symlink and is unchanged.
- `phantom_core::fs::read_regular_file`, the read that repairs and
  exact-replace writes take their before-image from (dotenvs, `.gitignore`,
  `.env.example`, `.phantom.toml` and other local state, across init, doctor,
  import, export, cloud, team and the MCP server), now shares that open. On Unix it adds `O_NONBLOCK` and `O_NOCTTY`. On Windows a symlink or
  junction is still refused, but another reparse file (a OneDrive/Cloud Files
  file) was refused outright and is now re-opened from the same handle and
  read for its real contents, so `phantom doctor --fix` works on a synced
  folder. The check that the path still names the file after the read compares
  identity instead of refusing any reparse attribute.

### Fixed (`phantom init` no longer replaces an existing `.env.example`)

- `phantom init` replaced an existing, often committed and hand-written,
  `.env.example` with a generated stub, silently. On one real project that
  dropped about 600 documented lines. init now leaves an existing
  `.env.example` byte-for-byte unchanged, says so on an `->` line, and points at
  `phantom env --output <file>` for a generated example in a new file. It still
  generates `.env.example` when there is none. The pre-commit check
  (`phantom check --staged`) still scans a staged `.env.example` for real
  values, and init now warns, by key name only, when the example it keeps
  holds values that check would refuse.

### Fixed (MCP listing and compliance tools before init or with a locked vault)

- `phantom_list_secrets` and `phantom_list_with_expiry` returned -32603
  "Not initialized" before `phantom init`, which a client shows as a server
  failure. They now return their empty report with `initialized: false` and a
  `next_step`, and open no vault.
- `phantom_compliance_status` resolved the dotenv for its `env_clean` check by
  opening the vault, so before init or with a locked vault the whole report
  failed with -32603. `env_clean` is now read value-blind, without the vault,
  and the vault checks report `pass: false` as before. It also judged one file
  only, so plaintext in `.env.local` passed beside a protected or absent
  `.env`. It now scans `.env`, `.env.local`, `.env.development`,
  `.env.development.local`, `.env.production`, `.env.production.local`,
  `.env.test`, `.env.test.local` and the configured `dotenv_path`, naming each
  offending key by file; a symlinked or unparseable file is indeterminate and
  fails the check. `phantom check` scans the same list (it previously skipped
  `.env.development.local`, `.env.production.local` and the `.env.test` files).
- MCP `phantom_check` kept its own four-file list, ignored `dotenv_path` and
  followed symlinks, so an agent's check could pass a repo the CLI failed, or
  report a file outside the project. It now scans the same list as
  `phantom check` and `env_clean`; a symlink is not read and is reported as
  indeterminate, so the result is not clean.
- The `confirm: true` refusal called every gated tool "a destructive vault
  operation", including `phantom_cloud_status`, `phantom_team_list`,
  `phantom_team_members` and `phantom_validate_all`, which read but send a
  stored credential to a provider. The gate is unchanged (both `confirm` and an
  approval token are still required, as `docs/claude-code.md` specifies); the
  message now says what it guards.

### Fixed (MCP Registry catalog drift)

- `mcp-registry/server.json` still carried the pre-#201 `format` parameter
  descriptions for `phantom_audit_analytics` and `phantom_audit_export_report`,
  so it no longer matched the server's `tools/list`. It is regenerated from the
  runtime catalog, and CI now runs the same registry-parity smoke the release
  build runs, so a tool schema change cannot leave the catalog stale until a
  tag.

### Fixed (MCP `phantom_why` before init and with a locked vault)

- MCP `phantom_why` failed with an internal error (-32603) in a project where
  `phantom init` has not run yet, which is exactly when an agent asks why a key
  is not protected. `phantom why` on the CLI already answered there. It also
  opened the vault only to list names, so a locked keychain or a wrong
  `PHANTOM_VAULT_PASSPHRASE` turned a value-free question into an error.
  - `phantom_why` now reads only `.phantom.toml` and the dotenv, never the
    vault. Before init it classifies `./.env` as `phantom why` does, says the
    project is not initialized, and returns `exec: null`; `next_step` for an
    unprotected secret points at `phantom init`.
  - Its JSON now comes from the same `why_report` that `phantom why --json`
    prints, so the two cannot drift. A malformed `.phantom.toml` or dotenv is
    still an error. Nothing is created or initialized by asking.
  - Before init, `phantom why` and `phantom_why` refuse a `./.env` that is a
    symlink or not a regular file, as the managed-dotenv resolver already
    does after init, so neither reads a file outside the project.
  - When `.phantom.toml` lists no secrets and the dotenv holds no tokens,
    the human summary adds that `phantom_why` does not read the vault and
    points at `phantom_doctor` / `phantom_status` for vault/dotenv drift. The
    JSON is unchanged.

### Fixed (protected keys with no proxy route)

- A protected key that no proxy route injects (for example `GROQ_API_KEY`,
  or a signing secret such as `NEXTAUTH_SECRET`) reaches a `phantom exec`
  child only as a session token that no provider accepts. Nothing said so:
  `phantom why` and MCP `phantom_why` reported it as `PROTECTED` with no next
  step, and `phantom exec` counted it as proxied.
  - `phantom exec` now counts only routed secrets as proxied and warns, on
    stderr and also under `--quiet`, naming each protected key it hands the
    child with no route. Names only, never values.
  - `phantom why`, `phantom why --json` and MCP `phantom_why` add a
    value-free `exec` object for a protected key: `delivery` (`proxied`,
    `no_route`, `withheld`, `connection_string_refused` or
    `custom_route_refused`), `service`, `upstream` and `blocked_by`.
    `blocked_by` names the service when the config stops exec from starting
    for every key (a custom or altered route, or a protected connection
    string), using the same check exec runs. `next_step` explains every
    answer but an unblocked `proxied`. Routing, injection and the effects
    gate are unchanged.

### Fixed (CLI and MCP JSON output)

- `phantom audit stats --json` with an empty audit log now prints the same
  JSON object as a populated log (`total_events: 0`, `secrets: []`) instead
  of a human hint; the hint goes to stderr.
- `phantom audit export --format json` with no matching records now prints
  `[]` instead of nothing on stdout.
- `phantom why <KEY> --json` now honors the global `--json` flag and prints
  the value-free report the MCP `phantom_why` tool returns (`key`,
  `dotenv_exists`, `found`, `classification`, `protected`, `reason`,
  `matched_pattern`, `service`, `next_step`), including `found: false` when
  the key or the `.env` file is missing. Human output is unchanged.
- The MCP `phantom_audit_analytics` and `phantom_audit_export_report` tools
  accept `format` as `json` or `csv` in any letter case and reject any other
  value with an invalid-params (-32602) error. They previously fell back to
  JSON for unrecognized values, including `CSV`.

### Fixed (MCP)

- `phantom_add_secret_interactive` works out of the box again. It only returns
  `phantom add NAME` for the user's trusted terminal (no value accepted, nothing
  stored, no file or network access), yet it required
  `PHANTOM_MCP_EFFECTS=trusted-terminal` plus an approval token, so the add flow
  that `phantom init` documents always failed. It now needs neither gate nor
  `confirm`, keeps strict `[A-Za-z_][A-Za-z0-9_]*` name validation, and no
  longer advertises `approval_token` (legacy callers that send it are still
  accepted). Every tool that performs an effect keeps both gates unchanged.
- Every MCP tool whose schema takes `approval_token` now says so in its
  description, including how approval is obtained; a unit test walks the tool
  catalog to keep it that way.
- The refusal for effectful tools with effects disabled now also says that the
  operator must approve each call in their own trusted terminal and supply the
  `approval_token`, and `docs/claude-code.md` documents how to set
  `PHANTOM_MCP_EFFECTS` outside agent authority.
- MCP secret-name validation now also rejects names longer than 256 bytes.

### Fixed (upgrade)

- `phantom upgrade` no longer depends on the `zip` 8 line, which crates.io has
  yanked in full and which failed the `cargo-deny` dependency policy.
  `self_update` is now built without its zip backend, and Windows `.zip`
  release assets go through Phantom's own path on `zip` 9.0.3: the same
  exact-asset selection, writability probe, and `SHA256SUMS` (plus GitHub
  asset digest) verification before anything is extracted, then a
  `self-replace` swap of the running executable. Only the root
  `phantom.exe` regular-file entry is extracted, to a path Phantom chooses;
  an archive with any absolute, drive-qualified, or `..` entry name, a
  duplicate or symlinked `phantom.exe`, or an entry over the 256 MiB binary
  limit is refused. Linux and macOS `.tar.gz` upgrades are unchanged.

### Fixed (proxy)

- Cloudflare tooling now works under `phantom exec`. The built-in
  `cloudflare` route exported only `CLOUDFLARE_API_TOKEN_BASE_URL`, which no
  Cloudflare tool reads, so Wrangler and the official SDKs sent the `phm_`
  token straight to `api.cloudflare.com` and got `401`. `phantom exec` now
  also exports `CLOUDFLARE_API_BASE_URL` (Wrangler) and `CLOUDFLARE_BASE_URL`
  (the `cloudflare` TypeScript and Python SDKs), and the route restores the
  `/client/v4` path those tools expect in their base URL, so
  `/accounts/...` reaches `https://api.cloudflare.com/client/v4/accounts/...`.
  Requests that already send `/client/v4/...` are unchanged. Both variables
  are scrubbed from the inherited environment like the other route
  overrides. The route definition and its auth handling are unchanged, so
  agentic validation is unaffected and no config change is needed.
- The built-in `twilio` route now sends valid HTTP Basic credentials. It
  previously injected `Authorization: Basic <raw auth token>`, which Twilio
  rejects on every request. The route now keeps the username from the
  client's first `Authorization: Basic` header (the Account SID, a non-secret
  identifier) and replaces the password with the vault value; the client's
  password is always discarded. A request with no usable username (missing,
  non-Basic, containing a `phm_` token, over 128 bytes, or outside
  `[A-Za-z0-9._@+-]`) now gets a local `400` from the proxy naming the fix
  (`Authorization: Basic base64(<ACCOUNT_SID>:<anything>)`) and never
  reaches Twilio. This handling applies only to the exact trusted `twilio`
  route definition, not to custom routes with the same header shape. No
  config change is needed.
- The built-in `google_ai` (Gemini) route now owns every slot where Google
  accepts an API key. The client's `key` and `api_key` query parameters
  (matched case-insensitively after percent-decoding) are dropped, and an
  `Authorization` header carrying a `phm_` token is dropped, so
  `curl ...?key=$GEMINI_API_KEY` and the OpenAI-compatible endpoint
  (`Authorization: Bearer $GEMINI_API_KEY`) reach Gemini with the injected
  `x-goog-api-key`. A client's own OAuth bearer (no `phm_` token) is still
  forwarded. Other routes forward `key` query parameters unchanged.
- The `phantom_token` query parameter is now stripped with the same
  percent-decoded, case-insensitive name match.
- `phantom init` no longer protects a Twilio Account SID (`AC` plus 32
  lowercase hex characters under a key ending in `ACCOUNT_SID`). It is a
  public identifier that appears in every Twilio REST path, so replacing it
  with a `phm_` token broke `/Accounts/{sid}/...` requests. Projects
  initialized earlier keep the SID protected until it is written back to
  `.env` as its plain value.

### Changed (MCP, agent-visible)

- `phantom_list_secrets`, `phantom_status`, `phantom_why`, `phantom_sync`, and
  `phantom_list_with_expiry` now return a human summary, a value-blind JSON
  report as a second text block, and the same report as MCP
  `structuredContent`. Agents that read only the first text block see the
  same summary as before. `phantom_list_with_expiry` reports `expired` and
  `expiring_soon` as `null` when `show_expiry=false`. `phantom_sync` echoes
  `token_env` only when it is a valid env var name and otherwise reports
  `<invalid env var name>`.
- Tools that already returned a JSON object (`phantom_capability`,
  `phantom_do`, `phantom_setup_workspace`, and the audit, leak-incident,
  compliance, validation, expiry, and rotation-schedule tools) keep their
  JSON text unchanged and now also attach it as `structuredContent`.
- The compliance export tool's `report` action with `save=true` no longer
  prefixes the JSON with a `// saved to: <path>` line. It now returns
  `Compliance report saved to: <path>` as its own first text block, followed
  by the JSON report as a separate text block and as `structuredContent`.
- An unknown compliance export `action` now fails with `INVALID_PARAMS`
  (previously `INTERNAL_ERROR`) and tells the agent to retry with `export` or
  `report`.
- Config-load, vault-initialization, and missing-secret errors now name the
  next step (`phantom_doctor`, `phantom doctor` or `PHANTOM_VAULT_PASSPHRASE`,
  `phantom_list_secrets`).

### Fixed

- **SDKs under `phantom exec` reach the versioned API.** `phantom exec`
  exports `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai/_phantom/TOKEN/`, but
  the official OpenAI SDKs and Codex treat `OPENAI_BASE_URL` as the `/v1` root
  and request `<base>/models`, `<base>/chat/completions`. The proxy forwarded
  those to `https://api.openai.com/models` (404). Each built-in route now
  carries the version path its official SDK keeps in the default base URL:
  `/v1` for OpenAI, xAI, Mistral, and Replicate. Unversioned requests on those
  routes get the prefix; requests already starting with a version segment are
  unchanged. Anthropic, Perplexity, Cohere, Gemini, Hugging Face, and the
  non-LLM routes keep their paths as sent. Every route also collapses the
  leading `//` produced when a caller appends `/v1/...` to the slash-terminated
  base URL.
- `phantom exec` / `phantom start` proxy: the upstream timeout is now a 600 s
  idle (per-read) timeout instead of a 30 s total deadline. Previously any SSE
  stream or slow non-streaming reasoning call longer than 30 s (routine for
  Claude Code, Codex and the OpenAI/Anthropic SDKs, which allow 600 s) was cut
  off mid-response.
- A streaming response that the upstream drops midway now aborts the client
  connection instead of ending cleanly, so SDKs see a transport error instead
  of silently accepting a truncated stream.
- Base-URL overrides are exported only for routes whose credential is loaded
  in the session. Previously the default config pointed every supported SDK
  at the proxy, so for example `phantom exec -- claude` with only an OpenAI
  key protected sent every Claude Code request to a proxy 503.
- Also export the base-URL variables the official SDKs actually read:
  `GOOGLE_GEMINI_BASE_URL` (google-genai, Gemini CLI) and `CO_API_URL`
  (Cohere), alongside the existing names. `REPLICATE_BASE_URL` is not
  exported: replicate-python 1.x reads it as the host root while 2.x expects
  it to include `/v1`.
- `phantom start` prints shell `unset` lines for base-URL variables it no
  longer exports, so a stale value from an earlier session is cleared.
- The default global burst guard (`PHANTOM_RATE_LIMIT_BURST`) is now 100
  requests per 10 s. It was 20, below the 50-per-secret limit, so a single
  agent session hit proxy 429s before the per-secret limit could ever apply.
- Upstream responses without a declared `content-length` (close-delimited or
  otherwise unframed bodies such as NDJSON and JSON-array streams) are now
  streamed through the byte-level scrubber instead of buffered until the
  upstream closes and capped at the body limit.
- When the client disconnects mid-stream, the proxy now closes the upstream
  connection immediately instead of holding it until the next upstream byte
  or the idle timeout.
- The default request (and buffered response) body cap is now 32 MiB,
  matching Anthropic's request limit; it was 10 MiB, which image-heavy agent
  turns exceeded. A shared 320 MiB budget (the old 10 MiB x 32-slot worst
  case) bounds bytes buffered across all in-flight requests; a request that
  would exceed it gets a 503 with `retry-after`.
- Proxy-generated error bodies are built with a JSON encoder, and the 429 and
  503 bodies now carry `"source":"phantom-proxy"`,
  the service or secret name, and a fix hint, so agents can tell them apart
  from provider errors.

## [0.7.9] - 2026-09-06

This fix-forward release repairs agent onboarding and Ashlr Hub inspection
compatibility. It does not move or replace the immutable `v0.7.8` tag or its
GitHub Release.

**Release receipt:** the immutable
[`v0.7.9` GitHub release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.9)
(published 2026-09-07) binds 19 assets to source commit
`7a51ce512ec4aee12cc29ff859036af63fbe93db`. Tag-bound workflow
[34153902556](https://github.com/ashlrai/phantom-secrets/actions/runs/34153902556)
passed source verification, all six native release rows, checksum and SPDX SBOM
verification, and artifact attestations. As of 2026-09-29 the Homebrew formula
still installs `v0.7.8`, npm `latest` remains `0.6.0`, and no crates.io or MCP
Registry `0.7.9` publication exists.

### Fixed

- Emit a stable, metadata-only `phantom status --json` response so integrations
  can inspect initialization state without opening the vault, using a bearer,
  or probing the legacy proxy listener.
- Write Claude project MCP registration to `.mcp.json`, preserve unrelated
  settings in `.claude/settings.local.json`, and make legacy-only registration
  visible in readiness diagnostics.
- Exercise the installed CLI and MCP onboarding walkthrough in the
  cross-platform CI matrix, in addition to source-level tests.

### Breaking changes and migration

There are no intentional CLI, proxy, vault, or network-policy breaking changes.
For a project configured by an earlier Phantom build, run
`phantom setup --client claude` from a trusted terminal and review the
generated `.mcp.json`; existing permission settings remain in
`.claude/settings.local.json`. Existing `v0.7.8` artifacts stay immutable.

## [0.7.8] - 2026-09-05

This patch fixes the Windows npm-wrapper failures exposed by the independent
post-release package gate for `v0.7.7`. It does not move or replace the
immutable `v0.7.7` tag or GitHub Release, and `0.7.8` remains a source
candidate until its own tag-bound native, release, and distribution gates pass.

### Fixed

- Accept a Windows 8.3 lexical alias such as `RUNNER~1` only when bigint
  `lstat` volume and file identifiers prove that the alias and native realpath
  name the same filesystem object. Symlinks, junctions, other reparse escapes,
  zero file identifiers, and identity mismatches remain fail-closed.
- Run the bounded Windows ZIP extractor from a private temporary PowerShell
  script with separately passed file arguments. Preserve the exact,
  case-sensitive two-member archive contract and report sanitized extraction
  or candidate-version phase failures without echoing child output or paths.
- Make every native npm-wrapper regression command an independent workflow
  step, so a later passing command cannot mask an earlier Windows failure.
- Install and execute both wrappers from the exact matrix archive with fresh
  caches on every native release runner, including Windows x64 and ARM64.

### Breaking changes and migration

There are no intentional CLI, MCP, proxy, configuration, or network-policy
breaking changes. Existing `v0.7.7` GitHub artifacts remain immutable. Do not
advertise or install `v0.7.8` as a public release until its separately reviewed
release and package receipts exist.

## [0.7.7] - 2026-09-03

This fix-forward patch moves the completed adoption and cross-platform work to
a new release identity. The remote annotated `v0.7.6` tag remains immutably
bound to source commit `618f9f261433d99449ab1541db8a326f40c6493a` and has no
GitHub Release. It must not be moved or reused for the newer source.

### Added

- Render the primary installation, client-integration, architecture, platform,
  troubleshooting, and enterprise guides as first-party static documentation
  with canonical metadata, structured data, sitemap entries, and bounded
  Markdown link handling.
- Add an explicit trusted-terminal Linux migration from the existing volatile
  kernel keyring to Secret Service. Unmigrated projects retain their existing
  backend, partial or contradictory migration state fails closed, and the
  encrypted-file vault remains the documented headless option.
- Exercise both npm wrappers inside every matching native release runner after
  the exact archive and transactional installer have passed acceptance.

### Fixed

- Preserve the six-host package acceptance boundary while passing native
  absolute npm tarball paths through unchanged.
- Keep Windows short-path tildes such as `RUNNER~1` from being encoded as a
  literal `%7E` path segment.
- Resolve native home and cache paths consistently on Windows, including when
  Git Bash or MSYS exports a Unix-shaped `HOME`, without widening accepted
  filesystem authority.
- Restore the adoption-focused landing experience, direct GitHub star actions,
  six-target download chooser, machine-readable discovery files, and truthful
  public release metadata while keeping hosted-service and deployment claims
  separately gated.
- Strengthen encrypted-file restart coverage and Linux backend reporting so a
  volatile kernel-keyring project is not described as reboot-persistent.
- Carry forward dedicated security, pricing, enterprise, and government pages
  from the unpublished `0.7.6` public-site tranche.
- Retain its privacy-preserving analytics, accessibility, responsive behavior,
  and fail-closed rendering when hosted dependencies are not commissioned.

### Breaking changes and migration

There are no intentional CLI, MCP, proxy, or configuration breaking changes.
Linux users must explicitly run and approve `phantom vault migrate-linux` from
an attached trusted terminal before a project switches to Secret Service. The
source and automation are release-candidate evidence only until an immutable
`v0.7.7` GitHub Release and its six native acceptance rows are verified.
Existing direct or Homebrew `v0.7.5` installations can remain in place until
that release is available and independently verified.

## [0.7.6] - 2026-09-03

This patch fixes the Windows path handling in Phantom's exact npm
prepublication gate and refreshes the public adoption experience. It does not
weaken the six-host package acceptance boundary: `0.7.6` must pass that gate
from immutable tagged source before either npm package can be promoted.

### Fixed

- Pass native absolute tarball paths to npm during prepublication acceptance.
  This avoids double-encoding Windows short-path tildes such as `RUNNER~1`,
  which previously made npm resolve a nonexistent literal `%7E` directory.
- Add regression coverage for Windows 8.3-style temporary paths while
  preserving exact tag, source-SHA, package-integrity, cache, and dist-tag
  receipts.

### Public project experience

- Rebuild the landing page around Phantom's local, value-blind security model
  and add dedicated security, pricing, enterprise, and government pages.
- Define the MIT core and written-scope commercial evaluation, integration,
  and support paths without claiming unavailable hosted controls,
  certifications, procurement vehicles, or contractual service levels.
- Reduce the public site's initial JavaScript and harden privacy-preserving
  analytics, accessibility, responsive behavior, and fail-closed dashboard
  rendering when hosted dependencies are not commissioned.

### Breaking changes and migration

There are no intentional CLI, MCP, configuration, vault, proxy, or network
policy breaking changes. The npm acceptance correction affects release
validation only. Existing direct or Homebrew `v0.7.5` installations can remain
in place until an immutable `v0.7.6` release is available and verified.

## [0.7.5] - 2026-09-03

This patch is an immutable GitHub fix-forward release carrying npm-wrapper
portability fixes. The immutable
`0.7.4` npm versions were published under `release-candidate`, were not
promoted to `latest`, and remain available by exact version. Acceptance found
cross-platform first-use installation defects. The immutable `v0.7.5` GitHub
release at source commit `d2969e73995cc139e6253e0c8a70f1d683f88e20`
supersedes those candidates without overwriting or withdrawing them. Its 19
assets, all six native rows, and GitHub provenance and SPDX attestations passed
workflow 33709338577. That GitHub receipt does not prove a Homebrew, npm,
crates.io, or MCP Registry `0.7.5` publication, a commissioned hosted service,
provider activation, signing/notarization, certification, or customer acceptance.

### Fixed

- Open downloaded native binaries read/write before `fsync`, preserving the
  durability barrier on Windows where `FlushFileBuffers` rejects a read-only
  file handle.
- Normalize extracted Unix release binaries from archive mode `0755` to the
  private cache mode `0700` before applying the strict owned-path policy, then
  verify the installed executable retains that private mode.
- Apply the same portability behavior and regression coverage to both the
  `phantom-secrets` and `phantom-secrets-mcp` wrappers.
- Preserve a checksum-matched previous-version cache byte-for-byte until the
  replacement binary and manifest are fully verified and atomically promoted;
  failed downloads, extraction, flushes, or version checks leave no transaction
  debris and never execute the prior binary under the new wrapper version.

### Breaking changes and migration

There are no intentional CLI, MCP, configuration, vault, or network-policy
breaking changes. Users who explicitly installed an npm `0.7.4`
`release-candidate` should replace it with the exact `v0.7.5` GitHub release
artifact for their OS and architecture, after verifying the published
checksum. Do not rely on an unpinned package-manager dist-tag: no npm `0.7.5`
publication is represented by this release receipt.

## [0.7.4] - 2026-09-02

This release hardens local agent setup, transactional secret protection, MCP
effect authorization, retained filesystem authority, Windows private-file
permissions, and the default-closed hosted-service boundary. Its immutable
GitHub Release and Homebrew formula are published. Its npm packages remain
quarantined under `release-candidate` after cross-platform acceptance failed;
crates.io, MCP Registry, hosted-service commissioning, provider integrations,
and customer acceptance are not represented by this release.

### Security and filesystem integrity

- Project transactions now retain the directory identity acquired with the
  project lock. Before-image reads for governed mutations, compare-and-swap
  writes, unlinks, permission changes, and parent creation resolve relative to
  that retained capability, reject paths outside the governed root, and do not
  follow symlink or Windows reparse-point components.
- Sensitive anchored file updates require a regular, single-link target and an
  exact identity-and-content before-image. This rejects hard-linked targets and
  byte-for-byte replacement inodes, while rename-and-decoy tests verify that a
  swapped ambient project path is not mutated.
- Initialization admission now retains the reviewed project-root identity and
  exact leaf snapshots before vault provisioning. After the project lock is
  acquired, Phantom revalidates that root and each reviewed leaf's identity,
  bytes, and permissions before mutation; a byte-identical rename decoy is
  rejected as concurrent drift.
- Anchored writes, unlinks, and directory creation return explicit effect
  outcomes. `CommittedVerifiedButDurabilityUncertain` is a committed, exactly
  verified success with a value-free warning/receipt when the platform cannot
  prove directory crash durability; callers must not roll it back or retry it.
  `CommittedButUncertain` remains a **Partial** result when post-publish
  verification or durability is unresolved and requires reconciliation. Exact
  creation receipts permit cleanup only of the directory identity Phantom
  created.
- On Windows, new private anchored files and directories establish and verify
  a protected current-user DACL before secret bytes are written. Replacement
  files receive and verify the reviewed file's exact DACL, inheritance state,
  and read-only state before bytes are copied. These are source-level contracts;
  protected native Windows CI acceptance remains pending.
- Governed CLI and MCP project-file mutation paths now use the retained project
  root for initialization, token remapping, wrapping, unwrapping, environment
  selection, agent guidance, doctor repairs, rotation, and workspace
  participation. Read-only check, status, audit, and proposal discovery remains
  observational and is not a sealed mutation snapshot or authority grant.
- Workflows that need both machine-local vault authority and a project lock now
  retain the reviewed project identity, resolve vault/application authority
  (which can take the process-environment guard), and only then acquire the
  project transaction lock. They compare the acquired root identity with the
  reviewed anchor and reread exact config state before use. This removes the
  inverse environment-lock/project-lock order and rejects a same-path root
  replacement during vault resolution.
- Noninteractive `phantom mcp-approve` admission now fails before inspecting
  approval state, generating a challenge, or reading stdin. The denial path
  therefore does not strand a project-lock waiter behind a test or host
  environment guard.
  Rollback restores only verified transaction-owned effects and preserves
  rename-replacement decoys.
- Git-hook installation retains the effective hook parent resolved through
  Git, including linked worktrees and `core.hooksPath`. Project-local hook
  targets use the project capability; externally located hook targets require
  their own explicitly authorized retained root and do not gain project-root
  authority. CLI doctor repairs prepare one exact hook plan and require an
  attached trusted-terminal authorization for global/system hook roots; MCP
  repair refuses those external writes.
- `phantom setup` distinguishes project-local Claude settings from explicitly
  authorized global Cursor, Windsurf, and Codex configuration roots. Global
  parents are traversed or created beneath a retained home-directory anchor,
  exact directory receipts bound rollback, and setup coordination lives under
  retained `~/.phantom` application state instead of an ambient home-root or a
  rollback-owned client directory.

### Architecture and evidence

- Local filesystem authority, effect receipts, operator boundaries, and
  source-contract versus native-platform evidence are now documented across
  the architecture, threat model, platform matrix, audit index, onboarding,
  troubleshooting, and machine-readable documentation surfaces.
- Phantom uses Rama's upstream main snapshot
  [`267e4790c899736e6f60d982c8a0932406d4079e`](https://github.com/plabayo/rama/commit/267e4790c899736e6f60d982c8a0932406d4079e),
  reviewed 2026-09-01, as a benchmark for explicit stacks, modular crates,
  runnable examples, and tiered platform CI. Rama is not a Phantom dependency,
  and this comparison does not claim feature or platform parity.
- Locus verification, broker leases, production engineering execution, and
  externally trusted receipts remain inactive and fail closed. Enterprise
  packaging remains a planned contract/commissioning path, not an activated or
  customer-accepted service.

### Breaking changes and migration

- Rust callers of `phantom-core` must now handle `Result` from
  `DotenvFile::rewrite_with_phantoms` and
  `DotenvFile::generate_example_content`. Mutation and generated-output APIs
  reject malformed or duplicate mappings instead of returning partial output;
  `DotenvFile::upsert_with_phantoms` is the format-preserving API for adding
  prepared mappings. Phantom remains pre-1.0, but this source-level signature
  change is called out explicitly for library consumers.
- `phantom setup` and initialization no longer generate an unpinned `npx`
  fallback when a local MCP runtime cannot be resolved. After the immutable
  `0.7.4` release receipt exists, install both `phantom` and `phantom-mcp` from
  that same release, then rerun setup; until then, `0.7.3` remains the reviewed
  distribution. Existing legacy registry-backed entries are migrated only when
  the local replacement can be resolved safely.
- Initialization now requires a supported dry-run flag combination, an exact
  canonical executable pre-commit hook, and a transaction that commits the
  managed dotenv file last. Rerun `phantom init` from a trusted terminal to
  repair stale setup. Partial failures roll back only transaction-owned state;
  operators should still keep a separately protected recovery copy.
- Legacy `phantom watch --auto-rotate` and scheduled placeholder-remap paths no
  longer claim provider credential rotation. The MCP compatibility names
  `phantom_secrets_auto_rotate` and `phantom_rotate_with_expiry` perform only
  approved local `phm_` remaps and do not renew credential lifecycle metadata,
  clear incidents, or sync. Rotate through the provider's trusted interface,
  then store the successor with trusted-terminal `phantom add`.
- `phantom watch --auto` now fails before vault or dotenv mutation. The legacy
  watcher could leave partial state after a concurrent edit or nth write
  failure. Use `phantom watch` for detection, review the change, and run
  transactional `phantom init` from a trusted terminal.
- All live vendor issuance/rotation execution is unavailable in 0.7.4. Batch,
  single-provider CLI, MCP, enrollment exchange, additive issuance, and rolling
  refresh paths fail before provider credential access and network I/O. Source
  adapters and exact `cfg(test)` mocks are local transaction evidence only, not
  provider activation or acceptance. Operators must rotate at the vendor and
  then use Phantom's trusted local secret-entry path.
- Hosted billing, personal cloud-vault, and team routes now return unavailable
  unless their exact commissioning gates are enabled. Operators must separately
  verify required migrations, environment variables, provider configuration,
  rollback, and authenticated acceptance before enabling those gates.
- Effectful advanced MCP tools are now disabled unless
  `PHANTOM_MCP_EFFECTS=trusted-terminal` is configured outside the requesting
  agent's authority. Approval requires an attached terminal, a displayed
  value-blind effect and exact parameter summary, and a fresh typed challenge.
  A same-user shell or agent-controlled PTY is not human-presence proof; leave
  effects disabled when the approval command or storage is within agent scope.
- Windows rejects `--passphrase-file` before path access because native
  handle-bound owner/DACL verification is not yet implemented. Use the hidden
  trusted-terminal prompt. Unix private regular files remain supported.
- A live v0.7.3 standalone proxy cannot be stopped by the new binary because
  v0.7.3 did not ship an authenticated remote-shutdown endpoint. Stop it with
  Ctrl-C in its owning v0.7.3 terminal. If that terminal is unavailable, use a
  checksum-verified v0.7.3 binary from a trusted terminal, or independently
  verify that no process/listener owns the legacy record before manually
  removing `.phantom.pid`; v0.7.4 never kills or deletes that state.
- Legacy direct installs sharing the npm installation root may be ambiguous.
  Reinstall with the reviewed direct installer to create a source receipt;
  `phantom upgrade` now fails closed instead of guessing ownership.

### Security

- Dotenv parsing now retains exact source spans and preserves BOM, LF, CRLF,
  lone-CR endings, quotes, comments, spacing, multiline values, and terminal
  newline shape outside explicitly changed values. Every mutating caller fails
  closed on malformed, duplicate, unsafe, or concurrently changed mappings
  before vault, approval, provider, or unrelated repair effects where the
  command contract permits; diagnostics contain locations and fixed categories,
  never source values.
- Serializes the full MCP terminal-approval and one-use consumption critical
  sections across threads and processes, uses collision-safe atomic storage,
  and gives approved tokens a fresh five-minute use window. Concurrent replay
  of one approval now permits exactly one successful consumption.
- Classifies all 54 current MCP tools by effect. Tools that write state,
  retrieve or use credentials, or make provider/network requests require both
  `confirm: true` and a matching out-of-band one-use approval token; conditional
  tools require those gates whenever effectful parameters are supplied.
- Keeps incident reads read-only, removes false auto-rotation behavior, rejects
  unsupported team ownership invitation, and keeps stored secret values out of
  approval and MCP response contracts.
- Removes dummy `phm_cand_` shadow "credential" promotion. Candidate and
  promotion compatibility paths now fail closed until a real provider-backed,
  out-of-band candidate workflow exists.
- Resolves the effective Git hook through Git, including linked worktrees and
  `core.hooksPath`, and requires Phantom's canonical local check to be first and
  executable before readiness passes.
- Makes fallback vault provisioning fail closed unless a generated passphrase
  is durably persisted and verified, serializes keychain index/metadata
  transactions, compensates partial mutations (including legacy plaintext-name
  migration), exposes a fallible public vault constructor, and propagates
  backend errors instead of replacing missing encryption keys or panicking.
- Makes standalone proxy lifecycle foreground-only and three-terminal-gated.
  Its persistent advisory lock is stored in the OS user-data directory, keyed
  by local project identity, contains no PID, port, or bearer, and is not
  listener authentication. Unix permissions are restricted; Windows uses the
  inherited user-data-directory ACL, which Phantom does not independently
  verify. Detached `start --daemon` and all external shutdown fail closed;
  `phantom stop` authenticates legacy v0.7.3 state only to report safe manual
  migration guidance and never kills a process or deletes the record.
- Removes the file-vault passphrase and ambient protected dotenv values from
  both proxied and direct `phantom exec` child environments, inserts only fresh
  session tokens for protected keys, scrubs configured service, connection,
  rotation, sync, proxy-control, and built-in base-URL variables, and refuses
  missing vault mappings or configured connection strings before child launch.
- Persists one strictly validated dotenv-like filename beside `.phantom.toml`,
  migrates conventional legacy dotenv names without path traversal or symlinks,
  and refuses direct launch when protected state has no token-bearing managed file.
- Disables all client-controlled token substitution in request headers and
  bodies. Only the authenticated, exactly matched route injects its configured
  vault value into its fixed authentication header; missing mappings fail before
  any upstream call. Bodies remain byte-preserving under a hard size cap.
  Credential-bearing upstream HTTP disables ambient forward-proxy discovery.

### Reliability and authority boundaries

- Makes initialization recoverable across vault, config, guidance, hook, and
  dotenv updates using compare-and-swap checks, collision-safe atomic writes,
  and rollback that never stores plaintext secret backups or journals.
- Spans initialization and token-remap compare-and-swap checks with
  cross-process project locks so concurrent writers cannot overwrite a newer
  dotenv or vault state between verification and commit. All MCP token-remap
  paths use the same locked before-image discipline.
- Propagates vault inspection, credential-read, and provider-rotation metadata
  failures across MCP and CLI flows instead of rendering an empty vault,
  starting a partially mapped session, overwriting on an unknown destination
  state, or reporting a false rotation success. Non-forced cloud pulls preflight
  every overwrite decision before their first store.
- Scopes competitor-import overwrite approval to the exact existing names the
  user reviewed; a newly appearing duplicate remains untouched unless
  `--force` is explicit.
- Normalizes Pro access from an exact lowercase plan plus a strictly valid,
  timezone-qualified future expiry. Billing lookup exhausts bounded Stripe
  subscription pagination and fails closed on malformed or non-progressing
  pages.
- Keeps generated scripts and hooks on reviewed local executables, and aligns
  current-source package metadata, MCP schemas, and documentation with shipped
  behavior rather than uncommissioned pricing or hosted-service promises.
- Serializes direct and npm installer promotion with owner/stale-recovery
  locks, records distribution ownership transactionally, and verifies the
  reviewed direct binaries before promotion. PowerShell no longer recommends
  piping a network response into execution.
- Builds GNU Linux archives on an explicit Ubuntu 22.04 baseline and rejects
  either binary when ELF requirements exceed `GLIBC_2.35` or cannot be proven.
  This is a symbol ceiling, not native archive acceptance. Shell exports use
  quoted Bash, Fish, PowerShell, or cmd syntax with `PHANTOM_SHELL` available
  for nested-shell overrides.
- The authority, Locus-contract, broker, runtime, session, and evidence crates
  remain fail-closed foundations. This release does not activate a Locus
  verifier, issue broker leases, execute production engineering actions, or
  create externally trusted execution receipts.

## [0.7.3] - 2026-08-31

This is the security fix-forward for `0.7.0`. The protected `0.7.1` and `0.7.2`
tag workflows both stopped before creating a GitHub Release: `0.7.1` failed its
release-note contract, while `0.7.2` exposed and removed a non-hermetic proxy
unit test that depended on public `httpbin.org`. Publication remains gated on
protected-branch CI and the tag-triggered immutable-release workflow. The web
changes also require the included Supabase migration before deployment; source
publication does not imply that migration or the web application is active in
production.

### Breaking security changes

- `phantom exec` and `phantom start` accept only Phantom's exact built-in API
  routes. Repository-defined or altered proxy destinations now fail closed
  until a future trusted-terminal approval format can bind custom routes to a
  machine-local decision.
- `.phantom.toml` keeps its committed project ID as the portable cloud/team
  identity, while local vault, shadow, and scheduler state are namespaced from
  the canonical checkout directory. A clone or move therefore keeps its remote
  identity but starts with isolated local state and cannot select another
  checkout's vault through repository config.
- Protected connection strings such as `DATABASE_URL` are no longer injected
  into an agent child process. These now fail closed pending a protocol-aware
  database broker.
- Runtime mock-rotation and alternate Stripe endpoint environment variables no
  longer activate in shipped binaries. Hermetic mock behavior is compiled only
  into unit tests.

### Security

- Pins Phantom Cloud authentication to `https://phm.dev/api/v1`; runtime API
  origin overrides are rejected before cloud network access.
- Replaces secret-derived response labels with the constant
  `[REDACTED:vault-secret]`, including short and Unicode values.
- Disables upstream redirects, buffers and validates complete bounded request
  bodies before contacting an upstream, and bounds buffered upstream responses
  before redaction.
- Rejects unsafe file-vault project IDs before creating any vault path.
- Makes audit statistics verify the HMAC chain and treats unsigned records
  appended after a signed chain as tampering.
- Makes GitHub login identity immutable to ordinary user updates, resolves team
  invites through a normalized unique identity, and moves device-code issuance
  plus per-client/global rate limiting into one database transaction.
- Removes device codes from OAuth URLs and analytics page-view capture, strictly
  validates team X25519 public keys, and adds browser isolation headers.
- Updates Rust and video dependency graphs to resolve actionable advisories.

### Breaking changes and migration

- Treat `0.7.0` and the unpublished `0.7.1` and `0.7.2` tags as superseded, and
  upgrade to `0.7.3` before using cloud, team,
  proxy, connection-string, provider-rotation, or agent execution workflows.
- Local vault namespaces now use a domain-separated SHA-256 digest of the
  canonical checkout path. The former 64-bit path namespace is deliberately
  not opened automatically because collision compatibility would preserve a
  cross-vault selection risk. Before upgrading an offline-only `0.7.0`
  checkout, create an encrypted backup with `phantom export --output FILE` from
  a trusted terminal; after upgrading, restore it with `phantom import FILE`.
  Cloud/team users can instead repopulate through a normal encrypted pull.
  Never copy plaintext secret values into a repository.

## [0.7.2] - 2026-08-31

The protected tag exists as evidence of a failed-closed release attempt. The
release-note contract passed, but the exact-tag workspace suite exposed a proxy
unit test whose mock route still depended on public `httpbin.org`; a transient
upstream 502 failed the suite before any artifacts or GitHub Release were
created. The test is hermetic in `0.7.3`.

## [0.7.1] - 2026-08-31

The protected tag exists as evidence of a failed-closed release attempt. All
source, platform-build, artifact-set, SBOM, and attestation gates passed, but
the workflow rejected the changelog heading before creating a GitHub Release.
No `0.7.1` release assets were published. Use `0.7.3`.

## [0.7.0] - 2026-08-31

Publication is gated on exact-source CI and the tag-triggered release workflow.
Provider activation, native signing/notarization, and customer acceptance
remain separate evidence gates.

### Breaking changes and migration

- Positional secret values are rejected. Replace `phantom add KEY VALUE` with
  `phantom add KEY` for a hidden trusted-terminal prompt, or pipe one value to
  `phantom add KEY --stdin` from a trusted producer.
- Plaintext backup export is removed. Use `phantom export --output FILE` and a
  hidden passphrase prompt, or `--passphrase-file PRIVATE_FILE` for bounded
  automation; use the same input mode with `phantom import`.
- The former `--passphrase` command-line option is rejected because process
  arguments are observable. Move automation to a private, non-symlink regular
  file with mode `0600` or stricter on Unix.
- Noninteractive reveal through `--yes` is rejected. Run `phantom reveal KEY`
  from a trusted interactive terminal; Phantom copies to the clipboard and
  refuses plaintext stdout fallback.
- `phantom init` no longer leaves plaintext dotenv backup files. Create a
  separately protected recovery copy before upgrading if your operating
  procedure depended on the former backup behavior.

### Added

- Trusted-terminal `phantom grant add`, `list`, and `status` workflows for
  provider credentials, with implemented issuance paths for GitHub App,
  Vercel Integration, Sentry Integration, Supabase OAuth, and Stripe App OAuth.
- Direct-to-vault issuance root storage and value-free provider-grant lifecycle
  output. The current [grant specification](docs/grants-spec.md) is distinct
  from inactive execution-kernel authority grants.
- Value-blind workspace planning and bearerless request handling, with a
  separate trusted-terminal Unix apply transaction.
- Fail-closed authority, Locus-contract, broker, runtime, session, and evidence
  foundations for future governed engineering execution.
- Canonical architecture, platform-support, release-readiness, audit-index,
  security-policy, and repository-contribution documentation.
- Bounded web request parsing and an atomic Stripe billing-event transaction
  with retryable claims, historical subscription bindings, and monotonic
  event ordering.
- Six-target release packaging with exact artifact-set verification,
  archive-specific SPDX 2.3 SBOMs, and GitHub provenance attestations.

### Changed

- The primary npm CLI wrapper now verifies a private cached binary through an
  exact version and checksum manifest, uses bounded allowlisted downloads and
  archive validation, and preserves the prior verified binary across failed
  installation attempts.
- Encrypted backup and restore now use hidden or private-file passphrase input,
  bounded reads, zeroizing buffers, private staging, durable atomic
  no-overwrite publication, and nonzero partial-restore failures.
- `phantom setup` removes only legacy dotenv read grants while preserving all
  unrelated allow and deny rules. `phantom init` no longer creates plaintext
  dotenv backups.

### Security

- Provider issuance uses a closed production endpoint map, names provider
  client secrets by environment variable instead of command-line value, and
  keeps issued roots out of CLI output.
- `phantom grant revoke` fails closed before local mutation while supported
  provider remote revocation remains unwired.
- Production engineering execution remains unavailable: provider grants do not
  become authority grants, broker leases, or execution permits.
- Plaintext backup export, positional secret values, argv passphrases, and
  noninteractive secret reveal bypasses fail closed before project mutation.
- Rust advisories, licenses, duplicate families, and registry sources are
  enforced by cargo-deny; the documented no-fix RSA advisory remains limited
  to a dev-only test dependency.

## [0.6.0] - 2026-05-04

### Added

- Opt-in JSONL audit log with an HMAC-SHA256 integrity chain and `phantom audit verify`.
- Streaming proxy request handling while preserving scoped phantom-token replacement.
- Bundled MCP serving from the main CLI and dedicated MCP package support.
- Multi-project initialization and setup helpers for multiple AI clients.
- Importers for Doppler, Infisical, dotenvx, 1Password, and dotenv files.
- A repository threat model covering assets, actors, mitigations, cryptography, trust boundaries, and known gaps.

For older release notes and downloadable artifacts, see [GitHub Releases](https://github.com/ashlrai/phantom-secrets/releases).

[Unreleased]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.9...HEAD
[0.7.9]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.8...v0.7.9
[0.7.8]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.7...v0.7.8
[0.7.7]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.6...v0.7.7
[0.7.6]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.5...v0.7.6
[0.7.5]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...v0.7.3
[0.7.2]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...v0.7.2
[0.7.1]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/ashlrai/phantom-secrets/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ashlrai/phantom-secrets/releases/tag/v0.6.0
