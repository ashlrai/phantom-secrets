# Troubleshooting

## Common Issues

### "No .phantom.toml found"

You haven't initialized Phantom in this directory yet.

```bash
phantom init
```

This reads your `.env`, stores real secrets in the vault, and rewrites `.env` with phantom tokens.
If this is a new project with no dotenv file, run `phantom init --empty` before
the first `phantom add`; `add` does not bootstrap project state.

### "Secret not found in vault"

The secret name doesn't match what's stored. Check available secrets:

```bash
phantom list
```

Common causes:
- You're in a different directory than where you ran `phantom init`
- The secret was added with a different name (names are case-sensitive)
- The vault was created on a different machine

### API calls return 401 Unauthorized

If your API calls fail with authentication errors after setting up Phantom:

1. **Check the proxy is running**: `phantom status`
2. **Verify the secret is in the vault**: `phantom list`
3. **Verify the real value only in a trusted attached terminal**: run
   `phantom reveal <KEY>` and complete the exact typed confirmation, or use
   `--clipboard` to avoid printing it on screen
4. **Check BASE_URL is set**: The proxy only works when `OPENAI_BASE_URL` (or equivalent) points to the local proxy. Use `phantom exec -- <cmd>` which sets these automatically.
5. **Check the key has a proxy route**: `phantom why <KEY>` (or MCP `phantom_why`) reports how `phantom exec` delivers a protected key. `no_route` means no built-in route injects it (for example `GROQ_API_KEY` or `JWT_SECRET`), so the child gets only a session token that no provider accepts. `phantom exec` names these keys at launch with `warn No proxy route for ...`. Custom routes: `phantom start` serves custom routes from `.phantom.toml`; `phantom exec` refuses them and runs only Phantom's exact built-in routes. The reason: `phantom start` is run by a person on project config they have reviewed. `phantom exec` launches an agent, and anything in the repository, `.phantom.toml` included, may have been written by that agent or by an untrusted change, so accepting custom routes there would widen the attack surface.

### Proxy hangs or times out

The proxy's upstream timeout is an idle timeout of 600 seconds (matching the
OpenAI and Anthropic SDK defaults): it applies to each wait for upstream bytes,
not to the whole request, so long SSE streams and slow reasoning calls are not
cut off. If an upstream drops a streaming response midway, the proxy aborts the
client connection instead of ending the body cleanly, so SDKs report the
truncation rather than acting on partial output. If a request still hangs:

- Check your network connection
- Verify the upstream service is accessible
- The proxy deliberately does not follow upstream redirects. Inspect a returned
  3xx response and use the reviewed canonical service endpoint instead.

### HTTP 429 with `"source":"phantom-proxy"`

This 429 comes from Phantom's local burst guard, not from the provider. By
default it trips above 50 requests per secret or 100 requests in total within
10 seconds. Busy multi-agent sessions can raise the limits before launching:

```bash
PHANTOM_RATE_LIMIT_PER_SECRET=20 PHANTOM_RATE_LIMIT_BURST=400 phantom exec -- claude
```

### HTTP 503 `route credential unavailable`

The request reached a proxy route whose key is not protected in this session.
`phantom exec` only exports a service's base-URL variable when that service's
key is loaded, so this usually means a client hardcoded the proxy URL. Protect
the key (`phantom add` or `phantom init`) and restart `phantom exec`.

### Request body larger than 32 MiB returns HTTP 413

The proxy buffers each request body under a strict size limit before contacting
the upstream. Bodies over the default 32 MiB limit (Anthropic's request limit) fail closed with HTTP 413, so
the upstream receives no truncated prefix. Accepted bodies are forwarded
byte-for-byte; no client header or body resolves a `phm_` token. Only the
matched route's fixed authentication header receives its route-owned value.

All in-flight requests also share a 320 MiB buffer budget; when many large
requests overlap, the proxy answers 503 with `retry-after: 1` instead of
buffering more. Split larger requests. The body-limit configuration is not currently exposed
through `.phantom.toml`; track the repository issues for future configuration.

### Claude Code can't read my .env file

Many Claude Code setups block reading `.env` files by default. Keep that
boundary: Phantom-managed `phm_` entries are not provider credentials and are
never resolved from client headers or bodies. An active bearer authorizes exact
routes that inject their own route-owned credentials. Sibling dotenv
files or backups from other tools can also still contain plaintext.

Fix it automatically:
```bash
phantom setup --client claude
```

This wires the MCP server, removes legacy Phantom-managed dotenv allow grants, and preserves deny rules in `.claude/settings.local.json`. For other AI tools, swap in `--client cursor|windsurf|codex|gemini`. Agents can use Phantom's value-blind MCP inventory without dotenv read access.

You can verify with:
```bash
phantom doctor
```

### "Refusing to reveal secret in non-interactive context"

This is a security feature. `phantom reveal` blocks in non-interactive contexts (pipes, scripts, AI agents) to prevent secrets from leaking into AI context windows.

There is no non-interactive bypass. Move to a trusted attached terminal and run
`phantom reveal <KEY>`, then complete the exact typed confirmation. Phantom
refuses this operation in scripts, pipes, CI, or agent tool calls.

### Keychain access denied

On macOS, you may see a keychain access prompt the first time. Click "Always Allow" for the `phantom-secrets` entry.

On Linux, Phantom uses the kernel keyring by default. Its entries do not
survive a reboot. On a headed desktop with an unlocked Secret Service, run
`phantom vault migrate-linux` from a terminal you exclusively control. Phantom
copies and verifies the project before switching; conflicts, a locked service,
or missing source entries fail closed. After migration, Secret Service remains
authoritative and its unavailability does not silently revive keyutils. For
headless Linux, WSL, and CI, set `PHANTOM_VAULT_PASSPHRASE` to select the
encrypted-file backend explicitly.

The persistent selection requires matching owner-only records under Phantom's
application-data and configuration roots; the migration also stores a Secret
Service corroboration sentinel used by the explicit migration/recovery path.
Loss of one local record, including across a reboot, fails closed without a
desktop-service probe. Unmarked headless vault opens do not probe a desktop
service. If all local Phantom state was deleted, restore a verified backup
rather than recreating backend records by hand.
Kernel-keyring entries do not survive a reboot, and the per-user key quota is
finite. If an entry is unavailable after reboot, create it again through the
normal trusted-terminal workflow. For an explicit encrypted-file backend in
headless or CI environments, provide the passphrase through a protected
environment or process manager:
```bash
export PHANTOM_VAULT_PASSPHRASE="your-secure-passphrase"
```

### Windows Credential Manager unavailable or denied

Phantom's Windows backend is mapped to Windows Credential Manager through the
Rust `keyring` integration. That source mapping is not proof that an exact
Phantom archive has passed native credential-store acceptance under your user
and device policy.

Run `phantom doctor` from the same interactive Windows user session that will
run Phantom, and preserve the exact backend error for diagnosis. Confirm that
the user's profile and Credential Manager are available and that endpoint
policy is not denying credential access. Do not delete unrelated Windows
credentials or disable application-control policy as a generic repair.

Set `PHANTOM_REQUIRE_KEYCHAIN=1` when policy requires Phantom to fail instead of
changing storage posture. Without that setting, Phantom permits its documented
encrypted-file fallback only when fallback key material can be persisted
securely and verified; it prints a warning when the backend changes. For an
explicit encrypted-file vault, supply `PHANTOM_VAULT_PASSPHRASE` through a
protected process or secret manager and keep it outside agent-controlled shell
history. Windows rejects encrypted-backup `--passphrase-file` before path
access; use the attached hidden terminal prompt for import/export ceremonies.

```powershell
$env:PHANTOM_REQUIRE_KEYCHAIN = "1"
phantom doctor
```

If the error persists, record it as a native-platform blocker rather than
assuming the source integration works. See [Platform
support](platform-support.md) for the source-contract versus native-acceptance
boundary.

### "WARNING — OS keychain unavailable"

This appears in Docker/CI environments where no keychain is available. Set the passphrase explicitly:

```bash
export PHANTOM_VAULT_PASSPHRASE="$(openssl rand -hex 32)"
```

Store this passphrase securely (e.g., as a CI secret) — you'll need it on every run to decrypt the vault.
`phantom exec` consumes it in the trusted parent and removes it before spawning
either a proxied or direct child. Commands launched manually from the same shell
still inherit the export, so do not launch an agent outside `phantom exec` while
the variable is set.

### "Vault locked: this project's secrets are in an encrypted-file vault this process cannot open"

The project's secrets were stored in the encrypted-file vault (for example by a
shell that had `PHANTOM_VAULT_PASSPHRASE` set), but this process has no
passphrase, so Phantom opened the OS keychain instead. Rather than answer from
that empty view, commands refuse with exit 1: `list`, `expiry enforce`,
`secrets-expiring-soon`, `validate`, `sync`, and `agent report`/`agent doctor`
(which report `unsafe`). `phantom exec` and `phantom start` refuse to launch the
child. `cloud push` and `team vault-push` also refuse a keychain-only partial
inventory instead of replacing the remote copy with it. The same refusal comes
from the MCP inventory tools as error `-32600`. With `PHANTOM_REQUIRE_KEYCHAIN=1`
the file vault is never opened, even with a passphrase set, and the message
says so.

Fix: export the same `PHANTOM_VAULT_PASSPHRASE` the secrets were stored with
in the shell, or for MCP clients in the server's env config, then retry or
restart the server. The message names the vault file. If the vault was made by
the automatic keychain-unavailable fallback, its passphrase was generated and
kept in the OS credential store, and the message says how that case differs.
If your secrets now live in the OS keychain, the file may be stale: back it up
or move it aside rather than deleting it.

### Proxy port conflicts ("address already in use")

Phantom does not use a fixed proxy port. `phantom exec` and `phantom start` both
ask the OS for a free loopback port (`127.0.0.1`, port 0) every time, so another
program holding a port such as 8080 cannot collide with them. Read the actual
port from the startup line (`Proxy started on 127.0.0.1:PORT`) or from the
`PHANTOM_PROXY_PORT` variable that `phantom exec` sets for the child. Do not
hardcode a port in your app or `.env`.

If you see `Another foreground Phantom proxy session already owns <dir>`, the
cause is a second `phantom start` for the same project, not a busy port. Stop
the first one with Ctrl-C in its terminal, or use `phantom exec`, which starts
its own child-owned proxy.

If a hardcoded port from an older setup is still referenced and requests fail
with connection refused, replace it with `PHANTOM_PROXY_PORT`.

### `phantom start --daemon` or `phantom stop` is refused

This is intentional. Phantom does not persist a live proxy bearer, PID, or port
in the workspace, so detached startup and current external process control fail closed.
Use `phantom exec -- <command>` for the normal child-owned lifecycle. For an
explicitly supervised shared proxy, run `phantom start` in a trusted terminal,
keep that terminal open, and press Ctrl-C there to stop. `phantom status` can
report whether the OS user-data-directory lifecycle lock is held, but that does
not authenticate a listener and cannot recover a port or bearer. `phantom start`
also refuses headless invocation unless stdin, stdout, and stderr are terminals.
Unix lock permissions are restricted. On Windows, Phantom relies on the
inherited user-data-directory ACL and does not independently verify it.

During an upgrade only, a v0.7.3 workspace may contain `.phantom.pid` in the
legacy `PID:port:bearer` format. v0.7.3 did not ship an authenticated remote
shutdown endpoint, so the new `phantom stop` authenticates the recorded
loopback service only to distinguish a live owner from unverified state. It
never kills a process or deletes the record. Stop the old proxy with Ctrl-C in
its owning v0.7.3 terminal. If that is unavailable, use a checksum-verified
v0.7.3 binary from a trusted terminal; as a last resort, independently verify
that neither the recorded process nor loopback listener remains before manually
removing `.phantom.pid`. Malformed, stale, unauthenticated, or symlinked records
remain untouched. Phantom never creates new `.phantom.pid` or
`.phantom.start.lock` state.

### An enterprise HTTP proxy is ignored

The credential-bearing local proxy intentionally disables inherited
`HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` discovery so an agent-controlled
environment cannot redirect upstream credentials. Enterprise forward-proxy
support requires an explicit reviewed trust design and is not supported in this release.

### An older registry-based install command fails

See [distribution status](distribution-status.md) for dated npm, Homebrew, crates.io, and MCP Registry evidence. Prefer the checksum-verified `v0.7.9` GitHub assets for an exact install.

1. Select the matching asset in [getting started](./getting-started.md#install).
2. Verify its adjacent `.sha256` checksum before executing either binary.
3. Check both binary versions after installation.

## CI/CD Usage

### GitHub Actions

```yaml
- name: Set up Phantom
  run: |
    cargo install --locked --git https://github.com/ashlrai/phantom-secrets.git --rev 7a51ce512ec4aee12cc29ff859036af63fbe93db phantom-secrets
    echo "PHANTOM_VAULT_PASSPHRASE=${{ secrets.PHANTOM_VAULT_PASSPHRASE }}" >> $GITHUB_ENV
    phantom pull --from vercel --project ${{ vars.VERCEL_PROJECT_ID }}
  env:
    VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
```

### Docker

```dockerfile
# Install phantom
RUN cargo install --locked --git https://github.com/ashlrai/phantom-secrets.git --rev 7a51ce512ec4aee12cc29ff859036af63fbe93db phantom-secrets

# Set passphrase for encrypted vault (pass at runtime, not build time)
ENV PHANTOM_VAULT_PASSPHRASE=""

# Use phantom exec to run your app with secrets injected
CMD ["phantom", "exec", "--", "node", "server.js"]
```

## FAQ

### Can I use Phantom with teammates who don't have it installed?

Yes. Phantom only modifies your local `.env` file. If a teammate doesn't use Phantom:
- Share `.env.example` (generated with `phantom env`) for them to create their own `.env`
- The `.phantom.toml` config file can be committed to git (it contains no secrets)

### What if I need to see a real secret value?

```bash
phantom reveal OPENAI_API_KEY              # prints to stdout
phantom reveal OPENAI_API_KEY --clipboard  # copies to clipboard (auto-clears 30s)
```

### Does Phantom work with Docker Compose?

Yes. Use `phantom exec` to wrap your compose command:
```bash
phantom exec -- docker compose up
```

The proxy runs on the host, and `*_BASE_URL` env vars are passed to containers.

### Can I use Phantom in production?

Phantom is designed for local development and CI/CD. In production, your deployment platform (Vercel, Railway, etc.) manages secrets directly. Use `phantom sync` to push secrets to your platform.

### What happens if I lose access to my vault?

If using macOS Keychain or Windows Credential Manager, secrets are tied to your
user account and can persist across reboots. Linux kernel-keyring entries do
not survive a reboot; recover from an independently protected backup or re-add
the credential through the trusted-terminal workflow.

If using file vault: you need the `PHANTOM_VAULT_PASSPHRASE` to decrypt. If lost, re-pull from your deployment platform:
```bash
phantom pull --from vercel --project prj_xxx --force
```

### Is Phantom safe to use with Claude Code / Cursor?

That is the intended boundary when the agent uses value-blind MCP tools and a
supported API is launched through `phantom exec`. The upstream provider does
not accept `phm_` values directly, and `phantom exec` issues fresh child-process
placeholders for each run. Treat any exposed token as sensitive metadata and
rotate it. Client headers and bodies never resolve placeholders, but a stolen
live proxy bearer can authorize exact routes that inject their own vault value.
Phantom does not cover unmanaged plaintext files or tools
launched outside the proxy environment.

## Vault Backup

### Where secrets are stored

Phantom stores your real secret values in one of two locations:

- **Platform credential backend (primary):** macOS Keychain, Linux keyutils or explicitly migrated desktop Secret Service, or Windows Credential Manager. Linux keyutils entries are in-memory and do not survive a reboot; `phantom vault migrate-linux` is a per-project trusted-terminal transition, not a headless default.
- **Encrypted file vault (explicit or guarded fallback):** stored below the operating system's Phantom application-data directory (the exact path varies across macOS, Linux, and Windows). Setting a non-empty `PHANTOM_VAULT_PASSPHRASE` selects this backend explicitly. Otherwise Phantom falls back only after the OS keychain is unavailable and a generated passphrase has been persisted to secure storage and verified by an exact read-after-write. If an encrypted vault already exists but its secure passphrase entry is missing, Phantom refuses to generate a replacement key. Set `PHANTOM_REQUIRE_KEYCHAIN=1` to reject any fallback. Phantom prints a warning whenever an automatic fallback changes the storage posture. Vault payloads use ChaCha20-Poly1305 with an Argon2id-derived key; provide automation passphrases through a protected environment or process manager, not shell history.

### How to back up your secrets

Use Phantom's encrypted export rather than printing every value. Supply a
dedicated high-entropy passphrase and protect both the archive and passphrase
as separate recovery material:

```bash
# Interactive: hidden prompt + confirmation on an attached terminal
phantom export --output phantom-backup.enc

# Export never accepts passphrase files. Review the exact value-blind plan,
# type its fresh challenge, and enter a dedicated passphrase at the hidden prompt.
```

Recover into an initialized Phantom project from attached stdin/stdout/stderr
after reviewing and typing the exact source/target/name/overwrite challenge:

```bash
phantom import phantom-backup.enc
phantom import phantom-backup.enc \
  --passphrase-file /secure/path/phantom-backup.pass
```

Export rejects `--passphrase-file` on every platform. Import passphrase files on
non-Windows platforms must be regular files, not symlinks, and are limited to
4096 bytes; on Unix they must be mode `0600` or stricter. Import passphrase files
fail closed on Windows. A passphrase file never makes import headless: all three
standard streams and exact typed consent are still required.
Export refuses existing targets and symlinks; it creates a `0600` staging file
on Unix (or uses the containing directory's inherited ACL on Windows), flushes
it, and publishes it without overwriting. Store neither the encrypted backup
nor its passphrase in the repository. Plaintext JSON export and the legacy argv
`--passphrase` flow are disabled.

If the command reports that audit logging failed after publication, the backup
already exists at the reported path. Do not retry with the same output path;
preserve that file and repair audit logging before the next export.

### Recovery options

If you lose access to your vault (e.g., you reset your machine or the vault file is deleted), you have a few options:

1. **Re-pull from a deployment platform.** If you previously ran `phantom sync` to push secrets to Vercel or Railway, you can recover them:
   ```bash
   phantom pull --from vercel --project prj_abc123def456 --force
   ```

2. **Re-enter secrets manually.** If you have the real values saved elsewhere (password manager, team wiki), create a fresh `.env` with the real values and re-run `phantom init`.

3. **Ask a teammate.** If another developer on your team has the same secrets in their vault, they can `phantom sync` to the deployment platform and you can `phantom pull`.

## Cloud Sync Issues

The source-backed commands in this section require a separately verified hosted
deployment and account entitlement. The public hosted service is not currently
commissioned for authenticated use; a 404/5xx or unavailable entitlement is a
commissioning blocker, not evidence that local vault protection failed.

### "Not authenticated" when running `phantom cloud push`

After commissioning is verified, log in first:
```bash
phantom login
```

This is designed to open the configured device flow. A browser page alone does
not prove that authentication, account linking, or the hosted API completed.

### Cloud push fails with encryption error

Ensure your OS keychain is accessible. The cloud encryption key is stored in that
keychain, and Phantom Cloud push and pull currently require keychain access.
`PHANTOM_VAULT_PASSPHRASE` selects the local encrypted-file vault in headless/CI
environments; it is not a substitute for the separate cloud encryption key. Run
cloud commands on a machine with the original keychain entry. A headless-only
cloud-key workflow is not currently shipped.

### Cloud pull doesn't restore all secrets

Cloud sync is per-vault. Make sure you pushed from the same project directory. Each project has its own vault and cloud backup.

### "Subscription required" on cloud push

There is no self-service hosted-plan upgrade available today. Keep the vault
local, or request a bounded pilot through
[Phantom for enterprise](https://phm.dev/enterprise). Hosted-plan eligibility,
vault and team limits, and pricing are still to be determined and are confirmed
during pilot onboarding.

## Audit Log

### Enabling the audit log

For compliance or forensic visibility, set `PHANTOM_AUDIT=1` to record every vault store/retrieve/delete:

```bash
export PHANTOM_AUDIT=1
phantom exec -- npm run dev
```

Each line is JSON with `ts`, `op`, `name` (the secret name — **never the value**), `process`, and `pid`. Off by default; enable per-shell or in your `.zprofile` / `.envrc`.

### `phantom audit verify` reports tampered entries

The audit log uses an HMAC-SHA256 chain: each entry signs the hash of the previous entry. If `phantom audit verify` exits 1 and reports tampered line numbers, it means those entries were modified, deleted, or inserted after being written.

Possible causes:
- A log-rotation tool or editor truncated or rewrote the file
- The log file was manually edited
- An attacker with write access to `~/.phantom/` modified the file to cover tracks

What to do:
1. Note the tampered line numbers from the output: `phantom audit verify` prints them to stderr.
2. Compare against a backup copy if available.
3. Treat the log as unreliable for the period covered by tampered entries.
4. If you suspect a security incident, revoke affected credentials in each
   upstream provider, then store replacements through Phantom's trusted-terminal
   workflow. `phantom rotate` only invalidates local `phm_` mappings and does not
   revoke or replace provider credentials.

Note: entries written before HMAC chaining was introduced (pre-PR #62) are counted as `legacy` in the verify output and do not fail the check.

### Audit log is empty / "No audit events yet"

The log file is only created once the first event is written. Ensure `PHANTOM_AUDIT=1` is set in the shell where `phantom exec` or vault-mutating commands run. Check the log path with `phantom audit path`.

With an empty log, `phantom audit stats --json` still prints valid JSON (`total_events: 0`, `secrets: []`) and sends the hint to stderr, and `phantom audit export --format json` prints `[]`.

## Importing from other secret managers

### `phantom import --from` fails to parse the export file

Each importer expects a specific file format:

| Source | Expected format | Notes |
|--------|----------------|-------|
| `doppler` | JSON object: flat `{"KEY": "value"}`, or `{"KEY": {"computed": "...", "raw": "..."}}` | `doppler secrets download --no-file --format json > dump.json` writes the flat form; `doppler secrets --json` writes the nested form, and its `computed` value is imported. `DOPPLER_*` metadata keys are skipped |
| `infisical` | `.env` key=value lines, or a JSON array `[{"key": "KEY", "value": "value"}, ...]` | `infisical export --format=dotenv > export.env` or `infisical export --format=json > export.json`. A file whose first character is `[` is read as JSON |
| `dotenvx` | Plaintext `.env`, or a flat JSON object `{"KEY": "value"}` | A file whose first character is `{` is read as JSON. Encrypted `.env.vault` files and `encrypted:` values are **not** supported: run `dotenvx decrypt --stdout > .env` first |
| `1password` | One flat JSON object `{"KEY": "value"}` that you assemble. Names must be environment variable names (`[A-Za-z_][A-Za-z0-9_]*`); values are strings, numbers or booleans | Phantom does not run `op`. Raw `op item get --format json` output (with its `fields` array) is refused; flatten it as shown below |
| `env` | Plaintext `.env` key=value | Any standard dotenv format, including `export KEY=value`, quotes, and CRLF line endings |

In every format, empty (and JSON `null`) values are skipped, while a nested
object or array value refuses the whole file. A leading UTF-8 byte-order mark,
as written by Windows PowerShell 5.1, is ignored.

Every format must be UTF-8. A UTF-16 or UTF-32 file, which Windows PowerShell
5.1 writes for `>` and for `Out-File` without `-Encoding`, is refused with an
error that names the encoding; nothing is imported. Re-save it as UTF-8 and
retry:

```bash
iconv -f UTF-16LE -t UTF-8 export.json > export-utf8.json
# PowerShell: Get-Content export.json | Set-Content -Encoding utf8 export-utf8.json
```

`phantom import --help` lists the expected format for every source.

For 1Password, collect one item's fields into a flat object with `op` and
`jq`. The `jq` filter stops on two fields with the same label instead of
keeping only one of them:

```bash
op item get "My App Secrets" --vault Dev --format json \
  | jq '[.fields[] | select(.value != null and .value != "")]
        | if (map(.label) | unique | length) != length
          then error("duplicate field labels") else map({(.label): .value}) | add end' \
  > 1p-export.json
phantom import --from 1password --file 1p-export.json
```

If the file format is wrong, the importer returns a parse error. Re-export from the source tool and retry.

A name that appears more than once refuses the whole file, in every format.
JSON imports also refuse the whole file when a name is not an environment
variable name (`[A-Za-z_][A-Za-z0-9_]*`), for example a 1Password field label
such as `API Key` or an Infisical key such as `db-host`. The error lists every
such entry with a suggested name (`"db-host" (rename to "db_host")`); Phantom
never renames a secret for you. Rename the entries to the variables your app
reads and retry.

### Existing secrets not overwritten during import

By default, `phantom import --from` excludes existing vault entries from its
reviewed destination set. `--force` selects them for overwrite, but never skips
the attached-terminal exact-consent ceremony:

```bash
phantom import --from doppler --file dump.json --force
```

### Import succeeds but `.env` still has plaintext secrets

`phantom import --from` stores secrets in the vault but does not rewrite your `.env`. After importing, run:

```bash
phantom init
```

This replaces any plaintext secrets in `.env` with phantom tokens.

### `phantom upgrade` identifies a direct, npm, or legacy shared-root install

The direct installers and npm wrappers both use `~/.phantom-secrets/bin`. New direct installs include a private `.phantom-install-source.json` receipt, while npm wrappers create an explicit npm ownership marker; `phantom upgrade` can therefore distinguish ownership without guessing from the path. All installers coordinate on the same sibling owner lock. A direct install owns `phantom` and `phantom-mcp` as one versioned pair, so the single-binary updater refuses to split their versions. Download the installer from the exact reviewed release, compare its published checksum, inspect the local file, and run that local file to upgrade both binaries transactionally.

An npm-owned binary is also not replaced in place because the wrapper would overwrite it on its next run. Use an exact, reviewed npm package version only after that package is published and independently verified; the GitHub release does not prove npm publication.

Older shared-root installs may have no receipt. Phantom recognizes a structurally valid legacy npm manifest, but otherwise reports an ambiguous legacy install and fails closed. Re-running a checksum-verified direct installer establishes the receipt without relying on a path guess.

For Homebrew installs, use the reviewed tap and fully qualified formula. The
formula currently publishes `v0.7.8`; direct GitHub assets remain available for
explicit checksum verification:

```bash
brew tap ashlrai/phantom
brew trust --formula ashlrai/phantom/phantom
brew upgrade ashlrai/phantom/phantom
```

Cargo-owned and otherwise unshared standalone binaries can continue to use `phantom upgrade`. A successful source build or GitHub release does not by itself prove that a crate, npm package, or Homebrew formula has been published.

`phantom upgrade --force` is disabled. An eligible standalone replacement
requires stdin, stdout, and stderr attached to a trusted terminal, one fresh
exact challenge before release-metadata access, and a second challenge bound to
the verified replacement plan. `--check-only` is read-only; managed installs
route to their package owner and ambiguous ownership fails closed.

### npm wrapper feels "stuck on an old version"

The npm wrapper auto-detects when its cached binary's `--version` doesn't match the wrapper's published version and re-downloads. If something is wrong and the cache feels stale, force a refresh:

```bash
rm -f ~/.phantom-secrets/bin/phantom
phantom --version       # triggers re-download via the npm wrapper
```

### Warning: vault corruption means secret loss

If your vault becomes corrupted or inaccessible and you have no backup (no deployment platform copy, no password manager record), **those secrets are permanently lost**. Phantom cannot recover secrets from phantom tokens -- the tokens are random values with no reversible relationship to the real secrets.

Take backups seriously. At minimum, ensure your secrets are synced to at least one deployment platform (`phantom sync`) so you always have a recovery path.
