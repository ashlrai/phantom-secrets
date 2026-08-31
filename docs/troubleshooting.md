# Troubleshooting

## Common Issues

### "No .phantom.toml found"

You haven't initialized Phantom in this directory yet.

```bash
phantom init
```

This reads your `.env`, stores real secrets in the vault, and rewrites `.env` with phantom tokens.

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

### Proxy hangs or times out

The default upstream timeout is 30 seconds. For long-running API calls:

- Check your network connection
- Verify the upstream service is accessible
- The proxy follows redirects automatically (up to 5 hops)

### Streaming request body larger than 10 MB is silently dropped

For `text/*` and `application/x-www-form-urlencoded` content types, the proxy uses a streaming token-replacement path. If the body exceeds the 10 MB limit, the streaming task is dropped and the upstream sees a broken connection (not a clean HTTP 413). For JSON bodies the proxy returns HTTP 413 cleanly.

If you are sending large streaming bodies through the proxy and seeing broken-pipe errors upstream, either split the payload or increase the body limit via a future `.phantom.toml` option (not yet exposed; track [#issues](https://github.com/ashlrai/phantom-secrets/issues)).

### Claude Code can't read my .env file

Many Claude Code setups block reading `.env` files by default. Keep that boundary: although Phantom-managed entries become worthless `phm_` tokens, sibling dotenv files or backups from other tools can still contain plaintext.

Fix it automatically:
```bash
phantom setup --client claude
```

This wires the MCP server, removes legacy Phantom-managed dotenv allow grants, and preserves deny rules in `.claude/settings.local.json`. For other AI tools, swap in `--client cursor|windsurf|codex`. Agents can use Phantom's value-blind MCP inventory without dotenv read access.

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

On Linux, ensure the Secret Service daemon is running:
```bash
# GNOME
systemctl --user start gnome-keyring-daemon

# For headless/CI environments, set the passphrase env var instead:
export PHANTOM_VAULT_PASSPHRASE="your-secure-passphrase"
```

### "WARNING — OS keychain unavailable"

This appears in Docker/CI environments where no keychain is available. Set the passphrase explicitly:

```bash
export PHANTOM_VAULT_PASSPHRASE="$(openssl rand -hex 32)"
```

Store this passphrase securely (e.g., as a CI secret) — you'll need it on every run to decrypt the vault.

### `phantom start --daemon` fails silently

If the daemon starts but the proxy fails:

1. Try running in foreground first: `phantom start` (without `--daemon`)
2. Check for port conflicts
3. Verify `.phantom.toml` is valid: `phantom doctor`

### `npx phantom-secrets` fails to download

The binary is downloaded from GitHub Releases. If it fails:

1. Check your internet connection
2. Verify the release exists: https://github.com/ashlrai/phantom-secrets/releases
3. Try installing directly: `cargo install phantom-secrets`

## CI/CD Usage

### GitHub Actions

```yaml
- name: Set up Phantom
  run: |
    cargo install phantom-secrets
    echo "PHANTOM_VAULT_PASSPHRASE=${{ secrets.PHANTOM_VAULT_PASSPHRASE }}" >> $GITHUB_ENV
    phantom pull --from vercel --project ${{ vars.VERCEL_PROJECT_ID }}
  env:
    VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
```

### Docker

```dockerfile
# Install phantom
RUN cargo install phantom-secrets

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

If using OS keychain: secrets are tied to your user account. They persist across reboots.

If using file vault: you need the `PHANTOM_VAULT_PASSPHRASE` to decrypt. If lost, re-pull from your deployment platform:
```bash
phantom pull --from vercel --project prj_xxx --force
```

### Is Phantom safe to use with Claude Code / Cursor?

That's exactly what it's built for. The AI agent only sees phantom tokens (`phm_...`), never real secrets. Even if the AI includes a phantom token in generated code or sends it to an LLM, the token is worthless — it only works through the local proxy during the current session.

## Vault Backup

### Where secrets are stored

Phantom stores your real secret values in one of two locations:

- **OS keychain (primary):** macOS Keychain or Linux Secret Service. This is the default on desktop systems. Secrets are tied to your user account and persist across reboots.
- **Encrypted file vault (fallback):** `~/.phantom/vaults/`. Used automatically in environments without an OS keychain (Docker, CI runners), or when `PHANTOM_VAULT_PASSPHRASE` is explicitly set. Vault payloads use ChaCha20-Poly1305 with an Argon2id-derived key.

### How to back up your secrets

Use Phantom's encrypted export rather than printing every value. Supply a
dedicated high-entropy passphrase and protect both the archive and passphrase
as separate recovery material:

```bash
# Interactive: hidden prompt + confirmation on an attached terminal
phantom export --output phantom-backup.enc

# Automation: bounded private file, never argv
chmod 600 /secure/path/phantom-backup.pass
phantom export --output phantom-backup.enc \
  --passphrase-file /secure/path/phantom-backup.pass
```

Recover into an initialized Phantom project with the symmetric input method:

```bash
phantom import phantom-backup.enc
phantom import phantom-backup.enc \
  --passphrase-file /secure/path/phantom-backup.pass
```

Passphrase files must be regular files, not symlinks, and are limited to 4096
bytes. On Unix they must be mode `0600` or stricter. Export refuses existing
targets and symlinks; it creates a `0600` staging file on Unix (or uses the
containing directory's inherited ACL on Windows), flushes it, and publishes it
without overwriting. Store neither the encrypted backup nor its passphrase in
the repository. Plaintext JSON export and the legacy argv `--passphrase` flow
are disabled.

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

### "Not authenticated" when running `phantom cloud push`

You need to log in first:
```bash
phantom login
```

This opens your browser for GitHub OAuth. Once authenticated, your device is linked to your Phantom Cloud account.

### Cloud push fails with encryption error

Ensure your OS keychain is accessible. The cloud encryption key is stored in your keychain. If you are in a headless environment, set `PHANTOM_VAULT_PASSPHRASE` before running cloud commands.

### Cloud pull doesn't restore all secrets

Cloud sync is per-vault. Make sure you pushed from the same project directory. Each project has its own vault and cloud backup.

### "Subscription required" on cloud push

The free tier allows 1 cloud vault. If you need more, upgrade to Pro ($8/mo) at [phm.dev/pricing](https://phm.dev/pricing).

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
4. If you suspect a security incident, revoke affected secrets via `phantom rotate` and re-add them.

Note: entries written before HMAC chaining was introduced (pre-PR #62) are counted as `legacy` in the verify output and do not fail the check.

### Audit log is empty / "No audit events yet"

The log file is only created once the first event is written. Ensure `PHANTOM_AUDIT=1` is set in the shell where `phantom exec` or vault-mutating commands run. Check the log path with `phantom audit path`.

## Importing from other secret managers

### `phantom import --from` fails to parse the export file

Each importer expects a specific file format:

| Source | Expected format | Notes |
|--------|----------------|-------|
| `doppler` | JSON object (`{"KEY": "value", ...}`) | Use `doppler secrets download --no-file --format json > dump.json` |
| `infisical` | `.env` key=value lines | Use `infisical export --format=dotenv > export.env` |
| `dotenvx` | Plaintext `.env` | Encrypted `.env.vault` files are **not** supported — run `dotenvx decrypt --stdout > .env` first |
| `1password` | JSON array of item objects | Use `op item list --format json > 1p-export.json` |
| `env` | Plaintext `.env` key=value | Any standard dotenv format |

If the file format is wrong, the importer returns a parse error. Re-export from the source tool and retry.

### Existing secrets not overwritten during import

By default, `phantom import --from` prompts before overwriting existing vault entries. Pass `--force` to skip the prompt:

```bash
phantom import --from doppler --file dump.json --force
```

### Import succeeds but `.env` still has plaintext secrets

`phantom import --from` stores secrets in the vault but does not rewrite your `.env`. After importing, run:

```bash
phantom init
```

This replaces any plaintext secrets in `.env` with phantom tokens.

### `phantom upgrade` says "use npm" instead of upgrading

This is intentional. When phantom is installed via npm (binary cached at `~/.phantom-secrets/bin/phantom`), running `phantom upgrade` directly would be reverted by the next `npm install`. Use the npm path instead:

```bash
npm i -g phantom-secrets@latest
```

For brew installs, use `brew upgrade phantom`. For curl-installed binaries (`~/.local/bin/phantom`) or cargo-installed (`~/.cargo/bin/phantom`), `phantom upgrade` is the right command.

### npm wrapper feels "stuck on an old version"

The npm wrapper auto-detects when its cached binary's `--version` doesn't match the wrapper's published version and re-downloads. If something is wrong and the cache feels stale, force a refresh:

```bash
rm -f ~/.phantom-secrets/bin/phantom
phantom --version       # triggers re-download via the npm wrapper
```

### Warning: vault corruption means secret loss

If your vault becomes corrupted or inaccessible and you have no backup (no deployment platform copy, no password manager record), **those secrets are permanently lost**. Phantom cannot recover secrets from phantom tokens -- the tokens are random values with no reversible relationship to the real secrets.

Take backups seriously. At minimum, ensure your secrets are synced to at least one deployment platform (`phantom sync`) so you always have a recovery path.
