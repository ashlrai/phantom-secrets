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
3. **Verify the real value is correct**: `phantom reveal <KEY> --yes`
4. **Check BASE_URL is set**: The proxy only works when `OPENAI_BASE_URL` (or equivalent) points to the local proxy. Use `phantom exec -- <cmd>` which sets these automatically.

### Proxy hangs or times out

The default upstream timeout is 30 seconds. For long-running API calls:

- Check your network connection
- Verify the upstream service is accessible
- The proxy follows redirects automatically (up to 5 hops)

### "Refusing to reveal secret in non-interactive context"

This is a security feature. `phantom reveal` blocks in non-interactive contexts (pipes, scripts, AI agents) to prevent secrets from leaking into AI context windows.

To override: `phantom reveal <KEY> --yes`

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
3. Try installing directly: `cargo install phantom --git https://github.com/ashlrai/phantom-secrets`

## CI/CD Usage

### GitHub Actions

```yaml
- name: Set up Phantom
  run: |
    cargo install phantom --git https://github.com/ashlrai/phantom-secrets
    echo "PHANTOM_VAULT_PASSPHRASE=${{ secrets.PHANTOM_VAULT_PASSPHRASE }}" >> $GITHUB_ENV
    phantom pull --from vercel --project ${{ vars.VERCEL_PROJECT_ID }}
  env:
    VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
```

### Docker

```dockerfile
# Install phantom
RUN cargo install phantom --git https://github.com/ashlrai/phantom-secrets

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
