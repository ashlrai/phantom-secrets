# Phantom Secrets -- GitHub Actions

Pull secrets from Phantom Cloud into your CI/CD pipeline. Secrets are end-to-end encrypted and only decrypted inside the GitHub Actions runner -- they never pass through Phantom's servers in plaintext.

## How It Works

1. The action installs the `phantom-secrets` CLI via npm
2. Authenticates with Phantom Cloud using your device token
3. Pulls the encrypted vault for your project
4. Decrypts it locally inside the runner using your vault passphrase
5. Secrets are available in the vault for the rest of the workflow
6. Use `phantom exec -- <command>` to run commands with secrets injected via the local proxy

## Prerequisites

- A Phantom Cloud account (`phantom login` on your local machine)
- A project initialized with `phantom init` and secrets added via `phantom add`
- Secrets pushed to Phantom Cloud with `phantom cloud push`
- Three GitHub Actions secrets configured in your repository (see Setup below)

## Setup

### Step 1: Get Your Device Token

Generate a CI-specific device token. This token authenticates the GitHub Actions runner with Phantom Cloud.

```bash
phantom login --ci
# Outputs a device token -- copy it
```

### Step 2: Find Your Project ID

Your project ID is in your `.phantom.toml` file at the root of your project:

```bash
cat .phantom.toml | grep project_id
# project_id = "proj_abc123..."
```

### Step 3: Get Your Vault Passphrase

If you use a vault passphrase (recommended for CI), retrieve it from your local keychain:

```bash
phantom reveal --passphrase
# Outputs your vault passphrase
```

If your project uses keychain-only mode, you can skip this step and omit the `vault-passphrase` input.

### Step 4: Add GitHub Actions Secrets

Go to your GitHub repository: **Settings > Secrets and variables > Actions > New repository secret**.

Add these secrets:

| Secret Name                  | Value                        | Required |
|------------------------------|------------------------------|----------|
| `PHANTOM_TOKEN`              | Device token from Step 1     | Yes      |
| `PHANTOM_PROJECT_ID`         | Project ID from Step 2       | Yes      |
| `PHANTOM_VAULT_PASSPHRASE`   | Vault passphrase from Step 3 | No       |

### Step 5: Add the Action to Your Workflow

```yaml
- name: Load secrets from Phantom Cloud
  uses: ashlrai/phantom-secrets/integrations/github-actions@main
  with:
    phantom-token: ${{ secrets.PHANTOM_TOKEN }}
    project-id: ${{ secrets.PHANTOM_PROJECT_ID }}
    vault-passphrase: ${{ secrets.PHANTOM_VAULT_PASSPHRASE }}
```

## Inputs

| Input                | Description                                              | Required | Default  |
|----------------------|----------------------------------------------------------|----------|----------|
| `phantom-token`      | Phantom Cloud device token                               | Yes      |          |
| `project-id`         | Phantom project ID (from `.phantom.toml`)                | Yes      |          |
| `vault-passphrase`   | Cloud vault encryption passphrase                        | No       | `""`     |
| `phantom-version`    | Version of phantom-secrets to install                    | No       | `latest` |
| `environment`        | Target environment (e.g., `staging`, `production`)       | No       | `""`     |
| `working-directory`  | Directory containing `.phantom.toml`                     | No       | `.`      |

## Outputs

| Output          | Description                              |
|-----------------|------------------------------------------|
| `secrets-count` | Number of secrets loaded into the vault  |
| `project-id`    | The Phantom project ID that was used     |

### Using Outputs

```yaml
- name: Load secrets
  id: phantom
  uses: ashlrai/phantom-secrets/integrations/github-actions@main
  with:
    phantom-token: ${{ secrets.PHANTOM_TOKEN }}
    project-id: ${{ secrets.PHANTOM_PROJECT_ID }}
    vault-passphrase: ${{ secrets.PHANTOM_VAULT_PASSPHRASE }}

- name: Check secrets loaded
  run: echo "Loaded ${{ steps.phantom.outputs.secrets-count }} secrets"
```

## Workflow Examples

### Basic Deployment

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Load secrets
        uses: ashlrai/phantom-secrets/integrations/github-actions@main
        with:
          phantom-token: ${{ secrets.PHANTOM_TOKEN }}
          project-id: ${{ secrets.PHANTOM_PROJECT_ID }}
          vault-passphrase: ${{ secrets.PHANTOM_VAULT_PASSPHRASE }}

      - name: Deploy
        run: phantom exec -- npm run deploy
```

### Integration Tests with Real API Keys

```yaml
name: Integration Tests
on: [pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - run: npm ci

      - name: Load secrets
        uses: ashlrai/phantom-secrets/integrations/github-actions@main
        with:
          phantom-token: ${{ secrets.PHANTOM_TOKEN }}
          project-id: ${{ secrets.PHANTOM_PROJECT_ID }}
          vault-passphrase: ${{ secrets.PHANTOM_VAULT_PASSPHRASE }}

      - name: Run integration tests
        run: phantom exec -- npm test
```

### Multi-Environment Deployment

```yaml
name: Deploy Pipeline
on:
  push:
    branches: [main]

jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4

      - name: Load staging secrets
        uses: ashlrai/phantom-secrets/integrations/github-actions@main
        with:
          phantom-token: ${{ secrets.PHANTOM_TOKEN }}
          project-id: ${{ secrets.PHANTOM_PROJECT_ID }}
          vault-passphrase: ${{ secrets.PHANTOM_VAULT_PASSPHRASE }}
          environment: staging

      - run: phantom exec -- npm run deploy:staging

  deploy-production:
    runs-on: ubuntu-latest
    needs: deploy-staging
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Load production secrets
        uses: ashlrai/phantom-secrets/integrations/github-actions@main
        with:
          phantom-token: ${{ secrets.PHANTOM_TOKEN }}
          project-id: ${{ secrets.PHANTOM_PROJECT_ID }}
          vault-passphrase: ${{ secrets.PHANTOM_VAULT_PASSPHRASE }}
          environment: production

      - run: phantom exec -- npm run deploy:production
```

### Monorepo with Custom Working Directory

```yaml
- name: Load secrets for backend
  uses: ashlrai/phantom-secrets/integrations/github-actions@main
  with:
    phantom-token: ${{ secrets.PHANTOM_TOKEN }}
    project-id: ${{ secrets.PHANTOM_PROJECT_ID }}
    vault-passphrase: ${{ secrets.PHANTOM_VAULT_PASSPHRASE }}
    working-directory: ./packages/backend
```

### Pinned Version

```yaml
- name: Load secrets (pinned)
  uses: ashlrai/phantom-secrets/integrations/github-actions@main
  with:
    phantom-token: ${{ secrets.PHANTOM_TOKEN }}
    project-id: ${{ secrets.PHANTOM_PROJECT_ID }}
    vault-passphrase: ${{ secrets.PHANTOM_VAULT_PASSPHRASE }}
    phantom-version: '0.3.2'
```

## Troubleshooting

### "Failed to install phantom-secrets"

- Check that the version you specified exists on npm. Remove the `phantom-version` input to use the latest release.
- If your runner has no internet access, you may need to pre-install phantom-secrets in your Docker image.

### "Failed to pull secrets from Phantom Cloud"

- Verify your `PHANTOM_TOKEN` is valid. Tokens expire -- regenerate with `phantom login --ci`.
- Verify your `PHANTOM_PROJECT_ID` matches the project in your `.phantom.toml`.
- If secrets were pushed from a different machine, ensure you are using the correct vault passphrase.

### "Phantom status check returned a non-zero exit code"

- This is a warning, not a failure. It usually means the vault is partially loaded or a non-critical check failed.
- Run `phantom doctor` locally to diagnose vault issues.

### Secrets Not Available in Subsequent Steps

- Make sure you run your commands with `phantom exec -- <command>`. The proxy injects secrets at the network layer -- they are not exported as environment variables.
- If you need secrets as environment variables, use `phantom env` to export them (note: this is less secure than the proxy approach).

### "No vault passphrase provided -- using keychain-only mode"

- This is informational, not an error. If your project requires a passphrase, add the `PHANTOM_VAULT_PASSPHRASE` secret to your repository.

### Permission Errors

- Ensure your device token has access to the project. Check with `phantom cloud status` locally.
- For organization projects, verify the token has the required scopes.

## Security Considerations

### GitHub Actions Secrets

- GitHub encrypts secrets at rest using libsodium sealed boxes.
- Secrets are not passed to workflows triggered by pull requests from forks.
- Secrets are masked in workflow logs if they are printed to stdout.
- Read more: [GitHub Encrypted Secrets documentation](https://docs.github.com/en/actions/security-guides/encrypted-secrets)

### Phantom's Security Model in CI

- **End-to-end encryption**: Your vault is encrypted before it leaves your machine. Phantom Cloud stores only ciphertext. Decryption happens inside the GitHub Actions runner.
- **No plaintext in transit**: The device token authenticates the pull, but secrets are never decrypted server-side.
- **Ephemeral runners**: GitHub Actions runners are ephemeral VMs. Secrets are destroyed when the job completes.
- **Proxy isolation**: `phantom exec` runs a local proxy on `127.0.0.1` that injects secrets at the network layer. Secrets never touch disk or environment variables.

### Best Practices

- Use separate device tokens for CI (generated with `phantom login --ci`). Revoke them independently of your personal token.
- Use GitHub Environments with protection rules for production secrets.
- Pin the `phantom-version` input in production workflows to avoid unexpected breaking changes.
- Rotate your vault passphrase periodically with `phantom rotate --passphrase`.
- Audit secret access in Phantom Cloud's dashboard.

## License

See the [Phantom Secrets repository](https://github.com/ashlrai/phantom-secrets) for license information.
