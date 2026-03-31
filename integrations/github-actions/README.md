# Phantom Secrets — GitHub Actions

Pull secrets from Phantom Cloud into your CI/CD pipeline. End-to-end encrypted.

## Usage

```yaml
- name: Load secrets
  uses: ashlrai/phantom-secrets/integrations/github-actions@v0.3
  with:
    phantom-token: ${{ secrets.PHANTOM_TOKEN }}
    project-id: ${{ secrets.PHANTOM_PROJECT_ID }}
    vault-passphrase: ${{ secrets.PHANTOM_VAULT_PASSPHRASE }}
```

## Setup

1. Run `phantom login` locally to get a device token
2. Add these GitHub Actions secrets:
   - `PHANTOM_TOKEN` — your device token
   - `PHANTOM_PROJECT_ID` — from `.phantom.toml`
   - `PHANTOM_VAULT_PASSPHRASE` — your cloud vault passphrase
3. Add the action to your workflow

## How It Works

1. Action installs `phantom-secrets` via npm
2. Pulls encrypted vault from Phantom Cloud
3. Decrypts locally in the CI runner
4. Secrets are available in the vault for the rest of the workflow
