# Homebrew tap for Phantom

This directory mirrors the contents of the public Homebrew tap at
[`ashlrai/homebrew-phantom`](https://github.com/ashlrai/homebrew-phantom).
Code review of formula changes happens here — the tap repo is the
delivery channel.

## One-time setup (Mason)

The tap repo doesn't exist yet. To create it:

1. Create a new public repo named **`homebrew-phantom`** under the `ashlrai`
   GitHub account. Description: "Homebrew tap for Phantom — stop AI agents
   from leaking your API keys."
2. In the new repo, create a directory `Formula/` and copy `phantom.rb`
   from this directory into it.
3. Push and the tap is live. End users install with:

   ```
   brew tap ashlrai/phantom
   brew install phantom
   ```

After that, every release should bump `version` + the four `sha256` lines
in `Formula/phantom.rb` of the tap. The simplest workflow is:

```bash
# After tagging and the binaries are uploaded:
curl -sL https://github.com/ashlrai/phantom-secrets/releases/download/vX.Y.Z/SHA256SUMS
# Update Formula/phantom.rb with the new version + new SHAs
git -C ~/code/homebrew-phantom commit -am "phantom X.Y.Z"
git -C ~/code/homebrew-phantom push
```

A future enhancement would add a step to `.github/workflows/release.yml`
in this repo that opens a PR against `homebrew-phantom` automatically
on every tag push.

## Verifying the formula locally

Before pushing to the tap, you can test the formula against the local
copy:

```bash
brew install --formula ./integrations/homebrew/Formula/phantom.rb
phantom --version  # → "phantom 0.5.1"
brew uninstall phantom
```
