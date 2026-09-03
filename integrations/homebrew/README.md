# Homebrew tap for Phantom

This directory mirrors the contents of the public Homebrew tap at
[`ashlrai/homebrew-phantom`](https://github.com/ashlrai/homebrew-phantom).
Code review of formula changes happens here — the tap repo is the
delivery channel.

## Tap maintenance

The tap repo is live. End users install with:

```bash
brew tap ashlrai/phantom
```

Homebrew 6.0 and later require third-party formulae to be trusted explicitly.
On those versions, trust Phantom's specific formula:

```bash
brew trust --formula ashlrai/phantom/phantom
```

Then install the fully qualified formula:

```bash
brew install ashlrai/phantom/phantom
```

Every release should update the four release URLs and four `sha256` lines in
`Formula/phantom.rb` of the tap after the exact archives and checksums are
verified. Homebrew infers the version from those concrete URLs. This is a
separately authorized, manual distribution step; the current release workflow
does not mutate the tap. The simplest workflow is:

```bash
# After tagging and the binaries are uploaded:
curl -sL https://github.com/ashlrai/phantom-secrets/releases/download/vX.Y.Z/SHA256SUMS
# Update Formula/phantom.rb with the four new URLs + four new SHAs
git -C ~/code/homebrew-phantom commit -am "phantom X.Y.Z"
git -C ~/code/homebrew-phantom push
```

A future enhancement would add a step to `.github/workflows/release.yml`
in this repo to propose a reviewed PR against `homebrew-phantom` after artifact
verification. That automation is not present today.

## Verifying the formula locally

Before pushing to the tap, you can test the formula against the local
copy:

```bash
brew tap-new --no-git codex/phantom-local-test
tap_dir="$(brew --repository codex/phantom-local-test)"
cp ./integrations/homebrew/Formula/phantom.rb "${tap_dir}/Formula/phantom.rb"
brew trust --formula codex/phantom-local-test/phantom
brew install codex/phantom-local-test/phantom
brew test codex/phantom-local-test/phantom
phantom --version  # → "phantom 0.7.4"
phantom-mcp --version  # → "phantom-mcp 0.7.4"
brew uninstall phantom
brew untap codex/phantom-local-test
```
