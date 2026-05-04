# Phantom — Homebrew formula
#
# This formula lives in the ashlrai/homebrew-phantom tap repo.
# It is mirrored here in the main repo so changes can be reviewed
# alongside the code that produces the binaries it downloads.
#
# To update for a new release, the release.yml workflow opens a PR
# against ashlrai/homebrew-phantom that bumps `version` and the
# four sha256 lines.

class Phantom < Formula
  desc "Stop AI coding agents from leaking your API keys"
  homepage "https://phm.dev"
  version "0.6.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-aarch64-apple-darwin.tar.gz"
      sha256 "a924eb14971cddb56cf9728b46dfa401c525b864afd7c075907ca38fda986453"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-x86_64-apple-darwin.tar.gz"
      sha256 "e82fb7e773af3701e8813f3bc851abb1c5677735751a93eebf0ede91f533974d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "1b94f2dcf47df2b6d82ec81897555e9293345133ce227c267f18e616c54c6ca4"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "cdc8ac1fc874d8c7d0d84221ee6a90bf3619ca313bf0d2835be23319bec9b8cc"
    end
  end

  def install
    bin.install "phantom"
    bin.install "phantom-mcp"
  end

  test do
    assert_match "phantom #{version}", shell_output("#{bin}/phantom --version")
  end
end
