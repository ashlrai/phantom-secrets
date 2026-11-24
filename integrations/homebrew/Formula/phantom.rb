# frozen_string_literal: true

# Phantom — Homebrew formula
#
# This formula lives in the ashlrai/homebrew-phantom tap repo.
# It is mirrored here in the main repo so changes can be reviewed
# alongside the code that produces the binaries it downloads.
#
# Updates are reviewed and applied manually after the exact release archives
# and checksums are published. The current release workflow does not open a tap
# pull request automatically.

class Phantom < Formula
  desc "Reduce API-key exposure when working with AI coding agents"
  homepage "https://phm.dev"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.8.11/phantom-aarch64-apple-darwin.tar.gz"
      sha256 "f94d7087f04cb58a2c285e4939bbe2cbcc6f56a85930832f971e19c80b6b24c4"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.8.11/phantom-x86_64-apple-darwin.tar.gz"
      sha256 "c1ba310090df40567a91135634995695e667c5f120ab687b4bd6c573aea4d3a6"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.8.11/phantom-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5d1bbd445819daf66e64124810e74b70b886fc0116bdcb80b8d25627572ae05d"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.8.11/phantom-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c7f6d35a16c5e8c1c192486912d3ee2aabaa76029dc5c1f296755a2fbef12e62"
    end
  end

  def install
    bin.install "phantom"
    bin.install "phantom-mcp"
  end

  test do
    assert_match "phantom #{version}", shell_output("#{bin}/phantom --version")
    assert_match "phantom-mcp #{version}", shell_output("#{bin}/phantom-mcp --version")
  end
end
