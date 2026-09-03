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
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.4/phantom-aarch64-apple-darwin.tar.gz"
      sha256 "c1b88312fb0d36ffb3a3b8ed1622de9f95907f3a7a1cac70404856b82ae6b34b"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.4/phantom-x86_64-apple-darwin.tar.gz"
      sha256 "1f71730467bff259d407b98948c1ce3bf89a868dc9a54e1bce44e42d59930c5a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.4/phantom-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "a4ed92c3662daf95584d9a77a13edce7af055b849d25c38acd192d13de7eed5e"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.4/phantom-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "dc94282a47ff04f88245c750248b1557a220a35acb9aa206443ddb04f94accbc"
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
