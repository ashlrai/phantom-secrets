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
  desc "Stop AI coding agents from leaking your API keys"
  homepage "https://phm.dev"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-apple-darwin.tar.gz"
      sha256 "c89dffde878f73692a000978c1e432fa1e9c15d6ceaa9adfafffe765b3303bf6"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-apple-darwin.tar.gz"
      sha256 "f8f44575db8737064ca1e733f80c39b6626bde15654ab08138134100f73c7155"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b392dbd11fb171970b3f55e8ef8165718ab4d88604fb045c7faf985f1ebecea9"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "64930e9f43f8c29a0678facc32e4dfea3f114bc032874908a7d9584a6f9dfe20"
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
