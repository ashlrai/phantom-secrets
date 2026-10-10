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
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.9/phantom-aarch64-apple-darwin.tar.gz"
      sha256 "0c30d0404f3cb809ad95d2e8bfbe346348929e54e40e4574153107c5e7cad38a"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.9/phantom-x86_64-apple-darwin.tar.gz"
      sha256 "cdc22e66bcb070edf6a47eb79d8810623f8da70b8e3da65a2438df367ac4ee8c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.9/phantom-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "d29250aecc8a11eba710da97865e36c9acd35b77fa77447086926604f0ee3295"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.9/phantom-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "d791d27389d6ebc8c9224458a30d4f708b52fa6cbc71954907ab895760b41598"
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
