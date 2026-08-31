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
  version "0.7.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-aarch64-apple-darwin.tar.gz"
      sha256 "c5f259fe7a8c6fd4ac05385529040b4d66f2a4e71760ef6a5798539127a74c70"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-x86_64-apple-darwin.tar.gz"
      sha256 "de23343d284db4ef0d3011da5c2521ebd64ca953666cbf97e0fe43935a2dd9fc"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "fc91f90f98a85f1fd8b63f455877e2d5a225aa147d9d7945b077f729eb97515b"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "a6fd418652fe0aa85c8e01283c3b7f761cc57c3a803b5e30c5fa040ae66b4824"
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
