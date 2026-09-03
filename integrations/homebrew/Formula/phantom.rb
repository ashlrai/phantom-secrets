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
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.5/phantom-aarch64-apple-darwin.tar.gz"
      sha256 "8f5dac49da5f1a32ea826dff79012bb52c3ee36024075cd0cd5e272bc626bded"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.5/phantom-x86_64-apple-darwin.tar.gz"
      sha256 "f7e5d13e6a20a096e5ea4df39a7a81f159d0b85b8e560a0698f6b09dd59f28ea"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.5/phantom-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b0898defc89b013a9fecd64ae14aa9087591dde52898f4622881ad923cc3b5a3"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.5/phantom-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "b5e2f58ced5b3a606f68787fea50e042f60ccf03b3e205998bc04cfdc8df3d7d"
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
