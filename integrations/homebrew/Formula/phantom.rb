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
  version "0.5.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-aarch64-apple-darwin.tar.gz"
      sha256 "b105cc44e383ee8c509f10306617792e7fe39c393a7bcb61c7e42e9730e1ed3b"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-x86_64-apple-darwin.tar.gz"
      sha256 "2df5310406ec5a9dc9c92dae774cccd0f2d866fe41ed6f9cab68d1f491bbef2c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "85887b38f628cdeb3532352b7506dd22269d946a5fc240c8ede776b1abbabf9e"
    end
    on_intel do
      url "https://github.com/ashlrai/phantom-secrets/releases/download/v#{version}/phantom-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "de4eef7295f6607feae9aff96c807b37af9cc1c3155b50e6cb68f33d2e640958"
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
