#!/bin/sh
# Render the Homebrew formula from release tarballs.
#   scripts/render-formula.sh <version> <base-url> <dist-dir>
# <base-url> is where the tarballs are downloadable (GitHub release URL, or file:// for tests).
set -eu
VERSION="$1"; BASE="$2"; DIST="$3"
sha() { cut -d' ' -f1 "$DIST/sealctl-$VERSION-$1.tar.gz.sha256"; }
cat <<EOF
class Sealctl < Formula
  desc "Hardware-wallet backed encryption: volumes, backups, secrets, SSH (Ledger OpenPGP)"
  homepage "https://github.com/sealctl/sealctl"
  version "$VERSION"
  license "MIT"

  on_macos do
    on_arm do
      url "$BASE/sealctl-$VERSION-aarch64-apple-darwin.tar.gz"
      sha256 "$(sha aarch64-apple-darwin)"
    end
    on_intel do
      url "$BASE/sealctl-$VERSION-x86_64-apple-darwin.tar.gz"
      sha256 "$(sha x86_64-apple-darwin)"
    end
  end

  on_linux do
    on_arm do
      url "$BASE/sealctl-$VERSION-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "$(sha aarch64-unknown-linux-gnu)"
    end
    on_intel do
      url "$BASE/sealctl-$VERSION-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "$(sha x86_64-unknown-linux-gnu)"
    end
  end

  depends_on "restic"

  def install
    bin.install "sealctl"
    bash_completion.install "completions/sealctl.bash" => "sealctl"
    zsh_completion.install "completions/_sealctl"
    fish_completion.install "completions/sealctl.fish"
  end

  def caveats
    <<~EOS
      sealctl needs the OpenPGP app on your Ledger (Ledger Live → developer mode).
      For Bluetooth, see https://github.com/sealctl/sealctl/blob/main/docs/bluetooth-app.md
      Get started: sealctl setup --uid "Your Name <you@example.org>"
      To leave the Ledger: sealctl unseal --all
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sealctl --version")
    assert_match "volume", shell_output("#{bin}/sealctl --help")
  end
end
EOF
