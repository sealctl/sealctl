#!/bin/sh
# Build release artefacts for one target into ./dist (used by CI; works locally too).
#   scripts/package.sh <target-triple> [binary-path]
# Produces: dist/sealctl-<version>-<target>.tar.gz (+ .sha256) containing the binary,
# LICENSE, THIRD-PARTY-NOTICES.md, README and shell completions; on macOS also
# "sealctl Notifier.app" (desktop notifications, scripts/build-notifier-macos.sh), on Linux the
# icon and desktop entry the notifications name (sealctl.png, sealctl.desktop).
set -eu
TARGET="$1"
BIN="${2:-target/$TARGET/release/sealctl}"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -x "$BIN" ] || { echo "binary $BIN not found" >&2; exit 1; }

COMP=crates/sealctl/completions
mkdir -p "$COMP" dist
# completions come from the host-runnable binary (CLI is identical on every target)
RUNNABLE="${COMPLETIONS_BIN:-$BIN}"
"$RUNNABLE" completions bash > "$COMP/sealctl.bash"
"$RUNNABLE" completions zsh  > "$COMP/_sealctl"
"$RUNNABLE" completions fish > "$COMP/sealctl.fish"

NAME="sealctl-$VERSION-$TARGET"
rm -rf "dist/$NAME"
mkdir -p "dist/$NAME/completions"
cp "$BIN" "dist/$NAME/sealctl"
cp LICENSE THIRD-PARTY-NOTICES.md README.md "dist/$NAME/"
cp "$COMP"/* "dist/$NAME/completions/"
case "$TARGET" in
  aarch64-apple-darwin) scripts/build-notifier-macos.sh arm64 "dist/$NAME" ;;
  x86_64-apple-darwin) scripts/build-notifier-macos.sh x86_64 "dist/$NAME" ;;
  *-linux-*)
    cp packaging/linux/sealctl.desktop "dist/$NAME/"
    cp packaging/icons/sealctl-256.png "dist/$NAME/sealctl.png"
    ;;
esac
tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
rm -rf "dist/$NAME"
( cd dist && { sha256sum "$NAME.tar.gz" 2>/dev/null || shasum -a 256 "$NAME.tar.gz"; } > "$NAME.tar.gz.sha256" )
echo "dist/$NAME.tar.gz"
