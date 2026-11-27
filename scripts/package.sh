#!/bin/sh
# Build release artefacts for one target into ./dist (used by CI; works locally too).
#   scripts/package.sh <target-triple> [binary-path]
# Produces: dist/sealctl-<version>-<target>.tar.gz (+ .sha256) containing the binary,
# LICENSE, THIRD-PARTY-NOTICES.md, README and shell completions; on macOS also
# "sealctl Notifier.app" (desktop notifications, scripts/build-notifier-macos.sh), on Linux the
# icon and desktop entry the notifications name (sealctl.png, sealctl.desktop).
# The archive is reproducible (SPEC 21): the same inputs give the same bytes, with entries in
# a fixed order, every time stamp at SOURCE_DATE_EPOCH (default: the last commit's time),
# owner root, no extended attributes, and a gzip header without a name or time.
set -eu
TARGET="$1"
BIN="${2:-target/$TARGET/release/sealctl}"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -x "$BIN" ] || { echo "binary $BIN not found" >&2; exit 1; }
EPOCH="${SOURCE_DATE_EPOCH:-$(git -c safe.directory="$(pwd)" log -1 --format=%ct 2>/dev/null || echo 0)}"

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

# the same modes whatever the umask, and one time stamp on everything
find "dist/$NAME" -type d -exec chmod 755 {} +
find "dist/$NAME" -type f -exec chmod u+rw,go+r,go-w {} +
STAMP=$(date -u -d "@$EPOCH" +%Y%m%d%H%M.%S 2>/dev/null || date -u -r "$EPOCH" +%Y%m%d%H%M.%S)
find "dist/$NAME" -exec env TZ=UTC touch -h -t "$STAMP" {} +
# every entry listed in byte order, nothing added by recursion
LIST=$(mktemp)
( cd dist && find "$NAME" -print | LC_ALL=C sort ) > "$LIST"
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar -C dist --no-recursion -T "$LIST" -cf - --format=ustar \
    --owner=root:0 --group=root:0 --mtime="@$EPOCH" | gzip -9n > "dist/$NAME.tar.gz"
else
  # bsdtar (macOS): no extended attributes, ACLs or AppleDouble files
  COPYFILE_DISABLE=1 tar -C dist -n -T "$LIST" -cf - --format=ustar \
    --uid 0 --gid 0 --uname root --gname root --no-xattrs --no-acls --no-mac-metadata |
    gzip -9n > "dist/$NAME.tar.gz"
fi
rm -f "$LIST"
rm -rf "dist/$NAME"
( cd dist && { sha256sum "$NAME.tar.gz" 2>/dev/null || shasum -a 256 "$NAME.tar.gz"; } > "$NAME.tar.gz.sha256" )
echo "dist/$NAME.tar.gz"
