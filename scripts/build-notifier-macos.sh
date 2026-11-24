#!/bin/sh
# Build "sealctl Notifier.app", the helper that shows sealctl's desktop notifications on macOS
# under the name "sealctl" with its icon (SPEC 5.2). Needs swiftc (the Command Line Tools are
# enough), sips and iconutil.
#   scripts/build-notifier-macos.sh [arm64|x86_64] [out-dir]
# Produces <out-dir>/sealctl Notifier.app (default: dist/notifier-<arch>/), signed with
# $NOTIFIER_SIGN_IDENTITY: "-" (the default) is an ad-hoc signature, which needs no Apple
# certificate; a "Developer ID Application: …" identity gives a stable signature.
set -eu
ARCH="${1:-$(uname -m)}"
OUT="${2:-dist/notifier-$ARCH}"
IDENTITY="${NOTIFIER_SIGN_IDENTITY:--}"
case "$ARCH" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64) ;;
  *) echo "unknown architecture $ARCH" >&2; exit 2 ;;
esac
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
SRC=packaging/macos/notifier
APP="$OUT/sealctl Notifier.app"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -swift-version 5 -target "$ARCH-apple-macos11.0" \
  -o "$APP/Contents/MacOS/sealctl-notifier" "$SRC/main.swift"
sed "s/@VERSION@/$VERSION/g" "$SRC/Info.plist" > "$APP/Contents/Info.plist"
plutil -lint -s "$APP/Contents/Info.plist"

# the icon: every size of a macOS iconset, from the 1024 px desktop icon
SET=$(mktemp -d)/sealctl.iconset
mkdir -p "$SET"
for s in 16 32 128 256 512; do
  sips -z "$s" "$s" packaging/icons/sealctl-1024.png --out "$SET/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2))
  sips -z "$d" "$d" packaging/icons/sealctl-1024.png --out "$SET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$SET" -o "$APP/Contents/Resources/sealctl.icns"
rm -rf "$(dirname "$SET")"

codesign --force --sign "$IDENTITY" --identifier com.sealctl.notifier --timestamp=none "$APP"
codesign --verify --strict "$APP"
echo "$APP"
