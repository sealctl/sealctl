#!/bin/sh
# Build the sealctl release binary for one target, reproducibly (SPEC 21): the same commit,
# toolchain (rust-toolchain.toml) and Cargo.lock give the same bytes in any folder, as any
# user. Paths of the build machine (the checkout, the target folder, CARGO_HOME) are mapped to
# fixed ones, so the source file names in panic messages do not depend on where it was built.
#   scripts/build-release.sh [<target-triple>]
# Produces target/[<target>/]release/sealctl (or under CARGO_TARGET_DIR).
set -eu
cd "$(dirname "$0")/.."
TARGET="${1:-}"
SRC=$(pwd -P)
mkdir -p "${CARGO_HOME:-$HOME/.cargo}"
CARGO_DIR=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)
# Arguments are separated by 0x1f (CARGO_ENCODED_RUSTFLAGS), so a path may hold spaces.
US=$(printf '\037')
FLAGS="--remap-path-prefix=$SRC=/build/sealctl$US--remap-path-prefix=$CARGO_DIR=/build/cargo"
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  mkdir -p "$CARGO_TARGET_DIR"
  FLAGS="$FLAGS$US--remap-path-prefix=$(cd "$CARGO_TARGET_DIR" && pwd -P)=/build/target"
fi
# macOS: ld hashes the linked file into its LC_UUID before the release profile strips it, and
# the debug map in it names the object files by their path in the target folder; leaving the
# debug map out at link time (-S) keeps that path out of the UUID
case "${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}" in
  *-apple-darwin) FLAGS="$FLAGS$US-Clink-arg=-Wl,-S" ;;
esac
# extra flags from RUSTFLAGS (split on whitespace, as cargo does) go first
for f in ${RUSTFLAGS:-}; do FLAGS="$f$US$FLAGS"; done
unset RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="$FLAGS"
if [ -n "$TARGET" ]; then
  cargo build --release --locked -p sealctl --target "$TARGET"
else
  cargo build --release --locked -p sealctl
fi
