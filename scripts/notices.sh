#!/bin/sh
# Write THIRD-PARTY-NOTICES.md: the licences of every crate in the sealctl binary, for the
# release targets in about.toml. Needs cargo-about 0.9.3 (the release binary from
# github.com/EmbarkStudios/cargo-about, x86_64-unknown-linux-musl SHA-256
# 3ad1e94ea1e63d69d1961f4fb15ccbbe9575d906111f96d2cb4dce6df48f71b4).
#   scripts/notices.sh            regenerate the file
#   scripts/notices.sh --check    fail if the committed file is out of date
set -eu
cd "$(dirname "$0")/.."
cargo fetch --locked >/dev/null
OUT=THIRD-PARTY-NOTICES.md
[ "${1:-}" = --check ] && OUT="${TMPDIR:-/tmp}/sealctl-notices.$$.md"
cargo about generate --locked --offline --fail \
  -c about.toml -m crates/sealctl/Cargo.toml -o "$OUT" scripts/notices.hbs
if [ "${1:-}" = --check ]; then
  if ! diff -u THIRD-PARTY-NOTICES.md "$OUT"; then
    rm -f "$OUT"
    echo "THIRD-PARTY-NOTICES.md is out of date: run scripts/notices.sh and commit it" >&2
    exit 1
  fi
  rm -f "$OUT"
fi
