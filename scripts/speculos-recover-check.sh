#!/usr/bin/env bash
# Prove that `sealctl recover` computes the same decryption key as the Ledger OpenPGP app.
#
# Runs the app in Speculos (Ledger's emulator, public test seed), lets it generate a
# seed-derived cv25519 decryption key exactly as `sealctl setup` does, and compares the public
# key with the one sealctl derives in software from the same 24 words.
#
#   scripts/speculos-recover-check.sh <path/to/app.elf> [model]     (model: flex, stax, nanox…)
set -euo pipefail

ELF=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
MODEL=${2:-flex}
NAME=speculos-sealctl-check
PORT=${SPECULOS_PORT:-5001}
# Speculos' default seed (public, test only)
WORDS="glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -v "$(dirname "$ELF"):/app" -p "$PORT:5000" \
  ghcr.io/ledgerhq/speculos:latest --model "$MODEL" --display headless --api-port 5000 \
  "/app/$(basename "$ELF")" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

for _ in $(seq 60); do
  curl -sf "http://127.0.0.1:$PORT/events" >/dev/null 2>&1 && break
  sleep 1
done

apdu() { # hex in → hex out (data + status word)
  curl -sf -X POST "http://127.0.0.1:$PORT/apdu" -H 'Content-Type: application/json' \
    -d "{\"data\":\"$1\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"])'
}
expect_ok() { # $1 name, $2 response
  [[ "${2: -4}" == "9000" ]] || { echo "❌ $1 failed: $2" >&2; exit 1; }
}

expect_ok "SELECT OpenPGP" "$(apdu 00a4040006d27600012401)"
expect_ok "VERIFY admin PIN" "$(apdu 00200083083132333435363738)"
# decryption key: ECDH over cv25519 (what sealctl setup sets)
expect_ok "PUT DATA C2" "$(apdu 00da00c20b122b060104019755010501)"
GEN=$(apdu 0047800002b80000)
expect_ok "GENERATE" "$GEN"
# 7F49 <len> 86 <len> <point>
PUB=$(python3 - "$GEN" <<'EOF'
import sys
r = bytes.fromhex(sys.argv[1])[:-2]
i = r.index(b"\x86")
n = r[i + 1]
p = r[i + 2:i + 2 + n]
if len(p) == 33 and p[0] == 0x40:
    p = p[1:]
print(p.hex())
EOF
)
echo "device decryption public key:   $PUB"

SEALCTL_TEST_PHRASE="$WORDS" SEALCTL_EXPECT_DEC_PUB="$PUB" \
  cargo test -q -p sealctl --lib recover::tests::matches_device -- --exact --nocapture
echo "✅ software recovery reproduces the device key"
