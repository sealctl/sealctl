#!/bin/sh
# Manual end-to-end check with a real Ledger (OpenPGP app open on the device).
# Creates only throwaway items named "smoketest" and removes them at the end.
# Usage: scripts/hardware-smoke-test.sh [-t usb|ble]
set -eu
S="${SEALCTL:-sealctl} $*"
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

step "1/6 doctor: certificate ↔ card, decryption, reproducible derived keys (PIN on the device)"
SEALCTL_NO_AGENT=1 $S doctor --full

step "2/6 secrets + run (agent starts; PIN at most once)"
printf 'it-works' | $S secret set smoketest/demo --force
$S run -e DEMO=smoketest/demo -- sh -c 'test "$DEMO" = it-works && echo "run: secret injected ✅"'
$S secret rm smoketest/demo

step "3/6 volume: create → lock → unlock with the seed-derived key → lock"
$S volume create smoketest --kind sparsebundle --size 200m
echo hello > "/Volumes/smoketest/hello.txt" 2>/dev/null || true
$S lock smoketest
$S unlock smoketest
$S lock smoketest
$S volume rm smoketest --delete-data <<EOF
y
EOF

step "4/6 agent session"
$S agent status
$S agent stop

step "5/6 SSH agent: encrypted key file unlocked by the Ledger"
TMPD=$(mktemp -d); SOCK="$TMPD/agent.sock"; KEY="$TMPD/sealctl_smoketest"; AGENT=
trap 'if [ -n "$AGENT" ]; then kill "$AGENT" 2>/dev/null || true; fi; rm -rf "$TMPD"' EXIT
SEALCTL_SSH_DIR="$TMPD" $S ssh keygen smoketest
SEALCTL_SSH_DIR="$TMPD" $S ssh agent --socket "$SOCK" & AGENT=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S "$SOCK" ] && break; sleep 0.5; done
echo "signed with a Ledger-unlocked key" > "$TMPD/msg"
printf '%s %s\n' "smoke@test" "$(cat "$KEY.pub")" > "$TMPD/allowed"
SSH_AUTH_SOCK="$SOCK" ssh-keygen -Y sign -f "$KEY.pub" -n smoketest "$TMPD/msg" >/dev/null
ssh-keygen -Y verify -f "$TMPD/allowed" -I smoke@test -n smoketest -s "$TMPD/msg.sig" < "$TMPD/msg"
rm -f "$TMPD/msg.sig"
SSH_AUTH_SOCK="$SOCK" ssh-keygen -Y sign -f "$KEY.pub" -n smoketest "$TMPD/msg" >/dev/null
ssh-keygen -Y verify -f "$TMPD/allowed" -I smoke@test -n smoketest -s "$TMPD/msg.sig" < "$TMPD/msg"
echo "second signature from the agent's cache (no device needed) ✅"
kill "$AGENT"; wait "$AGENT" 2>/dev/null || true; AGENT=
rm -rf "$TMPD"; trap - EXIT

step "6/6 status"
$S status
printf '\n✅ hardware smoke test passed\n'
