#!/bin/sh
# Pair a real phone with a throwaway sealctl "machine": a temporary HOME, never yours.
#
#   SEALCTL_RELAY=https://<relay origin> scripts/pair-test.sh
#
# It builds sealctl if needed, makes a temporary HOME under /tmp, runs `sealctl pair` there
# (QR code on a terminal, the link below it), and then waits. While it waits, open a second
# terminal, load the printed env file, and send requests to the phone (see the list it prints).
# Press Enter in this terminal to stop the daemon and delete the temporary HOME.
#
# Nothing here touches your own HOME, keychain, login services, ~/.ssh or git config:
# HOME, XDG folders and SSH are all inside the temporary folder, and SEALCTL_NO_SERVICE=1
# keeps launchd/systemd out of it.
set -eu

: "${SEALCTL_RELAY:?Set SEALCTL_RELAY to the relay origin to test against (for example the staging relay).}"

repo=$(cd "$(dirname "$0")/.." && pwd)
bin=${SEALCTL_BIN:-$repo/target/debug/sealctl}
if [ ! -x "$bin" ] || [ -z "${SEALCTL_BIN:-}" ]; then
    (cd "$repo" && cargo build -q -p sealctl)
fi

tmp=$(mktemp -d /tmp/sealctl-pairtest.XXXXXX)
home="$tmp/home"
mkdir -p "$home"
chmod 700 "$tmp" "$home"
case "$home" in
"$HOME"/*) echo "refusing: the temporary HOME is inside your HOME" >&2; exit 2 ;;
esac

envfile="$tmp/env.sh"
cat >"$envfile" <<EOF
# sealctl pair test: source this in another terminal (sh, bash, zsh)
export HOME='$home'
unset XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME SEALCTL_SSH_DIR SSH_AUTH_SOCK
export SEALCTL_RELAY='$SEALCTL_RELAY'
export SEALCTL_NO_SERVICE=1
export SEALCTL_AGENT=0
export PATH='$(dirname "$bin")':"\$PATH"
cd '$home'
EOF

cleanup() {
    HOME="$home" SEALCTL_NO_SERVICE=1 "$bin" daemon --stop >/dev/null 2>&1 || true
    # sparse bundles made while testing may still be attached
    if command -v hdiutil >/dev/null 2>&1; then
        for m in "$home"/mnt/*; do [ -d "$m" ] && hdiutil detach -quiet "$m" 2>/dev/null || true; done
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "Temporary HOME: $home"
echo
env -u XDG_CONFIG_HOME -u XDG_DATA_HOME -u XDG_STATE_HOME -u SEALCTL_SSH_DIR \
    HOME="$home" SEALCTL_NO_SERVICE=1 SEALCTL_AGENT=0 \
    "$bin" pair --name "pairtest@$(hostname -s 2>/dev/null || echo box)"

cat <<EOF

Paired. In another terminal:

    . $envfile

Then each request kind, as the phone should see it:

  open (level 1, One tap): the session opens; store key and keys of auto volumes/backups
    sealctl open
    printf 'a-test-value' | sealctl secret set test/one        # also opens when Locked
    sealctl lock                                               # back to Locked

  keys (level 1): a new object while Open
    printf 'own-value' | sealctl secret set test/own --own-approval
    sealctl volume create t1 --kind sparsebundle --size 64m --path ~/t1.sparsebundle --mountpoint ~/mnt/t1

  own (level 1, every use): an own-approval secret
    sealctl secret get test/own | wc -c

  agent (level 1): an AI agent's first use of a secret in this folder, while Open
    SEALCTL_AGENT=1 sealctl run -e K=test/one -- sh -c 'echo \$K'

  keys at level 2 with the number (seal of something you have): pick the number shown
    printf 'own-pass' | hdiutil create -quiet -size 32m -type SPARSEBUNDLE -fs APFS \\
        -encryption AES-256 -stdinpass -volname mine ~/mine.sparsebundle
    sealctl seal volume mine ~/mine.sparsebundle --mountpoint ~/mnt/mine   # passphrase: own-pass

  unseal (level 2): one object back, number match if the phone cannot tell it is near
    sealctl unseal secret test/one

  unseal --all (level 3): number match, plan signature, delay away from a trusted place,
  then the hand-back report and the unpairing
    sealctl unseal --all
    sealctl status                 # in a third terminal: the Pending line while delayed
    sealctl cancel                 # cancels a delayed approval from this machine

  machine channel: lock on the phone, then
    sealctl status                 # "Locked from your phone"

  licence
    sealctl status --json          # "licence": "unpaid"
    sealctl buy --seats 2          # staging: exit 6, payments not configured

Press Enter here to stop the daemon and delete $tmp.
EOF
read -r _
