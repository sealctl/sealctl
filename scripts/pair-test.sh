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
# HOME is the temporary folder, every XDG_* variable, SEALCTL_SSH_DIR and SSH_AUTH_SOCK are
# unset (for the pairing, the cleanup and the env file alike), and SEALCTL_NO_SERVICE=1 keeps
# launchd/systemd out of it. The cleanup stops a daemon only if its socket is inside the
# temporary folder.
set -eu

: "${SEALCTL_RELAY:?Set SEALCTL_RELAY to the relay origin to test against (for example the staging relay).}"

repo=$(cd "$(dirname "$0")/.." && pwd)
bin=${SEALCTL_BIN:-$repo/target/debug/sealctl}
if [ ! -x "$bin" ] || [ -z "${SEALCTL_BIN:-}" ]; then
    (cd "$repo" && cargo build -q -p sealctl)
fi
# an absolute path: the env file puts its folder on PATH and then changes directory
bin=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")

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
for v in \$(env | sed -n 's/^\\(XDG_[A-Za-z0-9_]*\\)=.*/\\1/p'); do unset "\$v"; done
unset SEALCTL_SSH_DIR SSH_AUTH_SOCK CLAUDE_CONFIG_DIR GEMINI_CLI_HOME
export SEALCTL_RELAY='$SEALCTL_RELAY'
export SEALCTL_NO_SERVICE=1
export SEALCTL_AGENT=0
export PATH='$(dirname "$bin")':"\$PATH"
cd '$home'
EOF

# Runs a command as the throwaway machine: HOME in the temporary folder and none of the
# caller's XDG folders, SSH agent or sealctl paths, so nothing can reach the real ones. The
# pairing and the cleanup both go through here.
isolated() (
    for v in $(env | sed -n 's/^\(XDG_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$v"; done
    unset SEALCTL_SSH_DIR SSH_AUTH_SOCK CLAUDE_CONFIG_DIR GEMINI_CLI_HOME
    HOME="$home" SEALCTL_NO_SERVICE=1 SEALCTL_AGENT=0
    export HOME SEALCTL_NO_SERVICE SEALCTL_AGENT
    exec "$@"
)

cleanup() {
    # stop only the throwaway daemon: its socket, as sealctl resolves it in the isolated
    # environment, must be inside the temporary folder
    # shellcheck disable=SC2016 # expanded by the isolated shell, not this one
    sock=$(isolated sh -c 'echo "${XDG_STATE_HOME:-$HOME/.local/state}/sealctl/daemon.sock"')
    case "$sock" in
    "$tmp"/*)
        if [ -S "$sock" ]; then
            isolated "$bin" daemon --stop >/dev/null 2>&1 || true
        fi
        ;;
    *) echo "not stopping a daemon at $sock: it is outside $tmp" >&2 ;;
    esac
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
isolated "$bin" pair --name "pairtest@$(hostname -s 2>/dev/null || echo box)"

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
