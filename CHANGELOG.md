# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- Agent hooks no longer deny harmless commands: text in a here-document fed to a program that
  is not a shell (a quoted `python3 - <<'EOF'`, notes written with `cat > file <<'EOF'`) is no
  longer read as commands, and `echo $SSH_AUTH_SOCK` and other variables ending in `_SOCK`,
  `_PID`, `_DIR`, `_PATH` or `_FILE` may be printed. Here-documents fed to a shell, and
  substitutions in unquoted ones, are still checked.

- Output names the 4-character fingerprint of your 24 words as the seed: `seed 6qdC` instead of
  `words 6qdC` (`volume ls`, `status`, `seal`, `migrate`, `recover` and error messages). JSON
  keys, flags and stored files are unchanged.
- `sealctl seal volume` and `sealctl recover` take an APFS volume by the name Finder and Disk
  Utility show, as well as by UUID or disk identifier. When several volumes share the name, the
  error lists their disk identifiers to choose from.

## 0.7.0 - 2026-11-24

Keys for developers and their AI agents: API keys, SSH and git signing keys, encrypted volumes
and backups, opened only when your phone approves. Every key is derived from 24 words held by
the sealctl phone app, and the 24 words alone open every object.

### Added

- `sealctl-core`: the protocol and crypto shared with the phone apps (HKDF derivation from the
  24 words, `.sealed` and `.id` files, pairing, HPKE-sealed requests and signed replies, plan
  signatures), with test vectors in `docs/vectors/` and UniFFI bindings for Swift and Kotlin.
- `sealctl pair` (QR code on a terminal, a link without one) and `unpair`; a relay client with
  signed calls and WebSocket waits; `SEALCTL_RELAY` / `--relay`, recorded at pairing.
- The session daemon: Locked / Open / Waiting, an idle allowance and hard stop set by the
  phone, per-agent allowances and remembered answers, own-approval secrets, on-lock backups,
  status to the phone and locks from it, and an SSH agent on store keys. `SEALCTL_NO_DAEMON=1`
  for CI runners.
- The secret store on `.sealed` files (`secret set/get/ls/rm/mv/store`, `--own-approval`);
  `sealctl run` with `.sealctl.toml` mappings and `[command."<words>"]` sections, masking values
  in output.
- Project files trusted on first use: `sealctl run` asks before it first uses a `.sealctl.toml`,
  and again after it changes, listing the secret names it maps; without a terminal it refuses
  until `sealctl project trust`. Files written by `seal env` and `scan` are trusted; agents never
  trust one.
- `sealctl ai install` for Claude Code, Codex, Gemini CLI, Qwen Code, Copilot CLI and Cursor:
  skill, hooks and deny rules, so agents use secrets by name and never see values.
- `sealctl ssh keygen`, `ssh setup`, `git setup` (SSH commit signing), `git credentials <host>`
  and the git credential helper; `sealctl aws credentials` for `credential_process`.
- Encrypted volumes (APFS, sparse bundles, LUKS2) that mount when the session opens and close
  when it locks; restic backups with stored storage credentials, on lock and on a schedule.
- `sealctl scan`: keys in `.env` files, shell rc files, shell histories and `~/.aws/credentials`
  moved into the store, references left behind.
- `sealctl migrate`: every object rewrapped to new words (also started by the daemon when the
  phone moves to new words), `old_words` for retired words, re-encryption of sparse bundles and
  restic repositories, `--scan`.
- `sealctl seal volume|backup|ssh|secret|env` and `seal --from <hand-back list>` to take over
  what you already have.
- `sealctl unseal <object>` and `unseal --all`: everything handed back in plain, standard form
  into `~/sealctl-unsealed-<date>` (or the Keychain, 1Password or Bitwarden with `--to` and
  `--secrets-to`), with a plan, number match, plan signature, a two-hour delay away from a
  trusted place, a hand-back report, `--resume`, and `sealctl cancel` from any paired machine.
- `sealctl recover <store | .sealed | sparse bundle | LUKS file | APFS volume | restic
  repository>` with the 24 words alone: no phone, relay or configuration.
- `sealctl status` (with `--json`), `doctor`, `inventory`, `rules`; `sealctl buy` (`--seats`,
  `--code`).
- Packages: Homebrew, `.deb`, `.rpm`, Arch `PKGBUILD`, Nix.
- `crates/sealctl-fakerelay` (test only), fuzz targets and `scripts/pair-test.sh` for tests
  with a real phone.
- `THIRD-PARTY-NOTICES.md`: the licence texts of every crate in the binary, generated with
  cargo-about (`scripts/notices.sh`) and shipped in every tarball, .deb, .rpm, PKGBUILD,
  Homebrew and Nix package.

### Changed

- `sealctl run` also masks values printed as hex, in lower or upper case, alongside the raw,
  base64, base64url and URL-encoded forms.
- A leak test stores a canary and checks that none of those forms reaches the output of
  `sealctl run`, `daemon.log`, or any file in the config, state and data folders.
- protocol.md, Delayed approvals (planned), matches the relay: a cancel keeps the record until
  `releaseAt` + 2,400 s (900 s when not cancelled), and cancelled records do not count toward
  the 4 per phone but do toward 16 in all. The fake relay keeps cancelled records as long.
- `SEALCTL_AGENT=0` (agent detection off) is documented, and when an agent's own variable is
  also set, sealctl says on stderr, once per command, that detection is off although that agent
  is running.

### Fixed

- A sparse bundle listed by `hdiutil info` without its devices (as macOS lists an image while
  it or another one attaches or detaches) is no longer read as not attached: sealctl reads
  the list again, for a second at most. Before, a lock could pass over a mounted volume or
  report it closed while it stayed mounted, and an open could detach the volume it had just
  mounted (`image attached but not mounted`).
- `hdiutil` failures name their reason: sealctl no longer runs `hdiutil create`, `attach` or
  `detach` with `-quiet`, which closes hdiutil's output and left errors as an empty
  `hdiutil create failed:`. A create refused as `Resource busy` that left nothing behind is
  tried again, three times in all, a second apart.
- `sealctl lock` no longer passes over a volume whose state it cannot read (`hdiutil info`
  failing) as closed, which printed `Locked.` and exited 0 with the volume still mounted: it
  tries to close it, and if that fails too reports it busy (exit 11) and retries every minute.
- A `lock` from the phone applies even when its message `seq` is below the highest the
  machine has seen: each install of the app numbers its messages by its own clock, so a lock
  from an install whose clock is behind another's was ignored. Other messages keep the `seq`
  rule, and the highest `seq` seen never goes down.
