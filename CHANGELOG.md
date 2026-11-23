# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `THIRD-PARTY-NOTICES.md`: the licence texts of every crate in the binary, generated with
  cargo-about (`scripts/notices.sh`) and shipped in every tarball, .deb, .rpm, PKGBUILD,
  Homebrew and Nix package.

### Fixed

- Session daemon timing: locks take turns and run their backups and unmounts in the
  background (the hard stop no longer clears a session approved during them, and nothing is
  unmounted under a running backup); the idle allowance and hard stop are checked before an
  input sample counts as work and before any key is handed out (time asleep counts as idle);
  a clock set back locks; the hard stop takes the second 02:00 on the night clocks go back;
  a wait for the phone no longer holds up lock messages and statuses; the phone hears of an
  Open session before the next request; lock messages allow a minute of clock skew; busy
  volumes are retried every minute; on-lock backups stop at 15 minutes; SIGTERM locks.
- Daemon exit: once it begins, no session opens and on-lock backups still running stop
  (restic gets SIGINT first, so it removes its repository lock), so the unmount and the last
  status fit the service's stop timeout, now 60 seconds (launchd `ExitTimeOut`, systemd
  `TimeoutStopSec` with `KillMode=mixed`) for services installed from this version on. A hung mount no longer holds up locks for more than 2 minutes, or an exit at all.
- Key requests check the timers again after waiting; a `sealctl lock` or lock message while
  the phone is asked to open leaves that approval with its command only; statuses while
  Locked carry the busy volumes and are sent again after a failure, also after a restart.

## 0.7.0

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
- `sealctl recover <store | .sealed | sparse bundle | restic repository>` with the 24 words
  alone: no phone, relay or configuration.
- `sealctl status` (with `--json`), `doctor`, `inventory`, `rules`; `sealctl buy` (`--seats`,
  `--code`).
- Packages: Homebrew, `.deb`, `.rpm`, Arch `PKGBUILD`, Nix.
- `crates/sealctl-fakerelay` (test only), fuzz targets and `scripts/pair-test.sh` for tests
  with a real phone.
