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
- Long operations take turns on an object: `seal`, `unseal`, rewrap, the re-encryption job,
  `volume create`, `volume open`, `backup init` and `backup run` lock the volume or restic
  repository on the machine, and a second command on it exits 11 before asking the phone;
  `backup run` exits 11 when every backup that failed was busy, and never writes a snapshot
  into a repository that is being re-encrypted or handed back. `volume open` finds a volume
  another command just mounted, or waits a minute for its lock.
- The secret store has a write lock on the machine: a store move to new words waits up to a
  minute for writes under way, a write during the move is refused at once (exit 11), and a
  session that still holds the old key cannot write under it.
- The re-encryption job: a runner waits for an object another command holds (shown in
  `migrate --status`, ended by `--pause` or `--cancel`), reads the definition again under the
  lock, makes a left-over copy its key does not open again, keeps any repository a definition
  still names, and saves the new definition before the old repository goes; `--resume` beside
  a running job goes on with it, and no new job is written under a runner. A rewrap that stopped
  between adding the new restic key and removing the old one removes the old one.
- Resumable steps: `seal` saves the definition before the old way in (a LUKS slot, a restic
  key) is removed, and an `unseal` step lists its object in `handback.json` before it removes
  the definition, so a step resumed after a stop finishes from there.
- Clock changes: backups prune again (restic `forget --prune`, weekly) after the clock was set
  back; an `unseal` continuation the phone finds expired while this machine's clock says it is
  current asks the phone again, and the wait for an approval to start checks the wall clock
  every minute.
- `scan` reads a file again before rewriting it (a history that grew is masked as it is now,
  any other changed file is left, exit 13) and replaces zsh and fish histories under the
  shells' own locks.
- Ctrl-C of a command waiting for the phone withdraws its request; the commands that joined
  it ask for themselves.
- A pending open declined on the phone, or left without an answer, ends the commands that
  joined it too, instead of asking the phone again right after.
- A command queued behind another request prints `Waiting for your phone`, and an agent use
  granted for the session meanwhile is not asked for again.
- A request asked before the machine slept past its 5 minutes ends on waking (exit 5) instead
  of waiting up to 5 more minutes on a connection that may be dead.
- A delayed action that finished or expired leaves the daemon's pending list; one announced
  without its time stays listed until it can have taken effect.
- `sealctl cancel <id>` takes an id that starts with `-`.

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
