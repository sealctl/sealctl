# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `sealctl buy` while card payments are not open on the relay: `1  I'd buy it` records that you
  would buy (nothing is charged) so sealctl can tell you when you can, and `2  Give feedback`
  asks four short questions and gives a year's licence, once per phone. The answers are sent
  with the phone's id; no name or email. With payments open, the usual menu adds
  `4  Give feedback instead` until this phone has given feedback. Wrong answers in the menus
  are asked again instead of ending the command, and the menus are refused in CI as well as in
  pipes and AI agents.
- `sealctl status` shows `Licensed until 2027-11-26 (feedback)` while a feedback licence lasts,
  and `--json` has `"licence": "feedback"` with `"until"`. When it ends, sealctl counts the
  phone as unpaid at once instead of waiting for the hour-long licence cache. In its last 30
  days, one line after a command you typed says when it ends.
- Protocol: `POST /v1/phones/{phone}/intent` and `POST /v1/phones/{phone}/feedback`, and the
  licence answer's `kind`, `until`, `feedback`, `intent` and `payments` (docs/protocol.md,
  planned on the relay). Deleting a phone's relay data deletes its feedback answers and
  intent; the feedback licence record (granted, and its end) stays, as a paid one does.

### Changed

- The session's hard stop is now 02:00 local time or 24 hours after the first `open` granted
  today, whichever comes first (it was 14 hours). A session first opened in the morning stays
  Open until 02:00 that night while you keep working; one opened at 03:00 runs until 02:00 the
  next night. The idle allowance, the nights when the clocks change and a clock set back work
  as before.

### Fixed

- Agent hooks no longer deny writing a script with a quoted here-document
  (`cat > voices.mjs <<'EOF'` … `EOF`, `tee`) because it reads a variable
  (`process.env.ELEVENLABS_API_KEY`), prints the environment or mentions a `.env` file. A quoted
  body is data only when `cat` or `tee` writes it to a file and nothing else on the command line
  uses it. A body fed to any other program (a shell, `node -`, `python3 -`, `awk -f -`,
  `make -f -`, `psql`, an unknown program), piped on, or written to a file that the same line
  then runs or reads is still checked. Code that opens a `.env` or credentials file by a quoted
  path in `python3 -c`, `node -e` or a body that runs (`open('.env')`) is now denied. `.env` is
  matched as a file path, not inside `process.env`. `printenv`, `env` and `export` count as
  environment dumps when they run as commands, including on a line of their own in a body a
  shell reads, but not as a line of a commit message.
- A reference to a secret kept elsewhere (`process.env.ELEVENLABS_API_KEY` or
  `settings.stripe.secret_key` assigned to a key-like name, `os.getenv("API_KEY")`) is no
  longer taken for a key-like literal in written files, commands or prompts. Quoted values and
  dotted tokens still are.

## 0.7.1 - 2026-11-25

### Added

- macOS: desktop notifications come from `sealctl Notifier.app` (in the release tarball,
  installed by Homebrew into `libexec`) under the name sealctl with its icon, instead of Script
  Editor; macOS asks once whether sealctl may notify. Linux: notifications go over D-Bus with
  the sealctl icon and desktop entry, which the packages now install.
- `notifications = false` in `config.toml` turns desktop notifications off.
- Where git signs through sealctl, the agent hooks deny turning commit or tag signing off or
  pointing it at another program or key: `git -c commit.gpgsign=false`, `--no-gpg-sign`,
  `git config commit.gpgsign false` or `--unset` (any scope or file), `gpg.format`,
  `gpg.ssh.program` and `user.signingkey`, the same through `GIT_CONFIG_KEY_<n>`, and
  `sealctl git setup --undo`, also through `env`, `sudo`, `sh -c`, `eval` and `$(…)`. The
  request on the phone is your approval; only you change it. Reading config, `git commit -S`
  and `git tag -s` are fine, and nothing changes where git does not sign through sealctl.

### Changed

- Desktop notifications say what waits for your phone: "Approve on your phone" with the request
  in the phone's words (`Sign a git commit · sealctl/app · Claude Code`, `SSH login to
  github.com`, `Open volume safe`, `Back up safe`, `Use 2 secrets for npm test`), names only. The
  answer replaces it: `Signed` or `Approved`, `Declined`, `Expired: nothing was signed`.
- Level 3 notices are titled sealctl and no longer start with `sealctl:`.
- protocol.md, Delayed approvals: a level 3 action on the phone (showing the words, deleting
  the relay data, leaving) can be finished up to an hour after its delay ends, instead of 15
  minutes: the relay keeps a record with no machine until `releaseAt` + 3,600 s, and a cancel
  never shortens it. A machine's delayed reply is still kept 900 s (2,400 s once cancelled).
  The fake relay does the same.
- The AI agent skill and session line say that signed git commits, `git push` over SSH and `ssh`
  wait silently for approval on the phone, and what `agent refused operation` means, so agents
  no longer look for a prompt on the computer or fall back to unsigned commits. They also commit
  whenever they normally would: the request on the phone is the approval, so they do not ask
  you for a go-ahead first.
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

### Fixed

- The phone's countdown for an Open session follows your work: the daemon sends a status when
  activity moves the lock 2 minutes later (or anything moves it 1 minute earlier), at most once
  every 2 minutes, instead of up to 15 minutes later.
- Requests that nobody sees waiting (the SSH agent and git signing, the git and AWS credential
  helpers, the backup schedule) always show a desktop notification, also when an AI agent made
  them. Before, a daemon started from an agent's shell showed none, so a signed `git commit` run
  by an agent waited silently.
- `sealctl lock` (and `volume close`) right after a backup or a write could leave a volume
  mounted and exit 11 with `Volume <name> is busy: hdiutil detach ... Resource busy`, when a
  macOS service still held the volume for a few seconds. An unmount refused while none of your
  processes has files open on the volume is now tried again for up to 10 seconds; a volume one
  of your processes holds is still reported busy at once, with the process.

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
