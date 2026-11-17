# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.0] - 2026-11-17

### Changed

- **Breaking:** the SSH agent no longer offers the Ledger's OpenPGP authentication key. Signing
  every login on the device made SSH depend on the Ledger being awake and unlocked. The agent
  now serves only encrypted key files (`~/.ssh/sealctl_<name>`), unlocked once per session by a
  passphrase derived on the Ledger. To migrate: `sealctl ssh keygen`, then put
  `~/.ssh/sealctl_ed25519.pub` on your servers (`ssh-copy-id -i ~/.ssh/sealctl_ed25519.pub host`)
  and GitHub, and remove the old `sealctl ledger …` key there.
- **Breaking:** `sealctl git setup` signs with the key file `~/.ssh/sealctl_ed25519` by default
  (`--key NAME` for another one) and fails if it doesn't exist. Re-run `sealctl git setup`;
  add the new public key to GitHub as a signing key.
- `sealctl ssh pubkey [NAME]` prints a key file's public key (default `ed25519`).
- `sealctl ssh install` suggests `sealctl ssh keygen` when there is no key file yet.

## [0.4.0] - 2026-11-17

### Added

- `sealctl ai install | uninstall | status`: integration with AI coding agents — Claude Code,
  Codex, Gemini CLI, Qwen Code, GitHub Copilot CLI, Cursor (skill + hooks + deny rules where
  supported), and the `sealctl-secrets` skill for OpenCode, Amp, Goose, Antigravity and Kiro.
  Hooks block prompts containing API keys, deny commands / file reads / writes that would
  reveal secrets, and add session context. See docs/ai-agents.md.
- `sealctl run` masks secret values (`****`) in the program's output inside AI agents and
  whenever output isn't a terminal.
- `sealctl secret set --from-clipboard` (reads and clears the clipboard).

- SSH keys unlocked in the agent now live as long as the sealctl session: signing counts as
  activity, and they are forgotten when the session ends (idle, 24 h, `sealctl lock`).

### Security (from an internal audit)

- **Device identity:** every new connection derives a check value and compares it with the one
  recorded from your Ledger (`~/.config/sealctl/device-check-*`, written on first use). A
  device that only looks like a Ledger (e.g. a Bluetooth impostor echoing requests) could
  otherwise have made derived keys computable.
- Blinding clears the small-order component of the request (`8·s·u`), so requests no longer
  leak the torsion class of the id; device replies must be torsion-free points (forged
  small-order replies are rejected). Derived keys are unchanged.
- Session timers count system sleep (a closed laptop no longer keeps keys past "1 h idle").
- A malformed device reply can no longer crash or permanently disable the agents; wrong PIN /
  "reject" on the device is not retried; the framing decoder can't underflow.
- `sealctl lock` forgets SSH keys and stops the agent even if a volume refuses to lock, locks
  the remaining volumes, and the auto-started agent no longer keeps a volume busy.
- `backup restore` only restores the requested volume's snapshots (restic ORs repeated
  `--tag`); `backup init` keeps working credentials until the new repository checks out.
- `secret import-env`: a real dotenv parser (multi-line quoted values such as PEM keys,
  escapes, comments); refuses unreadable files and existing secret names (`--force`); with
  `--delete` the file is removed only after every value read back identically.
- `sealctl run` masks base64 and URL-encoded forms and overlapping values; `SEALCTL_NO_MASK`
  is ignored inside AI agents; it now prints which secrets it gives the program.
- AI hooks: many more leaking commands and credential files are denied (`printenv VAR`,
  `export`, environment dumps, `gh auth token`, `~/.aws/credentials`, `.npmrc`, `grep -r` over a
  `.env`, …); Codex argv commands, MultiEdit and Grep are checked.
- Settings files edited by `ai install` keep symlinks and permissions (new files 0600).
- `git setup`: commit signing works — `gpg.ssh.program` now points to a small wrapper script
  (git can't run a program with arguments there; every signed commit failed). Re-run
  `sealctl git setup` once.
- LUKS (Linux): a failed mount closes the decrypted device; "unlocked" includes an open
  mapper; mount detection handles symlinked homes and spaces.
- Unlock keeps the configured volume id unless the disk's id actually unlocks the volume;
  systemd units are quoted correctly; hooks never use a relative `sealctl` from PATH;
  custom SSH agent sockets must be in a private folder; more secret copies are zeroized.

### Changed

- `secret get`, `secret get --clip` and `ssh passphrase` refuse to run inside AI agents, and
  don't print to a terminal without `--show` (copy with `--clip`, cleared after 30 s).
- Services (SSH agent, backup schedule), git signing and hooks use the stable
  `/opt/homebrew/bin/sealctl` path, so they keep working after `brew upgrade`.

## [0.3.0] - 2026-11-17

### Added

- Encrypted SSH key files: `sealctl ssh keygen` makes a random Ed25519 key in standard OpenSSH
  format, encrypted with a passphrase derived on the Ledger from the key's own fingerprint
  (purpose `ssh`). The SSH agent unlocks it on first use and keeps it for the session (1 h idle,
  24 h max), so signatures don't need the device each time; `ssh-add -D` / `sealctl lock` forget
  it. `sealctl ssh pubkey <name>`, `sealctl ssh passphrase <name>`,
  `sealctl git setup --key <name>`, `sealctl git setup --undo`.

- `sealctl recover`: disaster recovery without a Ledger. Recomputes the OpenPGP app's
  seed-derived decryption key from the 24 words in software (BIP39 → BIP32 secp256k1
  `m/0x80475047'/(slot+1)'` → app "v2" key derivation), verifies it against the certificate,
  and serves it through the agent so unlock / restore / secrets work. Checked against the real
  app in Speculos (`scripts/speculos-recover-check.sh`).
- Backup repositories derive their password from a **key id** (default: the volume name)
  instead of the repository URL, so a repository can move and is recovered with only the seed
  and the name. `sealctl backup init --key-id`, and `sealctl backup rekey <volume>` to move a
  0.2.0 repository (restic key add/remove; data unchanged).
- When the Ledger is needed, sealctl (including the SSH agent and git signing) says what to do
  — unlock, open OpenPGP, enter the PIN — on stderr and as a desktop notification, and waits up
  to `SEALCTL_WAIT` seconds (default 90) instead of failing.

### Fixed

- macOS: `diskutil`, `hdiutil` and `launchctl` (and `cryptsetup`/`systemctl` on Linux) are found
  in `/usr/sbin`, `/sbin`, … even when those are not on `PATH`. Previously `volume ls` showed a
  mounted volume as locked, and unlock/lock failed, in shells without `/usr/sbin`.
- `volume ls` shows ❓ with the error instead of 🔒 when the state cannot be determined.
- `backup init` no longer prints restic's "repository does not exist" while probing, and
  explains a permission error on a root-owned APFS volume (`sudo chown "$USER" <mountpoint>`).
- SSH agent: no more log noise for OpenSSH's optional extension requests.

## [0.2.0] - 2026-11-17

Breaking: volumes, backups and secrets now use keys derived from the Ledger seed; there are no
key files anymore. Volumes from 0.1.0 convert with `sealctl volume rekey <name>`; secrets from
0.1.0 must be re-added (`sealctl secret set`).

### Added
- Seed-derived keys (docs/derived-keys.md): volume passphrase from seed + volume UUID, restic
  password from seed + repository URL, secret-store key from seed. Only the 24 words are needed
  to recover everything. Pinned test vectors.
- Blinded key derivation (RFC 9497-style): the device and the USB/Bluetooth link only see
  random-looking points; results are identical to unblinded derivation.
- `sealctl agent`: session cache after one PIN entry; exits after 1 h idle and at most 24 h;
  `agent status|stop`; `sealctl lock` (all) stops it; one thread per client.
- `volume import` (register a disk on a new machine), `volume rekey` (convert 0.1.0 volumes).
- macOS default volume kind is now `apfs-volume` (native volume on the internal disk).

### Removed
- Per-volume `.key.asc` and `.backup.asc` escrow files; `backup init --existing`.
- `pass`/`.gpg-id` compatibility of the secret store (now password-encrypted OpenPGP messages).

## [0.1.0] - 2026-11-17

### Added
- Ledger USB-HID and Bluetooth LE transports implementing the `openpgp-card` `CardBackend`
  (on-device PIN entry via the OpenPGP app's PIN-pad mode).
- `sealctl devices` and `sealctl status` (verified on Ledger Flex over Bluetooth).
- `sealctl setup`: Curve25519, seed-derived keys (verified by regenerating), fixed creation time
  (2026-01-01T00:00:00Z) so fingerprints are reproducible, certificate self-signed on the card.

- `encrypt` / `decrypt` (standard OpenPGP, multiple recipients).
- `pin user|admin`, `doctor [--full]`, `kit export|import` (recovery kit with instructions).
- Volumes: `volume create|ls|rm`, `unlock`, `lock` — macOS sparse bundles and APFS volumes,
  Linux LUKS2; passphrase escrowed (OpenPGP) before the volume is created.
- Backups with restic: `backup init|run|snapshots|restore|check|policy|schedule`; credentials
  live inside the unlocked volume, backup before lock, launchd/systemd schedules.
- Secrets: pass-compatible store, `secret set|get|ls|rm|import-env`, `run` with `.sealctl.toml`,
  clipboard copy with auto-clear.
- SSH agent (`ssh agent|install|pubkey`) and git commit signing (`git setup`).
- `status` overview and shell `completions`.
- Integration tests driving hdiutil/diskutil, cryptsetup and restic with a software key.

- Opens the OpenPGP app automatically when the Ledger is on its dashboard.
- Verified on a Ledger Flex over Bluetooth: decryption, secrets/run, volume unlock, SSH
  signatures (`scripts/hardware-smoke-test.sh`).

- Packages: Homebrew tap formula, .deb and .rpm (x86_64/aarch64, glibc 2.34+), Arch PKGBUILD,
  Nix flake, tarballs; all install-tested on CI on every commit.

### Changed
- Minimum supported Rust version is 1.89 (required by dependencies).
- `sealctl status` is now the local overview; card details moved to `sealctl card`.

[Unreleased]: https://github.com/oleksiyp/sealctl/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/oleksiyp/sealctl/releases/tag/v0.5.0
[0.4.0]: https://github.com/oleksiyp/sealctl/releases/tag/v0.4.0
[0.3.0]: https://github.com/oleksiyp/sealctl/releases/tag/v0.3.0
[0.2.0]: https://github.com/oleksiyp/sealctl/releases/tag/v0.2.0
[0.1.0]: https://github.com/oleksiyp/sealctl/releases/tag/v0.1.0
