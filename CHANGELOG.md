# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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

[Unreleased]: https://github.com/oleksiyp/sealctl/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/oleksiyp/sealctl/releases/tag/v0.2.0
[0.1.0]: https://github.com/oleksiyp/sealctl/releases/tag/v0.1.0
