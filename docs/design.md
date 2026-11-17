# Design

## Components

```
sealctl (CLI, clap)
 ├─ card        setup / status / doctor          ─┐
 ├─ crypto      encrypt / decrypt (rPGP)           │  openpgp-card  ──▶  CardBackend
 ├─ volume      APFS (diskutil) · LUKS2 (cryptsetup)│                       │
 ├─ backup      restic                             │            sealctl-ledger
 └─ secrets     pass-compatible store             ─┘        ├─ USB HID  (hidapi)
                                                            └─ Bluetooth LE (btleplug)
```

* **sealctl-ledger** implements Ledger APDU framing over USB HID and Bluetooth LE and exposes it
  as a `card_backend::CardBackend`. It knows nothing about OpenPGP beyond the PIN-pad CLA.
* **openpgp-card** speaks the OpenPGP card protocol (SELECT, GET DATA, PSO:DECIPHER, …).
* **openpgp-card-rpgp + rPGP** turn card keys into OpenPGP certificates and decrypt / sign
  standard OpenPGP messages.

## Keys

The Ledger OpenPGP app derives keys from the device seed (BIP32 path
`m/0x80475047'/(slot+1)'`, then per key name and algorithm). `sealctl setup` will:

1. select Curve25519 (Ed25519 for signing/auth, X25519 for decryption) in all three keys;
2. generate keys in seeded mode (deterministic);
3. write fingerprints and a **fixed creation time** to the card so the certificate — and thus
   every fingerprint — is reproducible from the device alone;
4. export the certificate to every configured backup location.

`sealctl doctor` re-derives the certificate from the device and compares fingerprints.

## Derived keys and the agent

Volume passphrases, restic passwords and the secret-store key are derived on the Ledger from
its seed-derived X25519 key and a public id — see [derived-keys.md](derived-keys.md). Derived
values go to OS tools through stdin only and are zeroized after use.

`sealctl agent` (started on demand, one thread per client, 0600 Unix socket) caches the card's
X25519 results so a session needs one PIN entry. It exits after 1 h idle or 24 h total;
`sealctl lock` stops it.

## Transports

| | USB HID | Bluetooth LE |
|---|---|---|
| Works with the official OpenPGP app | ✅ | ❌ (built without Bluetooth) |
| Works with the Bluetooth build | ✅ | ✅ |
| Opening the app remotely | possible | drops the link — open the app on the device |
| PIN entry | on device | on device |

## Backups

* `backup init` derives the restic password from the repository URL; it and the repository
  credentials are cached (0600) in `<mount>/.sealctl/`. Re-running `init` with the same URL
  reconnects to an existing repository.
* `backup run --all --if-unlocked` (launchd `StartInterval` / systemd timer) backs up every
  unlocked volume with `RESTIC_PASSWORD_FILE` pointing inside the volume — no device needed.
* `lock` runs the same backup first; a failed backup never prevents locking.
* `snapshots` / `restore` / `check` derive the password on the Ledger when the volume is locked
  (credentials from the environment or a prompt) and give it to restic through a stdin pipe.
* Retention (`forget --prune`, 7 daily / 4 weekly / 12 monthly by default) runs at most weekly.

## Secrets

`~/.local/share/sealctl/secrets/<name>.gpg`: OpenPGP messages (SKESK + SEIPD, AES-256)
encrypted with the seed-derived store key. `sealctl run` decrypts all mapped secrets with one
key derivation and `exec`s the command with them in its environment only.

## SSH

`sealctl ssh agent` implements the ssh-agent protocol (ssh-agent-lib) and offers the encrypted
key files `~/.ssh/sealctl_<name>` (standard OpenSSH format). A key's passphrase is derived on
the Ledger from its public fingerprint (docs/derived-keys.md); the agent decrypts the key on
first use and keeps it in memory for the sealctl agent session, so signing needs no device
round trip. Git uses it via `gpg.format=ssh` and a `gpg.ssh.program` shim that sets
`SSH_AUTH_SOCK`. (Until 0.4 the agent also signed with the Ledger's OpenPGP authentication key
via INTERNAL AUTHENTICATE; that made every login depend on the device and was removed.)

## Recovery

Only the seed (24 words) is needed: `sealctl setup --force` recreates the identical keys and
certificate; volumes, backups and secrets are re-derived. `sealctl kit export` writes a recovery kit with step-by-step
instructions (`README.txt`) for both sealctl and plain GnuPG + restic.
