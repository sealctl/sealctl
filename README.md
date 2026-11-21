# sealctl

**Your hardware wallet as an everyday developer key.**
`sealctl` uses the OpenPGP application on a Ledger device — over **USB** or **Bluetooth** — to
unlock encrypted volumes, back them up with restic, keep API keys out of `.env` files, and unlock
SSH keys for logins and signed git commits. The OpenPGP keys never leave the device, and **the
24-word recovery phrase is the only thing you need to back up** (plus SSH key files, if you make
them).

> ⚠️ **Early project.** It works end-to-end on macOS with a Ledger Flex; Linux support (LUKS) is
> tested in CI but young. Keep an independent backup of anything important.

## Principles

- **Only the 24 words.** No key files: volume passphrases, backup passwords and the secret store
  key are derived on the Ledger from its seed and a public id (the volume UUID, the repository
  URL). Lose the computer, keep the words — everything opens again.
- **Standard tools, one documented construction.** OpenPGP via [rPGP](https://github.com/rpgp/rpgp)
  and [`openpgp-card`](https://crates.io/crates/openpgp-card), volumes via APFS / LUKS2, backups
  via [restic](https://restic.net), secrets as OpenPGP messages. The key derivation is sealctl's
  single custom construction (2HashDH over X25519, like RFC 9497 OPRFs), fully specified in
  [docs/derived-keys.md](docs/derived-keys.md) with test vectors.
- **One PIN per session.** A small agent remembers derived keys after you enter the PIN, for
  1 hour of inactivity and at most 24 hours; `sealctl lock` forgets everything at once.
- **PINs never touch the computer.** They're entered on the Ledger screen.

## Install

| | |
|---|---|
| macOS / Linuxbrew | `brew install sealctl/tap/sealctl` |
| Debian / Ubuntu | `sudo apt install ./sealctl_<version>_<arch>.deb` from [Releases](https://github.com/sealctl/sealctl/releases) |
| Fedora / RHEL 9 / Rocky | `sudo dnf install ./sealctl-<version>.<arch>.rpm` |
| openSUSE | `sudo zypper install --allow-unsigned-rpm ./sealctl-<version>.<arch>.rpm` |
| Arch Linux | `PKGBUILD` in each release (AUR: `sealctl-bin`) |
| Nix | `nix run github:sealctl/sealctl` / `nix profile install github:sealctl/sealctl` |
| From source | `cargo install --git https://github.com/sealctl/sealctl sealctl` |

Linux binaries are built on Rocky Linux 9 (glibc 2.34) for x86_64 and aarch64 and are
install-tested on Debian 12/13, Ubuntu 22.04/24.04, Fedora, Rocky 9, openSUSE Tumbleweed and
Arch on every commit. Backups need [restic](https://restic.net) (`brew`/`apt`/`dnf install
restic`), Linux volumes need `cryptsetup`. Building from source on Linux needs
`libudev-dev libdbus-1-dev pkg-config`.

**Device:** install the **OpenPGP** app (Ledger Live → Settings → Experimental → Developer mode).
For **Bluetooth**, install the Bluetooth-enabled build instead — see
[docs/bluetooth-app.md](docs/bluetooth-app.md). Open the app on the device before using sealctl.

## First run

```sh
sealctl setup --uid "Jane Doe <jane@example.org>"   # seed-derived keys + certificate
sealctl pin user && sealctl pin admin               # replace the default PINs (on the device)
sealctl kit export /Volumes/USB/sealctl-kit         # recovery kit, keep it off this computer
sealctl doctor --full                               # proves decryption works
```

## Everyday use

### Encrypted volume with automatic backups
```sh
sealctl volume create work --container disk3  # macOS: encrypted APFS volume on the internal disk
sealctl backup init work --repo s3:https://<account>.r2.cloudflarestorage.com/<bucket>/work
sealctl backup schedule install               # hourly backups of unlocked volumes

sealctl unlock work      # morning: confirm on the Ledger
sealctl lock             # evening: backs up, then locks every volume
sealctl status           # what's unlocked, when was the last backup
```
How it works — nothing to back up besides your 24 words:

* the volume passphrase is **derived on the Ledger from its seed and the volume's UUID**; the
  UUID is read from the (locked) disk, so any machine with the seed can unlock it
  (`sealctl volume import` + `sealctl unlock`);
* the restic password is derived the same way from the repository URL; it and the cloud
  credentials are cached **inside** the encrypted volume, so the scheduled job (launchd /
  systemd timer) can back up whatever is unlocked without the Ledger;
* `sealctl lock` takes a final backup before unmounting (`--no-backup` to skip);
* snapshots can be listed and restored even when the volume is locked or lost:
  `sealctl backup snapshots work`, `sealctl backup restore work --target ~/restore`.

Kinds: `apfs-volume` (default on macOS — an encrypted APFS volume in a container, like Disk
Utility's "APFS (Encrypted)"), `sparsebundle` (an encrypted disk-image file, portable), and
`luks` (Linux).

### The session agent
The first command that needs the Ledger starts `sealctl agent` in the background. Enter the PIN
once; it then answers repeated requests (secrets, unlocks, backups) without the device. It
forgets everything after **1 hour without use** and at the latest **24 hours** after it started.
```sh
sealctl agent status      # cached items, time left
sealctl agent stop        # forget now   (also: `sealctl lock` without a volume name)
```
Tune with `SEALCTL_AGENT_IDLE_MIN` / `SEALCTL_AGENT_MAX_HOURS`; `SEALCTL_NO_AGENT=1` always
asks the device.

### API keys without `.env` files
```sh
sealctl secret set openai                 # asks for the value (no echo)
sealctl secret import-env .env --prefix myapp --delete   # migrate an existing .env
sealctl run -- npm start                  # injects variables mapped in .sealctl.toml
sealctl run -e GITHUB_TOKEN=github -- gh release list
sealctl secret get openai -c              # clipboard, cleared after 45 s
```
Secrets are OpenPGP messages encrypted with a key derived from your seed — no public-key file,
nothing to back up; the store is local only. `.sealctl.toml` (safe to commit — names, not values):
```toml
[env]
OPENAI_API_KEY = "myapp/openai-api-key"
DATABASE_URL   = "myapp/database-url"
```
All secrets for one command are decrypted in a single device session.

### SSH and signed git commits
```sh
sealctl ssh install        # agent as a login service; prints the ~/.ssh/config line
sealctl ssh keygen         # ~/.ssh/sealctl_ed25519 (+ .pub), passphrase from the Ledger — back it up
sealctl ssh pubkey         # add to servers / GitHub (or: ssh-copy-id -i ~/.ssh/sealctl_ed25519.pub host)
sealctl git setup          # sign commits & tags with it
sealctl git setup --undo   # stop signing
```
The key is a normal encrypted OpenSSH key file whose passphrase is derived on the Ledger. The
agent unlocks it on its first use (PIN on the Ledger) and keeps it for the session — 1 h without
use, 24 h at most — so `ssh`, `git push` and commit signing don't wait for the device.
`sealctl lock` or `ssh-add -D` forget it. More keys: `sealctl ssh keygen <name>`, then
`ssh pubkey <name>` / `git setup --key <name>`; pick one per host with
`IdentityFile ~/.ssh/sealctl_<name>.pub` + `IdentitiesOnly yes`.

### Files
```sh
sealctl encrypt report.pdf -o report.pdf.gpg          # to yourself
sealctl encrypt notes.txt -r alice.asc -o notes.asc    # to someone else (and you)
sealctl decrypt report.pdf.gpg -o report.pdf
```

### AI coding agents
```sh
sealctl ai install         # Claude Code, Codex, Gemini CLI, Copilot, Cursor, Qwen Code, …
```
Agents can then store keys you copy (`secret set --from-clipboard`) and run programs with them
(`sealctl run`), but never see the values: output is masked, pasted keys are blocked before
the model sees them, and commands that would print secrets are denied.
See [docs/ai-agents.md](docs/ai-agents.md).

### Recovery without a Ledger
```sh
sealctl recover            # 24 words → your decryption key, checked against your certificate
```
Then `unlock`, `backup restore` and `secret get` work as usual until you stop it. Typing the
words exposes them to that computer: only for a real recovery, ideally offline.

### Transport
`auto` (default) tries USB, then Bluetooth. Force with `-t usb` / `-t ble`, or set
`SEALCTL_TRANSPORT`. The Ledger keeps the PIN verified while the OpenPGP app stays open, so you
enter it about once per session.

## Command reference

| | |
|---|---|
| `status`, `devices`, `card` | overview / list devices / card details |
| `setup`, `pin`, `doctor`, `kit export\|import` | keys, PINs, health check, recovery kit |
| `volume create\|ls\|rm`, `unlock`, `lock` | encrypted volumes |
| `backup init\|run\|snapshots\|restore\|check\|policy\|schedule` | restic backups |
| `secret set\|get\|ls\|rm\|import-env`, `run` | API keys and project environments |
| `ssh keygen\|pubkey\|passphrase\|agent\|install\|uninstall`, `git setup` | SSH and commit signing |
| `encrypt`, `decrypt` | OpenPGP files |
| `completions <shell>` | shell completions |

## Recovery

With only the 24 words: restore them on any Ledger, install the OpenPGP app, run
`sealctl setup --force` (the same seed-derived keys come back), then
`sealctl volume import <name> <disk-image-or-APFS-UUID> --kind …` and `sealctl unlock <name>`.
Backups: `sealctl backup init` with the same repository URL reconnects to the repository.
The derivation is specified in [docs/derived-keys.md](docs/derived-keys.md).

## Documentation

[Derived keys](docs/derived-keys.md) · [Design](docs/design.md) · [Threat model](docs/threat-model.md) ·
[Bluetooth app](docs/bluetooth-app.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## License

[MIT](LICENSE). Not affiliated with Ledger SAS; "Ledger" is used only to describe compatibility.
