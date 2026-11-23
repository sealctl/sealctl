# sealctl

**Keys for developers and their AI agents.**
API keys, SSH and git signing keys, encrypted volumes and backups, opened only when your phone
approves. One tap per use; your AI agents never see the key.

`sealctl` keeps API keys out of `.env` files, signs SSH logins and git commits, opens encrypted
volumes and runs encrypted backups with restic. Every key is derived
from **24 words** held by the sealctl phone app; the phone hands keys to a paired machine when
you approve, and **the 24 words alone open every object**, with no phone, relay or company.

## How it works

- **The phone holds the root.** The app makes 24 words; the root and every object key come
  from them by HKDF (docs/protocol.md). A machine is paired once (`sealctl pair`, a QR code)
  and asks the phone over the relay for the keys it needs. Requests and replies are sealed end
  to end (HPKE to the phone's key, signed by the machine's pairing key); the relay sees only
  sealed strings, ids and timing.
- **One tap a day.** The first use opens a session on the machine; while it is Open, the
  daemon holds the keys and nothing asks again until the idle allowance runs out (it grows the
  more you work, 4 hours at most at a trusted place) or the hard stop (02:00 or 14 hours). The
  phone can lock the machine at any time.
- **Agents use secrets, never see them.** `sealctl run` gives a program its keys in its
  environment and masks them in its output; an agent's first use of a secret in a repository
  asks the phone once.
- **Leaving is always possible.** `sealctl unseal` hands objects back in plain, standard form;
  `sealctl recover` opens any object with the 24 words alone.

## Install

| | |
|---|---|
| macOS / Linuxbrew | `brew install sealctl/tap/sealctl` |
| Debian / Ubuntu | `sudo apt install ./sealctl_<version>_<arch>.deb` from [Releases](https://github.com/sealctl/sealctl/releases) |
| Fedora / RHEL 9 / Rocky | `sudo dnf install ./sealctl-<version>.<arch>.rpm` |
| Arch Linux | `PKGBUILD` in each release (AUR: `sealctl-bin`) |
| Nix | `nix profile install github:sealctl/sealctl` |
| From source | `cargo install --locked --git https://github.com/sealctl/sealctl sealctl` |

From 0.7.0 each release has `SHA256SUMS` and a build provenance attestation for every file: check a
download with `sha256sum -c SHA256SUMS --ignore-missing` or
`gh attestation verify <file> --repo sealctl/sealctl`.

Backups need [restic](https://restic.net); Linux volumes need `cryptsetup`.

## First run

```sh
sealctl pair          # scan the QR code with the sealctl app (or open the printed link on the phone)
sealctl status        # Locked · dev@mbp.example.com #k7m2 · words qHWf
sealctl ai install    # skills, hooks and deny rules for Claude Code, Codex, Gemini CLI, …
```

`sealctl pair` installs the session daemon as a login service (launchd or systemd); where
there is none, the CLI starts the daemon itself. On CI runners, `SEALCTL_NO_DAEMON=1` makes
each command ask the phone itself.

## Everyday use

### API keys without `.env` files

```sh
sealctl secret set shop/openai-api-key --from-clipboard   # or piped, or a hidden prompt
sealctl seal env .env --prefix shop --delete             # move an existing .env into the store
sealctl run -- npm start                                 # variables from .sealctl.toml
sealctl run -e GITHUB_TOKEN=git/github.com -- gh release list
sealctl secret ls                                        # names only, no key needed
sealctl secret set deploy/token --own-approval           # asks the phone on every use
```

`.sealctl.toml` (safe to commit: names, not values):

```toml
[env]
OPENAI_API_KEY = "shop/openai-api-key"

[command."npm run deploy"]
DEPLOY_TOKEN = "shop/deploy-token"
```

A `.sealctl.toml` can come with a cloned repository, so `sealctl run` asks before it first uses
one, and again after it changes, listing the secrets it names. Without a terminal (scripts, CI)
it refuses until you trust the file once: `sealctl project trust`. Files that `seal env` and
`scan` write are trusted already.

The store is a folder of `.sealed` files under a store id (docs/protocol.md, Store format). It
can live in a synced folder or a git repository: `sealctl secret store --use <folder>`.

### SSH and signed git commits

```sh
sealctl ssh keygen                 # ssh/ed25519 in the store, ~/.ssh/sealctl_ed25519.pub
sealctl ssh setup                  # the IdentityAgent line for ~/.ssh/config
sealctl seal ssh ~/.ssh/id_ed25519 # take over an existing key
sealctl git setup                  # sign commits and tags through the daemon's SSH agent
sealctl git credentials github.com # git asks sealctl for the token git/github.com
```

### Volumes and backups

```sh
sealctl volume create work --container disk3          # macOS: encrypted APFS volume
sealctl volume create work --kind sparsebundle        # a portable encrypted disk image
sealctl backup init work --from work --repo s3:https://<account>.r2.cloudflarestorage.com/<bucket>
sealctl backup schedule install                       # hourly while the session is Open
sealctl lock                                          # back up, close volumes, wipe keys
sealctl volume open work                              # after a lock
```

Volumes mount when the session opens and close when it locks. The passphrase is
`hex(volume key)`, given to `diskutil`, `hdiutil` or `cryptsetup` on stdin only; restic gets the
backup key on a pipe. Storage credentials are secrets `backup/<name>/<VAR>`.

### Finding keys lying around

```sh
sealctl scan --dry-run            # .env files in this repository: file, line, first 4 characters
sealctl scan --home               # also shell rc files, histories and ~/.aws/credentials
```

Values move into the store; `.sealctl.toml` mappings, comments in rc files and
`credential_process` lines in `~/.aws/config` are left behind; keys in histories are masked.

### New words

When you change the words on the phone, it moves each machine to its new key and the daemon
rewraps every object by itself. At the machine's terminal:

```sh
sealctl migrate --depth rewrap    # objects that could not be rewrapped, or sealed with retired words
sealctl migrate                   # the table, then re-encrypt sparse bundles and restic repositories
sealctl migrate --status          # the re-encryption job
```

### Taking over what you have, and handing it back

```sh
sealctl seal volume safe <APFS UUID | bundle | LUKS file>  # your passphrase stops working
sealctl seal backup safe --repo <restic URL>             # your password is removed
sealctl unseal volume safe                               # back under a new password of yours
sealctl unseal --all                                     # everything, then sealctl itself
```

Taking over or handing back one object is confirmation level 2 on the phone (biometrics; the
number shown at the terminal when the phone cannot tell it is near). `unseal --all` is level 3:
pick the number shown at the terminal, the phone signs the plan, and away from a trusted place
it takes effect two hours later. Every paired machine is told and can stop it with
`sealctl cancel`. `--words` uses the 24 words instead of the phone.

`unseal` writes everything into one new folder, `~/sealctl-unsealed-<date>`: `passwords.txt`,
`secrets.env`, `backup-<name>.env`, `handback.json` (no values in it) and `README.txt`. Volumes
and backups stay encrypted under new random passwords; SSH keys become plain key files.
Delete the folder once the new passwords work. `--to keychain|op|bw|show` and
`--secrets-to keychain|op|bw|env` send them to the macOS Keychain (labels like
`sealctl: volume safe`), 1Password, Bitwarden, the terminal once, or a `.env` file instead.
`sealctl seal --from ~/sealctl-unsealed-<date>/handback.json` takes everything back.

### Recovery

```sh
sealctl recover ~/.local/share/sealctl/store/<store-id> --out ~/recovered
sealctl recover ~/Vaults/work.sparsebundle
sealctl recover ~/Vaults/safe.luks         # Linux: mounted at ~/Vaults/safe
sealctl recover <APFS volume UUID>         # macOS: see diskutil apfs list
sealctl recover s3:https://…/<repo-id> -- snapshots
```

The words are typed one at a time without echo (the first four letters are enough). No phone,
relay, pairing or configuration is needed.

## Licence

Everything is free. If sealctl earns its place, `sealctl buy` pays $5.99 once, which keeps the
relay running (`--seats N` for a team, `--code` to claim a seat). After 30 days with use,
`status`, `pair` and `secret ls` typed by a person may say so, at most once a week; never in
`sealctl run`, pipes, CI or anything an agent reads.

## Settings

| Variable | Effect |
| --- | --- |
| `SEALCTL_RELAY` / `--relay` | Relay origin (default `https://relay.sealctl.com`); recorded at pairing |
| `SEALCTL_NO_DAEMON=1` | No daemon: each command asks the phone itself |
| `SEALCTL_AGENT=1` | Treat this process as inside an AI agent |
| `SEALCTL_AGENT=0` | Turn agent detection off (yours to set: the agent hooks deny an agent setting it). When an agent's own variable is set too, sealctl says so once on stderr |
| `SEALCTL_NO_MASK=1` | No masking in `sealctl run` (ignored inside an agent) |
| `SEALCTL_NO_SERVICE=1` | Do not install login services (also skipped when `HOME` is not your home folder) |
| `SEALCTL_RESTIC`, `SEALCTL_SSH_DIR`, `SEALCTL_LOG` | restic binary, SSH folder, log level |

Exit codes: 0 done, 2 usage, 3 not paired, 4 declined on the phone, 5 no answer, 6 relay
error, 7 relay limit, 8 refused (agent or no terminal), 9 not found, 10 wrong words or key,
11 volume busy, 12 clock off, 13 stopped part way (`--resume`).

## Development

```sh
cargo test                                  # unit tests, and the CLI against an in-process fake relay
SEALCTL_TEST_RELAY=https://<relay> cargo test   # the same end-to-end tests against a live relay
SEALCTL_RELAY=https://<relay> scripts/pair-test.sh   # pair a real phone with a throwaway HOME
```

The integration tests run the real `sealctl` binary in temporary HOMEs, with a scripted phone
built on `sealctl-core` (crate `sealctl-fakerelay`); commands that need a terminal run on a
pseudo-terminal. Specs: [SPEC.md](SPEC.md) (the CLI), [docs/protocol.md](docs/protocol.md)
(wire formats and vectors), [docs/ai-agents.md](docs/ai-agents.md),
[docs/threat-model.md](docs/threat-model.md), [docs/design.md](docs/design.md).

## License

MIT
