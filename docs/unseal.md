# Leaving sealctl: `sealctl unseal`

`sealctl unseal` is the inverse of sealing: everything sealctl holds comes back to you in
plain, standard form. Volumes and backups **stay encrypted** (a format that needs a password
keeps one: a new random one, saved for you); SSH keys become ordinary key files; secrets become
a plain dotenv file. By default nothing is written to Keychain, 1Password or Bitwarden: it all
goes into one folder, `~/sealctl-unsealed-<date>`, which you delete once everything works.
Nothing needs the Ledger afterwards, and nothing is deleted that could still be needed.

It is in sealctl 0.6.0, the last release that reads the Ledger. Use it to leave sealctl, or to
move to sealctl 0.7 (which approves with a phone): unseal everything with 0.6.0, install 0.7,
then `sealctl seal --from <folder>/handback.json`.

```sh
sealctl unseal --all --dry-run     # the plan; changes nothing
sealctl unseal --all               # shows the plan again, then asks you to type: unseal
sealctl unseal --resume            # continue a run that stopped
sealctl unseal volume work         # one object (asks y)
```

Objects: `secrets` (the whole store), `secret <name>`, `volume <name>`, `backup <volume>`,
`ssh <name>`, `git`, `ai [TOOL...]`.

## The folder

Each run (other than `--dry-run`) makes a visible folder in your home folder, made only once you
confirm the plan:

```
~/sealctl-unsealed-2026-11-21        (-2, -3, … when one exists already)
```

Mode 0700, every file in it 0600. sealctl **never deletes it**; delete it yourself once the new
passwords and keys work (`rm -rf ~/sealctl-unsealed-2026-11-21`). It holds:

| File | Content |
| --- | --- |
| `README.txt` | What is in the folder, the commands to check each item by hand, and that you delete the folder when everything works |
| `passwords.txt` | One line per volume and backup: `volume safe: <new passphrase>`, `backup safe: <new restic password>` |
| `backup-<volume>.env` | `RESTIC_REPOSITORY`, `RESTIC_PASSWORD` and the storage credentials (`AWS_*`, …): `set -a; . ./backup-safe.env; set +a; restic snapshots` |
| `secrets.env` | Every secret of the store, plain: `SHOP_OPENAI_API_KEY="…"` (the name in upper case, `/ - . @ +` as `_`, `_2` when two names collide; README.txt lists them) |
| `secrets-binary/<VAR>` | A secret that is not text, as a raw file (only when there is one) |
| `handback.json` | Every object and where its password went — no passwords. `sealctl seal --from` (0.7) reads it |
| `plan.json`, `journal.jsonl`, `run.lock`, `done` | The run itself: the plan as confirmed, one line per step, held while running, written last |
| `files/` | The copy of every file sealctl edited, by its path under `$HOME`, with its mode |
| `kept/` | sealctl's originals, still encrypted to the Ledger: the secret store, settings, the certificate, the old SSH key files |

`secrets.env` and `backup-*.env` use double quotes with `\ " $` and backquotes escaped and line
breaks kept, so both dotenv parsers and a POSIX shell (`set -a; . file`) read back exactly the
value, multi-line JSON included.

Before anything is written in plain form, the run:

- writes `README.txt`;
- on macOS, excludes the folder from Time Machine (`tmutil addexclusion`; a failure is noted in
  the journal and the run goes on — Linux has no equivalent);
- adds rules that keep AI agents out of `~/sealctl-unsealed-*` to every AI tool found that has
  such rules: Claude Code and Qwen Code get `permissions.deny` entries
  `Read(~/sealctl-unsealed-*/**)` and `Bash(*sealctl-unsealed-*)`; Gemini CLI gets
  `~/.gemini/policies/deny-sealctl-unsealed.toml`. These rules stay after sealctl is gone (they
  don't need it); remove them with the folder if you like.

## The rules it keeps

- **Plan first.** Nothing changes before the plan is shown and you confirm it: `y` for one
  object, the typed word `unseal` for `--all`. Anything else changes nothing and makes no folder.
- **A person at a terminal.** It refuses inside AI coding agents and when stdin or stderr is
  not a terminal (exit 8). Agents are told by their skill and deny rules to ask you to run it.
- **Write ahead.** A new password is written to `passwords.txt` (or the store you chose) first:
  written to a temporary file, `fsync`ed, renamed, the folder `fsync`ed, read back and compared
  (SHA-256, in memory). Only then is it set on the volume or repository, and the object is opened
  with it, as read back, before sealctl's key or key slot is removed. APFS volumes and sparse
  bundles swap the passphrase in one step; if the check after the swap fails, it is swapped back.
- **Durable writes.** Every file sealctl writes — in the folder, SSH key files, `~/.ssh/config`,
  shell rc files, AI settings — is replaced through a temporary file, `fsync` (F_FULLFSYNC on
  macOS), a rename and an `fsync` of its directory; copies into `files/` and moves into `kept/`
  are `fsync`ed the same way. A power cut leaves the old file or the new one, never a part.
- **A journal.** Every step is written, with `fsync`, to the folder before and after it runs.
  After a crash, power cut or Ctrl-C, `sealctl unseal --resume` continues; a journal line cut
  short is dropped, and each step first looks at the object itself (does the new password
  already open it? is sealctl's key already gone?), so nothing is done twice or skipped. A step
  that stored a password but was cut before the journal said so stores a new one (nothing used
  the first yet).
- **Copies before edits.** Every file it edits (`~/.ssh/config` and its includes, shell rc
  files, git config files, AI tool settings, launchd plists / systemd units) is copied into
  `files/` first, with its mode.
- **No values shown.** Passwords and secret values go only to the folder's plain files or the
  store you chose. The single exception is `--to show`, which you choose: each new password is
  shown once on the terminal. The journal, the hand-back list, README.txt and the output never
  hold a value.
- **Nothing deleted that could be needed.** The old secret store, the old SSH key files and
  sealctl's settings move to `kept/`, still encrypted to the Ledger.

## What happens to each object

Order with `--all`: secrets; each volume's backup, then the volume; SSH keys; git; AI tools;
services; local files.

| Object | What `unseal` does | Checked before sealctl's key goes | Left behind |
| --- | --- | --- | --- |
| Secrets | Each value opened with the store key and written to `secrets.env` | Each value read back with the same SHA-256 | `secrets.env`; the store folder in `kept/secrets` (`unseal secret <name>` leaves the store in place) |
| Backup of a volume | The volume is mounted with its derived key if needed (and locked again after). New random password to `passwords.txt`; `backup-<volume>.env` written; `restic key add --new-password-file /dev/fd/4` (old password on stdin, new on a pipe); `restic key remove <sealctl's key>`; `<mount>/.sealctl/` deleted; the backup schedule removed when no volume backs up any more | `restic cat config` opens with the new password, which is the current key; afterwards the derived password gives "wrong password" | The repository and every snapshot, under the new password. Backups no longer run by themselves |
| APFS volume | New random passphrase to `passwords.txt`, then `diskutil apfs changePassphrase` from the derived passphrase to it | `diskutil apfs unlockVolume <uuid> -user <disk user> -verify` passes with the new one, fails with the derived one; otherwise swapped back | The volume, still encrypted, mounted or locked as it was |
| Sparse bundle | Ejected if attached, `hdiutil chpass`, mounted again if it was; `sealctl.id` removed | `hdiutil attach -nomount` with the new one, not with the derived one | The bundle, still encrypted |
| LUKS file | `cryptsetup luksAddKey` (both passphrases on pipes), then sealctl's slot found with `--test-passphrase -v` and removed with `luksKillSlot` | The new one opens its own slot before the kill; the derived one opens none after | The LUKS file, still encrypted |
| SSH keys | `~/.ssh/sealctl_<name>` written as `~/.ssh/<name>` (`<name>-1` if taken) and `.pub`: standard OpenSSH, **no passphrase**; nothing goes to ssh-agent or the Keychain. `~/.ssh/config` and its includes: sealctl's `IdentityAgent` lines removed, `IdentityFile …/sealctl_<name>` pointed at the new file; `export SSH_AUTH_SOCK=<sealctl's socket>` in shell rc files commented out | `ssh-keygen -y -P "" -f <key>` prints the key's public key | Standard key files; the old ones in `kept/ssh` |
| Git signing | Global config and `.git/config` of repositories under `$HOME` (6 levels, skipping `Library`, `node_modules`, `.cache`, `target` and the unseal folders) that sign through sealctl: `gpg.ssh.program` unset, `user.signingkey` set to the plain key file, `gpg.ssh.allowedSignersFile` to `~/.ssh/allowed_signers` (sealctl's lines added); the wrapper removed | A test signature made like git's (`-n git`) verifies with `ssh-keygen -Y verify` against the allowed signers file | Signing through standard `ssh-keygen`, no agent needed |
| AI tools | `sealctl ai uninstall` for each tool where something of sealctl's is installed. Unless `--drop-env-rules` (asked otherwise): Claude Code and Qwen Code keep `permissions.deny` rules for `.env` files and common credential files; Gemini CLI gets `~/.gemini/policies/deny-env-files.toml`. The rules for `~/sealctl-unsealed-*` (above) stay either way | Nothing of sealctl's left; every edited file still parses | Deny rules that don't need sealctl |
| Services | sealctl's launchd agents / systemd user units removed; the session agent stopped last | Their files are gone | |
| Local files | The certificate moves to `kept/keys` (`--words` needs it to check old copies later); `~/.local/share/sealctl` and `~/.config/sealctl` move to `kept/`; `~/.local/state/sealctl` is removed | The folders are gone | |

Nothing is done to the Ledger. The OpenPGP app can stay, or be removed in Ledger Live.

`sealctl unseal` never removes the program. The last lines name the command for how it was
installed, for example `brew uninstall sealctl/tap/sealctl`, and the `rm -rf` for the folder.

## Password stores, if you want them

The folder is the default. To put new passwords and secrets into a password store instead, as
before, choose it: new passwords (volumes, backups, SSH keys) with `--to`, secrets and backup
storage credentials with `--secrets-to` (default: the same as `--to`; with `--to show`, the
folder). With a store, SSH keys get a new passphrase of their own (stored there) and, on macOS,
are added with `ssh-add --apple-use-keychain`, with `UseKeychain yes` / `AddKeysToAgent yes`
under `Host *`; `--no-ssh-passphrase` writes them without one.

| Store | What happens |
| --- | --- |
| `folder` (default) | The run folder: `passwords.txt`, `secrets.env`, `backup-<volume>.env` (above) |
| `keychain` | macOS Keychain or the Linux Secret Service: service `sealctl-unsealed`, account `<kind>/<name>` (`volume/safe`, `backup/safe/password`, `backup/safe/AWS_SECRET_ACCESS_KEY`, `ssh/ed25519`, `secret/shop/openai-api-key`), and a readable label: `sealctl: volume safe`, `sealctl: backup safe password`, `sealctl: secret shop/openai-api-key` — the name Keychain Access shows |
| `op` | 1Password (`op` signed in): one item per value, titled like the label above, tagged `sealctl`, in `--op-vault` or your default vault. The item's notes say what it opens |
| `bw` | Bitwarden (`bw` unlocked, `BW_SESSION` set): one login item per value, in `--bw-folder` if given |
| `show` | New passwords only: shown once on the terminal; type the last 4 characters to go on |
| `env` | Secrets only: a 0600 dotenv file outside the folder (`--env-file`, default `~/sealctl-secrets.env`). **This file holds your keys in plain text, where AI agents can read them. Move them to a password manager, then delete it.** |

New passwords are generated: 32 characters `a-z0-9` in groups of four (about 165 bits).
`--type-passwords` asks for each one instead (twice, at least 12 characters). Values reach a
store through stdin or its API, never a command line.

## Keys: Ledger or words

By default keys come from the Ledger through the session agent, so the PIN is asked once. If
the Ledger is lost or broken, `--words` asks for its 24 words instead and checks them against
your certificate, as `sealctl recover` does. **These words also guard anything else on your
Ledger. Type them only if the Ledger is lost or broken.**

## When something stops

A failed step stops the run; the steps before it stay done. The message says which key opens
the object now and ends with `Run sealctl unseal --resume after fixing this.`

- `--skip <kind>/<name>` leaves an object out (for example `--skip backup/safe` when its storage
  is offline). sealctl's services and settings then stay, so the object keeps working; the run
  ends with exit 13 and says so.
- A volume that can't be mounted (to remove `.sealctl/`) or ejected (a busy sparse bundle) is
  reported with exit 11.

| Exit | Meaning |
| --- | --- |
| 0 | Done |
| 2 | Usage, or another run is active |
| 8 | Inside an AI agent, or not at a terminal |
| 9 | No such object, or something to fix first |
| 10 | sealctl's key does not open the object (other Ledger words?) |
| 11 | A volume is busy or could not be mounted |
| 13 | Stopped part way (Ctrl-C, a failed step), or objects were left out |

## After `unseal --all`

README.txt in the folder has the exact commands for your volumes, backups and keys.

- Volumes: Finder asks for the passphrase: the line `volume <name>` in `passwords.txt`.
  `diskutil apfs unlockVolume <uuid>` / `hdiutil attach <bundle>` /
  `sudo cryptsetup open <file> <name>`. Change it to one of your own with Disk Utility,
  `diskutil apfs changePassphrase <uuid> -user disk`, `hdiutil chpass` or
  `cryptsetup luksChangeKey`.
- Backups: `set -a; . ~/sealctl-unsealed-<date>/backup-<volume>.env; set +a; restic snapshots`.
  `restic key passwd` sets a password of your own. Backups no longer run by themselves.
- SSH: the keys work as they are (`ssh-keygen -y -f ~/.ssh/<name>` asks nothing). Add a
  passphrase with `ssh-keygen -p -f ~/.ssh/<name>`.
- Secrets: in `secrets.env`. Programs that used `sealctl run` need another way to get them
  (your password manager's CLI, or `.sealctl.toml` again with 0.7).
- Keep the passwords where you keep passwords, then delete the folder. Keep your Ledger and
  paper card until no old copies of the backups or volumes remain (old snapshots of a disk, an
  old copy of the repository): those still open only with the Ledger.
