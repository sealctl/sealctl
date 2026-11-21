# Leaving sealctl: `sealctl unseal`

`sealctl unseal` hands what sealctl holds back to you, under passwords of your own. Your
volumes and backups **stay encrypted**; afterwards they open with your own passphrase instead
of a key derived on the Ledger. Nothing needs the Ledger afterwards, and nothing is deleted
that could still be needed.

It is in sealctl 0.6.0, the last release that reads the Ledger. Use it to leave sealctl, or to
move to sealctl 0.7 (which approves with a phone): unseal everything with 0.6.0, install 0.7,
then `sealctl seal --from <hand-back list>`.

```sh
sealctl unseal --all --dry-run     # the plan; changes nothing
sealctl unseal --all               # shows the plan again, then asks you to type: unseal
sealctl unseal --resume            # continue a run that stopped
sealctl unseal volume work         # one object (asks y)
```

Objects: `secrets` (the whole store), `secret <name>`, `volume <name>`, `backup <volume>`,
`ssh <name>`, `git`, `ai [TOOL...]`.

## The rules it keeps

- **Plan first.** Nothing changes before the plan is shown and you confirm it: `y` for one
  object, the typed word `unseal` for `--all`. Anything else changes nothing.
- **A person at a terminal.** It refuses inside AI coding agents and when stdin or stderr is
  not a terminal (exit 8). Agents are told by their skill and deny rules to ask you to run it.
- **Check before removing.** Each new password is stored first, read back and compared
  (SHA-256, in memory). Each object is opened with the new password, as read back from the
  store, before sealctl's key or key slot is removed. APFS volumes and sparse bundles swap the
  passphrase in one step; if the check after the swap fails, it is swapped back.
- **A journal.** Every step is written, with `fsync`, to the run folder before and after it
  runs. After a crash, power cut or Ctrl-C, `sealctl unseal --resume` continues; each step
  first looks at the object itself (does the new password already open it? is sealctl's key
  already gone?), so nothing is done twice or skipped.
- **Copies before edits.** Every file it edits (`~/.ssh/config` and its includes, shell rc
  files, git config files, AI tool settings, launchd plists / systemd units) is copied into
  the run folder first, with its mode.
- **No values shown.** Passwords and secret values go only to the store you chose. The single
  exception is `--to show`, which you choose: each new password is shown once on the terminal.
  The journal, the hand-back list and the output never hold a value.
- **Nothing deleted that could be needed.** The old secret store, the old SSH key files and
  sealctl's settings move to the run folder's `kept/`, still encrypted to the Ledger.

## Where passwords and secrets go

New passwords (volumes, backups, SSH keys) go to `--to`; secrets and backup storage
credentials to `--secrets-to` (default: the same).

| Store | What happens |
| --- | --- |
| `keychain` (default) | macOS Keychain or the Linux Secret Service: service `sealctl-unsealed`, account `<kind>/<name>`, e.g. `volume/safe`, `backup/safe/password`, `backup/safe/AWS_SECRET_ACCESS_KEY`, `ssh/ed25519`, `secret/shop/openai-api-key`. Find them in Keychain Access by searching for `sealctl-unsealed`. |
| `op` | 1Password (`op` signed in): one item per value, tagged `sealctl`, in `--op-vault` or your default vault. The item's notes say what it opens. |
| `bw` | Bitwarden (`bw` unlocked, `BW_SESSION` set): one login item per value, in `--bw-folder` if given. |
| `show` | New passwords only: shown once on the terminal; type the last 4 characters to go on. |
| `env` | Secrets only: a 0600 dotenv file (`--env-file`, default `~/sealctl-secrets.env`), `SHOP_OPENAI_API_KEY="…"`. **This file holds your keys in plain text, where AI agents can read them. Move them to a password manager, then delete it.** |

New passwords are generated: 32 characters `a-z0-9` in groups of four (about 165 bits).
`--type-passwords` asks for each one instead (twice, at least 12 characters).
`--no-ssh-passphrase` writes SSH keys without a passphrase.

## What happens to each object

Order with `--all`: secrets; each volume's backup, then the volume; SSH keys; git; AI tools;
services; local files.

| Object | What `unseal` does | Checked before sealctl's key goes | Left behind |
| --- | --- | --- | --- |
| Secrets | Each value opened with the store key and written to the secrets store | Each value read back with the same SHA-256 | The store folder in `kept/secrets` (`unseal secret <name>` leaves the store in place) |
| Backup of a volume | The volume is mounted with its derived key if needed (and locked again after). `restic key add --new-password-file /dev/fd/4` (old password on stdin, new on a pipe); storage credentials to the secrets store; `restic key remove <sealctl's key>`; `<mount>/.sealctl/` deleted; the backup schedule removed when no volume backs up any more | `restic cat config` opens with the new password, which is the current key; afterwards the derived password gives "wrong password" | The repository and every snapshot, under your password. Backups no longer run by themselves |
| APFS volume | `diskutil apfs changePassphrase` from the derived passphrase to yours | `diskutil apfs unlockVolume <uuid> -user <disk user> -verify` passes with yours, fails with the derived one; otherwise swapped back | The volume, still encrypted, mounted or locked as it was |
| Sparse bundle | Ejected if attached, `hdiutil chpass`, mounted again if it was; `sealctl.id` removed | `hdiutil attach -nomount` with yours, not with the derived one | The bundle, still encrypted |
| LUKS file | `cryptsetup luksAddKey` (both passphrases on pipes), then sealctl's slot found with `--test-passphrase -v` and removed with `luksKillSlot` | Yours opens its own slot before the kill; the derived one opens none after | The LUKS file, still encrypted |
| SSH keys | `~/.ssh/sealctl_<name>` written as `~/.ssh/<name>` (`<name>-1` if taken) and `.pub`, standard OpenSSH, with your passphrase; macOS: `ssh-add --apple-use-keychain` (the passphrase passed through a private pipe to `sealctl askpass`); `~/.ssh/config` and its includes: sealctl's `IdentityAgent` lines removed, `IdentityFile …/sealctl_<name>` pointed at the new file, `UseKeychain yes` / `AddKeysToAgent yes` under `Host *` on macOS; `export SSH_AUTH_SOCK=<sealctl's socket>` in shell rc files commented out | The new file opens with the passphrase read back from the store and has the same public key; on macOS `ssh-add -l` lists it | Standard key files; the old ones in `kept/ssh` |
| Git signing | Global config and `.git/config` of repositories under `$HOME` (6 levels, skipping `Library`, `node_modules`, `.cache`, `target`) that sign through sealctl: `gpg.ssh.program` unset, `user.signingkey` set to the new `.pub`, `gpg.ssh.allowedSignersFile` to `~/.ssh/allowed_signers` (sealctl's lines added); the wrapper removed | A test signature made like git's (`-n git`) verifies with `ssh-keygen -Y verify` against the allowed signers file | Signing through standard `ssh-keygen` |
| AI tools | `sealctl ai uninstall` for each tool where something of sealctl's is installed. Unless `--drop-env-rules` (asked otherwise): Claude Code and Qwen Code keep `permissions.deny` rules for `.env` files and common credential files; Gemini CLI gets `~/.gemini/policies/deny-env-files.toml` | Nothing of sealctl's left; every edited file still parses | Optional `.env` deny rules that don't need sealctl |
| Services | sealctl's launchd agents / systemd user units removed; the session agent stopped last | Their files are gone | |
| Local files | The certificate moves to `kept/keys` (`--words` needs it to check old copies later); `~/.local/share/sealctl` and `~/.config/sealctl` move to `kept/`; `~/.local/state/sealctl` is removed | The folders are gone | |

Nothing is done to the Ledger. The OpenPGP app can stay, or be removed in Ledger Live.

`sealctl unseal` never removes the program. The last line names the command for how it was
installed, for example `brew uninstall sealctl/tap/sealctl`.

## Keys: Ledger or words

By default keys come from the Ledger through the session agent, so the PIN is asked once. If
the Ledger is lost or broken, `--words` asks for its 24 words instead and checks them against
your certificate, as `sealctl recover` does. **These words also guard anything else on your
Ledger. Type them only if the Ledger is lost or broken.**

## The run folder

`~/.sealctl-unseal/<start time>/` (mode 0700), outside sealctl's own folders:

| File | Content |
| --- | --- |
| `plan.json` | The plan as confirmed |
| `journal.jsonl` | One line per step: `{"v":1,"t":"…","n":7,"step":"volume:safe:change","state":"done","note":"…"}` |
| `files/` | The copy of every edited file, by its path under `$HOME` |
| `kept/` | The old secret store, SSH key files, certificate and settings, still encrypted |
| `handback.json` | Every object and where its password went — no passwords. `sealctl seal --from` (0.7) reads it |
| `run.lock`, `done` | Held while running; written last |

Delete the run folder once everything opens with your new passwords. Keep your Ledger and its
paper card until no old copies of the backups or volumes remain (old snapshots of a disk, an
old copy of the repository): those still open only with the Ledger.

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

- Volumes: Finder asks for the passphrase; it is in Keychain Access (search `sealctl-unsealed`).
  `diskutil apfs unlockVolume <uuid>` / `hdiutil attach <bundle>` / `sudo cryptsetup open <file> <name>`.
- Backups: `restic -r <repository> snapshots`, with `RESTIC_PASSWORD_COMMAND` reading the
  password from your store, and the storage credentials from it in the environment.
- SSH: log out and in once; `ssh-add -l` lists your keys.
- Secrets: in your store under `secret/<name>`. Programs that used `sealctl run` need another
  way to get them (your password manager's CLI, or `.sealctl.toml` again with 0.7).
