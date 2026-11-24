# Design

How sealctl is put together. The rules for every byte on the wire, every key and every
file format are in [protocol.md](protocol.md); the command-line behaviour is in
[../SPEC.md](../SPEC.md). This page is the map.

## Components

```text
crates/
  sealctl-core      protocol and crypto, shared with the phone apps (UniFFI)
  sealctl           CLI and daemon (binary `sealctl`)
  sealctl-fakerelay test only: in-process relay and scripted phone
```

```text
sealctl (CLI)                       sealctl daemon (one per user)
 ├─ pair       QR code / link        ├─ session: Locked / Open / Waiting, timers, credit
 ├─ secret     store on .sealed      ├─ keys held while Open (store, volumes, backups)
 ├─ run        env + masking         ├─ agent allowances, own-approval keys per command
 ├─ volume     APFS · bundle · LUKS  ├─ machine channel: status out; lock/answers/notice in
 ├─ backup     restic                ├─ SSH agent socket on store keys
 ├─ seal       take over             └─ socket ~/.local/state/sealctl/daemon.sock (0600, peer uid)
 ├─ unseal     hand back
 ├─ recover    24 words only
 └─ status, cancel, buy, doctor
        │
        ▼ approve: seal request (HPKE to the phone, signed), wait socket, open reply
      relay (Cloudflare Worker; sees sealed strings, ids, timing)
        │
        ▼
      phone app (sealctl-core): open request, number match, plan signature, sealed reply
```

## Keys

The phone's root comes from the 24 words (BIP39 seed, then HKDF); every object key is
`derive(root, "<purpose>:<object id>", 16)` with the id readable from the object itself (store
folder name, volume UUID, repository folder). A machine keeps only its pairing key and box key
(`machine.json`, 0600). Object keys reach a machine only inside a reply sealed to a one-time
key of that request, and live in daemon memory while the session is Open (or for one command).
Each object carries a public `.id` file or marker with the seed fingerprint (`seed qHWf`: it
names the seed the 24 words make) and a key check, so a wrong key is noticed before it is used
and `recover` can check the words.

## Approvals

| Situation | Request | Level |
| --- | --- | --- |
| First use while Locked (`run`, `secret get`, `volume open`, SSH signing) | `open`, with agent `uses` when an agent asks | 1 |
| An agent's first use of a secret in a repository while Open | `agent` | 1 |
| A new object while Open | `keys` | 1 |
| An own-approval secret | `own`, every time | 1 |
| `seal` of an existing object | `keys`, `lvl` 2, number match | 2 |
| `unseal <object>` | `unseal` with the plan, number match | 2 |
| `unseal --all` | `unseal` with the plan, number match, delay away from trusted places | 3 |

The CLI prints `Waiting for your phone` once, with the number when one is shown. The phone
decides the level; the CLI can only raise it. A level 3 approval comes back with a plan
signature over the plan hash, the request id and the not-before time; the CLI checks it and
acts only on objects named by the plan. Delayed approvals are held by the relay and can be
cancelled from the phone or any paired machine (`sealctl cancel`).

## Session

The daemon opens the session with one `open` request covering the store key, the keys of
volumes that mount with the session, and backup keys. The idle allowance is
`min(cap, base + rate × minutes worked)` with `cap/base/rate` from the phone's reply (they
depend on where the phone is); the hard stop is 02:00 or 14 hours after the first open. Credit
survives locks and restarts (`session.json`, no keys). Locking wipes the keys, runs on-lock
backups, closes volumes and tells the phone. While Open, the daemon keeps the machine socket
to the relay: it sends sealed status (state, time left, usage log) and applies sealed
messages from the phone (lock, remembered answers, notices of level 3 actions).

## Files

| Path | Content |
| --- | --- |
| `~/.config/sealctl/config.toml`, `machine.json` | Relay and store folder; the pairing |
| `~/.config/sealctl/volumes/*.toml`, `backups/*.toml` | Object definitions with id, words, check |
| `~/.local/share/sealctl/store/<store-id>/` | `.sealed` files and `<store-id>.id` |
| `~/.local/state/sealctl/` | Sockets, `session.json`, `licence.json`, `answers.json`, logs |
| `~/sealctl-unsealed-<date>/` | One `seal`/`unseal` run: plan, journal, the folder store |

## Testing

`sealctl-fakerelay` implements the Relay API in memory with real signature checks, and a
scripted phone built on `sealctl-core` answers requests the way a test says (approve, decline,
pick the right or a wrong number, delay, send a lock message). The integration tests run the
real binary in temporary HOMEs against it, or against a live relay with
`SEALCTL_TEST_RELAY`. macOS runs sparse bundles with `hdiutil`; restic uses folder
repositories.
