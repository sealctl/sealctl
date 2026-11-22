# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
**Security → Report a vulnerability** on this repository
(GitHub private vulnerability reporting).

Include the affected version or commit, your OS, the phone's OS and app version if the phone
was involved, and steps to reproduce. Never include your 24 words or real secret values. You
should get a first response within 7 days.

## Scope

In scope:

- `sealctl-core`: key derivation, `.sealed` and `.id` formats, pairing, request and reply
  sealing, plan signatures (specified in [docs/protocol.md](docs/protocol.md));
- the `sealctl` CLI and daemon: secret handling (pipes, memory, files), masking and agent
  refusals, file permissions, command construction, `seal`, `unseal` and `recover`;
- the relay API as the CLI uses it (Relay API in docs/protocol.md). Report relay problems
  here too.

The phone app has its own repository: [sealctl/app](https://github.com/sealctl/app).

Out of scope (report upstream instead):

- The cryptographic crates sealctl builds on: RustCrypto (`sha2`, `hmac`, `hkdf`,
  `chacha20poly1305`), `ed25519-dalek`, `x25519-dalek`, `hpke`, `bip39`
- restic, APFS, LUKS/cryptsetup

## Supported versions

Only the latest release receives fixes.
