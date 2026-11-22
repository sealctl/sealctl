# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
**Security → Report a vulnerability** on this repository
(GitHub private vulnerability reporting).

Include the affected version or commit, your OS, the phone's OS and app version if the phone
was involved, and steps to reproduce. Never include your 24 words or real secret values. You
get a first answer within three working days.

## Safe harbour

We welcome good-faith security research. If you follow this policy, we will not pursue or
support legal action against you, and we will treat your research as authorised. That means:
test only with your own phone, words and machines, and on the relay only your own pairings and
identities; never access, change or keep other people's data; don't degrade the relay (no
denial-of-service or load tests) and don't test Cloudflare's, Paddle's, Apple's or Google's
systems; give us a reasonable time to fix before you publish (90 days by default, sooner by
agreement). If a third party takes action against you for research done under this policy, we
will say that it was authorised.

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
