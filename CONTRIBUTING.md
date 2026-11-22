# Contributing to sealctl

Thanks for your interest in sealctl.

**Issues are welcome:** bug reports, questions and ideas, on
[GitHub issues](https://github.com/sealctl/sealctl/issues). **Security reports are welcome**,
privately: see [SECURITY.md](SECURITY.md), never a public issue.

**Code pull requests are not accepted for now.** The terms for outside contributions (a
contributor licence agreement, and an AGPL section 7 permission for the phone app) are not
settled yet, so pull requests can only be opened by maintainers. This file will say when that
changes. The rules below are how the code is written and apply to maintainers today.

## The hard rule: no new cryptography

`sealctl` is built only from established components: HKDF, HPKE (RFC 9180), Ed25519, X25519,
ChaCha20-Poly1305 and BIP39 from established Rust crates, and APFS, LUKS2 and restic for data at
rest. How they are combined (derivation, sealed files, pairing, requests and replies) is
specified in [docs/protocol.md](docs/protocol.md) and pinned by the test vectors in
`docs/vectors/`, which must never change for an existing protocol version. Pull requests that
add new constructions or alter the derivation will be declined, however well-meant. Changes to
the protocol, key handling or the store format start as a pull request to `docs/protocol.md`.
Orchestration, UX, platform support and docs are all fair game.

Other rules for security-sensitive code:

- Secrets go to child processes via stdin or inherited file descriptors — never arguments or
  environment variables visible to other users.
- Zeroize secret buffers when done; never log them, even at trace level.
- Never add files that must be backed up: everything must be recoverable from the 24 words.

## Development

```sh
cargo build
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

`cargo test` runs the unit tests and the real `sealctl` binary against an in-process fake relay
with a scripted phone (`crates/sealctl-fakerelay`). To test with a real phone, pair it with a
throwaway HOME: `SEALCTL_RELAY=https://<relay> scripts/pair-test.sh`.

Backup tests need `restic`; on Linux, volume tests need `cryptsetup`.

Tests that kill a run at a set point and resume it need the test hooks:
`cargo test -p sealctl --features test-hooks --test unseal resume_after_a_kill`.

## Pull requests (maintainers)

- Keep PRs focused; describe what you tested (OS, and the phone's OS and app version if the
  phone was involved).
- Add tests for pure logic (parsing, formats, plans).
- Update `CHANGELOG.md` under *Unreleased*.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
