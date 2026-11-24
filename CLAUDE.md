# sealctl: rules for AI agents

This file is read by Claude Code, including the GitHub review and "@claude" workflows. It holds
the rules for working in this repository; `SPEC.md` is the build spec. When a rule here and the
SPEC disagree, say so and fix one of them in the pull request; don't silently pick.

## What this is

- `sealctl`: keys for developers and their AI agents. API keys, SSH and git signing keys,
  encrypted volumes and backups, opened only when the user's phone approves. Every key comes
  from 24 words held by the phone app; the 24 words alone open every object (`sealctl recover`).
- This repository: the CLI and session daemon (`crates/sealctl`), the protocol core shared with
  the phone apps (`crates/sealctl-core`, MIT, UniFFI behind the `uniffi` feature), the
  in-process fake relay and scripted phone used by the tests (`crates/sealctl-fakerelay`), fuzz
  targets (`fuzz/`), and the protocol (`docs/protocol.md`, vectors in `docs/vectors/`).
- Specs: `SPEC.md` (CLI, daemon, core, tests, CI), `docs/protocol.md` (wire formats,
  derivation, Relay API, vectors), `docs/ai-agents.md`, `docs/threat-model.md`,
  `docs/design.md`. Read the relevant section before changing behaviour, and update it in the
  same pull request when behaviour changes.

## Product facts that must stay consistent

- Describe the current product only (0.7 and later): no Ledger, OpenPGP-on-Ledger, 0.5 or 0.6
  history in READMEs, docs or the CHANGELOG.
- Approval is per work session or on every use (own-approval secrets). "One tap per use" is
  wrong.
- When summarising sealctl, name encrypted volumes and backups alongside API and SSH keys.
- Level 3 (unseal everything, show the words, delete relay data) waits two hours away from a
  trusted place; a place added by hand lifts that wait only after 24 hours.
- Output uses these words and no others for the same things: Locked, Open, Waiting, One tap,
  Places, words, seed, phone, machine (SPEC 1). The 4-character fingerprint is shown as
  `seed qHWf`; "words" is the 24 words the user writes down and types.
- Claims in docs are true and checkable: no counts, badges, quotes or invented audits.

## The protocol is a contract

- `docs/protocol.md` and the vectors (`docs/vectors/v1.json`, `relay-signing.json`) are the
  contract between this CLI, the phone apps and the relay. The apps load `v1.json`; the relay's
  tests load `relay-signing.json`. Changing a vector for an existing protocol version is a
  protocol break.
- No new cryptography (CONTRIBUTING.md): only the established crates in SPEC 2.1; no
  hand-written HKDF, HPKE, AEAD, base64 or constant-time compare. Changes to the protocol, key
  handling or the store format start as a pull request to `docs/protocol.md`, and
  `docs/vectors/generate.mjs`, the JSON and the code move together (CI regenerates and diffs).
- Secrets go to child processes through stdin or inherited file descriptors, never arguments or
  environment variables visible to other users. Secret types zeroise, are never logged, and
  have no `Debug`, `Display` or `Serialize` (SPEC 20).
- Never add files that must be backed up: everything is recoverable from the 24 words.

## Tests

- Tests run against the in-process fake relay (`crates/sealctl-fakerelay`) with temporary
  `HOME` folders. Never point tests, scripts or loops at the staging or production relay; never
  set `SEALCTL_TEST_RELAY` in CI or from an agent. Never touch a real `HOME`, keychain,
  `~/.ssh`, `~/.config/sealctl`, volumes or backups.
- A bug fix comes with a test that fails without the fix (write it first and watch it fail).
- Flaky tests are fixed, not retried into green. Order events with the fake clock, a gate or an
  explicit signal, never with a sleep.
- Every client loop pauses after an error, backs off (doubling up to a cap, with jitter), waits
  out `429` and `Retry-After`, and never repeats a call that got a final answer (`404 gone`,
  `403`, any `400`); `401 clock_skew` is retried once.
- Before pushing: `cargo fmt --all`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked` (or the crates and tests the change touches). Resume tests need
  `--features test-hooks`; OS-tool tests need restic and, on Linux, cryptsetup.

## CI shape

- One run per pull request, cancelled by a newer push; runs on `main`, tags, schedules and
  manual runs get a concurrency group of their own (`github.run_id`) and are never cancelled.
  Every job has `timeout-minutes`.
- Required checks never sit behind a workflow-level `paths:` filter (it leaves them pending
  forever): a `changes` job reads the pull request's file list and jobs use a job-level `if`
  (a skipped job passes). macOS extras run on pull requests only when their files change.
- Workflows that hold secrets never run pull request code: no secrets on `pull_request` jobs
  (the Claude workflows' `CLAUDE_CODE_OAUTH_TOKEN` is the one documented exception), no
  `pull_request_target`, no `${{ }}` inside `run:` (pass values through `env:`).

## Supply chain

- GitHub Actions pinned to full commit SHAs with the version in a comment; least-privilege
  `permissions` (workflow default `{}`); `persist-credentials: false`. A new third-party action
  needs a pull request that says why, and the org allow-list changes only by the owner.
- Rust: `Cargo.lock` committed; `cargo deny` (advisories, licences, sources, bans) and
  `cargo vet` pass. A `cargo vet` exemption or audit written by an agent says so in its notes:
  "reviewed by an AI agent (Claude) on <date> ... not a human audit". No git dependencies.
- A new dependency needs a reason in the pull request: who maintains it, how widely it is used,
  what runs at build time. No new crate for what a few lines of safe code can do (except
  crypto, which always comes from an established crate).
- Dependabot is grouped with a cooldown; review its updates like any other change.

## Privacy

- Never add personal names, personal email addresses, home addresses, phone numbers or any
  Cloudflare Workers development hostname (the "workers dot dev" domain) to code, docs, tests,
  fixtures, commits or pull requests. The staging relay's hostname is private: write
  `https://<relay>` instead. Examples use `dev@mbp.example.com` style names. Public contact is
  `support@sealctl.com`.
- Never read, print or copy secret values (tokens, keys, `.env` contents, the 24 words).

## Security wording

Until a fix is released, commit messages, pull request titles and descriptions, CHANGELOG
lines and code comments describe a security fix neutrally (what changed, not how to exploit
the old behaviour), with no severity or attack details. Findings are discussed privately; see
SECURITY.md.

## Commits and pull requests (also for @claude)

- Work on a branch and open a pull request; `main` is protected. Squash merges only, done by a
  maintainer after CI is green and review comments are answered.
- Keep commits focused; stage files by path. Describe what was tested. Add a line to
  `CHANGELOG.md` under *Unreleased* for user-visible changes.
- An agent never merges, approves, force-pushes, pushes to `main`, creates or moves tags,
  creates releases, deploys, changes workflows, rulesets, repository settings or secrets, or
  spends quotas at scale. When asked to, it explains that a maintainer has to.
- The "@claude" workflow runs on Linux without restic, cryptsetup or macOS tools: run the tests
  the change touches and say which ones could not run there.

## Reviewing

Reviews follow `.github/claude-review.md`: report only real, specific problems with a severity,
the reason and a concrete fix, and one summary of what was checked.
