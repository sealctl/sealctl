# How Claude reviews pull requests here

The automated review (`.github/workflows/claude-code-review.yml`) and "@claude review this"
both follow this file, together with `CLAUDE.md`. The review is advice: it never approves,
blocks, pushes or merges.

## What to report

Report only real, specific problems you can point to in this pull request's diff, in this
order of priority (skip the areas the change does not touch):

1. **Correctness.** Wrong results, missed cases the code claims to handle, broken error paths,
   off-by-one, wrong units, state left half-changed after a failure, resume or retry that
   repeats a step that already took effect.
2. **Security.** Secrets or key material reaching logs, errors, arguments, the environment of
   other processes, files or the network; checks done after use instead of before; signatures,
   proofs, sizes or times not checked; anything weakening the approval model.
3. **Privacy.** Personal names, emails, home addresses, phone numbers, Cloudflare Workers
   development hostnames (the "workers dot dev" domain) or the staging relay's hostname in code,
   docs, tests, fixtures or commit text; locations, IP addresses or request contents leaving
   where the SPEC keeps them.
4. **Protocol and SPEC consistency.** Behaviour that differs from `SPEC.md` or
   `docs/protocol.md` without changing them in the same pull request; any change to the test
   vectors (a protocol break); words the product does not use (Locked, Open, Waiting, One tap,
   Places, words, phone, machine).
5. **Concurrency and timing.** Locks or guards held across an `await`; races between a timer
   and a request; wall clock where a monotonic clock is needed (or the reverse: sleep and clock
   changes); retry or reconnect loops without a pause, backoff or `429` handling.
6. **Test quality.** A fix without a test that fails without it; tests that sleep to order
   events instead of using a fake clock, a gate or an explicit signal; tests that talk to a
   live relay; assertions that cannot fail.
7. **Supply chain and CI shape.** Actions not pinned to a full commit SHA; broader
   `permissions` than the job needs; secrets on `pull_request` jobs; `pull_request_target`;
   jobs without `timeout-minutes`; required checks behind a workflow-level `paths:` filter;
   new dependencies without a reason; `cargo vet` exemptions without the note "reviewed by an
   AI agent, not a human audit"; npm installs that run scripts.

Do not report:

- style, naming, formatting, comment wording or "could be cleaner" (formatters and linters run
  in CI);
- "consider adding tests" or "consider handling errors" without naming the concrete case that
  is not covered and what goes wrong;
- problems that were there before this pull request, unless the change makes them worse;
- guesses. Read the code around a change before you claim a bug, check `SPEC.md` when
  behaviour changes, and when you cannot settle a point, say "I could not verify X" in the
  summary instead of filing it as a finding.

## Generated files

Do not review these line by line; review the source change that produced them instead:

- `Cargo.lock` and `flake.lock`: review `Cargo.toml` and `flake.nix` (which dependency, why,
  who maintains it, what runs at build time: `build.rs`, proc macros);
- `supply-chain/imports.lock`: review `supply-chain/config.toml` and `audits.toml`;
- `THIRD-PARTY-NOTICES.md`: review `scripts/notices.sh`, `about.toml` and the dependency change.

When the diff changes a source without the file generated from it (or the reverse), say so.

## Checklist for this repository

- **Core crypto and vectors** (`crates/sealctl-core`, `docs/protocol.md`, `docs/vectors/`):
  no new construction and no hand-written primitive (SPEC 21); established crates only;
  `#![forbid(unsafe_code)]` outside the UniFFI scaffolding; secret types zeroise and have no
  `Debug`, `Display`, `Serialize` or unneeded `Clone` (SPEC 20); no `format!` of a value; key
  material never crosses the UniFFI boundary. A change to `v1.json` or `relay-signing.json`
  for an existing protocol version is a protocol break: **blocker** unless the pull request is
  the protocol change itself and says so. `generate.mjs`, protocol.md and the JSON move
  together.
- **Daemon state machine** (`crates/sealctl/src/daemon/`, SPEC 6): Locked, Open, Waiting
  transitions as in 6.3, including joiners of a pending `open` and Ctrl-C; the lock order of
  6.5 (keys wiped first, backups, unmount, status); idle allowance, hard stop and clock changes
  as in 6.4 (a request right after a wake checks the time first); a grant arriving while a lock
  or exit runs gives nothing to a later session; no lock or mutex guard held across an
  `.await` that waits on the phone, the relay or an OS tool.
- **Volume, migrate and unseal resume safety** (`volume/`, `migrate.rs`, `seal/`, SPEC 13,
  16, 18): every step is checked against the object before it is repeated, so a step that took
  effect before a kill is recorded, not redone; never remove the only key that opens an
  object; passwords and values only to the chosen store, never to the journal, `plan.json`,
  `handback.json`, arguments or logs; journal lines appended and `fsync`ed; exit 13 on a stop
  part way; the kill-and-resume tests (`--features test-hooks`) cover a new step.
- **AI agent hooks** (`crates/sealctl/src/ai/`, `guard.rs`, `docs/ai-agents.md`): refusals
  inside agents (`secret get`, `recover`, `seal`, `unseal`, helpers, `buy`) stay; masking
  cannot be turned off inside an agent; `ai install` then `ai uninstall` leaves settings
  byte-identical; hook output never carries a value.
- **Relay client** (`relay.rs`): every poll and reconnect pauses after an error and backs off;
  `429` waits out `Retry-After`; terminal answers are not retried (relay rules referenced in
  CLAUDE.md).
- **Output and exit codes** (SPEC 5): the documented exit code for each failure; messages to
  stderr; nothing an agent reads changes because of the licence ask.

## How to write each comment

- One inline comment per distinct problem, on the line that causes it. At most about 8 inline
  comments; if there are more, keep the most severe and list the rest in one line each in the
  summary.
- Start with the severity in bold: **blocker** (wrong behaviour, security or privacy problem,
  protocol break: must not merge as is), **should fix** (a real problem with limited impact, or
  a missing test for a concrete case), **nit** (small but real, such as a misleading error
  message; at most 2 per review, and never for style).
- Then: what is wrong, why it matters here (the input or sequence that triggers it), and a
  concrete fix. Use a suggestion block only when committing it fixes the problem entirely.
- Quote the rule when the finding is a `CLAUDE.md` or `SPEC.md` rule, with its section.

## The summary comment

One comment, rewritten on every push, in this shape:

```markdown
### Claude review: <verdict>

<one or two sentences: what the change does, as you understood it>

**Checked:** <the areas you actually checked, e.g. correctness of the resume path, SPEC 18.6,
the new test, workflow permissions>
**Findings:** <n> blocker, <n> should fix, <n> nit (inline). <one line per finding that did not
fit inline>
**Could not verify:** <what you could not settle and why, or "nothing">
```

Verdicts: **no issues found**, **minor issues** (nits or should-fix only), **changes
suggested** (at least one should-fix that matters), **blocking issues** (at least one blocker).
Saying "no issues found" is a good outcome; do not invent findings to fill the review.
